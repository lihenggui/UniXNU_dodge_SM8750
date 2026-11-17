// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
using IOReturn=int;
using IOOptionBits=unsigned;
using IOFixed=int32_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnBusy=-3,
    kIOReturnNoMemory=-4,kIOReturnUnsupported=-5;
constexpr unsigned kOSKextExcludeNone=0;
class OSObject;class IOService;class IOHIDEvent;class IOWorkLoop;class IOInterruptEventSource;
struct PE_Video {uint64_t v_width=1440,v_height=3168,v_rotate=0;};
namespace hid_peer {
struct Control {
    IOWorkLoop *loop=nullptr;
    bool initOk=true,startOk=true,videoOk=true,validProvider=true,requireStartGate=true;
    bool cleanupOk=true,addOk=true;
    bool willOk=true;
    std::atomic<unsigned> inits{0},starts{0},stops{0},forwards{0},nativeFrees{0},activeStart{0},activeDispatch{0};
    std::atomic<unsigned> activeProducer{0},cleanupSignals{0},cleanupCallbacks{0};
    std::atomic<unsigned> interfaceCloses{0},nativeWillCalls{0},nativeDidCalls{0},originalDidCalls{0};
    std::vector<IOOptionBits> didOptions;
    std::vector<bool> didDeferred;
    std::function<void()> onClose,onWill,onDid;
    PE_Video video;
    std::function<void(IOService *)> onStart,onStop,onVideo;
    std::function<void()> beforeGate;
    std::function<void(IOService *,IOHIDEvent *,unsigned)> onDispatch;
};
inline Control state;
}
class OSMetaClass {
    unsigned bytes;
public:
    explicit OSMetaClass(unsigned n=0):bytes(n) {}
    unsigned getClassSize()const{return bytes;}
    void releaseMetaClass()const{}
    static const OSMetaClass *copyMetaClassWithName(const OSObject *){return nullptr;}
    static void *preModLoad(const char *){return nullptr;}
    static IOReturn postModLoad(void *){return kIOReturnNotReady;}
};
class OSObject {
    mutable std::atomic<unsigned> references{1};
public:
    virtual ~OSObject()=default;
    void retain()const{assert(references.fetch_add(1)>0);}
    void release()const{assert(references.fetch_sub(1)>0);}
    unsigned retainCount()const{return references.load();}
    virtual void free(){++hid_peer::state.nativeFrees;}
};
class OSDictionary:public OSObject {};
class OSSymbol:public OSObject {
public:
    static const OSSymbol *withCStringNoCopy(const char *){return nullptr;}
};
class OSArray:public OSObject {
public:
    unsigned getCount()const{return 0;}
    OSObject *getObject(unsigned)const{return nullptr;}
};
class IOWorkLoop:public OSObject {
    std::recursive_mutex mutex;
    inline static thread_local IOWorkLoop *current=nullptr;
    std::vector<IOInterruptEventSource *> sources;
public:
    using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    IOReturn runAction(Action action,OSObject *target,void *a=nullptr,void *b=nullptr,void *c=nullptr,void *d=nullptr){
        if(hid_peer::state.beforeGate)hid_peer::state.beforeGate();
        std::lock_guard<std::recursive_mutex> lock(mutex);
        auto *previous=current;current=this;const auto result=action(target,a,b,c,d);current=previous;return result;
    }
    bool inGate(){return current==this;}
    IOReturn addEventSource(IOInterruptEventSource *source);
    void drain();
};
class IOInterruptEventSource:public OSObject {
public:
    using Action=void (*)(OSObject *,IOInterruptEventSource *,int);
    OSObject *owner;Action action;IOWorkLoop *loop=nullptr;unsigned pending=0;
    IOInterruptEventSource(OSObject *target,Action callback):owner(target),action(callback){}
    static IOInterruptEventSource *interruptEventSource(OSObject *owner,Action action);
    virtual void interruptOccurred(void *,IOService *,int){assert(loop && loop->inGate());++pending;++hid_peer::state.cleanupSignals;}
};
namespace hid_peer {inline std::vector<std::unique_ptr<OSObject>> allocations;}
inline IOInterruptEventSource *IOInterruptEventSource::interruptEventSource(OSObject *owner,Action action){
    if(!hid_peer::state.cleanupOk)return nullptr;
    auto value=std::make_unique<IOInterruptEventSource>(owner,action);auto *result=value.get();
    hid_peer::allocations.emplace_back(std::move(value));return result;
}
inline IOReturn IOWorkLoop::addEventSource(IOInterruptEventSource *source){
    assert(inGate() && source);
    if(!hid_peer::state.addOk)return kIOReturnNoMemory;
    source->loop=this;source->retain();sources.push_back(source);return kIOReturnSuccess;
}
inline void IOWorkLoop::drain(){
    assert(!inGate());
    runAction([](OSObject *owner,void *,void *,void *,void *){
        auto *self=static_cast<IOWorkLoop *>(owner);assert(!hid_peer::state.activeProducer);
        for(auto *source:self->sources)if(source->pending){
            const auto count=source->pending;source->pending=0;++hid_peer::state.cleanupCallbacks;
            source->action(source->owner,source,count);
        }
        return kIOReturnSuccess;
    },this);
}
class IOService:public OSObject {
public:
    bool inactive=false;
    IOService *openedClient=nullptr;
    virtual bool init(OSDictionary * =nullptr){return true;}
    virtual bool start(IOService *){return true;}
    virtual void stop(IOService *){}
    virtual bool isOpen(const IOService *client=nullptr)const{return client?openedClient==client:openedClient!=nullptr;}
    virtual void close(IOService *client,IOOptionBits=0){
        auto &h=hid_peer::state;assert(!h.activeProducer && !h.activeStart && !h.activeDispatch);
        assert(h.loop && h.loop->inGate());
        assert((!openedClient || openedClient==client) && "interface close targeted another client");
        openedClient=nullptr;++h.interfaceCloses;if(h.onClose)h.onClose();
    }
    virtual bool willTerminate(IOService *,IOOptionBits){
        auto &h=hid_peer::state;++h.nativeWillCalls;if(h.onWill)h.onWill();return h.willOk;
    }
    virtual bool didTerminate(IOService *,IOOptionBits options,bool *defer){
        auto &h=hid_peer::state;assert(defer);++h.nativeDidCalls;h.didOptions.push_back(options);h.didDeferred.push_back(*defer);
        if(h.onDid)h.onDid();return true;
    }
    bool isInactive()const{return inactive;}
    void *metaCast(const char *name)const{return hid_peer::state.validProvider && !strcmp(name,"IOHIDInterface") ? const_cast<IOService *>(this):nullptr;}
    IOWorkLoop *getWorkLoop()const{return hid_peer::state.loop;}
};
class IOHIDEvent:public OSObject {
public:
    virtual unsigned getType(){return 11;}
    virtual OSArray *getChildren(){return nullptr;}
    virtual int32_t getIntegerValue(unsigned,unsigned){return 0;}
    virtual void setIntegerValue(unsigned,int32_t,unsigned){}
    virtual IOFixed getFixedValue(unsigned,unsigned){return 0;}
};
class IOHIDEventDriver:public IOService {
    IOService *originalInterface=nullptr;
public:
    inline static OSMetaClass gMetaClass{264};
    bool init(OSDictionary *)override{++hid_peer::state.inits;return hid_peer::state.initOk;}
    bool start(IOService *provider)override{
        auto &h=hid_peer::state;
        assert(!h.requireStartGate || (h.loop && h.loop->inGate()));
        originalInterface=provider;provider->openedClient=this;
        ++h.starts;++h.activeStart;if(h.onStart)h.onStart(this);--h.activeStart;return h.startOk;
    }
    void stop(IOService *provider)override{
        auto &h=hid_peer::state;
        assert(!h.activeStart && !h.activeDispatch && "parent stop overlapped admitted work");
        assert(!h.activeProducer && "parent stop overlapped original producer");
        assert(h.loop && h.loop->inGate() && "parent stop escaped gate");
        assert(!provider->isOpen(this) && "parent stop retained interface callback");
        ++h.stops;if(h.onStop)h.onStop(this);
    }
    bool didTerminate(IOService *provider,IOOptionBits options,bool *defer)override{
        ++hid_peer::state.originalDidCalls;
        if(originalInterface)originalInterface->close(this);
        originalInterface=nullptr;return IOService::didTerminate(provider,options,defer);
    }
    virtual void dispatchEvent(IOHIDEvent *event,IOOptionBits options){
        auto &h=hid_peer::state;assert(h.loop && h.loop->inGate());
        ++h.forwards;++h.activeDispatch;if(h.onDispatch)h.onDispatch(this,event,options);--h.activeDispatch;
    }
    void free()override{assert(false && "unqualified original free entered");}
};
class OSKext {
public:
    static IOReturn loadKextWithIdentifier(const char *,bool,bool,unsigned,unsigned,void *){return kIOReturnNotReady;}
};
inline int PE_current_console(PE_Video *video){
    *video=hid_peer::state.video;if(hid_peer::state.onVideo)hid_peer::state.onVideo(nullptr);
    return hid_peer::state.videoOk ? 0:-1;
}
struct kmod_info_t {const char *name;};
#define OSDynamicCast(type,object) dynamic_cast<type *>(object)
#define OSDeclareDefaultStructors(type) public: type(); ~type()override; static OSMetaClass gMetaClass; private:
#define OSDefineMetaClassAndStructors(type,parent) \
    type::type()=default; type::~type()=default; OSMetaClass type::gMetaClass{sizeof(type)};
