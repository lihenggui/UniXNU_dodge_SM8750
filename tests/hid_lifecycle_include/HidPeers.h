// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>
using IOReturn=int;
using IOOptionBits=unsigned;
using IOFixed=int32_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnBusy=-3,
    kIOReturnNoMemory=-4,kIOReturnUnsupported=-5;
constexpr unsigned kOSKextExcludeNone=0;
class OSObject;class IOService;class IOHIDEvent;class IOWorkLoop;
struct PE_Video {uint64_t v_width=1440,v_height=3168,v_rotate=0;};
namespace hid_peer {
struct Control {
    IOWorkLoop *loop=nullptr;
    bool initOk=true,startOk=true,videoOk=true,validProvider=true,requireStartGate=true;
    std::atomic<unsigned> inits{0},starts{0},stops{0},forwards{0},nativeFrees{0},activeStart{0},activeDispatch{0};
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
    unsigned depth=0;
    std::thread::id owner;
public:
    using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    IOReturn runAction(Action action,OSObject *target,void *a=nullptr,void *b=nullptr,void *c=nullptr,void *d=nullptr){
        if(hid_peer::state.beforeGate)hid_peer::state.beforeGate();
        std::lock_guard<std::recursive_mutex> lock(mutex);
        if (!depth) owner=std::this_thread::get_id();
        ++depth;const auto result=action(target,a,b,c,d);--depth;return result;
    }
    bool inGate(){std::lock_guard<std::recursive_mutex> lock(mutex);return depth && owner==std::this_thread::get_id();}
};
class IOService:public OSObject {
public:
    bool inactive=false;
    virtual bool init(OSDictionary * =nullptr){return true;}
    virtual bool start(IOService *){return true;}
    virtual void stop(IOService *){}
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
public:
    inline static OSMetaClass gMetaClass{264};
    bool init(OSDictionary *)override{++hid_peer::state.inits;return hid_peer::state.initOk;}
    bool start(IOService *)override{
        auto &h=hid_peer::state;
        assert(!h.requireStartGate || (h.loop && h.loop->inGate()));
        ++h.starts;++h.activeStart;if(h.onStart)h.onStart(this);--h.activeStart;return h.startOk;
    }
    void stop(IOService *)override{
        auto &h=hid_peer::state;
        assert(!h.activeStart && !h.activeDispatch && "parent stop overlapped admitted work");
        assert(h.loop && h.loop->inGate() && "parent stop escaped gate");
        ++h.stops;if(h.onStop)h.onStop(this);
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
