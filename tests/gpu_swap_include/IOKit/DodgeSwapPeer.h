// SPDX-License-Identifier: MIT
// Software ownership/work-loop peers. These classes are not an IOKit ABI.
#pragma once
#include <cassert>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <utility>

using IOReturn=int32_t;
using IODirection=uint32_t;
enum : IOReturn {
    kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,
    kIOReturnNotPermitted=-3,kIOReturnNoMemory=-4,kIOReturnAborted=-5,
    kIOReturnBusy=-6,kIOReturnError=-7,kIOReturnUnsupported=-8
};
enum : uint32_t {kIODirectionIn=1,kIODirectionOut=2,kIODirectionInOut=3,
    kIOMapAnywhere=1,kIOMapReadOnly=2,kIOMapInhibitCache=4};
enum class DodgeSwapKind : uint32_t {Other,Display,Presenter,Gate,Loop,Map,Memory,Request,Timer};

class OSObject {
public:
    mutable std::atomic<unsigned> references{1};
    DodgeSwapKind kind;
    explicit OSObject(DodgeSwapKind k):kind(k) {}
    virtual ~OSObject() {assert(references<=1);}
    virtual const OSObject *metaCast(const char *name) const {
        return (kind==DodgeSwapKind::Display && !strcmp(name,"IOMobileFramebufferLegacy")) ||
               (kind==DodgeSwapKind::Gate && !strcmp(name,"IOCommandGate")) ? this : nullptr;
    }
    virtual void retain() const {assert(references);++references;}
    virtual void release() const {assert(references);if(!--references)delete this;}
};
class IOTimerEventSource;
class IOWorkLoop : public OSObject {
    std::recursive_mutex mutex;
    inline static thread_local IOWorkLoop *held=nullptr;
public:
    using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
    unsigned actions=0;
    void (*beforeAction)()=nullptr;
    IOWorkLoop():OSObject(DodgeSwapKind::Loop) {}
    bool inGate() const {return held==this;}
    template<class F> auto withGate(F function) {
        std::lock_guard<std::recursive_mutex> lock(mutex);
        struct Restore {IOWorkLoop *previous;~Restore(){held=previous;}} restore{held};
        held=this;
        return function();
    }
    IOReturn runAction(Action action,OSObject *target,void *a=nullptr,void *b=nullptr,void *c=nullptr,void *d=nullptr) {
        return withGate([&] {
            ++actions;auto callback=beforeAction;beforeAction=nullptr;
            if(callback)callback();
            return action(target,a,b,c,d);
        });
    }
    IOReturn addEventSource(IOTimerEventSource *);
    IOReturn removeEventSource(IOTimerEventSource *);
};
class IOMemoryMap;
class IOService : public OSObject {
public:
    IOWorkLoop *loop=nullptr;
    IOMemoryMap *deviceMap=nullptr;
    explicit IOService(DodgeSwapKind k):OSObject(k) {}
    virtual IOWorkLoop *getWorkLoop() const {return loop;}
    virtual IOMemoryMap *mapDeviceMemoryWithIndex(unsigned,uint32_t);
};
class IOCommandGate : public OSObject {
public:
    bool enabled=true;
    IOWorkLoop *loop=nullptr;
    IOCommandGate():OSObject(DodgeSwapKind::Gate) {}
    bool isEnabled() const {return enabled;}
    IOWorkLoop *getWorkLoop() const {return loop;}
};
class IOMemoryMap : public OSObject {
public:
    uintptr_t address=0;
    uint64_t bytes=0,physical=0;
    IOMemoryMap():OSObject(DodgeSwapKind::Map) {}
    uintptr_t getVirtualAddress() const {return address;}
    uint64_t getLength() const {return bytes;}
    uint64_t getPhysicalAddress() const {return physical;}
};
inline IOMemoryMap *IOService::mapDeviceMemoryWithIndex(unsigned index,uint32_t options) {
    assert(index==0 && options==kIOMapInhibitCache);
    if(deviceMap)deviceMap->retain();
    return deviceMap;
}
class IOMemoryDescriptor : public OSObject {
public:
    uint64_t bytes=0;
    IODirection direction=kIODirectionOut;
    IOMemoryMap *mapping=nullptr;
    IOReturn prepareResult=kIOReturnSuccess,completeResult=kIOReturnSuccess;
    unsigned prepares=0,maps=0,completes=0,prepared=0;
    void (*prepareHook)()=nullptr;
    void (*completeHook)()=nullptr;
    IOMemoryDescriptor():OSObject(DodgeSwapKind::Memory) {}
    uint64_t getLength() const {return bytes;}
    IODirection getDirection() const {return direction;}
    IOReturn prepare(IODirection d) {
        assert(d==kIODirectionOut);++prepares;
        if(prepareHook)prepareHook();
        if(!prepareResult)++prepared;
        return prepareResult;
    }
    IOMemoryMap *map(uint32_t options) {
        assert(prepared && options==(kIOMapAnywhere|kIOMapReadOnly));++maps;
        if(mapping)mapping->retain();
        return mapping;
    }
    IOReturn complete(IODirection d) {
        assert(d==kIODirectionOut && prepared);--prepared;++completes;
        if(completeHook)completeHook();
        return completeResult;
    }
};
#define OSSafeReleaseNULL(object) do {if(object){(object)->release();(object)=nullptr;}} while(0)
