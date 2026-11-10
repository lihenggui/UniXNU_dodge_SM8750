// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeIPhoneFramebuffer.h"
#include "DodgeDisplayService.h"
#include "OriginalLegacyFramebufferABI.h"
#include "OriginalLegacySwapABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSSymbol.h>
#include <kern/debug.h>

// A fixed firmware-GOP backend for this one original iPhone ABI. Unsupported
// controller/telemetry operations return an error without touching outputs.
// This does not implement panel power, composition or a hardware vblank.
class DodgeIPhoneFramebuffer final : public IOMobileFramebufferLegacy {
    OSDeclareDefaultStructors(DodgeIPhoneFramebuffer)
    DodgeDisplayService *service=nullptr;
    IOOptionBits pendingOptions=0;
    bool starting=false,parentStarted=false,registrationRequested=false,everStarted=false;
    bool parentStopping=false,parentCleanupPending=false;
    IOService *pendingDetach=nullptr;
    // Legacy's startup thread retains this display, then reads its raw
    // provider at +5096. Stop does not join that thread. Keep the provider
    // alive even if drain and registry detach finish before it runs.
    IOService *lifetimeProvider=nullptr;
    void finishDetach() {
        auto *provider=pendingDetach;pendingDetach=nullptr;
        if(provider) {IOService::detach(provider);provider->release();}
    }
    void stopParent(IOService *provider) {
        if(__atomic_load_n(&starting,__ATOMIC_ACQUIRE))return;
        __atomic_store_n(&parentStarted,false,__ATOMIC_RELEASE);
        if(__atomic_exchange_n(&parentCleanupPending,false,__ATOMIC_ACQ_REL)) {
            parentStopping=true;
            IOMobileFramebufferLegacy::stop(provider);
            parentStopping=false;
        }
        finishDetach();
    }
    static IOReturn stopParentAction(OSObject *owner,void *argument,void *,void *,void *) {
        auto *self=static_cast<DodgeIPhoneFramebuffer *>(owner);
        if(__atomic_load_n(&self->starting,__ATOMIC_ACQUIRE))return kIOReturnBusy;
        self->stopParent(static_cast<IOService *>(argument));return kIOReturnSuccess;
    }
    void ensureParentCleanup(IOService *provider) {
        if(!__atomic_load_n(&parentCleanupPending,__ATOMIC_ACQUIRE))return;
        auto *loop=dodge_display_service_workloop(service);
        loop->retain();loop->runAction(stopParentAction,this,provider);loop->release();
    }
    static void stopped(IOService *owner,IOService *provider) {
        static_cast<DodgeIPhoneFramebuffer *>(owner)->stopParent(provider);
    }
    static IOReturn detachOnGate(OSObject *owner,void *argument,void *,void *,void *) {
        auto *self=static_cast<DodgeIPhoneFramebuffer *>(owner);
        auto *provider=static_cast<IOService *>(argument);
        if(self->pendingDetach && self->pendingDetach!=provider)return kIOReturnBadArgument;
        if(!self->pendingDetach) {provider->retain();self->pendingDetach=provider;}
        if(self->parentStopping)return kIOReturnBusy;
        if(__atomic_load_n(&self->starting,__ATOMIC_ACQUIRE)) {dodge_display_service_stop(self->service);return kIOReturnBusy;}
        DodgeDisplayServiceStatus status={};
        if(!dodge_display_service_status(self->service,&status))return kIOReturnNotReady;
        if(status.stopped) {self->stopParent(provider);return kIOReturnSuccess;}
        return dodge_display_service_stop(self->service);
    }
    struct ClientCall {task_t task;void *security;UInt32 type;IOUserClient **out;};
    static IOReturn createClient(IOService *owner,void *argument) {
        auto *self=static_cast<DodgeIPhoneFramebuffer *>(owner);
        auto *call=static_cast<ClientCall *>(argument);
        if(!__atomic_load_n(&self->parentStarted,__ATOMIC_ACQUIRE) || self->parentStopping)return kIOReturnNotReady;
        return self->IOMobileFramebufferLegacy::newUserClient(call->task,call->security,call->type,call->out);
    }
    static IOReturn cleanupInit(OSObject *owner,void *,void *,void *,void *) {
        auto *self=static_cast<DodgeIPhoneFramebuffer *>(owner);
        auto *gate=IPhone16Swap::load<IOCommandGate *>(self,5040);
        auto *loop=IPhone16Swap::load<IOWorkLoop *>(self,5048);
        if(gate && gate->getWorkLoop()) {
            if(gate->getWorkLoop()!=loop || loop->removeEventSource(gate)!=kIOReturnSuccess)
                panic("Dodge display: cannot detach original init gate");
        }
        IPhone16Swap::store<IOCommandGate *>(self,5040,nullptr);
        IPhone16Swap::store<IOWorkLoop *>(self,5048,nullptr);
        if(gate)gate->release();
        if(loop)loop->release();
        return kIOReturnSuccess;
    }
    static IOReturn publish(OSObject *owner,void *value,void *,void *,void *) {
        auto *self=static_cast<DodgeIPhoneFramebuffer *>(owner);
        if(!__atomic_load_n(&self->parentStarted,__ATOMIC_ACQUIRE) || !dodge_display_service_ready(self->service))return kIOReturnNotReady;
        self->IOService::registerService(reinterpret_cast<uintptr_t>(value));
        return __atomic_load_n(&self->parentStarted,__ATOMIC_ACQUIRE) && dodge_display_service_ready(self->service)?kIOReturnSuccess:kIOReturnNotReady;
    }
    IOReturn publishRequested(IOOptionBits options) {
        auto *loop=getWorkLoop();if(!loop)return kIOReturnNotReady;
        loop->retain();const IOReturn result=loop->runAction(publish,this,reinterpret_cast<void *>(uintptr_t(options)));
        loop->release();return result;
    }
public:
    bool start(IOService *provider) override {
        if(everStarted || !provider)return false;
        everStarted=true;
        provider->retain();lifetimeProvider=provider;
        service=dodge_display_service_create(this,provider,stopped);
        if(!service)return false;
        __atomic_store_n(&starting,true,__ATOMIC_RELEASE);
        const bool result=IOMobileFramebufferLegacy::start(provider);
        // In this pinned kernel the qualified IOService::start always returns
        // true. Legacy can still fail after retaining root/events/locks and
        // only logs that failure. Its partial resources require parent stop,
        // after start returns and the owned frontend has finished draining.
        __atomic_store_n(&parentCleanupPending,true,__ATOMIC_RELEASE);
        __atomic_store_n(&parentStarted,result,__ATOMIC_RELEASE);
        __atomic_store_n(&starting,false,__ATOMIC_RELEASE);
        if(!result || !registrationRequested || !dodge_display_service_ready(service)) {
            const IOReturn drained=dodge_display_service_stop(service);
            // Startup can have drained before the parent returned. In that
            // case the completion already ran while parentStarted was false.
            if(drained==kIOReturnSuccess)ensureParentCleanup(provider);
            return false;
        }
        if(publishRequested(pendingOptions)!=kIOReturnSuccess) {dodge_display_service_stop(service);return false;}
        return true;
    }
    void registerService(IOOptionBits options=0) override {
        // Original start calls virtual 84 before returning. Hold that request
        // until its result and the fully connected source frontend are known.
        if(__atomic_load_n(&starting,__ATOMIC_ACQUIRE)) {registrationRequested=true;pendingOptions=options;return;}
        publishRequested(options);
    }
    bool startHardware() override {return dodge_display_service_start(service)==kIOReturnSuccess;}
    IOReturn submitPacket(const void *packet,void *submitter) override {
        return dodge_display_service_submit(service,packet,submitter);
    }
    bool validateSwapRequest(IOMFBSwapIORequest *request) override {
        return dodge_display_service_validate(service,request);
    }
    void kickSwapQueue() override {dodge_display_service_kick(service);}
    void stop(IOService *provider) override {
        if(service && dodge_display_service_stop(service)==kIOReturnSuccess)ensureParentCleanup(provider);
    }
    void detach(IOService *provider) override {
        if(!provider)return;
        if(!service) {IOService::detach(provider);return;}
        // IOService retains this attachment. Keep it intact across a busy
        // asynchronous drain; completion calls parent stop before detaching.
        auto *loop=dodge_display_service_workloop(service);
        loop->retain();loop->runAction(detachOnGate,this,provider);loop->release();
    }
    IOReturn newUserClient(task_t task,void *security,UInt32 type,IOUserClient **out) override {
        if(!out)return kIOReturnBadArgument;
        *out=nullptr;ClientCall call={task,security,type,out};
        return dodge_display_service_admit(service,createClient,&call);
    }
    void systemWillShutdown(IOOptionBits) override {if(service)dodge_display_service_stop(service);}
    IOReturn setPowerState(unsigned long,IOService *) override {return kIOReturnUnsupported;}
    void free() override {
        if(pendingDetach)panic("Dodge display: freeing an attached pending drain");
        if(service) {
            auto *owned=service;service=nullptr;
            if(dodge_display_service_release(owned)!=kIOReturnSuccess)
                panic("Dodge display: freeing a controller before drain");
        }
        // Original free only calls its parent. Its failed init may still own
        // a gate and/or a work loop; successful original stop already nulled
        // them. Keep the loop alive throughout this final gated cleanup.
        auto *loop=IPhone16Swap::load<IOWorkLoop *>(this,5048);
        if(loop) {loop->retain();loop->runAction(cleanupInit,this);loop->release();}
        else cleanupInit(this,nullptr,nullptr,nullptr,nullptr);
        auto *provider=lifetimeProvider;lifetimeProvider=nullptr;
        if(provider)provider->release();
        IOMobileFramebufferLegacy::free();
    }
    uint32_t backend211(uint32_t,void *,uint32_t) override {return uint32_t(kIOReturnUnsupported);}
    uint32_t backend212(uint32_t,uint32_t *,void *) override {return uint32_t(kIOReturnUnsupported);}
    uint32_t backend242(void *,void *) override {return uint32_t(kIOReturnUnsupported);}
    // Raw ABI-only return leaf. No source caller or argument prototype is
    // asserted for 243; assembly preserves the exact stock register effects.
    __attribute__((naked,noinline)) void opaque243() override;
    void backend292(void *,bool) override {}
    uint32_t backend293(void *,void *) override {return uint32_t(kIOReturnUnsupported);}
    uint32_t backend321(uint32_t,void *,uint32_t *,uint32_t) override {return uint32_t(kIOReturnUnsupported);}
    void backend322(uint32_t) override {}
    uint32_t backend329() override {return 0;}
};
static_assert(sizeof(DodgeIPhoneFramebuffer)==5768,"Exact Legacy base plus owned source service state");
__attribute__((naked,noinline)) void DodgeIPhoneFramebuffer::opaque243() {
    __asm__ volatile("mov w0, #0x2c7\nmovk w0, #0xe000, lsl #16\nret");
}
OSDefineMetaClassAndStructors(DodgeIPhoneFramebuffer,IOMobileFramebufferLegacy)

extern "C" void dodge_iphone_framebuffer_class_initializer() asm("__GLOBAL__sub_I_DodgeIPhoneFramebuffer.cpp");
static bool initialized=false;
static bool registered(const char *className,const OSMetaClass *expected) {
    const OSSymbol *name=OSSymbol::withCStringNoCopy(className);
    if(!name)return false;
    const bool found=OSMetaClass::getMetaClassWithName(name)==expected;
    name->release();return found;
}
bool dodge_iphone_framebuffer_initialize() {
    if(__atomic_load_n(&initialized,__ATOMIC_ACQUIRE))return true;
    if(!registered("IOMobileFramebufferLegacy",&IOMobileFramebufferLegacy::gMetaClass))return false;
    dodge_iphone_framebuffer_class_initializer();__atomic_store_n(&initialized,true,__ATOMIC_RELEASE);return true;
}
IOService *dodge_iphone_framebuffer_allocate() {
    // The initializer constructs gMetaClass during preModLoad; postModLoad must
    // also have registered it before alloc/init/metaCast can use the instance.
    if(!dodge_iphone_framebuffer_registered())return nullptr;
    return new DodgeIPhoneFramebuffer;
}
bool dodge_iphone_framebuffer_registered() {
    return __atomic_load_n(&initialized,__ATOMIC_ACQUIRE) && registered("DodgeIPhoneFramebuffer",&DodgeIPhoneFramebuffer::gMetaClass);
}
