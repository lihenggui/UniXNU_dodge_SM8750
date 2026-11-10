// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSoftwareRefresh.h"
#include "OriginalLegacyRefreshABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>

extern "C" {
volatile uint64_t native_gop_vsync[3];
uint64_t mach_continuous_time(void);
}
struct DodgeSoftwareRefresh {
    uint32_t references;
    IOService *display;
    IOCommandGate *gate;
    IOWorkLoop *loop;
    IOTimerEventSource *timer;
    uint64_t interval,next,generation;
    IOReturn status;
    bool enabled,stopping;
};
static DodgeSoftwareRefresh *controllerOwner;

static bool ownsGate(const DodgeSoftwareRefresh *controller) {
    return controller && controller->loop->inGate();
}
static bool liveDisplay(const DodgeSoftwareRefresh *controller) {
    return !controller->stopping && controller->gate->isEnabled() &&
        controller->display->getWorkLoop()==controller->loop && controller->gate->getWorkLoop()==controller->loop &&
        IPhone16Swap::load<IOCommandGate *>(controller->display,5040)==controller->gate;
}
static void retainController(DodgeSoftwareRefresh *controller) {
    __atomic_fetch_add(&controller->references,1,__ATOMIC_RELAXED);
}
static void releaseController(DodgeSoftwareRefresh *controller) {
    if(__atomic_fetch_sub(&controller->references,1,__ATOMIC_ACQ_REL)!=1)return;
    auto *expected=controller;
    __atomic_compare_exchange_n(&controllerOwner,&expected,nullptr,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    if(controller->timer) {
        controller->timer->setRefcon(nullptr);
        controller->timer->release();
    }
    controller->gate->release();controller->loop->release();controller->display->release();
    IOFree(controller,sizeof(*controller));
}
static void disable(DodgeSoftwareRefresh *controller,IOReturn status) {
    ++controller->generation;
    controller->enabled=false;controller->next=0;controller->status=status;
    controller->timer->cancelTimeout();
    __atomic_store_n(&native_gop_vsync[0],0,__ATOMIC_RELAXED);
}
static IOReturn schedule(DodgeSoftwareRefresh *controller,uint64_t deadline) {
    const IOReturn result=controller->timer->wakeAtTime(deadline);
    if(result!=kIOReturnSuccess)disable(controller,result);
    else {controller->next=deadline;controller->status=kIOReturnSuccess;}
    return result;
}
static void fired(OSObject *owner,IOTimerEventSource *sender) {
    auto *controller=static_cast<DodgeSoftwareRefresh *>(sender->getRefcon());
    if(!ownsGate(controller) || owner!=controller->display || sender!=controller->timer)return;
    // The sender can indirectly stop/disable us. Neither the timer API nor its
    // refcon retains this plain controller or its original display owner.
    retainController(controller);sender->retain();
    if(controller->enabled) {
        if(!liveDisplay(controller))disable(controller,kIOReturnAborted);
        else {
            const uint64_t now=mach_absolute_time();
            const uint64_t deadline=controller->next;
            const uint64_t generation=controller->generation;
            if(now<deadline)schedule(controller,deadline);
            else {
                if(IPhone16Refresh::notifyIfListening(controller->display,now,mach_continuous_time(),controller->interval))
                    __atomic_fetch_add(&native_gop_vsync[1],1,__ATOMIC_RELAXED);
                if(controller->enabled && !controller->stopping && controller->generation==generation) {
                    const uint64_t after=mach_absolute_time();
                    if(!liveDisplay(controller) || after<now)disable(controller,kIOReturnAborted);
                    else if(deadline>UINT64_MAX-controller->interval)disable(controller,kIOReturnBadArgument);
                    else {
                        uint64_t next=deadline+controller->interval;
                        if(next<=after) {
                            __atomic_fetch_add(&native_gop_vsync[2],1,__ATOMIC_RELAXED);
                            if(after>UINT64_MAX-controller->interval)next=0;
                            else next=after+controller->interval;
                        }
                        if(!next)disable(controller,kIOReturnBadArgument);
                        else schedule(controller,next);
                    }
                }
            }
        }
    }
    sender->release();releaseController(controller);
}

extern "C" DodgeSoftwareRefresh *dodge_software_refresh_create(IOService *display) {
    if(!display || !display->metaCast("IOMobileFramebufferLegacy"))return nullptr;
    IOWorkLoop *loop=display->getWorkLoop();
    if(!loop || !loop->inGate())return nullptr;
    auto *gate=IPhone16Swap::load<IOCommandGate *>(display,5040);
    if(!gate || !gate->metaCast("IOCommandGate") || gate->getWorkLoop()!=loop || !gate->isEnabled())return nullptr;
    auto *controller=static_cast<DodgeSoftwareRefresh *>(IOMallocZero(sizeof(DodgeSoftwareRefresh)));
    if(!controller)return nullptr;
    controller->references=1;controller->display=display;controller->gate=gate;controller->loop=loop;
    display->retain();gate->retain();loop->retain();
    DodgeSoftwareRefresh *expected=nullptr;
    if(!__atomic_compare_exchange_n(&controllerOwner,&expected,controller,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        releaseController(controller);return nullptr;
    }
    nanoseconds_to_absolutetime(1000000000ULL/60,&controller->interval);
    if(!controller->interval) {releaseController(controller);return nullptr;}
    controller->timer=IOTimerEventSource::timerEventSource(display,fired);
    if(!controller->timer) {releaseController(controller);return nullptr;}
    controller->timer->setRefcon(controller);
    if(loop->addEventSource(controller->timer)!=kIOReturnSuccess) {releaseController(controller);return nullptr;}
    return controller;
}

extern "C" IOReturn dodge_software_refresh_set_enabled(DodgeSoftwareRefresh *controller,bool enabled) {
    if(!ownsGate(controller))return kIOReturnNotPermitted;
    if(controller->stopping)return kIOReturnNotReady;
    if(!enabled) {disable(controller,kIOReturnSuccess);return kIOReturnSuccess;}
    if(!liveDisplay(controller)) {disable(controller,kIOReturnAborted);return kIOReturnAborted;}
    if(controller->enabled)return kIOReturnSuccess;
    const uint64_t now=mach_absolute_time();
    if(now>UINT64_MAX-controller->interval) {disable(controller,kIOReturnBadArgument);return kIOReturnBadArgument;}
    controller->enabled=true;
    ++controller->generation;
    const IOReturn result=schedule(controller,now+controller->interval);
    if(result==kIOReturnSuccess)__atomic_store_n(&native_gop_vsync[0],60,__ATOMIC_RELAXED);
    return result;
}
extern "C" IOReturn dodge_software_refresh_status(const DodgeSoftwareRefresh *controller) {
    return ownsGate(controller)?controller->status:kIOReturnNotPermitted;
}
extern "C" IOReturn dodge_software_refresh_stop(DodgeSoftwareRefresh *controller) {
    if(!ownsGate(controller))return kIOReturnNotPermitted;
    controller->stopping=true;
    disable(controller,kIOReturnSuccess);
    controller->timer->setRefcon(nullptr);controller->timer->disable();
    const IOReturn result=controller->loop->removeEventSource(controller->timer);
    if(result!=kIOReturnSuccess) {controller->status=result;return result;}
    OSSafeReleaseNULL(controller->timer);
    releaseController(controller);
    return kIOReturnSuccess;
}
