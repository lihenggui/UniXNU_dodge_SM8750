// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGraphicsLate.h"
#include "DodgeGopProvider.h"
#include "DodgeGraphicsBoot.h"
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>

namespace {
unsigned phase=unsigned(DodgeGraphicsLatePhase::Cold),attempts=0;
IOReturn last=kIOReturnNotReady;
IOService *bootDisplay=nullptr;
constexpr unsigned MaxAttempts=200,RetryMilliseconds=10;

void worker(void *,wait_result_t) {
    __atomic_store_n(&phase,unsigned(DodgeGraphicsLatePhase::Running),__ATOMIC_RELEASE);
    IOReturn result=kIOReturnNotReady;
    for(unsigned i=0;i<MaxAttempts;++i) {
        __atomic_store_n(&attempts,i+1,__ATOMIC_RELAXED);
        IOService *display=nullptr;
        auto *platform=IOService::getPlatform();
        if(platform && !platform->isInactive())result=dodge_graphics_boot_gop(platform,&display);
        else result=kIOReturnNotReady;
        if(result==kIOReturnSuccess && display) {bootDisplay=display;break;}
        if(display) {display->release();result=kIOReturnError;break;}
        if(result==kIOReturnSuccess) {result=kIOReturnError;break;}
        DodgeGraphicsBootStatus boot={};dodge_graphics_boot_status(&boot);
        // A matching/root/loader Busy before hardware may settle. Never retry
        // any hardware attempt, a latched failure or a different error.
        if(boot.hardwareAttempted || boot.phase==DodgeGraphicsBootPhase::Failed ||
           (result!=kIOReturnNotReady && result!=kIOReturnBusy))break;
        if(i+1<MaxAttempts)IOSleep(RetryMilliseconds);
    }
    __atomic_store_n(&last,result,__ATOMIC_RELAXED);
    __atomic_store_n(&phase,unsigned(DodgeGraphicsLatePhase::Finished),__ATOMIC_RELEASE);
    thread_terminate(current_thread());
}
}

extern "C" IOReturn dodge_graphics_schedule() {
    unsigned enable=0;
    if(!PE_parse_boot_argn("dodge-graphics",&enable,sizeof(enable)) || enable!=1)return kIOReturnNotPermitted;
    unsigned expected=unsigned(DodgeGraphicsLatePhase::Cold);
    if(!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeGraphicsLatePhase::Queued),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeGraphicsLatePhase::Finished)?kIOReturnNotPermitted:kIOReturnBusy;
    thread_t thread=THREAD_NULL;
    const kern_return_t result=kernel_thread_start(worker,nullptr,&thread);
    if(result!=KERN_SUCCESS) {
        __atomic_store_n(&last,kIOReturnNoResources,__ATOMIC_RELAXED);
        __atomic_store_n(&phase,unsigned(DodgeGraphicsLatePhase::Cold),__ATOMIC_RELEASE);return kIOReturnNoResources;
    }
    thread_deallocate(thread);return kIOReturnSuccess;
}
extern "C" void dodge_graphics_late_status(DodgeGraphicsLateStatus *out) {
    if(!out)return;
    out->phase=DodgeGraphicsLatePhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->last=__atomic_load_n(&last,__ATOMIC_RELAXED);out->attempts=__atomic_load_n(&attempts,__ATOMIC_RELAXED);
    out->displayRetained=out->phase==DodgeGraphicsLatePhase::Finished && bootDisplay;
}
