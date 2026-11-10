// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSystemLate.h"
#include "DodgeUfsLifecycle.h"
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>

extern "C" IOReturn dodge_graphics_schedule();
namespace {
unsigned phase=unsigned(DodgeSystemLatePhase::Cold),attempts=0;
IOReturn storageLast=kIOReturnNotReady,graphicsLast=kIOReturnNotReady;
bool storageStarted=false;
void storageWorker(void *,wait_result_t) {
    __atomic_store_n(&phase,unsigned(DodgeSystemLatePhase::Running),__ATOMIC_RELEASE);
    IOReturn result=kIOReturnNotReady;
    for(unsigned i=0;i<200;++i) {
        __atomic_store_n(&attempts,i+1,__ATOMIC_RELAXED);IOService *driver=nullptr;
        auto *platform=IOService::getPlatform();
        IOService *root=platform && !platform->isInactive()?platform->getProvider():nullptr;
        result=root?dodge_ufs_start(root,&driver):kIOReturnNotReady;
        if(result==kIOReturnSuccess && driver) {
            driver->release();__atomic_store_n(&storageStarted,true,__ATOMIC_RELEASE);
            __atomic_store_n(&graphicsLast,dodge_graphics_schedule(),__ATOMIC_RELAXED);break;
        }
        if(driver) {driver->release();result=kIOReturnError;break;}
        if(result==kIOReturnSuccess) {result=kIOReturnError;break;}
        DodgeUfsStatus status={};dodge_ufs_status(&status);
        if(status.startAttempted || status.phase==DodgeUfsPhase::Failed ||
           (result!=kIOReturnNotReady && result!=kIOReturnBusy))break;
        if(i+1<200)IOSleep(10);
    }
    __atomic_store_n(&storageLast,result,__ATOMIC_RELAXED);
    __atomic_store_n(&phase,unsigned(DodgeSystemLatePhase::Finished),__ATOMIC_RELEASE);
    thread_terminate(current_thread());
}
}
extern "C" IOReturn dodge_system_schedule() {
    unsigned enable=0;
    if(!PE_parse_boot_argn("native-ufs-root",&enable,sizeof(enable)) || enable!=1) {
        const IOReturn result=dodge_graphics_schedule();__atomic_store_n(&graphicsLast,result,__ATOMIC_RELAXED);return result;
    }
    unsigned expected=unsigned(DodgeSystemLatePhase::Cold);
    if(!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeSystemLatePhase::Queued),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeSystemLatePhase::Finished)?kIOReturnNotPermitted:kIOReturnBusy;
    thread_t thread=THREAD_NULL;
    if(kernel_thread_start(storageWorker,nullptr,&thread)!=KERN_SUCCESS) {
        __atomic_store_n(&storageLast,kIOReturnNoResources,__ATOMIC_RELAXED);
        __atomic_store_n(&phase,unsigned(DodgeSystemLatePhase::Cold),__ATOMIC_RELEASE);return kIOReturnNoResources;
    }
    thread_deallocate(thread);return kIOReturnSuccess;
}
extern "C" void dodge_system_late_status(DodgeSystemLateStatus *out) {
    if(!out)return;
    out->phase=DodgeSystemLatePhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->storageLast=__atomic_load_n(&storageLast,__ATOMIC_RELAXED);out->graphicsScheduleLast=__atomic_load_n(&graphicsLast,__ATOMIC_RELAXED);
    out->attempts=__atomic_load_n(&attempts,__ATOMIC_RELAXED);out->storageStarted=__atomic_load_n(&storageStarted,__ATOMIC_ACQUIRE);
}
