// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeInputLate.h"
#include "DodgeInputLifecycle.h"
#include "DodgeSystemLate.h"
#include "DodgeGraphicsLate.h"
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
namespace {
unsigned phase=unsigned(DodgeInputLatePhase::Cold),attempts=0;
IOReturn keys=kIOReturnNotReady,touch=kIOReturnNotReady;
bool enabled(const char *name) {unsigned n=0;return PE_parse_boot_argn(name,&n,sizeof n) && n==1;}
bool earlierWorkersFinished() {
    if (enabled("native-ufs-root")) {
        DodgeSystemLateStatus s={};dodge_system_late_status(&s);
        if (s.phase!=DodgeSystemLatePhase::Finished) return false;
    }
    if (enabled("dodge-graphics")) {
        DodgeGraphicsLateStatus s={};dodge_graphics_late_status(&s);
        if (s.phase!=DodgeGraphicsLatePhase::Finished) return false;
    }
    return true;
}
void worker(void *,wait_result_t) {
    __atomic_store_n(&phase,unsigned(DodgeInputLatePhase::Running),__ATOMIC_RELEASE);
    bool pending[2]={true,true};
    for (unsigned i=0;i<1000;++i) {
        __atomic_store_n(&attempts,i+1,__ATOMIC_RELAXED);
        if (earlierWorkersFinished()) {
            auto *p=IOService::getPlatform();IOService *root=p && !p->isInactive()?p->getProvider():nullptr;
            for (unsigned d=0;d<2;++d) if (pending[d]) {
                IOService *driver=nullptr;IOReturn rc=root?dodge_input_start(root,d!=0,&driver):kIOReturnNotReady;
                if (driver) {driver->release();if (rc) rc=kIOReturnError;}
                else if (rc==kIOReturnSuccess) rc=kIOReturnError;
                __atomic_store_n(d?&touch:&keys,rc,__ATOMIC_RELAXED);
                DodgeInputStatus status={};dodge_input_status(&status);
                if (status.attempted[d] || status.start[d]==DodgeInputStart::Failed || status.phase==DodgeInputPhase::Failed ||
                    (rc!=kIOReturnNotReady && rc!=kIOReturnBusy)) pending[d]=false;
            }
            if (!pending[0] && !pending[1]) break;
        }
        if (i+1<1000) IOSleep(10);
    }
    __atomic_store_n(&phase,unsigned(DodgeInputLatePhase::Finished),__ATOMIC_RELEASE);
    thread_terminate(current_thread());
}
}
extern "C" IOReturn dodge_input_schedule() {
    if (!enabled("dodge-input")) return kIOReturnNotPermitted;
    unsigned expected=unsigned(DodgeInputLatePhase::Cold);
    if (!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeInputLatePhase::Queued),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeInputLatePhase::Finished)?kIOReturnNotPermitted:kIOReturnBusy;
    thread_t thread=THREAD_NULL;
    if (kernel_thread_start(worker,nullptr,&thread)!=KERN_SUCCESS) {
        __atomic_store_n(&phase,unsigned(DodgeInputLatePhase::Cold),__ATOMIC_RELEASE);return kIOReturnNoResources;
    }
    thread_deallocate(thread);return kIOReturnSuccess;
}
extern "C" void dodge_input_late_status(DodgeInputLateStatus *out) {
    if (!out) return;
    out->phase=DodgeInputLatePhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->keys=__atomic_load_n(&keys,__ATOMIC_RELAXED);out->touch=__atomic_load_n(&touch,__ATOMIC_RELAXED);
    out->attempts=__atomic_load_n(&attempts,__ATOMIC_RELAXED);
}
