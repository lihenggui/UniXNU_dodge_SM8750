// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGraphicsBoot.h"

extern "C" int dodge_gpu_start();
static unsigned bootPhase=unsigned(DodgeGraphicsBootPhase::Cold);
static IOReturn bootLast=kIOReturnNotReady;
static bool hardwareAttempted=false;

static void stage(DodgeGraphicsBootPhase value) {
    __atomic_store_n(&bootPhase,unsigned(value),__ATOMIC_RELEASE);
}
static IOReturn finish(DodgeGraphicsBootPhase value,IOReturn error) {
    __atomic_store_n(&bootLast,error,__ATOMIC_RELAXED);stage(value);return error;
}
extern "C" IOReturn dodge_graphics_boot(IOService *provider,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;if(!provider)return kIOReturnBadArgument;
    unsigned expected=unsigned(DodgeGraphicsBootPhase::Cold);
    if(!__atomic_compare_exchange_n(&bootPhase,&expected,unsigned(DodgeGraphicsBootPhase::Preparing),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        if(expected==unsigned(DodgeGraphicsBootPhase::Started))return kIOReturnNotPermitted;
        if(expected==unsigned(DodgeGraphicsBootPhase::Failed))return __atomic_load_n(&bootLast,__ATOMIC_RELAXED);
        return kIOReturnBusy;
    }
    provider->retain();
    IOService *root=nullptr,*display=nullptr;
    DodgeGraphicsStatus modules={};
    auto next=DodgeGraphicsBootPhase::Failed;
    IOReturn result=dodge_graphics_prepare();
    if(result!=kIOReturnSuccess) {
        dodge_graphics_status(&modules);
        if(modules.phase!=DodgeGraphicsPhase::Failed)next=DodgeGraphicsBootPhase::Cold;
        goto done;
    }
    stage(DodgeGraphicsBootPhase::Prerequisites);
    result=dodge_graphics_acquire_root(provider,&root);
    if(result!=kIOReturnSuccess) {next=DodgeGraphicsBootPhase::Cold;goto done;}
    if(!root) {result=kIOReturnError;goto done;}
    stage(DodgeGraphicsBootPhase::Hardware);
    __atomic_store_n(&hardwareAttempted,true,__ATOMIC_RELEASE);
    result=IOReturn(dodge_gpu_start());
    if(result!=kIOReturnSuccess)goto done;
    stage(DodgeGraphicsBootPhase::Display);
    result=dodge_graphics_attach(provider,&display);
    if(result!=kIOReturnSuccess)goto done;
    if(!display) {result=kIOReturnError;goto done;}
    *out=display;next=DodgeGraphicsBootPhase::Started;
done:
    // Keep the busy phase until release callbacks finish, so they cannot
    // recursively initiate a second board start during failure cleanup.
    if(root)root->release();
    provider->release();
    return finish(next,result);
}
extern "C" void dodge_graphics_boot_status(DodgeGraphicsBootStatus *out) {
    if(!out)return;
    out->phase=DodgeGraphicsBootPhase(__atomic_load_n(&bootPhase,__ATOMIC_ACQUIRE));
    out->last=__atomic_load_n(&bootLast,__ATOMIC_RELAXED);
    out->hardwareAttempted=__atomic_load_n(&hardwareAttempted,__ATOMIC_ACQUIRE);
}
