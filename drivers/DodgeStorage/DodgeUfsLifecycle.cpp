// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeUfsLifecycle.h"
#include "OriginalStorageABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
unsigned dodge_ufs_driver_bytes(),dodge_ufs_block_bytes();
const OSMetaClass *dodge_ufs_driver_meta(),*dodge_ufs_block_meta();
IOService *dodge_ufs_allocate();
void dodge_ufs_cpp_initializer() asm("__GLOBAL__sub_I_NativeUfs.cpp");
}
namespace {
unsigned phase=unsigned(DodgeUfsPhase::Cold),startPhase=unsigned(DodgeUfsStartPhase::Idle);
IOReturn last=kIOReturnNotReady;
const OSMetaClass *parentPin=nullptr;
IOService *retainedDriver=nullptr;
bool startAttempted=false;
IOReturn finish(DodgeUfsPhase next,IOReturn result) {
    __atomic_store_n(&last,result,__ATOMIC_RELAXED);__atomic_store_n(&phase,unsigned(next),__ATOMIC_RELEASE);return result;
}
bool registered(const char *name,const OSMetaClass *expected,unsigned bytes) {
    const OSSymbol *symbol=OSSymbol::withCStringNoCopy(name);if(!symbol)return false;
    const OSMetaClass *meta=OSMetaClass::copyMetaClassWithName(symbol);symbol->release();
    bool result=meta && meta==expected && meta->getClassSize()==bytes;
    if(meta)meta->releaseMetaClass();
    return result;
}
}
extern "C" IOReturn dodge_ufs_prepare() {
    unsigned expected=unsigned(DodgeUfsPhase::Cold);
    if(!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeUfsPhase::Loading),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeUfsPhase::Ready)?kIOReturnSuccess:expected==unsigned(DodgeUfsPhase::Failed)?__atomic_load_n(&last,__ATOMIC_RELAXED):kIOReturnBusy;
    const IOReturn loaded=OSKext::loadKextWithIdentifier("com.apple.iokit.IOStorageFamily",false,true,kOSKextExcludeNone,kOSKextExcludeNone,nullptr);
    if(loaded!=kIOReturnSuccess)return finish(DodgeUfsPhase::Cold,loaded);
    const OSSymbol *symbol=OSSymbol::withCStringNoCopy(DodgeOriginalStorageClass);
    if(!symbol)return finish(DodgeUfsPhase::Cold,kIOReturnNoMemory);
    parentPin=OSMetaClass::copyMetaClassWithName(symbol);symbol->release();
    if(!parentPin || static_cast<const void *>(parentPin)!=dodge_original_storage_meta || parentPin->getClassSize()!=DodgeOriginalStorageBytes) {
        if(parentPin)parentPin->releaseMetaClass();
        parentPin=nullptr;return finish(DodgeUfsPhase::Cold,kIOReturnUnsupported);
    }
    // All failures after entering the loader context are latched. The actual
    // exported compiler initializer (two native classes) runs exactly once.
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if(!handle)return finish(DodgeUfsPhase::Failed,kIOReturnNoMemory);
    dodge_ufs_cpp_initializer();const IOReturn posted=OSMetaClass::postModLoad(handle);
    if(posted!=kIOReturnSuccess)return finish(DodgeUfsPhase::Failed,posted);
    if(!registered("NativeUfs",dodge_ufs_driver_meta(),dodge_ufs_driver_bytes()) ||
       !registered("NativeUfsBlock",dodge_ufs_block_meta(),dodge_ufs_block_bytes()))return finish(DodgeUfsPhase::Failed,kIOReturnNotReady);
    return finish(DodgeUfsPhase::Ready,kIOReturnSuccess);
}
extern "C" IOReturn dodge_ufs_start(IOService *provider,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;if(!provider)return kIOReturnBadArgument;
    unsigned enable=0;
    if(!PE_parse_boot_argn("native-ufs-root",&enable,sizeof(enable)) || enable!=1)return kIOReturnNotPermitted;
    auto *platform=IOService::getPlatform();
    if(!platform || platform->isInactive() || platform->getProvider()!=provider || !platform->metaCast("IODTPlatformExpert") ||
       provider->isInactive() || !provider->metaCast("IOPlatformExpertDevice"))return kIOReturnUnsupported;
    IOReturn result=dodge_ufs_prepare();if(result!=kIOReturnSuccess)return result;
    unsigned expected=unsigned(DodgeUfsStartPhase::Idle);
    if(!__atomic_compare_exchange_n(&startPhase,&expected,unsigned(DodgeUfsStartPhase::Entering),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeUfsStartPhase::Entering)?kIOReturnBusy:expected==unsigned(DodgeUfsStartPhase::Failed)?__atomic_load_n(&last,__ATOMIC_RELAXED):kIOReturnNotPermitted;
    provider->retain();IOService *driver=dodge_ufs_allocate();
    if(!driver)result=kIOReturnNoMemory;
    else if(!driver->init() || !driver->attach(provider))result=kIOReturnNotReady;
    else {
        retainedDriver=driver;__atomic_store_n(&startAttempted,true,__ATOMIC_RELEASE);
        const bool started=driver->start(provider);
        if(started) {driver->retain();*out=driver;}
        result=started?kIOReturnSuccess:kIOReturnNotReady;
        // Never detach/free a controller that may have submitted DMA or
        // published root windows. Reset recovery is a separate qualification.
        provider->release();__atomic_store_n(&last,result,__ATOMIC_RELAXED);
        __atomic_store_n(&startPhase,unsigned(started?DodgeUfsStartPhase::Started:DodgeUfsStartPhase::Failed),__ATOMIC_RELEASE);return result;
    }
    if(driver)driver->release();
    provider->release();
    __atomic_store_n(&last,result,__ATOMIC_RELAXED);__atomic_store_n(&startPhase,unsigned(DodgeUfsStartPhase::Idle),__ATOMIC_RELEASE);return result;
}
extern "C" void dodge_ufs_status(DodgeUfsStatus *out) {
    if(!out)return;
    out->phase=DodgeUfsPhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->start=DodgeUfsStartPhase(__atomic_load_n(&startPhase,__ATOMIC_ACQUIRE));
    out->last=__atomic_load_n(&last,__ATOMIC_RELAXED);out->startAttempted=__atomic_load_n(&startAttempted,__ATOMIC_ACQUIRE);
    out->driverRetained=out->startAttempted && retainedDriver;
}
