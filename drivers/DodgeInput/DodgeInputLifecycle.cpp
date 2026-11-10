// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeInputLifecycle.h"
#include "OriginalHidDeviceABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned char dodge_original_hid_meta[];
unsigned dodge_input_driver_bytes();
const OSMetaClass *dodge_input_driver_meta();
IOService *dodge_input_allocate(bool);
void dodge_input_cpp_initializer() asm("__GLOBAL__sub_I_DodgeInput.cpp");
}
namespace {
unsigned phase=unsigned(DodgeInputPhase::Cold),starts[2]={};
IOReturn last[2]={kIOReturnNotReady,kIOReturnNotReady},prepareLast=kIOReturnNotReady;
const OSMetaClass *parentPin=nullptr;
IOService *drivers[2]={},*providers[2]={};
bool initializing[2]={},attempted[2]={};
IOReturn finish(DodgeInputPhase next,IOReturn result) {
    __atomic_store_n(&prepareLast,result,__ATOMIC_RELAXED);
    __atomic_store_n(&phase,unsigned(next),__ATOMIC_RELEASE);return result;
}
bool registered() {
    const OSSymbol *symbol=OSSymbol::withCStringNoCopy("DodgeInput");if (!symbol) return false;
    const OSMetaClass *meta=OSMetaClass::copyMetaClassWithName(symbol);symbol->release();
    bool ok=meta && meta==dodge_input_driver_meta() && meta->getClassSize()==dodge_input_driver_bytes();
    if (meta) meta->releaseMetaClass();
    return ok;
}
}
extern "C" IOReturn dodge_input_prepare() {
    unsigned expected=unsigned(DodgeInputPhase::Cold);
    if (!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeInputPhase::Loading),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeInputPhase::Ready)?kIOReturnSuccess:
            expected==unsigned(DodgeInputPhase::Failed)?__atomic_load_n(&prepareLast,__ATOMIC_RELAXED):kIOReturnBusy;
    IOReturn rc=OSKext::loadKextWithIdentifier("com.apple.iokit.IOHIDFamily",false,true,kOSKextExcludeNone,kOSKextExcludeNone,nullptr);
    if (rc) return finish(DodgeInputPhase::Cold,rc);
    const OSSymbol *symbol=OSSymbol::withCStringNoCopy("IOHIDDevice");
    if (!symbol) return finish(DodgeInputPhase::Cold,kIOReturnNoMemory);
    parentPin=OSMetaClass::copyMetaClassWithName(symbol);symbol->release();
    if (!parentPin || static_cast<const void *>(parentPin)!=dodge_original_hid_meta || parentPin->getClassSize()!=208) {
        if (parentPin) parentPin->releaseMetaClass();
        parentPin=nullptr;return finish(DodgeInputPhase::Cold,kIOReturnUnsupported);
    }
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(DodgeInputPhase::Failed,kIOReturnNoMemory);
    dodge_input_cpp_initializer();rc=OSMetaClass::postModLoad(handle);
    if (rc) return finish(DodgeInputPhase::Failed,rc);
    if (!registered()) return finish(DodgeInputPhase::Failed,kIOReturnNotReady);
    return finish(DodgeInputPhase::Ready,kIOReturnSuccess);
}
extern "C" IOReturn dodge_input_start(IOService *provider,bool touch,IOService **out) {
    if (!out) return kIOReturnBadArgument;
    *out=nullptr;if (!provider) return kIOReturnBadArgument;
    unsigned enabled=0;
    if (!PE_parse_boot_argn("dodge-input",&enabled,sizeof(enabled)) || enabled!=1) return kIOReturnNotPermitted;
    auto *platform=IOService::getPlatform();
    if (!platform || platform->isInactive() || platform->getProvider()!=provider || !platform->metaCast("IODTPlatformExpert") ||
        provider->isInactive() || !provider->metaCast("IOPlatformExpertDevice")) return kIOReturnUnsupported;
    IOReturn rc=dodge_input_prepare();if (rc) return rc;
    unsigned index=touch?1:0,expected=unsigned(DodgeInputStart::Idle);
    if (!__atomic_compare_exchange_n(&starts[index],&expected,unsigned(DodgeInputStart::Entering),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeInputStart::Entering)?kIOReturnBusy:
            expected==unsigned(DodgeInputStart::Failed)?__atomic_load_n(&last[index],__ATOMIC_RELAXED):kIOReturnNotPermitted;
    provider->retain();IOService *driver=dodge_input_allocate(touch);
    if (driver) {
        // The unchanged original free unconditionally reads the expansion
        // pointer. Never release an object after an unqualified partial init,
        // even when no hardware call was made. Each bounded leak is pinned
        // in this boot's coordinator rather than retried or freed unsafely.
        drivers[index]=driver;providers[index]=provider;
        __atomic_store_n(&initializing[index],true,__ATOMIC_RELEASE);
        bool ok=driver->init() && driver->attach(provider);
        if (ok) {
            __atomic_store_n(&attempted[index],true,__ATOMIC_RELEASE);
            ok=driver->start(provider);
        }
        rc=ok?kIOReturnSuccess:kIOReturnNotReady;
        if (ok) {driver->retain();*out=driver;}
        __atomic_store_n(&last[index],rc,__ATOMIC_RELAXED);
        __atomic_store_n(&starts[index],unsigned(ok?DodgeInputStart::Started:DodgeInputStart::Failed),__ATOMIC_RELEASE);return rc;
    }
    provider->release();
    rc=kIOReturnNoMemory;
    __atomic_store_n(&last[index],rc,__ATOMIC_RELAXED);
    __atomic_store_n(&starts[index],unsigned(DodgeInputStart::Idle),__ATOMIC_RELEASE);return rc;
}
extern "C" void dodge_input_status(DodgeInputStatus *out) {
    if (!out) return;
    out->phase=DodgeInputPhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    for (unsigned i=0;i<2;++i) {
        out->start[i]=DodgeInputStart(__atomic_load_n(&starts[i],__ATOMIC_ACQUIRE));
        out->last[i]=__atomic_load_n(&last[i],__ATOMIC_RELAXED);
        out->initializationAttempted[i]=__atomic_load_n(&initializing[i],__ATOMIC_ACQUIRE);
        out->attempted[i]=__atomic_load_n(&attempted[i],__ATOMIC_ACQUIRE);
        out->driverRetained[i]=out->initializationAttempted[i] && drivers[i];
        out->providerRetained[i]=out->initializationAttempted[i] && providers[i];
    }
}
