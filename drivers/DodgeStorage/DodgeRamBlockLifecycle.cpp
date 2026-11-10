// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeRamBlockLifecycle.h"
#include "OriginalStorageABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
unsigned dodge_ramblock_driver_bytes();
const OSMetaClass *dodge_ramblock_driver_meta();
IOService *dodge_ramblock_allocate();
void dodge_ramblock_cpp_initializer() asm("__GLOBAL__sub_I_DodgeRamBlock.cpp");
}
namespace {
unsigned phase = unsigned(DodgeRamBlockPhase::Cold);
unsigned startPhase = unsigned(DodgeRamBlockStartPhase::Idle);
IOReturn last = kIOReturnNotReady;
const OSMetaClass *parentPin = nullptr;
IOService *retainedDriver = nullptr;
bool instancePinned = false, startAttempted = false;
IOReturn finish(DodgeRamBlockPhase next, IOReturn result) {
    __atomic_store_n(&last, result, __ATOMIC_RELAXED);
    __atomic_store_n(&phase, unsigned(next), __ATOMIC_RELEASE);
    return result;
}
}
extern "C" IOReturn dodge_ramblock_prepare() {
    unsigned expected = unsigned(DodgeRamBlockPhase::Cold);
    if (!__atomic_compare_exchange_n(&phase, &expected, unsigned(DodgeRamBlockPhase::Loading), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == unsigned(DodgeRamBlockPhase::Ready) ? kIOReturnSuccess :
               expected == unsigned(DodgeRamBlockPhase::Failed) ? __atomic_load_n(&last, __ATOMIC_RELAXED) : kIOReturnBusy;
    IOReturn result = OSKext::loadKextWithIdentifier("com.apple.iokit.IOStorageFamily", false, true, kOSKextExcludeNone, kOSKextExcludeNone, nullptr);
    if (result != kIOReturnSuccess) return finish(DodgeRamBlockPhase::Cold, result);
    const OSSymbol *symbol = OSSymbol::withCStringNoCopy(DodgeOriginalStorageClass);
    if (!symbol) return finish(DodgeRamBlockPhase::Cold, kIOReturnNoMemory);
    parentPin = OSMetaClass::copyMetaClassWithName(symbol); symbol->release();
    if (!parentPin || static_cast<const void *>(parentPin) != dodge_original_storage_meta || parentPin->getClassSize() != DodgeOriginalStorageBytes) {
        if (parentPin) parentPin->releaseMetaClass();
        parentPin = nullptr;
        return finish(DodgeRamBlockPhase::Cold, kIOReturnUnsupported);
    }
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(DodgeRamBlockPhase::Failed, kIOReturnNoMemory);
    dodge_ramblock_cpp_initializer(); result = OSMetaClass::postModLoad(handle);
    if (result != kIOReturnSuccess) return finish(DodgeRamBlockPhase::Failed, result);
    symbol = OSSymbol::withCStringNoCopy("NativeRamBlock");
    if (!symbol) return finish(DodgeRamBlockPhase::Failed, kIOReturnNoMemory);
    const OSMetaClass *child = OSMetaClass::copyMetaClassWithName(symbol); symbol->release();
    const bool valid = child && child == dodge_ramblock_driver_meta() && child->getClassSize() == dodge_ramblock_driver_bytes();
    if (child) child->releaseMetaClass();
    return finish(valid ? DodgeRamBlockPhase::Ready : DodgeRamBlockPhase::Failed, valid ? kIOReturnSuccess : kIOReturnNotReady);
}
extern "C" IOReturn dodge_ramblock_start(IOService *provider, IOService **out) {
    if (!out) return kIOReturnBadArgument;
    *out = nullptr;
    if (!provider) return kIOReturnBadArgument;
    unsigned enable = 0;
    if (!PE_parse_boot_argn("dodge-data", &enable, sizeof(enable)) || enable != 1) return kIOReturnNotPermitted;
    auto *platform = IOService::getPlatform();
    if (!platform || platform->isInactive() || platform->getProvider() != provider || !platform->metaCast("IODTPlatformExpert") ||
        provider->isInactive() || !provider->metaCast("IOPlatformExpertDevice")) return kIOReturnUnsupported;
    IOReturn result = dodge_ramblock_prepare();
    if (result != kIOReturnSuccess) return result;
    unsigned expected = unsigned(DodgeRamBlockStartPhase::Idle);
    if (!__atomic_compare_exchange_n(&startPhase, &expected, unsigned(DodgeRamBlockStartPhase::Entering), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == unsigned(DodgeRamBlockStartPhase::Entering) ? kIOReturnBusy :
               expected == unsigned(DodgeRamBlockStartPhase::Failed) ? __atomic_load_n(&last, __ATOMIC_RELAXED) : kIOReturnNotPermitted;
    provider->retain();
    IOService *driver = dodge_ramblock_allocate();
    if (!driver) {
        provider->release();
        __atomic_store_n(&last, kIOReturnNoMemory, __ATOMIC_RELAXED);
        __atomic_store_n(&startPhase, unsigned(DodgeRamBlockStartPhase::Idle), __ATOMIC_RELEASE);
        return kIOReturnNoMemory;
    }
    // The original parent's complete failure/free behavior is not qualified.
    // Keep the first object and its provider alive even when original init fails.
    driver->retain();
    __atomic_store_n(&retainedDriver, driver, __ATOMIC_RELEASE);
    __atomic_store_n(&instancePinned, true, __ATOMIC_RELEASE);
    if (!driver->init() || !driver->attach(provider)) result = kIOReturnNotReady;
    else {
        __atomic_store_n(&startAttempted, true, __ATOMIC_RELEASE);
        const bool started = driver->start(provider);
        if (started) { driver->retain(); *out = driver; }
        result = started ? kIOReturnSuccess : kIOReturnNotReady;
    }
    __atomic_store_n(&last, result, __ATOMIC_RELAXED);
    __atomic_store_n(&startPhase, unsigned(result == kIOReturnSuccess ? DodgeRamBlockStartPhase::Started : DodgeRamBlockStartPhase::Failed), __ATOMIC_RELEASE);
    return result;
}
extern "C" void dodge_ramblock_status(DodgeRamBlockStatus *out) {
    if (!out) return;
    out->phase = DodgeRamBlockPhase(__atomic_load_n(&phase, __ATOMIC_ACQUIRE));
    out->start = DodgeRamBlockStartPhase(__atomic_load_n(&startPhase, __ATOMIC_ACQUIRE));
    out->last = __atomic_load_n(&last, __ATOMIC_RELAXED);
    out->instancePinned = __atomic_load_n(&instancePinned, __ATOMIC_ACQUIRE);
    out->startAttempted = __atomic_load_n(&startAttempted, __ATOMIC_ACQUIRE);
    out->driverRetained = __atomic_load_n(&retainedDriver, __ATOMIC_ACQUIRE) != nullptr;
}
