// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "OriginalStorageABI.h"
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned dodge_virtio_driver_bytes;
const OSMetaClass *dodge_virtio_driver_meta();
IOService *dodge_virtio_allocate();
void dodge_virtio_cpp_initializer() asm("__GLOBAL__sub_I_DodgeVirtioBlock.cpp");
volatile unsigned dodge_qemu_storage_phase = 0; // cold, entering, ready, failed
volatile unsigned dodge_qemu_storage_attempted = 0;
volatile unsigned dodge_qemu_storage_started = 0;
volatile IOReturn dodge_qemu_storage_result = kIOReturnNotReady;
__attribute__((noinline)) void dodge_qemu_storage_checkpoint() {
    __asm__ volatile("" ::: "memory");
}
}

namespace {
const OSMetaClass *parentPin = nullptr;
IOService *driverPins[32] = {};

IOReturn finish(IOReturn result) {
    __atomic_store_n(&dodge_qemu_storage_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_qemu_storage_phase, result == kIOReturnSuccess ? 2U : 3U, __ATOMIC_RELEASE);
    dodge_qemu_storage_checkpoint();
    return result;
}

IOReturn prepare() {
    IOReturn result = OSKext::loadKextWithIdentifier("com.apple.iokit.IOStorageFamily", false, true,
        kOSKextExcludeNone, kOSKextExcludeNone, nullptr);
    if (result != kIOReturnSuccess) return result;
    const OSSymbol *symbol = OSSymbol::withCStringNoCopy(DodgeOriginalStorageClass);
    if (!symbol) return kIOReturnNoMemory;
    parentPin = OSMetaClass::copyMetaClassWithName(symbol);
    symbol->release();
    if (!parentPin || static_cast<const void *>(parentPin) != dodge_original_storage_meta ||
        parentPin->getClassSize() != DodgeOriginalStorageBytes) return kIOReturnUnsupported;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return kIOReturnNoMemory;
    dodge_virtio_cpp_initializer();
    result = OSMetaClass::postModLoad(handle);
    if (result != kIOReturnSuccess) return result;
    symbol = OSSymbol::withCStringNoCopy("NativeVirtioBlock");
    if (!symbol) return kIOReturnNoMemory;
    const OSMetaClass *child = OSMetaClass::copyMetaClassWithName(symbol);
    symbol->release();
    const bool valid = child && child == dodge_virtio_driver_meta() &&
        child->getClassSize() == dodge_virtio_driver_bytes;
    if (child) child->releaseMetaClass();
    return valid ? kIOReturnSuccess : kIOReturnUnsupported;
}
}

// IOBSD calls this on an ordinary kernel thread after publishing its resource.
// This entry is present only in the separate QEMU candidate.
extern "C" IOReturn dodge_qemu_storage_start() {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-qemu-root", &enabled, sizeof(enabled)) || enabled != 1)
        return kIOReturnNotPermitted;
    IOService *platform = IOService::getPlatform();
    if (!platform || platform->isInactive() || !platform->metaCast("IODTPlatformExpert"))
        return kIOReturnUnsupported;
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    OSData *type = bus ? OSDynamicCast(OSData, bus->getProperty("device_type")) : nullptr;
    const bool virtualBus = type && type->getLength() == sizeof("qemu-virt") &&
        !memcmp(type->getBytesNoCopy(), "qemu-virt", sizeof("qemu-virt"));
    if (bus) bus->release();
    if (!virtualBus) return kIOReturnUnsupported;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_qemu_storage_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    uint64_t deadline;
    clock_interval_to_deadline(5000, kMillisecondScale, &deadline);
    while (!(platform->getState() & kIOServiceRegisteredState)) {
        if (mach_absolute_time() >= deadline) return finish(kIOReturnTimeout);
        IOSleep(1);
    }
    IOReturn result = prepare();
    if (result != kIOReturnSuccess) return finish(result);
    OSIterator *iterator = platform->getChildIterator(gIOServicePlane);
    if (!iterator) return finish(kIOReturnNoMemory);
    IOService *providers[32] = {};
    unsigned count = 0;
    IOService *provider;
    while ((provider = OSDynamicCast(IOService, iterator->getNextObject()))) {
        OSData *compatible = OSDynamicCast(OSData, provider->getProperty("compatible"));
        if (provider->isInactive() || !provider->metaCast("IOPlatformDevice") || !compatible ||
            compatible->getLength() != sizeof("virtio,mmio") ||
            memcmp(compatible->getBytesNoCopy(), "virtio,mmio", sizeof("virtio,mmio"))) continue;
        if (count >= 32) { result = kIOReturnNoResources; break; }
        provider->retain();
        providers[count++] = provider;
    }
    iterator->release();
    if (result != kIOReturnSuccess) {
        for (unsigned index = 0; index < count; ++index) providers[index]->release();
        return finish(result);
    }
    // Capture the published providers before any start changes the registry.
    for (unsigned index = 0; index < count; ++index) {
        provider = providers[index];
        IOService *driver = dodge_virtio_allocate();
        if (!driver) {
            for (unsigned pending = index; pending < count; ++pending) providers[pending]->release();
            result = kIOReturnNoMemory;break;
        }
        // Retain the device and provider before original init or any DMA setup.
        // A failed start stays pinned until VM teardown.
        driverPins[index] = driver;
        ++dodge_qemu_storage_attempted;
        if (driver->init() && driver->attach(provider) && driver->start(provider))
            ++dodge_qemu_storage_started;
    }
    if (result != kIOReturnSuccess) return finish(result);
    if (!dodge_qemu_storage_started) return finish(kIOReturnNotReady);
    result = OSKext::loadKextWithIdentifier("com.apple.filesystems.apfs", false, true,
        kOSKextExcludeNone, kOSKextExcludeNone, nullptr);
    return finish(result);
}
