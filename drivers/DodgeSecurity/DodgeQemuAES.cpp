// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned char dodge_original_aes_meta[];
const OSMetaClass *dodge_aes_driver_meta();
IOService *dodge_aes_allocate();
void dodge_aes_cpp_initializer() asm("__GLOBAL__sub_I_DodgeSoftwareAES.cpp");
volatile unsigned dodge_qemu_aes_phase = 0;
volatile IOReturn dodge_qemu_aes_result = kIOReturnNotReady;
__attribute__((noinline)) void dodge_qemu_aes_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

namespace {
const OSMetaClass *parentPin;
IOService *providerPin, *driverPin;
IOReturn finish(IOReturn result) {
    __atomic_store_n(&dodge_qemu_aes_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_qemu_aes_phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_qemu_aes_checkpoint();
    return result;
}
}

extern "C" IOReturn dodge_qemu_aes_start() {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-qemu-root", &enabled, sizeof(enabled)) || enabled != 1)
        return kIOReturnNotPermitted;
    IOService *platform = IOService::getPlatform();
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    OSData *type = bus ? OSDynamicCast(OSData, bus->getProperty("device_type")) : nullptr;
    const bool virtualBus = type && type->getLength() == sizeof("qemu-virt") &&
        !memcmp(type->getBytesNoCopy(), "qemu-virt", sizeof("qemu-virt"));
    if (bus) bus->release();
    if (!virtualBus || !platform || platform->isInactive() ||
        !(platform->getState() & kIOServiceRegisteredState)) return kIOReturnUnsupported;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_qemu_aes_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    IOReturn result = OSKext::loadKextWithIdentifier("com.apple.iokit.IOCryptoAcceleratorFamily", false, true,
        kOSKextExcludeNone, kOSKextExcludeNone, nullptr);
    if (result) return finish(result);
    const OSSymbol *name = OSSymbol::withCStringNoCopy("IOAESAccelerator");
    if (!name) return finish(kIOReturnNoMemory);
    parentPin = OSMetaClass::copyMetaClassWithName(name);name->release();
    if (!parentPin || static_cast<const void *>(parentPin) != dodge_original_aes_meta ||
        parentPin->getClassSize() != 0x120) return finish(kIOReturnUnsupported);
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(kIOReturnNoMemory);
    dodge_aes_cpp_initializer();
    result = OSMetaClass::postModLoad(handle);
    if (result) return finish(result);
    name = OSSymbol::withCStringNoCopy("NativeAES");
    if (!name) return finish(kIOReturnNoMemory);
    const OSMetaClass *child = OSMetaClass::copyMetaClassWithName(name);name->release();
    const bool valid = child && child == dodge_aes_driver_meta() && child->getClassSize() == 0x120;
    if (child) child->releaseMetaClass();
    if (!valid) return finish(kIOReturnUnsupported);
    driverPin = dodge_aes_allocate();
    if (!driverPin) return finish(kIOReturnNoMemory);
    platform->retain();providerPin = platform;
    // Registration and failed starts retain the object and its original parent.
    if (!driverPin->init() || !driverPin->attach(providerPin) || !driverPin->start(providerPin))
        return finish(kIOReturnError);
    return finish(kIOReturnSuccess);
}
