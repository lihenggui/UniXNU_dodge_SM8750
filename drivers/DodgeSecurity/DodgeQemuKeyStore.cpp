// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned dodge_keystore_layout[];
const OSMetaClass *dodge_keystore_driver_meta();
const OSMetaClass *dodge_keystore_client_meta();
IOService *native_keyevents_allocate();
size_t native_aks_device_id(uint8_t *, size_t);
void dodge_keystore_cpp_initializer() asm("__GLOBAL__sub_I_DodgeKeyStore.cpp");
volatile unsigned dodge_qemu_keystore_phase = 0, dodge_qemu_keystore_opened = 0, dodge_qemu_keystore_refused = 0;
volatile unsigned dodge_qemu_keystore_calls = 0, dodge_qemu_keystore_selector = 0;
volatile IOReturn dodge_qemu_keystore_result = kIOReturnNotReady;
volatile int32_t dodge_qemu_keystore_call_result = kIOReturnNotReady;
__attribute__((noinline)) void dodge_qemu_keystore_checkpoint() { __asm__ volatile("" ::: "memory"); }
__attribute__((noinline)) void dodge_qemu_keystore_call_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

namespace {
IOService *providerPin, *driverPin;
bool virtualPlatform() {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-qemu-root", &enabled, sizeof(enabled)) || enabled != 1) return false;
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    OSData *type = bus ? OSDynamicCast(OSData, bus->getProperty("device_type")) : nullptr;
    bool valid = type && type->getLength() == sizeof("qemu-virt") &&
        !memcmp(type->getBytesNoCopy(), "qemu-virt", sizeof("qemu-virt"));
    if (bus) bus->release();
    return valid;
}
IOReturn finish(IOReturn result) {
    __atomic_store_n(&dodge_qemu_keystore_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_qemu_keystore_phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_qemu_keystore_checkpoint();
    return result;
}
}

extern "C" bool native_aks_state_enabled() {
#if defined(DODGE_QEMU_KEYSTORE_CLOSED) && DODGE_QEMU_KEYSTORE_CLOSED
    return false;
#else
    uint8_t identity[8];
    return native_aks_device_id(identity, sizeof(identity)) == sizeof(identity);
#endif
}
extern "C" uint32_t native_aks_lock_state() { return 0; } // Unlocked, no passcode in this fresh VM fixture.
extern "C" void native_keyevents_open_refused() { __atomic_fetch_add(&dodge_qemu_keystore_refused, 1U, __ATOMIC_RELAXED); }
extern "C" void native_aks_opened() { __atomic_fetch_add(&dodge_qemu_keystore_opened, 1U, __ATOMIC_RELAXED); }
extern "C" void native_aks_call(uint32_t selector, int32_t result) {
    __atomic_store_n(&dodge_qemu_keystore_selector, selector, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_qemu_keystore_call_result, result, __ATOMIC_RELAXED);
    __atomic_fetch_add(&dodge_qemu_keystore_calls, 1U, __ATOMIC_RELAXED);
    dodge_qemu_keystore_call_checkpoint();
}
extern "C" size_t native_aks_device_id(uint8_t *out, size_t capacity) {
    if (!out || capacity < 8 || !virtualPlatform()) return 0;
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    OSData *identifier = chosen ? OSDynamicCast(OSData, chosen->getProperty("unique-chip-id")) : nullptr;
    uint64_t value = 0;
    if (identifier && identifier->getLength() == sizeof(value)) memcpy(&value, identifier->getBytesNoCopy(), sizeof(value));
    if (chosen) chosen->release();
    if (!value) return 0;
    memcpy(out, &value, sizeof(value));
    return sizeof(value);
}

extern "C" IOReturn dodge_qemu_keystore_start() {
    if (!virtualPlatform()) return kIOReturnNotPermitted;
    IOService *platform = IOService::getPlatform();
    if (!platform || platform->isInactive() || !(platform->getState() & kIOServiceRegisteredState)) return kIOReturnNotReady;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_qemu_keystore_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(kIOReturnNoMemory);
    dodge_keystore_cpp_initializer();
    IOReturn result = OSMetaClass::postModLoad(handle);
    if (result) return finish(result);
    for (unsigned index = 0; index < 2; ++index) {
        const OSSymbol *name = OSSymbol::withCStringNoCopy(index ? "AppleKeyStoreUserClient" : "AppleKeyStore");
        if (!name) return finish(kIOReturnNoMemory);
        const OSMetaClass *child = OSMetaClass::copyMetaClassWithName(name);name->release();
        bool valid = child && child == (index ? dodge_keystore_client_meta() : dodge_keystore_driver_meta()) &&
            child->getClassSize() == dodge_keystore_layout[index ? 3 : 2];
        if (child) child->releaseMetaClass();
        if (!valid) return finish(kIOReturnUnsupported);
    }
    driverPin = native_keyevents_allocate();
    if (!driverPin) return finish(kIOReturnNoMemory);
    platform->retain();providerPin = platform;
    if (!driverPin->init() || !driverPin->attach(providerPin)) return finish(kIOReturnError);
    driverPin->setProperty("DodgeQemuDevelopmentState", true);
    driverPin->setProperty("SoftwareKeysOnly", true);
    if (!driverPin->start(providerPin)) return finish(kIOReturnError);
    return finish(kIOReturnSuccess);
}
