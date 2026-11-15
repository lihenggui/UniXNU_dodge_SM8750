// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeOwnerSystem.h"
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned char dodge_original_aes_meta[];
extern const unsigned dodge_keystore_layout[];
const OSMetaClass *dodge_aes_driver_meta();
IOService *dodge_aes_allocate();
const OSMetaClass *dodge_keystore_driver_meta();
const OSMetaClass *dodge_keystore_client_meta();
IOService *native_keyevents_allocate();
void dodge_aes_cpp_initializer() asm("__GLOBAL__sub_I_DodgeSoftwareAES.cpp");
void dodge_keystore_cpp_initializer() asm("__GLOBAL__sub_I_DodgeKeyStore.cpp");
IOReturn dodge_native_entropy_start();
bool dodge_native_entropy_ready();
volatile unsigned dodge_native_aes_phase, dodge_native_keystore_phase;
volatile IOReturn dodge_native_security_result = kIOReturnNotReady;
volatile unsigned dodge_native_keystore_opened, dodge_native_keystore_refused, dodge_native_keystore_calls;
volatile uint32_t dodge_native_keystore_selector;
volatile int32_t dodge_native_keystore_call_result;
__attribute__((noinline)) void dodge_native_security_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

namespace {
const OSMetaClass *aesParentPin;
IOService *aesProviderPin, *aesDriverPin, *keyProviderPin, *keyDriverPin;
bool registered(const char *name, const OSMetaClass *expected, unsigned bytes) {
    const OSSymbol *symbol = OSSymbol::withCStringNoCopy(name);
    if (!symbol) return false;
    const OSMetaClass *meta = OSMetaClass::copyMetaClassWithName(symbol);symbol->release();
    const bool valid = meta && meta == expected && meta->getClassSize() == bytes;
    if (meta) meta->releaseMetaClass();
    return valid;
}
IOReturn finish(volatile unsigned *phase, IOReturn result) {
    __atomic_store_n(&dodge_native_security_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_native_security_checkpoint();
    return result;
}
IOReturn startAES(IOService *platform) {
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_native_aes_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    IOReturn result = OSKext::loadKextWithIdentifier("com.apple.iokit.IOCryptoAcceleratorFamily", false, true,
        kOSKextExcludeNone, kOSKextExcludeNone, nullptr);
    if (result) return finish(&dodge_native_aes_phase, result);
    const OSSymbol *name = OSSymbol::withCStringNoCopy("IOAESAccelerator");
    if (!name) return finish(&dodge_native_aes_phase, kIOReturnNoMemory);
    aesParentPin = OSMetaClass::copyMetaClassWithName(name);name->release();
    if (!aesParentPin || static_cast<const void *>(aesParentPin) != dodge_original_aes_meta ||
        aesParentPin->getClassSize() != 0x120) return finish(&dodge_native_aes_phase, kIOReturnUnsupported);
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(&dodge_native_aes_phase, kIOReturnNoMemory);
    dodge_aes_cpp_initializer();result = OSMetaClass::postModLoad(handle);
    if (result) return finish(&dodge_native_aes_phase, result);
    if (!registered("NativeAES", dodge_aes_driver_meta(), 0x120)) return finish(&dodge_native_aes_phase, kIOReturnUnsupported);
    aesDriverPin = dodge_aes_allocate();
    if (!aesDriverPin) return finish(&dodge_native_aes_phase, kIOReturnNoMemory);
    platform->retain();aesProviderPin = platform;
    if (!aesDriverPin->init() || !aesDriverPin->attach(aesProviderPin)) return finish(&dodge_native_aes_phase, kIOReturnError);
    if (!aesDriverPin->setProperty("DodgeOwnerDevelopmentState", true) || !aesDriverPin->setProperty("SoftwareKeysOnly", true))
        return finish(&dodge_native_aes_phase, kIOReturnNoMemory);
    if (!aesDriverPin->start(aesProviderPin)) return finish(&dodge_native_aes_phase, kIOReturnError);
    return finish(&dodge_native_aes_phase, kIOReturnSuccess);
}
IOReturn startKeyStore(IOService *platform) {
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_native_keystore_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(&dodge_native_keystore_phase, kIOReturnNoMemory);
    dodge_keystore_cpp_initializer();IOReturn result = OSMetaClass::postModLoad(handle);
    if (result) return finish(&dodge_native_keystore_phase, result);
    if (!registered("AppleKeyStore", dodge_keystore_driver_meta(), dodge_keystore_layout[2]) ||
        !registered("AppleKeyStoreUserClient", dodge_keystore_client_meta(), dodge_keystore_layout[3]))
        return finish(&dodge_native_keystore_phase, kIOReturnUnsupported);
    keyDriverPin = native_keyevents_allocate();
    if (!keyDriverPin) return finish(&dodge_native_keystore_phase, kIOReturnNoMemory);
    platform->retain();keyProviderPin = platform;
    if (!keyDriverPin->init() || !keyDriverPin->attach(keyProviderPin)) return finish(&dodge_native_keystore_phase, kIOReturnError);
    if (!keyDriverPin->setProperty("DodgeOwnerDevelopmentState", true) || !keyDriverPin->setProperty("SoftwareKeysOnly", true))
        return finish(&dodge_native_keystore_phase, kIOReturnNoMemory);
    if (!keyDriverPin->start(keyProviderPin)) return finish(&dodge_native_keystore_phase, kIOReturnError);
    return finish(&dodge_native_keystore_phase, kIOReturnSuccess);
}
}

extern "C" bool dodge_owner_security_ready() {
    return __atomic_load_n(&dodge_native_aes_phase, __ATOMIC_ACQUIRE) == 2 &&
        __atomic_load_n(&dodge_native_keystore_phase, __ATOMIC_ACQUIRE) == 2 && dodge_native_entropy_ready() && dodge_owner_system_allowed();
}
extern "C" IOReturn dodge_native_security_start() {
    if (!dodge_owner_system_allowed()) return kIOReturnNotPermitted;
    IOService *platform = IOService::getPlatform();
    if (!platform || platform->isInactive() || !(platform->getState() & kIOServiceRegisteredState)) return kIOReturnNotReady;
    IOReturn result = startAES(platform);
    if (!result) result = startKeyStore(platform);
    return result ? result : dodge_native_entropy_start();
}
extern "C" bool native_aks_state_enabled() { return dodge_owner_security_ready(); }
// Only this explicitly selected, unprotected development installation is unlocked.
extern "C" uint32_t native_aks_lock_state() { return dodge_owner_security_ready() ? 0 : 1; }
extern "C" size_t native_aks_device_id(uint8_t *out, size_t capacity) { return dodge_owner_system_identity(out, capacity); }
extern "C" void native_keyevents_open_refused() { __atomic_fetch_add(&dodge_native_keystore_refused, 1U, __ATOMIC_RELAXED); }
extern "C" void native_aks_opened() { __atomic_fetch_add(&dodge_native_keystore_opened, 1U, __ATOMIC_RELAXED); }
extern "C" void native_aks_call(uint32_t selector, int32_t result) {
    __atomic_store_n(&dodge_native_keystore_selector, selector, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_native_keystore_call_result, result, __ATOMIC_RELAXED);
    __atomic_fetch_add(&dodge_native_keystore_calls, 1U, __ATOMIC_RELAXED);
}
