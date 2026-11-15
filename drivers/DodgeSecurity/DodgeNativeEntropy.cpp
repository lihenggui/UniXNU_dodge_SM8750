// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeOwnerSystem.h"
#include "DodgeTrngRead.h"
#include "DodgeTrngHardware.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

extern "C" {
extern kmod_info_t g_kernel_kmod_info;
void dodge_entropy_cpp_initializer() asm("__GLOBAL__sub_I_DodgeNativeEntropy.cpp");
volatile unsigned dodge_native_entropy_phase, dodge_native_entropy_requests, dodge_native_entropy_failures;
volatile IOReturn dodge_native_entropy_result = kIOReturnNotReady;
volatile uint64_t dodge_native_entropy_bytes;
__attribute__((noinline)) void dodge_native_entropy_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

class DodgeEntropyClient;
// Compatibility class name required by the unchanged iPhone prng_seedctl.
// The provider is the captured Qualcomm TRNG, not a virtual device or kernel PRNG.
class AppleVirtIOEntropy final : public IOService {
    OSDeclareDefaultStructors(AppleVirtIOEntropy)
    IOMemoryMap *mapping = nullptr;
    IOLock *lock = nullptr;
    DodgeTrngState state{};
    bool ready = false;
    static bool read(void *opaque, unsigned offset, uint32_t *value) {
        auto *self = static_cast<AppleVirtIOEntropy *>(opaque);
        if (!value || !self->mapping || (offset != 0 && offset != 4) || self->mapping->getLength() != dodgeTrngBytes) return false;
        *value = *reinterpret_cast<const volatile uint32_t *>(self->mapping->getVirtualAddress() + offset);
        __asm__ volatile("dmb oshld" ::: "memory");
        return true;
    }
    static void delay(void *, unsigned us) { IODelay(us); }
public:
    bool healthy() const { return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) && !isInactive(); }
    bool start(IOService *provider) override {
        if (!dodge_owner_system_allowed() || !IOService::start(provider)) return false;
        lock = IOLockAlloc();
        auto *memory = IODeviceMemory::withRange(dodgeTrngPhysical, dodgeTrngBytes);
        if (!lock || !memory) { if (memory) memory->release();return false; }
        mapping = memory->map(kIOMapAnywhere | kIOMapInhibitCache);memory->release();
        if (!mapping || mapping->getLength() != dodgeTrngBytes) return false;
        uint8_t sample[32] = {};
        const DodgeTrngIo io{this, read, delay};
        const DodgeTrngResult result = dodge_trng_read32(&state, &io, sample, sizeof(sample));
        dodge_trng_erase(sample, sizeof(sample));
        if (result != DodgeTrngOk) return false;
        if (!setProperty("DodgeNativeHardwareEntropy", true) || !setProperty("EntropySource", "qcom,trng") ||
            !setProperty("HardwareEntropyQualified", false)) return false;
        __atomic_store_n(&ready, true, __ATOMIC_RELEASE);registerService();return true;
    }
    IOReturn obtain(void *out, size_t bytes) {
        if (!out || bytes != 32) return kIOReturnBadArgument;
        if (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE) || isInactive() || !dodge_owner_system_allowed()) return kIOReturnNotReady;
        uint8_t sample[32] = {};
        const DodgeTrngIo io{this, read, delay};
        IOLockLock(lock);
        const DodgeTrngResult result = dodge_trng_read32(&state, &io, sample, sizeof(sample));
        __atomic_fetch_add(&dodge_native_entropy_requests, 1U, __ATOMIC_RELAXED);
        if (result == DodgeTrngOk) {
            memcpy(out, sample, sizeof(sample));__atomic_fetch_add(&dodge_native_entropy_bytes, UINT64_C(32), __ATOMIC_RELAXED);
        } else {
            __atomic_fetch_add(&dodge_native_entropy_failures, 1U, __ATOMIC_RELAXED);
            if (state.healthFailed) __atomic_store_n(&ready, false, __ATOMIC_RELEASE);
        }
        dodge_trng_erase(sample, sizeof(sample));IOLockUnlock(lock);
        dodge_native_entropy_checkpoint();
        return result == DodgeTrngOk ? kIOReturnSuccess : result == DodgeTrngTimeout ? kIOReturnTimeout : kIOReturnIOError;
    }
    IOReturn newUserClient(task_t, void *, UInt32, OSDictionary *, IOUserClient **) override;
    IOReturn newUserClient(task_t, void *, UInt32, IOUserClient **) override;
};

class DodgeEntropyClient final : public IOUserClient {
    OSDeclareDefaultStructors(DodgeEntropyClient)
    AppleVirtIOEntropy *source = nullptr;
public:
    bool start(IOService *provider) override {
        source = OSDynamicCast(AppleVirtIOEntropy, provider);
        return source && IOUserClient::start(provider);
    }
    IOReturn clientClose() override { terminate();return kIOReturnSuccess; }
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments, IOExternalMethodDispatch *dispatch = nullptr,
                            OSObject *target = nullptr, void *reference = nullptr) override {
        (void)dispatch;(void)target;(void)reference;
        if (!arguments) return kIOReturnBadArgument;
        const bool valid = dodge_entropy_request_valid(selector, arguments->scalarInputCount, arguments->scalarOutputCount,
            arguments->structureInputSize, arguments->structureOutputSize, arguments->structureInputDescriptor != nullptr,
            arguments->structureOutputDescriptor != nullptr);
        if (!valid || !arguments->structureOutput) { arguments->structureOutputSize = 0;return kIOReturnBadArgument; }
        if (!source || isInactive()) { arguments->structureOutputSize = 0;return kIOReturnNotReady; }
        const IOReturn result = source->obtain(arguments->structureOutput, 32);
        arguments->structureOutputSize = result ? 0 : 32;
        return result;
    }
};
OSDefineMetaClassAndStructors(AppleVirtIOEntropy, IOService)
OSDefineMetaClassAndStructors(DodgeEntropyClient, IOUserClient)

IOReturn AppleVirtIOEntropy::newUserClient(task_t task, void *security, UInt32 type, OSDictionary *properties, IOUserClient **out) {
    if (!out) return kIOReturnBadArgument;
    *out = nullptr;
    if (type || !dodge_owner_security_ready() || !__atomic_load_n(&ready, __ATOMIC_ACQUIRE) || isInactive()) return kIOReturnNotReady;
    const IOReturn privilege = IOUserClient::clientHasPrivilege(task, kIOClientPrivilegeAdministrator);
    if (privilege) return privilege;
    auto *client = new DodgeEntropyClient;
    if (!client) return kIOReturnNoMemory;
    if (!client->initWithTask(task, security, type, properties) || !client->attach(this)) { client->release();return kIOReturnError; }
    if (!client->start(this)) { client->detach(this);client->release();return kIOReturnError; }
    *out = client;return kIOReturnSuccess;
}
IOReturn AppleVirtIOEntropy::newUserClient(task_t task, void *security, UInt32 type, IOUserClient **out) {
    return newUserClient(task, security, type, nullptr, out);
}

namespace {
IOService *providerPin;
AppleVirtIOEntropy *driverPin;
IOReturn finish(IOReturn result) {
    __atomic_store_n(&dodge_native_entropy_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_native_entropy_phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_native_entropy_checkpoint();return result;
}
}
extern "C" IOReturn dodge_native_entropy_start() {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-native-entropy", &enabled, sizeof(enabled)) || !enabled) return kIOReturnSuccess;
    if (enabled != 1 || !dodge_owner_system_allowed()) return kIOReturnNotPermitted;
    auto *platform = IOService::getPlatform();
    if (!platform || platform->isInactive() || !(platform->getState() & kIOServiceRegisteredState)) return kIOReturnNotReady;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_native_entropy_phase, &expected, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) return finish(kIOReturnNoMemory);
    dodge_entropy_cpp_initializer();const IOReturn posted = OSMetaClass::postModLoad(handle);
    if (posted) return finish(posted);
    driverPin = new AppleVirtIOEntropy;
    if (!driverPin) return finish(kIOReturnNoMemory);
    platform->retain();providerPin = platform;
    // Keep the object, its mapping and lock after the first hardware read.
    if (!driverPin->init() || !driverPin->attach(providerPin) || !driverPin->start(providerPin)) return finish(kIOReturnError);
    return finish(kIOReturnSuccess);
}
extern "C" bool dodge_native_entropy_ready() {
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-native-entropy", &enabled, sizeof(enabled)) || !enabled) return true;
    return enabled == 1 && __atomic_load_n(&dodge_native_entropy_phase, __ATOMIC_ACQUIRE) == 2 && driverPin && driverPin->healthy();
}
