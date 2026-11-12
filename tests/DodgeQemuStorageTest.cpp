// SPDX-License-Identifier: MIT
// Loader and registry peers for the actual storage coordinator. Native ABI,
// MMIO, DMA and APFS are exercised separately by check_qemu_storage.py.
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "OriginalStorageABI.h"

using IOReturn = int32_t;
enum : IOReturn { kIOReturnSuccess = 0, kIOReturnNotReady = -1, kIOReturnNotPermitted = -2,
    kIOReturnUnsupported = -3, kIOReturnNoMemory = -4, kIOReturnNoResources = -5, kIOReturnTimeout = -6 };
constexpr unsigned kIOServiceRegisteredState = 2, kMillisecondScale = 1, kOSKextExcludeNone = 0;
static std::string mode;
static unsigned ticks = 0, sleeps = 0, loads = 0, initializers = 0, pre = 0, post = 0,
    allocations = 0, starts = 0, version = 0, count = 32;
static bool insideLoader = false;
struct OSObject { virtual ~OSObject() = default; };
struct OSData : OSObject {
    const char *bytes;
    unsigned length;
    OSData(const char *p, unsigned n) : bytes(p), length(n) {}
    unsigned getLength() const { return length; }
    const void *getBytesNoCopy() const { return bytes; }
};
struct OSIterator;
struct IORegistryEntry : OSObject {
    unsigned references = 1;
    virtual OSObject *getProperty(const char *) const { return nullptr; }
    void retain() { ++references; }
    virtual void release() { assert(references); --references; }
    static IORegistryEntry *fromPath(const char *, const void *);
};
struct IOPlatformExpert;
struct IOService : IORegistryEntry {
    IOService *parent = nullptr;
    virtual bool init() { return true; }
    virtual bool attach(IOService *p) { parent = p; return true; }
    virtual bool start(IOService *) { return true; }
    virtual const IOService *metaCast(const char *) const { return nullptr; }
    virtual bool isInactive() const { return false; }
    virtual unsigned getState() const { return kIOServiceRegisteredState; }
    virtual OSIterator *getChildIterator(const void *) { return nullptr; }
    static IOPlatformExpert *getPlatform();
};
struct OSIterator : OSObject {
    unsigned index = 0, capturedVersion = version;
    OSObject *getNextObject();
    void release() { delete this; }
};
static OSData compatible("virtio,mmio", sizeof("virtio,mmio")), busType("qemu-virt", sizeof("qemu-virt")), wrongType("dodge", 6);
struct Provider : IOService {
    unsigned index = 0;
    OSObject *getProperty(const char *name) const override { return !std::strcmp(name, "compatible") ? &compatible : nullptr; }
    const IOService *metaCast(const char *name) const override { return !std::strcmp(name, "IOPlatformDevice") ? this : nullptr; }
    bool isInactive() const override { return mode == "inactive-device" && index == 0; }
};
static std::array<Provider, 33> providers;
OSObject *OSIterator::getNextObject() {
    // A driver start invalidates an outstanding registry iterator. Production
    // must finish taking the provider snapshot before its first start call.
    if (capturedVersion != version || index == count) return nullptr;
    return &providers[index++];
}
struct Bus : IORegistryEntry {
    OSObject *getProperty(const char *name) const override {
        assert(!std::strcmp(name, "device_type"));return mode == "wrong-bus" ? &wrongType : &busType;
    }
};
static Bus bus;
struct IOPlatformExpert : IOService {
    const IOService *metaCast(const char *name) const override { return !std::strcmp(name, "IODTPlatformExpert") ? this : nullptr; }
    bool isInactive() const override { return mode == "inactive-platform"; }
    unsigned getState() const override {
        return mode == "platform-timeout" || (mode == "platform-delay" && ticks < 3) ? 0 : kIOServiceRegisteredState;
    }
    OSIterator *getChildIterator(const void *) override { assert(getState() & kIOServiceRegisteredState);return new OSIterator; }
};
static IOPlatformExpert platform;
static const void *gIODTPlane = &bus, *gIOServicePlane = &platform;
IOPlatformExpert *IOService::getPlatform() { return mode == "no-platform" ? nullptr : &platform; }
IORegistryEntry *IORegistryEntry::fromPath(const char *path, const void *plane) {
    assert(!std::strcmp(path, "/arm-io") && plane == gIODTPlane);
    if (mode == "missing-bus") return nullptr;
    bus.retain();return &bus;
}
struct OSSymbol {
    const char *name;
    static const OSSymbol *withCStringNoCopy(const char *p) { return new OSSymbol{p}; }
    void release() const { delete this; }
};
struct OSMetaClass {
    unsigned size;
    mutable unsigned pins = 0;
    explicit OSMetaClass(unsigned n) : size(n) {}
    __attribute__((noinline, noipa)) unsigned getClassSize() const { return size; }
    void releaseMetaClass() const { assert(pins);--pins; }
    static const OSMetaClass *copyMetaClassWithName(const OSSymbol *);
    static void *preModLoad(const char *);
    static IOReturn postModLoad(void *);
};
struct OSKext { static IOReturn loadKextWithIdentifier(const char *, bool, bool, unsigned, unsigned, void *); };
struct kmod_info_t { char name[64]; };
bool PE_parse_boot_argn(const char *name, void *out, int bytes) {
    assert(!std::strcmp(name, "dodge-qemu-root") && bytes == 4);
    *static_cast<unsigned *>(out) = mode == "flag-zero" ? 0 : mode == "flag-two" ? 2 : 1;
    return mode != "flag-missing";
}
uint64_t mach_absolute_time() { return ticks; }
void clock_interval_to_deadline(unsigned ms, unsigned scale, uint64_t *out) { assert(scale == kMillisecondScale);*out = ticks + ms; }
void IOSleep(unsigned ms) { assert(!loads && !allocations);ticks += ms;++sleeps; }
#define OSDynamicCast(type, object) dynamic_cast<type *>(object)
#include "DodgeQemuStorage.extracted.h"

static OSMetaClass driverMeta(216), wrongMeta(144);
extern "C" {
kmod_info_t g_kernel_kmod_info = {"__kernel__"};
OSMetaClass dodge_test_qemu_parent(144);
extern const unsigned char dodge_original_storage_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_qemu_parent")));
extern const unsigned dodge_virtio_driver_bytes = 216;
const OSMetaClass *dodge_virtio_driver_meta() { return &driverMeta; }
}
// Keep the loader boundary opaque, as it is in the native translation units.
__attribute__((noinline, noipa)) const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *symbol) {
    OSMetaClass *result;
    if (!std::strcmp(symbol->name, DodgeOriginalStorageClass)) {
        result = mode == "parent-identity" ? &wrongMeta : &dodge_test_qemu_parent;
        if (mode == "parent-size") ++result->size;
    } else {
        assert(!std::strcmp(symbol->name, "NativeVirtioBlock") && initializers == 1 && post == 1);
        result = mode == "child-identity" ? &wrongMeta : &driverMeta;
        if (mode == "child-size") ++result->size;
    }
    ++result->pins;return result;
}
void *OSMetaClass::preModLoad(const char *name) {
    assert(!std::strcmp(name, "__kernel__") && !insideLoader && dodge_test_qemu_parent.pins == 1);
    ++pre;insideLoader = true;return mode == "pre-failure" ? nullptr : &pre;
}
IOReturn OSMetaClass::postModLoad(void *handle) {
    assert(handle == &pre && insideLoader && initializers == 1);insideLoader = false;++post;
    return mode == "post-failure" ? -91 : 0;
}
extern "C" void dodge_virtio_cpp_initializer() {
    assert(insideLoader && !initializers && dodge_qemu_storage_phase == 1);++initializers;
    assert(dodge_qemu_storage_start() == kIOReturnNotPermitted);
}
IOReturn OSKext::loadKextWithIdentifier(const char *name, bool defer, bool delay, unsigned start, unsigned match, void *p) {
    assert(!defer && delay && !start && !match && !p && platform.getState() & kIOServiceRegisteredState);++loads;
    if (!std::strcmp(name, "com.apple.iokit.IOStorageFamily")) {
        assert(!allocations && !initializers);
        if (mode == "concurrent-entry") {
            std::thread second([] { assert(dodge_qemu_storage_start() == kIOReturnNotPermitted); });second.join();
        }
        return mode == "load-failure" ? -90 : 0;
    }
    assert(!std::strcmp(name, "com.apple.filesystems.apfs") && dodge_qemu_storage_started == 2);
    return mode == "apfs-failure" ? -92 : 0;
}
struct Driver : IOService {
    bool init() override { return mode != "init-failure"; }
    bool attach(IOService *p) override { return mode != "attach-failure" && IOService::attach(p); }
    bool start(IOService *p) override {
        assert(p == parent && p->references == 2 && references == 1 && !insideLoader && !driverMeta.pins);
        ++version;++starts;
        return mode != "start-failure" && static_cast<Provider *>(p)->index >= 30;
    }
};
static std::vector<std::unique_ptr<Driver>> objects;
extern "C" IOService *dodge_virtio_allocate() {
    assert(initializers == 1 && post == 1 && !insideLoader && !driverMeta.pins);++allocations;
    if (mode == "allocation-failure" || (mode == "partial-allocation" && allocations == 8)) return nullptr;
    objects.push_back(std::make_unique<Driver>());return objects.back().get();
}
int main(int argc, char **argv) {
    assert(argc == 2);mode = argv[1];
    for (unsigned index = 0; index < providers.size(); ++index) providers[index].index = index;
    if (mode == "too-many") count = 33;
    const IOReturn result = dodge_qemu_storage_start();
    const bool preflight = mode == "flag-missing" || mode == "flag-zero" || mode == "flag-two" || mode == "no-platform" ||
        mode == "inactive-platform" || mode == "wrong-bus" || mode == "missing-bus";
    const bool success = mode == "success" || mode == "platform-delay" || mode == "snapshot-invalidation" ||
        mode == "inactive-device" || mode == "concurrent-entry";
    if (result == kIOReturnSuccess ? !success : success)
        std::fprintf(stderr, "unexpected result %d, phase %u, loads %u, init %u, allocations %u, starts %u\n",
            result, dodge_qemu_storage_phase, loads, initializers, allocations, starts);
    assert(result == kIOReturnSuccess ? success : !success);
    if (preflight) assert(!dodge_qemu_storage_phase && !loads && !allocations);
    else {
        assert(dodge_qemu_storage_phase == (success ? 2U : 3U));
        const unsigned oldLoads = loads, oldAllocations = allocations;
        assert(dodge_qemu_storage_start() == kIOReturnNotPermitted && loads == oldLoads && allocations == oldAllocations);
    }
    if (success || mode == "apfs-failure") {
        const unsigned expected = mode == "inactive-device" ? 31 : 32;
        assert(initializers == 1 && dodge_qemu_storage_attempted == expected && starts == expected &&
            dodge_qemu_storage_started == 2 && allocations == expected && loads == 2);
    }
    if (mode == "platform-delay") assert(sleeps == 3);
    if (mode == "platform-timeout") assert(result == kIOReturnTimeout && sleeps == 5000 && !loads && !initializers);
    if (mode == "too-many") assert(result == kIOReturnNoResources && !allocations);
    if (mode == "allocation-failure") assert(result == kIOReturnNoMemory && allocations == 1 && !objects.size());
    if (mode == "partial-allocation") assert(result == kIOReturnNoMemory && allocations == 8 && objects.size() == 7);
    if (mode == "init-failure" || mode == "attach-failure" || mode == "start-failure")
        assert(result == kIOReturnNotReady && allocations == 32 && objects.size() == 32 && !dodge_qemu_storage_started);
    for (unsigned index = 0; index < providers.size(); ++index) {
        const bool pinned = (index < dodge_qemu_storage_attempted && !(mode == "inactive-device" && index == 0)) ||
            (mode == "inactive-device" && index == 31);
        assert(providers[index].references == (pinned ? 2U : 1U));
    }
    assert(bus.references == 1 && !driverMeta.pins);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\"}\n", mode.c_str());
}
