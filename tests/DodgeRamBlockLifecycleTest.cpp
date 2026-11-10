// SPDX-License-Identifier: MIT
// Explicit IOKit/loader/original-init peers for the real lifecycle source.
#include "DodgeRamBlockLifecycle.h"
#include "OriginalStorageABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSKext.h>
#include <mach/kmod.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static std::string mode;
static OSMetaClass driverMeta(352), wrong(144);
extern "C" {
kmod_info_t g_kernel_kmod_info = {"__kernel__"};
OSMetaClass dodge_test_data_parent(144);
extern const unsigned char dodge_original_storage_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_data_parent")));
}
struct Root final : IOService {
    const IOService *metaCast(const char *name) const override {
        return mode != "wrong-provider" && !std::strcmp(name, "IOPlatformExpertDevice") ? this : nullptr;
    }
};
static Root *root = nullptr;
static IOPlatformExpert *platform = nullptr;
static IOService *live = nullptr;
static unsigned loads = 0, pre = 0, post = 0, initializers = 0, symbols = 0, allocations = 0, starts = 0, frees = 0, reentries = 0;
static bool registeredClass = false, insideLoader = false;
static void reenter(const char *stage) {
    if (mode != std::string("reentry-") + stage) return;
    IOService *out = nullptr; assert(dodge_ramblock_start(root, &out) == kIOReturnBusy && !out); ++reentries;
}
IOPlatformExpert *IOService::getPlatform() { return mode == "no-platform" ? nullptr : platform; }
bool PE_parse_boot_argn(const char *name, void *value, int bytes) {
    assert(!std::strcmp(name, "dodge-data") && bytes == 4);
    *static_cast<unsigned *>(value) = mode == "flag-zero" ? 0 : mode == "flag-two" ? 2 : 1;
    return mode != "flag-missing";
}
IOReturn OSKext::loadKextWithIdentifier(const char *name, bool defer, bool delay, OSKextExcludeLevel start, OSKextExcludeLevel match, void *p) {
    assert(!std::strcmp(name, "com.apple.iokit.IOStorageFamily") && !defer && delay && !start && !match && !p); ++loads;
    if (mode == "reentry-prepare") { assert(dodge_ramblock_prepare() == kIOReturnBusy); ++reentries; }
    return mode == "load-failure" ? -90 : kIOReturnSuccess;
}
const OSSymbol *OSSymbol::withCStringNoCopy(const char *name) {
    if ((mode == "parent-symbol-failure" && !std::strcmp(name, DodgeOriginalStorageClass)) ||
        (mode == "child-symbol-failure" && !std::strcmp(name, "NativeRamBlock"))) return nullptr;
    ++symbols; return new OSSymbol{name};
}
void OSSymbol::release() const { assert(symbols); --symbols; delete this; }
const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *name) {
    OSMetaClass *value = nullptr;
    if (!std::strcmp(name->name, DodgeOriginalStorageClass)) {
        if (mode == "parent-missing") return nullptr;
        value = mode == "parent-identity" ? &wrong : &dodge_test_data_parent;
        if (mode == "parent-size") value->size = 145;
    } else {
        assert(registeredClass && post == 1 && !std::strcmp(name->name, "NativeRamBlock"));
        if (mode == "child-missing") return nullptr;
        value = mode == "child-identity" ? &wrong : &driverMeta;
        if (mode == "child-size") ++value->size;
    }
    ++value->pins; return value;
}
void OSMetaClass::releaseMetaClass() const { assert(pins); --pins; }
void *OSMetaClass::preModLoad(const char *name) {
    assert(!std::strcmp(name, "__kernel__") && dodge_test_data_parent.pins == 1 && !insideLoader); ++pre; insideLoader = true;
    return mode == "pre-failure" ? nullptr : &pre;
}
IOReturn OSMetaClass::postModLoad(void *handle) {
    assert(handle == &pre && insideLoader && initializers == 1); insideLoader = false; ++post; registeredClass = true;
    return mode == "post-failure" ? -91 : 0;
}
extern "C" void dodge_ramblock_cpp_initializer() asm("__GLOBAL__sub_I_DodgeRamBlock.cpp");
extern "C" void dodge_ramblock_cpp_initializer() {
    assert(insideLoader && pre == 1 && !initializers); ++initializers; assert(dodge_ramblock_prepare() == kIOReturnBusy);
}
extern "C" unsigned dodge_ramblock_driver_bytes() { return 352; }
extern "C" const OSMetaClass *dodge_ramblock_driver_meta() { return &driverMeta; }
struct Driver final : IOService {
    ~Driver() override { ++frees; live = nullptr; }
    bool init() override {
        DodgeRamBlockStatus state{}; dodge_ramblock_status(&state);
        assert(state.instancePinned && state.driverRetained && !state.startAttempted && references == 2 && root->references == 2);
        reenter("init"); return mode != "init-failure";
    }
    bool attach(IOService *p) override {
        assert(p == root && references == 2); reenter("attach");
        if (mode == "attach-failure") return false;
        parent = p; return true;
    }
    bool start(IOService *p) override {
        assert(p == parent && p == root && root->references == 2 && references == 2); ++starts;
        DodgeRamBlockStatus state{}; dodge_ramblock_status(&state); assert(state.instancePinned && state.startAttempted);
        reenter("start");
        if (mode == "concurrent-start") {
            std::thread second([] { IOService *out = nullptr; assert(dodge_ramblock_start(root, &out) == kIOReturnBusy && !out); }); second.join();
        }
        return mode != "start-failure";
    }
};
extern "C" IOService *dodge_ramblock_allocate() {
    assert(registeredClass && !insideLoader && !driverMeta.pins && !live); ++allocations;
    if (mode == "allocation-failure") return nullptr;
    live = new Driver; return live;
}
int main(int argc, char **argv) {
    assert(argc == 2); mode = argv[1]; root = new Root; platform = new IOPlatformExpert; platform->parent = root;
    if (mode == "null-out") { assert(dodge_ramblock_start(root, nullptr) == kIOReturnBadArgument); goto done; }
    if (mode == "null-provider") { IOService *out = root; assert(dodge_ramblock_start(nullptr, &out) == kIOReturnBadArgument && !out); goto done; }
    if (mode == "inactive-provider") root->inactive = true;
    if (mode == "inactive-platform") platform->inactive = true;
    {
        IOService *out = root;
        const IOReturn result = dodge_ramblock_start(root, &out);
        DodgeRamBlockStatus state{}; dodge_ramblock_status(&state);
        if (mode == "flag-zero" || mode == "flag-two" || mode == "flag-missing") { assert(result == kIOReturnNotPermitted && !loads && !out); goto done; }
        if (mode == "wrong-provider" || mode == "no-platform" || mode == "inactive-provider" || mode == "inactive-platform") {
            assert(result == kIOReturnUnsupported && !loads && !out); goto done;
        }
        if (state.phase == DodgeRamBlockPhase::Cold || state.phase == DodgeRamBlockPhase::Failed) {
            assert(result && !out && !allocations && !starts && root->references == 1 && !symbols && !wrong.pins);
            assert(dodge_test_data_parent.pins == (state.phase == DodgeRamBlockPhase::Failed ? 1u : 0u));
            if (state.phase == DodgeRamBlockPhase::Failed) {
                unsigned oldLoads = loads; assert(dodge_ramblock_prepare() == result && loads == oldLoads && initializers <= 1);
            }
        } else if (mode == "allocation-failure") {
            assert(result == kIOReturnNoMemory && !out && !live && !state.instancePinned && state.start == DodgeRamBlockStartPhase::Idle && root->references == 1);
            assert(dodge_ramblock_start(root, &out) == kIOReturnNoMemory && allocations == 2 && !out && root->references == 1);
        } else {
            assert(allocations == 1 && live && !frees && root->references == 2 && state.instancePinned && state.driverRetained);
            IOService *again = nullptr;
            if (mode == "init-failure" || mode == "attach-failure" || mode == "start-failure") {
                assert(result == kIOReturnNotReady && !out && state.start == DodgeRamBlockStartPhase::Failed && live->references == 2);
                assert(state.startAttempted == (mode == "start-failure"));
                assert(dodge_ramblock_start(root, &again) == result && !again && allocations == 1 && !frees);
            } else {
                assert(!result && out == live && starts == 1 && state.start == DodgeRamBlockStartPhase::Started && live->references == 3);
                assert(dodge_ramblock_start(root, &again) == kIOReturnNotPermitted && !again && allocations == 1 && starts == 1);
                out->release(); assert(live->references == 2 && !frees);
            }
        }
        if (mode.find("reentry-") == 0) assert(reentries == 1);
    }
done:
    dodge_ramblock_status(nullptr);
    assert(!symbols && !driverMeta.pins && !wrong.pins);
    // Harness-only reclamation after all retention assertions; production keeps
    // these resources until reboot and has no corresponding cleanup operation.
    while (live) live->release();
    platform->release();
    while (root->references > 1) root->release();
    root->release();
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"loads\":%u,\"initializers\":%u,\"starts\":%u}\n", mode.c_str(), loads, initializers, starts);
}
