// SPDX-License-Identifier: MIT
#include "DodgeDataLate.h"
#include "DodgeRamBlockLifecycle.h"
#include "DodgeSystemLate.h"
#include "DodgeGraphicsLate.h"
#include <IOKit/IOPlatformExpert.h>
#include <kern/thread.h>
#include <cassert>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

static std::string mode;
static IOPlatformExpert platform;
static IOService root;
static thread_continue_t continuation = nullptr;
static unsigned queues = 0, deallocations = 0, terminations = 0, sleeps = 0, calls = 0, released = 0, reentries = 0;
static bool pinned = false;
static void *const peer = reinterpret_cast<void *>(uintptr_t(0x12345678));
static void reenter(const char *stage) {
    if (mode == std::string("reentry-") + stage) { assert(dodge_data_schedule() == kIOReturnBusy); ++reentries; }
}
IOPlatformExpert *IOService::getPlatform() {
    return mode == "no-platform" || (mode == "provider-late" && sleeps < 2) ? nullptr : &platform;
}
bool PE_parse_boot_argn(const char *name, void *out, int bytes) {
    assert(bytes == 4); bool on = false;
    if (!std::strcmp(name, "dodge-data")) {
        on = mode != "disabled" && mode != "missing";
        if (mode == "other") { *static_cast<unsigned *>(out) = 2; return true; }
    } else if (!std::strcmp(name, "native-ufs-root")) on = mode == "wait-storage" || mode == "storage-timeout" || mode == "both-workers";
    else if (!std::strcmp(name, "dodge-graphics")) on = mode == "wait-graphics" || mode == "graphics-timeout" || mode == "both-workers";
    else assert(false);
    *static_cast<unsigned *>(out) = on; return mode != "missing";
}
kern_return_t kernel_thread_start(thread_continue_t entry, void *arg, thread_t *out) {
    assert(entry && !arg && *out == THREAD_NULL); ++queues; reenter("queue");
    if (mode == "thread-failure" || (mode == "thread-retry" && queues == 1)) return -1;
    continuation = entry; *out = peer;
    if (mode == "eager") entry(nullptr, 0);
    return 0;
}
void thread_deallocate(thread_t thread) { assert(thread == peer); ++deallocations; }
thread_t current_thread() { return peer; }
kern_return_t thread_terminate(thread_t thread) { assert(thread == peer); ++terminations; return 0; }
void IOSleep(unsigned ms) { assert(ms == 10); ++sleeps; reenter("sleep"); }
extern "C" void dodge_system_late_status(DodgeSystemLateStatus *state) {
    *state = {}; state->phase = ((mode == "wait-storage" || mode == "both-workers") && sleeps >= 3) ?
        DodgeSystemLatePhase::Finished : DodgeSystemLatePhase::Running;
}
extern "C" void dodge_graphics_late_status(DodgeGraphicsLateStatus *state) {
    *state = {}; state->phase = ((mode == "wait-graphics" || mode == "both-workers") && sleeps >= 4) ?
        DodgeGraphicsLatePhase::Finished : DodgeGraphicsLatePhase::Running;
}
struct Driver final : IOService { ~Driver() override { ++released; reenter("release"); } };
extern "C" IOReturn dodge_ramblock_start(IOService *provider, IOService **out) {
    assert(provider == &root && out && !*out); ++calls; reenter("start");
    if (mode == "wait-storage" || mode == "both-workers") assert(sleeps >= 3);
    if (mode == "wait-graphics" || mode == "both-workers") assert(sleeps >= 4);
    if ((mode == "busy" || mode == "reentry-sleep") && calls < 3) return kIOReturnBusy;
    if (mode == "prestart-timeout") return kIOReturnNotReady;
    if (mode == "unsupported") return kIOReturnUnsupported;
    if (mode == "allocation-failed") return kIOReturnNoMemory;
    if (mode == "metadata-failed" || mode == "init-failed" || mode == "start-failed") {
        pinned = mode != "metadata-failed"; return kIOReturnNotReady;
    }
    pinned = true;
    if (mode == "null-driver") return 0;
    *out = new Driver;
    return mode == "driver-with-error" ? kIOReturnError : kIOReturnSuccess;
}
extern "C" void dodge_ramblock_status(DodgeRamBlockStatus *state) {
    *state = {}; state->phase = mode == "metadata-failed" ? DodgeRamBlockPhase::Failed : DodgeRamBlockPhase::Ready;
    state->instancePinned = pinned; state->driverRetained = pinned;
    if (mode == "init-failed" || mode == "start-failed") state->start = DodgeRamBlockStartPhase::Failed;
}
int main(int argc, char **argv) {
    assert(argc == 2); mode = argv[1]; platform.parent = mode == "no-root" ? nullptr : &root;
    if (mode == "inactive-platform") platform.inactive = true;
    IOReturn result = 0;
    if (mode == "concurrent") {
        std::atomic<unsigned> ok{0}, busy{0}; std::vector<std::thread> threads;
        for (unsigned i = 0; i < 16; ++i) threads.emplace_back([&] {
            auto status = dodge_data_schedule(); if (!status) ++ok; else { assert(status == kIOReturnBusy); ++busy; }
        });
        for (auto &thread : threads) thread.join();
        assert(ok == 1 && busy == 15);
    } else result = dodge_data_schedule();
    DodgeDataLateStatus state{}; dodge_data_late_status(&state);
    if (mode == "disabled" || mode == "missing" || mode == "other") {
        assert(result == kIOReturnNotPermitted && !queues && !continuation); goto done;
    }
    if (mode == "thread-failure" || mode == "thread-retry") {
        assert(result == kIOReturnNoResources && state.phase == DodgeDataLatePhase::Cold && !continuation);
        if (mode == "thread-failure") goto done;
        assert(!dodge_data_schedule());
    } else assert(!result);
    if (mode != "eager") {
        assert(continuation && !calls); std::thread work([] { continuation(nullptr, 0); }); work.join();
    }
    dodge_data_late_status(&state);
    assert(state.phase == DodgeDataLatePhase::Finished && deallocations == 1 && terminations == 1 && dodge_data_schedule() == kIOReturnNotPermitted);
    if (mode == "no-platform" || mode == "inactive-platform" || mode == "no-root" || mode == "storage-timeout" || mode == "graphics-timeout") {
        assert(state.attempts == 1000 && sleeps == 999 && !calls && !state.driverStarted);
    } else if (mode == "prestart-timeout") {
        assert(calls == 1000 && sleeps == 999 && !state.driverStarted);
    } else {
        assert(calls == ((mode == "busy" || mode == "reentry-sleep") ? 3u : 1u));
        const bool failed = mode == "unsupported" || mode == "allocation-failed" || mode == "metadata-failed" ||
            mode == "init-failed" || mode == "start-failed" || mode == "null-driver" || mode == "driver-with-error";
        assert(bool(state.last) == failed && state.driverStarted == !failed);
        assert(released == (failed && mode != "driver-with-error" ? 0u : 1u));
        if (mode == "provider-late") assert(sleeps == 2 && state.attempts == 3);
    }
    if (mode.rfind("reentry-", 0) == 0) assert(reentries > 0);
done:
    dodge_data_late_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"start_calls\":%u,\"sleeps\":%u,\"owned_releases\":%u}\n", argv[1], calls, sleeps, released);
}
