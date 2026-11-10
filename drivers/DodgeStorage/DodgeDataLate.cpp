// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeDataLate.h"
#include "DodgeRamBlockLifecycle.h"
#include "DodgeSystemLate.h"
#include "DodgeGraphicsLate.h"
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>

namespace {
unsigned phase = unsigned(DodgeDataLatePhase::Cold), attempts = 0;
IOReturn last = kIOReturnNotReady;
bool driverStarted = false;
bool enabled(const char *name) {
    unsigned value = 0;
    return PE_parse_boot_argn(name, &value, sizeof(value)) && value == 1;
}
bool earlierWorkersFinished() {
    if (enabled("native-ufs-root")) {
        DodgeSystemLateStatus status{}; dodge_system_late_status(&status);
        if (status.phase != DodgeSystemLatePhase::Finished) return false;
    }
    if (enabled("dodge-graphics")) {
        DodgeGraphicsLateStatus status{}; dodge_graphics_late_status(&status);
        if (status.phase != DodgeGraphicsLatePhase::Finished) return false;
    }
    return true;
}
void dataWorker(void *, wait_result_t) {
    __atomic_store_n(&phase, unsigned(DodgeDataLatePhase::Running), __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 1000; ++i) {
        __atomic_store_n(&attempts, i + 1, __ATOMIC_RELAXED);
        if (earlierWorkersFinished()) {
            auto *platform = IOService::getPlatform();
            IOService *root = platform && !platform->isInactive() ? platform->getProvider() : nullptr;
            IOService *driver = nullptr;
            IOReturn result = root ? dodge_ramblock_start(root, &driver) : kIOReturnNotReady;
            bool started = result == kIOReturnSuccess && driver;
            if (driver) { driver->release(); if (result) result = kIOReturnError; }
            else if (result == kIOReturnSuccess) result = kIOReturnError;
            __atomic_store_n(&last, result, __ATOMIC_RELAXED);
            __atomic_store_n(&driverStarted, started, __ATOMIC_RELAXED);
            DodgeRamBlockStatus state{}; dodge_ramblock_status(&state);
            if (state.instancePinned || state.start == DodgeRamBlockStartPhase::Failed || state.phase == DodgeRamBlockPhase::Failed ||
                (result != kIOReturnNotReady && result != kIOReturnBusy)) break;
        }
        if (i + 1 < 1000) IOSleep(10);
    }
    __atomic_store_n(&phase, unsigned(DodgeDataLatePhase::Finished), __ATOMIC_RELEASE);
    thread_terminate(current_thread());
}
}
extern "C" IOReturn dodge_data_schedule() {
    if (!enabled("dodge-data")) return kIOReturnNotPermitted;
    unsigned expected = unsigned(DodgeDataLatePhase::Cold);
    if (!__atomic_compare_exchange_n(&phase, &expected, unsigned(DodgeDataLatePhase::Queued), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == unsigned(DodgeDataLatePhase::Finished) ? kIOReturnNotPermitted : kIOReturnBusy;
    thread_t thread = THREAD_NULL;
    if (kernel_thread_start(dataWorker, nullptr, &thread) != KERN_SUCCESS) {
        __atomic_store_n(&phase, unsigned(DodgeDataLatePhase::Cold), __ATOMIC_RELEASE);
        return kIOReturnNoResources;
    }
    thread_deallocate(thread);
    return kIOReturnSuccess;
}
extern "C" void dodge_data_late_status(DodgeDataLateStatus *out) {
    if (!out) return;
    out->phase = DodgeDataLatePhase(__atomic_load_n(&phase, __ATOMIC_ACQUIRE));
    out->last = __atomic_load_n(&last, __ATOMIC_RELAXED);
    out->attempts = __atomic_load_n(&attempts, __ATOMIC_RELAXED);
    out->driverStarted = __atomic_load_n(&driverStarted, __ATOMIC_RELAXED);
}
