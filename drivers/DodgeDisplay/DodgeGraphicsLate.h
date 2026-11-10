// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>

enum class DodgeGraphicsLatePhase : unsigned {Cold,Queued,Running,Finished};
struct DodgeGraphicsLateStatus {
    DodgeGraphicsLatePhase phase;
    IOReturn last;
    unsigned attempts;
    bool displayRetained;
};
// The isolated IOKitBSDInit overlay calls this after publishing IOBSD.
// Only dodge-graphics=1 schedules a worker; the caller never loads modules,
// waits for matching or starts hardware. One worker runs per successful queue.
extern "C" IOReturn dodge_graphics_schedule();
extern "C" void dodge_graphics_late_status(DodgeGraphicsLateStatus *);
