// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeDataLatePhase : unsigned { Cold, Queued, Running, Finished };
struct DodgeDataLateStatus {
    DodgeDataLatePhase phase;
    IOReturn last;
    unsigned attempts;
    bool driverStarted;
};
// Queue only, after the combined system scheduler in IOBSD. A separate ordinary
// kernel thread waits for selected storage/graphics work, then starts the Data
// block provider once. This does not mount or authenticate an APFS volume.
extern "C" IOReturn dodge_data_schedule();
extern "C" void dodge_data_late_status(DodgeDataLateStatus *);
