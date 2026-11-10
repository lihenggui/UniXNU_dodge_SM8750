// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeSystemLatePhase : unsigned {Cold,Queued,Running,Finished};
struct DodgeSystemLateStatus {
    DodgeSystemLatePhase phase;
    IOReturn storageLast,graphicsScheduleLast;
    unsigned attempts;
    bool storageStarted;
};
// Isolated combined-candidate IOBSD hook. Without native-ufs-root=1, forwards
// directly to the existing opt-in graphics scheduler. With it, a separate
// thread attempts the read-only controller first, then schedules graphics only
// after controller start succeeds. Media mounting/authentication remain async.
extern "C" IOReturn dodge_system_schedule();
extern "C" void dodge_system_late_status(DodgeSystemLateStatus *);
