// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeRamBlockPhase : unsigned { Cold, Loading, Ready, Failed };
enum class DodgeRamBlockStartPhase : unsigned { Idle, Entering, Started, Failed };
struct DodgeRamBlockStatus {
    DodgeRamBlockPhase phase;
    DodgeRamBlockStartPhase start;
    IOReturn last;
    bool instancePinned, startAttempted, driverRetained;
};
// Ordinary kernel-thread entry; the caller must hold no loader or work-loop gate.
extern "C" IOReturn dodge_ramblock_prepare();
// Default off: requires dodge-data=1 and the current platform's root provider.
// The first object/provider are retained before original init. Any init/attach/
// start failure is latched without releasing potentially published resources.
// Success returns one extra owned reference. This does not mount APFS Data.
extern "C" IOReturn dodge_ramblock_start(IOService *, IOService **);
extern "C" void dodge_ramblock_status(DodgeRamBlockStatus *);
