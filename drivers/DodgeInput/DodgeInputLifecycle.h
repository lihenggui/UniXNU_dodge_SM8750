// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeInputPhase : unsigned {Cold,Loading,Ready,Failed};
enum class DodgeInputStart : unsigned {Idle,Entering,Started,Failed};
struct DodgeInputStatus {
    DodgeInputPhase phase;
    DodgeInputStart start[2]; // buttons, touch
    IOReturn last[2];
    bool initializationAttempted[2],attempted[2],driverRetained[2],providerRetained[2];
};
// Ordinary kernel thread only; no work-loop gate or loader context held.
extern "C" IOReturn dodge_input_prepare();
// dodge-input=1, exact original parent loaded/registered, current IODT platform
// root required. Each device may initialize/start once per boot. Before init
// the object/provider are pinned: original free dereferences its expansion
// even after an expansion-allocation failure. After hardware entry all
// mappings remain retained even on failure. No reset or
// hot-unplug cleanup is qualified. Success returns an extra owned reference.
extern "C" IOReturn dodge_input_start(IOService *,bool touch,IOService **);
extern "C" void dodge_input_status(DodgeInputStatus *);
