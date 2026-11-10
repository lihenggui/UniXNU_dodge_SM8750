// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeInputLatePhase : unsigned {Cold,Queued,Running,Finished};
struct DodgeInputLateStatus {DodgeInputLatePhase phase;IOReturn keys,touch;unsigned attempts;};
// Queue only. The separate thread waits for explicitly selected storage and
// graphics workers before starting input, serializing their boot-time MMIO.
extern "C" IOReturn dodge_input_schedule();
extern "C" void dodge_input_late_status(DodgeInputLateStatus *);
