// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
enum class DodgeUfsPhase : unsigned {Cold,Loading,Ready,Failed};
enum class DodgeUfsStartPhase : unsigned {Idle,Entering,Started,Failed};
struct DodgeUfsStatus {
    DodgeUfsPhase phase;
    DodgeUfsStartPhase start;
    IOReturn last;
    bool startAttempted,driverRetained;
};
// Explicit ordinary kernel-thread entries. No loader context or work-loop gate
// may be held. Preparation loads the exact original storage class, then registers
// both native UFS classes in the real Kernel preModLoad/postModLoad context.
extern "C" IOReturn dodge_ufs_prepare();
// Requires native-ufs-root=1 and the actual IOPlatformExpertDevice provider of
// the current IODTPlatformExpert. The read-only target was compiled for SM8750.
// Returns an extra owned reference after start succeeds. A start attempt is
// never repeated. Once start is called, driver/provider/resources stay retained
// for this boot even on failure: active DMA quiescence/rollback is unqualified.
// Success describes controller start; asynchronous media matching/mounting and
// authenticated-root readiness must be checked separately.
extern "C" IOReturn dodge_ufs_start(IOService *rootDevice,IOService **ownedDriver);
extern "C" void dodge_ufs_status(DodgeUfsStatus *);
