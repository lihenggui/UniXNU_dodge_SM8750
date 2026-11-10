// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "DodgeGraphicsLifecycle.h"

// Explicit synchronous startup on a normal kernel thread, after IOBSD and
// module loading are available. No work-loop gate or loader context held.
// The caller supplies and retains the real AppleARMIODevice/GOP provider.
// Loads original modules, retains their actual software root, starts the A830
// board, then attaches the concrete display. Success transfers one display
// reference to the caller. Never selected or invoked by early constructors.
// Pre-hardware failures can be retried. Any hardware attempt makes this entry
// one-shot, including failure: the board has no qualified rollback/reset API.
extern "C" IOReturn dodge_graphics_boot(IOService *provider,IOService **ownedDisplay);

enum class DodgeGraphicsBootPhase : unsigned {Cold,Preparing,Prerequisites,Hardware,Display,Started,Failed};
struct DodgeGraphicsBootStatus {DodgeGraphicsBootPhase phase;IOReturn last;bool hardwareAttempted;};
// Started records a completed startup; it is not a current liveness query.
extern "C" void dodge_graphics_boot_status(DodgeGraphicsBootStatus *);
