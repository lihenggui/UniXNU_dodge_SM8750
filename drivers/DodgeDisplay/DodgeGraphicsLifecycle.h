// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>

// Explicit blocking entry, called by a normal kernel thread after the module
// loader is available, with no work-loop gate or preModLoad context held.
// Starts original libraries through OSKext; it does not start GPU hardware.
extern "C" IOReturn dodge_graphics_prepare();

// Nonblocking prerequisite check after prepare. Returns an owned reference to
// the actual original IOSurfaceRoot; caller releases it. No display allocation
// or hardware startup occurs. Retention alone does not prevent termination.
extern "C" IOReturn dodge_graphics_acquire_root(IOService *provider,IOService **ownedRoot);

// One display start attempt per boot. Caller retains the real GOP provider
// throughout this call; index zero must describe the current PE console map.
// The provider must belong to the original AppleARMIODevice hierarchy, as
// required by Legacy's own cast; an arbitrary IOService map is insufficient.
// Returns NotReady without allocating until the original IOSurface software
// root is currently published/active; the caller can retry after IOBSD matching.
// Success returns an owned, initialized/attached/started display reference.
// On failed start, stop/detach may finish asynchronously; no retry is admitted.
extern "C" IOReturn dodge_graphics_attach(IOService *provider,IOService **ownedDisplay);

enum class DodgeGraphicsPhase : unsigned {Cold,Loading,Ready,Failed};
struct DodgeGraphicsStatus {DodgeGraphicsPhase phase;IOReturn last;unsigned attachment;};
extern "C" void dodge_graphics_status(DodgeGraphicsStatus *);
