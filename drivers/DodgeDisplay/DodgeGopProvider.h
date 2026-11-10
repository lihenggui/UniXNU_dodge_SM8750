// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>

enum class DodgeGopProviderPhase : unsigned {Cold,Creating,Published};
struct DodgeGopProviderStatus {
    DodgeGopProviderPhase phase;
    IOReturn last;
    uint64_t physicalAddress,length;
    uint32_t width,height,rowBytes;
};

// Call from a normal kernel thread after dodge_graphics_prepare(), with the
// actual current IODTPlatformExpert. No loader context or work-loop gate may
// be held. Publishes at most one nub using the original AppleARMIODevice
// allocator and inherited public IOService init; never uses Apple's bus init.
// A published nub and its original metaclass stay pinned for this boot.
// Success returns an additional owned reference. Before publication, every
// failure unwinds and can be retried. A changed PE/GOP mode is refused.
extern "C" IOReturn dodge_gop_provider_publish(IOService *platform,IOService **ownedProvider);
extern "C" void dodge_gop_provider_status(DodgeGopProviderStatus *);

// Explicit late entry: prepare original libraries, publish the real GOP nub,
// then enter the existing one-shot GPU/display coordinator. The same caller
// context requirements as dodge_graphics_boot() apply. No automatic startup.
extern "C" IOReturn dodge_graphics_boot_gop(IOService *platform,IOService **ownedDisplay);
