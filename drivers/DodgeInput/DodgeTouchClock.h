// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <PeripheralIO.h>

struct DodgeTouchClockResult {
    uint32_t hz=0,select=0,phase=0,writes=0;
    uint32_t voteBefore=0,commandBefore=0,configurationBefore=0,dfsBefore=0;
    bool programmed=false;
};

// Device-specific QUP1 SE4 clock ownership. Shared votes are only raised.
// A stopped, unvoted, non-DFS root can be initialized to the 19.2 MHz XO.
// Existing roots/DFS tables and live GPLL0 parameters are otherwise read-only.
// SE activity, foreign firmware, GPI/DMA ownership and ambiguous updates refuse
// takeover. Leave votes and the caller's mappings pinned after any attempt.
extern "C" int dodge_touch_clock_prepare(const peripheral_io *gcc,
                                         const peripheral_io *se,
                                         DodgeTouchClockResult *result);
