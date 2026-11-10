// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

struct DodgeAdrenoTimeline {
    uint64_t epoch;
    uint32_t submitted,retired;
};
static_assert(sizeof(DodgeAdrenoTimeline)==16,"Internal scalar timeline snapshot ABI");
// Strong backend import. Nonblocking: an unpublished/locked/poisoned GPU or
// active multi-ring preemption returns false and leaves output unchanged.
// Epoch changes before the publisher's recovery attempt. A display request
// must keep its first epoch and refuse completion after an observed change.
extern "C" bool dodge_adreno_display_timeline(DodgeAdrenoTimeline *);
