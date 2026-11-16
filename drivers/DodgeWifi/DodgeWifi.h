// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "WifiBringup.h"

// The caller supplies value-initialized state and callbacks for resources it
// owns. Stage 1 surveys without writes. Stages 2/3 explicitly power/train the
// link; endpoint bus mastering and DMA ownership are separate integrations.
// A state is single-use after any hardware attempt, including failed attempts.
extern "C" int dodge_wifi_prepare(pagani_wifi::Bringup *, const pagani_wifi::Hw *, unsigned stage, unsigned generation);
extern "C" unsigned dodge_wifi_rail_count();
