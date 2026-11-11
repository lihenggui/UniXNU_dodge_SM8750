/* SPDX-License-Identifier: MIT */
#pragma once
#include "Adreno830Board.h"

using DodgeNativeA830Argument = bool (*)(void *, const char *, uint32_t *);

/* Populate declarations and check firmware metadata. S0 hashes the actual bytes.
 * expectedSoc must be one of the captured DT's SoC IDs; S0 compares it to SMEM. */
IOReturn DodgeNativeA830FillBoard(Adreno830Board *board, uint32_t expectedSoc,
                                const Adreno830Firmware (&firmware)[4]);
void DodgeNativeA830ParseKnobs(Adreno830Board *board, DodgeNativeA830Argument get, void *cookie);

/* Explicit, synchronous, once per boot. No caller is selected in the default kernel. */
extern "C" IOReturn dodge_native_a830_start(uint32_t expectedSoc);
