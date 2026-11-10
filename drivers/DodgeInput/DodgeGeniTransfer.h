// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
extern "C" {
#include <GeniSpi.h>
}

// The target TouchComm implementation bounds every bus operation at 512+7.
constexpr size_t DODGE_GENI_TRANSFER_MAX=519;

// Owns one already-initialized SE, its buffers and serialized polling caller.
// Any failure latches *terminalError; future calls perform no bus/cache I/O.
// Never clear that error or release maps/buffers merely because cancellation
// or channel reset was acknowledged. Outputs are usable only on return zero.
extern "C" int dodge_geni_transfer(geni_spi *spi,const uint8_t *tx,uint8_t *rx,
                                   size_t bytes,int *terminalError);
