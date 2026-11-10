// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
extern "C" {
#include <GeniSpi.h>
}
struct DodgeGeniImage {
    const uint8_t *bytes=nullptr;
    size_t size=0;
    uint32_t core=0;
    uint16_t firmwareVersion=0,configurationVersion=0,words=0,wordOffset=0,
             configurations=0,indexOffset=0,valueOffset=0;
};
struct DodgeGeniResult {
    unsigned phase=0,writes=0;
    uint32_t firmwareBefore=0,firmwareAfter=0;
    bool loaded=false;
};
// The parser accepts raw SEFW only. ELF/PE ownership and exact OEM image hashes
// are checked offline; the generated original bytes live in ignored storage.
extern "C" int dodge_geni_parse(const uint8_t *,size_t,DodgeGeniImage *);
// Clocks must already be enabled. Adopt SPI firmware without changing it.
// Only a completely idle, empty QUP4.0 engine can be programmed. Other
// protocols, DMA ownership, hardware versions and partial loads are refused.
// After a programming attempt, keep the mapping/device pinned until reboot.
extern "C" int dodge_geni_prepare(geni_spi *,const uint8_t *,size_t,DodgeGeniResult *);
