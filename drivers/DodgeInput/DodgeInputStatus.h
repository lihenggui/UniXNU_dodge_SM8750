// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
enum {DODGE_KEYS,DODGE_TOUCH};
struct DodgeInputSample {uint32_t stage,sample;int32_t result;uint64_t reports;};
struct DodgeInputDiagnostics {
    DodgeInputSample device[2];
    uint32_t spi[6],dma[4],read[8],smmu[4],power[7],hid[8];
    uint64_t hidOutputXY;
};
extern "C" void dodge_input_observe(unsigned,const char *,int32_t,uint32_t,uint64_t);
extern "C" void dodge_input_touch_spi(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" void dodge_input_touch_dma(uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" void dodge_input_touch_read(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" void dodge_input_touch_power(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" void dodge_input_touch_hid(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint64_t,uint32_t);
extern "C" void dodge_input_touch_smmu(uint32_t,uint32_t,uint32_t,uint32_t);
// Per-field atomic diagnostic snapshot; fields need not be from one tick.
extern "C" void dodge_input_diagnostics(DodgeInputDiagnostics *);
