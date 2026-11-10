// SPDX-License-Identifier: BSD-2-Clause-Patent
// Target raw GPIO semantics and pinned Linux register facts; independent code.
#pragma once
#include "DodgeTouchPower.h"
struct DodgeGpioInitResult {
    DodgeAvddResult before;
    uint8_t digitalInput=0,mode=0,source=0,enable=0;
    unsigned writes=0;
    bool cold=false;
};
static inline int dodge_avdd_initialize(const peripheral_io *core,const peripheral_io *cnfg,
                                        const peripheral_io *obs,const peripheral_io *channels,
                                        unsigned channelBytes,unsigned ppid,unsigned ee,unsigned on,
                                        DodgeGpioInitResult *result) {
    if (!result || !obs || !obs->read || !obs->write || !obs->delay || on>1) return -22;
    *result=DodgeGpioInitResult{};auto &p=result->before;
    int apid=dodge_spmi_find_writer(core,cnfg,ppid,ee);p.apid=apid;if (apid<0) return apid;
    const uint8_t offsets[]={4,5,0x40,0x44,0x41,0x45,0x46,0x43};
    uint8_t *values[]={&p.type,&p.subtype,&p.mode,&p.source,&p.vin,&p.output,&p.enable,&result->digitalInput};
    for (unsigned i=0;i<8;++i) {
        int rc=spmi_read8(obs,ee,apid,offsets[i],values[i]);if (rc) return rc;
    }
    if (p.type!=0x10 || p.subtype<0x10 || p.subtype>0x13) return -19;
    const unsigned sources[]={1,2,2,3};
    // Electrical state is read and validated, never invented. Normal mux,
    // valid VIN, CMOS with a real drive strength and no DTEST are required.
    if ((p.vin&7)>=sources[p.subtype-0x10] || (p.source&15) || (p.output&0x30) ||
        !(p.output&3) || (result->digitalInput&0x80) || (p.mode&3)==3) return -95;
    result->mode=(uint8_t)((p.mode&~3u)|((p.mode&3)==0?2u:(p.mode&3)));
    result->source=(uint8_t)((p.source&~0x80u)|(on<<7));
    result->enable=(uint8_t)(p.enable|0x80u);
    result->cold=(p.mode&3)==0 || !(p.enable&0x80);
    // Preload the physical output before enabling its driver. Preserve input
    // enable as stock direction_output does: input -> input/output, not a
    // guessed pin voltage or a global PMIC reset. Every write rechecks owner.
    const uint8_t regs[]={0x44,0x40,0x46};
    const uint8_t before[]={p.source,p.mode,p.enable};
    const uint8_t after[]={result->source,result->mode,result->enable};
    for (unsigned i=0;i<3;++i) {
        if (before[i]!=after[i]) {
            int rc=dodge_spmi_write8(core,cnfg,channels,channelBytes,ppid,ee,apid,regs[i],after[i]);
            if (rc) return rc;
            ++result->writes;
        }
        uint8_t actual=0;int rc=spmi_read8(obs,ee,apid,regs[i],&actual);if (rc) return rc;
        if (actual!=after[i]) return -5;
    }
    // Detect concurrent changes to the electrical fields we chose to keep.
    const uint8_t preservedRegs[]={0x41,0x45,0x43};
    const uint8_t preserved[]={p.vin,p.output,result->digitalInput};
    for (unsigned i=0;i<3;++i) {
        uint8_t actual=0;int rc=spmi_read8(obs,ee,apid,preservedRegs[i],&actual);
        if (rc) return rc;
        if (actual!=preserved[i]) return -16;
    }
    return 0;
}
