// SPDX-License-Identifier: BSD-2-Clause-Patent
// Register facts independently checked against pinned Linux v6.12 SPMI
// arbiter / PMIC GPIO sources. No Linux implementation is included here.
#pragma once
#include <PeripheralIO.h>

struct DodgeAvddResult {
    int apid=-1;
    uint8_t type=0,subtype=0,mode=0,source=0,vin=0,output=0,enable=0,readback=0;
    bool wrote=false;
};
static inline bool dodge_spmi_owned(const peripheral_io *core,const peripheral_io *cnfg,
                                    unsigned apid,unsigned ppid,unsigned ee) {
    uint32_t map=peripheral_read(core,0x2000+4*apid);
    return map && ((map>>8)&0xfff)==ppid && (peripheral_read(cnfg,4*apid)&7)==ee;
}
static inline int dodge_spmi_find_writer(const peripheral_io *core,const peripheral_io *cnfg,
                                         unsigned ppid,unsigned ee) {
    if (!core || !cnfg || !core->read || !cnfg->read || ppid>0xfff || ee>7) return -22;
    uint32_t version=peripheral_read(core,0),count=peripheral_read(core,4)&0x7ff;
    if (version<0x70000000 || version>=0x80000000 || !count || count>1024) return -19;
    int found=-19;
    for (unsigned i=0;i<count;++i) if (dodge_spmi_owned(core,cnfg,i,ppid,ee)) {
        if (found>=0) return -16; // Ambiguous local write ownership is refused.
        found=(int)i;
    }
    return found;
}
static inline int dodge_spmi_write8(const peripheral_io *core,const peripheral_io *cnfg,
                                    const peripheral_io *channels,unsigned channelBytes,
                                    unsigned ppid,unsigned ee,int apid,uint8_t offset,uint8_t value) {
    if (!core || !cnfg || !core->read || !cnfg->read || !channels || !channels->read || !channels->write || !channels->delay ||
        apid<0 || apid>=1024 || ppid>0xfff || ee>7 || channelBytes<0x1000 ||
        (unsigned)apid>(channelBytes-0x1000)/0x1000) return -22;
    if (!dodge_spmi_owned(core,cnfg,(unsigned)apid,ppid,ee)) return -13;
    uint32_t ch=(unsigned)apid*0x1000;
    peripheral_write(channels,ch+0x10,value);
    peripheral_write(channels,ch,(uint32_t)offset<<4); // EXT_WRITEL, exactly one byte.
    for (unsigned n=0;n<1000;++n) {
        uint32_t status=peripheral_read(channels,ch+8);
        if (status&0xe) return -5;
        if (status&1) return 0;
        channels->delay(channels->context,1);
    }
    return -110;
}
static inline int dodge_avdd_adopt(const peripheral_io *core,const peripheral_io *cnfg,
                                   const peripheral_io *obs,const peripheral_io *channels,
                                   unsigned channelBytes,unsigned ppid,unsigned ee,unsigned on,
                                   DodgeAvddResult *out) {
    if (!out || !obs || !obs->read || !obs->write || !obs->delay || on>1) return -22;
    *out=DodgeAvddResult{};
    int apid=dodge_spmi_find_writer(core,cnfg,ppid,ee);out->apid=apid;
    if (apid<0) return apid;
    const uint8_t offsets[]={4,5,0x40,0x44,0x41,0x45,0x46};
    uint8_t *values[]={&out->type,&out->subtype,&out->mode,&out->source,&out->vin,&out->output,&out->enable};
    for (unsigned i=0;i<7;++i) {
        int rc=spmi_read8(obs,ee,apid,offsets[i],values[i]);if (rc) return rc;
    }
    // Adopt firmware's normal LV/MV CMOS output. VIN, pulls, drive strength,
    // enable and mux stay owned by firmware. Cold GPIO initialization is not
    // qualified; refuse it rather than invent a voltage source or pin policy.
    if (out->type!=0x10 || out->subtype<0x10 || out->subtype>0x13 ||
        (out->mode&3)!=1 || (out->source&15) || (out->output&0x30) || !(out->output&3) || !(out->enable&0x80)) return -95;
    uint8_t wanted=(uint8_t)((out->source&~0x80u)|(on<<7));
    if (wanted!=out->source) {
        int rc=dodge_spmi_write8(core,cnfg,channels,channelBytes,ppid,ee,apid,0x44,wanted);
        if (rc) return rc;
        out->wrote=true;
    }
    int rc=spmi_read8(obs,ee,apid,0x44,&out->readback);
    return rc?rc:out->readback==wanted?0:-5;
}
template <typename Vdd,typename Avdd,typename Wait>
static int dodge_touch_power_sequence(Vdd vdd,Avdd avdd,Wait wait,unsigned delayMs) {
    int rc=vdd();if (rc) return rc;
    rc=avdd();if (rc) return rc;
    wait(delayMs);return 0;
}
