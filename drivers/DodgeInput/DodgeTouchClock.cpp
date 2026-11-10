// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independent implementation from pinned CPH2653 DTB and OnePlus clock facts.
#include "DodgeTouchClock.h"
extern "C" {
#include <GeniSpi.h>
}

namespace {
constexpr uint32_t voteReg=0x52008,rootReg=0x183dc,cfgReg=rootReg+4;
constexpr uint32_t busVotes=0x003c0000,serialVote=1u<<26;
constexpr uint32_t rootOff=1u<<31,rootEnable=2,update=1,dirty=0xf0;
constexpr uint32_t cfgMask=0x10371f,xoConfiguration=(1u<<20)|1u;
constexpr uint32_t xoHz=19200000;
struct Branch {uint32_t reg;bool hwcg;};
constexpr Branch busBranches[]={{0x2315c,false},{0x23148,false},
                                {0x23140,true},{0x23144,true}};

bool valid(const peripheral_io *io) {
    return io && io->read && io->write && io->delay;
}
uint32_t get(const peripheral_io *io,uint32_t reg) {
    return io->read(io->context,reg);
}
void put(const peripheral_io *io,uint32_t reg,uint32_t value,DodgeTouchClockResult *r) {
    io->write(io->context,reg,value);++r->writes;
}
int vote(const peripheral_io *gcc,uint32_t bits,DodgeTouchClockResult *r) {
    uint32_t before=get(gcc,voteReg),after=before|bits;
    if (after!=before) put(gcc,voteReg,after,r);
    // Other clients may raise votes concurrently; never accept a lost old vote.
    return (get(gcc,voteReg)&after)==after?0:-5;
}
int branch(const peripheral_io *gcc,Branch b) {
    for (unsigned i=0;i<200;++i) {
        uint32_t v=get(gcc,b.reg);
        if ((b.hwcg && (v&2)) || !(v&rootOff) || ((v>>28)&7)==2) return 0;
        gcc->delay(gcc->context,1);
    }
    return -110;
}
int idle(const peripheral_io *se) {
    if (get(se,SE_GENI_STATUS)&(GENI_STATUS_M_ACTIVE|(1u<<12))) return -16;
    unsigned protocol=(get(se,GENI_FW_REVISION_RO)>>8)&255;
    if (protocol && protocol!=GENI_PROTO_SPI) return -71;
    const unsigned owned[]={SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,
        SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,
        SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT};
    for (unsigned reg:owned) if (get(se,reg)) return -16;
    if ((get(se,SE_GENI_TX_FIFO_STATUS)&0x0fffffffu) ||
        (get(se,SE_GENI_RX_FIFO_STATUS)&GENI_RX_WC_MASK)) return -16;
    return 0;
}
struct Pll {
    uint32_t mode,opmode,l,alpha,user;
};
Pll pll(const peripheral_io *gcc) {
    return {get(gcc,0),get(gcc,4),get(gcc,0x10),get(gcc,0x14),get(gcc,0x18)};
}
bool same(Pll a,Pll b) {
    return a.mode==b.mode && a.opmode==b.opmode && a.l==b.l &&
           a.alpha==b.alpha && a.user==b.user;
}
uint32_t rate(uint32_t cfg,uint32_t m,uint32_t n,Pll p) {
    unsigned parent=(cfg>>8)&7,mode=(cfg>>12)&3;
    uint64_t hz=xoHz;
    if (parent==1 || parent==6) {
        if ((p.mode&0x80000005u)!=0x80000005u || !(p.opmode&1) || !(p.l&65535)) return 0;
        hz=uint64_t(xoHz)*(p.l&65535)+((uint64_t(xoHz)*(p.alpha&65535))>>16);
        if (parent==6) {
            // The target has one documented EVEN postdivider encoding: /2.
            if (((p.user>>10)&15)!=1) return 0;
            hz/=2;
        }
    } else if (parent) return 0;
    unsigned div=cfg&31;
    if (div) hz=hz*2/(div+1);
    if (mode) {
        if (mode!=2) return 0;
        m&=65535;n=((~n)&65535)+m;
        if (!m || n<=m || n>65535) return 0;
        hz=hz*m/n;
    }
    // The target's published SE4 table has a 120 MHz ceiling. Do not adopt an
    // unqualified higher clock/power corner, or truncate a 64-bit PLL result.
    return hz && hz<=120000000?uint32_t(hz):0;
}
}

extern "C" int dodge_touch_clock_prepare(const peripheral_io *gcc,
                                         const peripheral_io *se,
                                         DodgeTouchClockResult *r) {
    if (!r) return -22;
    *r=DodgeTouchClockResult{};
    if (!valid(gcc) || !valid(se)) return -22;
    r->phase=1;r->voteBefore=get(gcc,voteReg);r->commandBefore=get(gcc,rootReg);
    r->configurationBefore=get(gcc,cfgReg);r->dfsBefore=get(gcc,rootReg+0x14);
    if (r->commandBefore&(update|dirty)) return -16;
    int rc=vote(gcc,busVotes,r);if (rc) return rc;
    for (Branch b:busBranches) {rc=branch(gcc,b);if (rc) return rc;}
    r->phase=2;rc=idle(se);if (rc) return rc;
    if (get(gcc,rootReg)!=r->commandBefore || get(gcc,cfgReg)!=r->configurationBefore ||
        get(gcc,rootReg+0x14)!=r->dfsBefore) return -16;
    if ((r->commandBefore&rootOff) && !(r->dfsBefore&1)) {
        // Only this stopped, unvoted SE4 root is changed. No PLL, DFS table,
        // other serial root, reset, rail voltage or interconnect policy write.
        if ((r->commandBefore&rootEnable) || (get(gcc,voteReg)&serialVote)) return -16;
        uint32_t cfg=(r->configurationBefore&~cfgMask)|xoConfiguration;
        put(gcc,cfgReg,cfg,r);if (get(gcc,cfgReg)!=cfg) return -5;
        if (get(gcc,rootReg)!=r->commandBefore || get(gcc,rootReg+0x14)!=r->dfsBefore) return -16;
        put(gcc,rootReg,r->commandBefore|rootEnable|update,r);
        unsigned i=0;
        for (;i<500;++i) {
            if (!(get(gcc,rootReg)&update)) break;
            gcc->delay(gcc->context,1);
        }
        if (i==500) return -110;
        for (i=0;i<500;++i) {
            uint32_t cmd=get(gcc,rootReg);
            if (!(cmd&rootEnable)) return -5;
            if (!(cmd&rootOff)) break;
            gcc->delay(gcc->context,1);
        }
        if (i==500) return -110;
        if (get(gcc,cfgReg)!=cfg || get(gcc,rootReg+0x14)!=r->dfsBefore) return -16;
        rc=idle(se);if (rc) return rc;
        r->programmed=true;
    }
    r->phase=3;
    Pll before=pll(gcc);unsigned best=0,index=0;uint32_t chosen=0,chosenM=0,chosenN=0;
    unsigned count=(r->dfsBefore&1)?8:1;
    for (unsigned i=0;i<count;++i) {
        unsigned at=rootReg+((r->dfsBefore&1)?0x1c+4*i:4);
        uint32_t cfg=get(gcc,at),m=get(gcc,rootReg+((r->dfsBefore&1)?0x5c+4*i:8)),
                 n=get(gcc,rootReg+((r->dfsBefore&1)?0x9c+4*i:12));
        unsigned hz=rate(cfg,m,n,before);
        if (hz && (!best || hz<best)) {best=hz;index=i;chosen=cfg;chosenM=m;chosenN=n;}
    }
    if (!best) return -95;
    rc=vote(gcc,serialVote,r);if (rc) return rc;
    rc=branch(gcc,{0x183cc,false});if (rc) return rc;
    uint32_t cmd=get(gcc,rootReg);
    if (cmd&(rootOff|update|dirty)) return -16;
    unsigned at=rootReg+((r->dfsBefore&1)?0x1c+4*index:4);
    if (get(gcc,at)!=chosen || get(gcc,rootReg+((r->dfsBefore&1)?0x5c+4*index:8))!=chosenM ||
        get(gcc,rootReg+((r->dfsBefore&1)?0x9c+4*index:12))!=chosenN ||
        (get(gcc,rootReg+0x14)&1)!=(r->dfsBefore&1)) return -16;
    if (((chosen>>8)&7) && !same(before,pll(gcc))) return -16;
    rc=idle(se);if (rc) return rc;
    r->hz=best;r->select=index;r->phase=4;return 0;
}
