// SPDX-License-Identifier: MIT
#include "DodgeTouchClock.h"
extern "C" {
#include <GeniSpi.h>
}
#include <cassert>
#include <cstdio>
#include <map>
#include <vector>

constexpr unsigned voteReg=0x52008,root=0x183dc,cfg=root+4,dfs=root+0x14;
constexpr uint32_t allVotes=0x043c0000,off=1u<<31;
struct Model {
    std::map<unsigned,uint32_t> gcc,se;
    struct Write {unsigned reg;uint32_t value;};
    std::vector<Write> writes;
    unsigned waits=0,fault=0,driftReg=~0u;
    bool updateStuck=false,rootStuck=false,dropEnable=false,lateBusy=false;
    Model() {gcc[voteReg]=allVotes;gcc[cfg]=(1u<<20)|1;gcc[0]=0x80000005;
             gcc[4]=1;gcc[0x10]=31;gcc[0x14]=0x4000;gcc[0x18]=1u<<10;}
    static uint32_t rd(void *p,uint32_t reg) {
        auto &m=*static_cast<Model *>(p);assert(reg<0x60000 && !(reg&3));
        uint32_t value=m.gcc[reg];
        if (m.fault && m.writes.size()==m.fault && m.writes.back().reg==reg) value^=reg==voteReg?1u<<18:reg==root?2:1;
        if (m.driftReg==reg && !m.writes.empty() && m.writes.back().reg==voteReg && (m.writes.back().value&(1u<<26))) value^=reg==dfs?1:1u<<8;
        return value;
    }
    static void wr(void *p,uint32_t reg,uint32_t value) {
        auto &m=*static_cast<Model *>(p);
        assert(reg==voteReg || reg==cfg || reg==root);
        m.writes.push_back({reg,value});m.gcc[reg]=value;
        if (reg==root) {
            if (!m.updateStuck) m.gcc[reg]&=~1u;
            if (!m.rootStuck) m.gcc[reg]&=~off;
            if (m.dropEnable) m.gcc[reg]&=~2u;
        }
        if (m.lateBusy && reg==voteReg && (value&(1u<<26))) m.se[SE_GENI_STATUS]=1;
    }
    static uint32_t srd(void *p,uint32_t reg) {
        assert(reg<0x4000 && !(reg&3));return static_cast<Model *>(p)->se[reg];
    }
    static void swr(void *,uint32_t,uint32_t) {assert(false && "clock setup must never write serial-engine registers");}
    static void delay(void *p,unsigned n) {assert(n==1);++static_cast<Model *>(p)->waits;}
    int run(DodgeTouchClockResult &r) {
        peripheral_io g={this,rd,wr,delay},s={this,srd,swr,delay};
        int rc=dodge_touch_clock_prepare(&g,&s,&r);assert(r.writes==writes.size());return rc;
    }
    void cold() {gcc[voteReg]=0x80000000;gcc[root]=off;gcc[cfg]=0xa034770f;}
};

int main() {
    unsigned checks=0;
    DodgeTouchClockResult result;
    {Model m;assert(!m.run(result) && result.hz==19200000 && !result.select && !result.programmed && m.writes.empty());++checks;}
    {Model m;m.cold();auto initial=m.gcc;assert(!m.run(result) && result.programmed && result.hz==19200000 && result.phase==4 && m.writes.size()==4);
     assert(m.writes[0].reg==voteReg && m.writes[0].value==(0x80000000|0x3c0000));
     assert(m.writes[1].reg==cfg && m.writes[1].value==((initial[cfg]&~0x10371fu)|0x100001));
     assert(m.writes[2].reg==root && m.writes[3].reg==voteReg && m.gcc[voteReg]==(0x80000000|allVotes));
     for (auto [reg,v]:initial) {if (reg!=voteReg && reg!=cfg && reg!=root) assert(m.gcc[reg]==v);}
     ++checks;}
    // Independent expected rates from the target vendor frequency table.
    struct Frequency {unsigned hz,parent,divider,m,n;};
    const Frequency rows[]={{7372800,6,1,384,15625},{14745600,6,1,768,15625},
        {19200000,0,1,0,0},{29491200,6,1,1536,15625},{32000000,6,1,8,75},
        {48000000,6,1,4,25},{51200000,6,1,64,375},{64000000,6,1,16,75},
        {75000000,6,7,0,0},{80000000,6,1,4,15},{96000000,6,1,8,25},
        {100000000,1,11,0,0},{102400000,6,1,128,375},{112000000,6,1,28,75},
        {117964800,6,1,6144,15625},{120000000,1,9,0,0}};
    for (auto row:rows) {
        Model m;m.gcc[cfg]=(row.parent<<8)|row.divider|(row.n?2u<<12:0);
        m.gcc[root+8]=row.m;m.gcc[root+12]=row.n?(~(row.n-row.m)&65535):0;
        assert(!m.run(result) && result.hz==row.hz && m.writes.empty());++checks;
    }
    // Read the live PLL instead of assuming it is 600 MHz.
    {Model m;m.gcc[0x10]=25;m.gcc[0x14]=0;m.gcc[cfg]=0x109;assert(!m.run(result) && result.hz==96000000);++checks;}
    for (unsigned div=0;div<32;++div) {
        Model m;m.gcc[cfg]=div;unsigned expected=div?38400000/(div+1):19200000;
        assert(!m.run(result) && result.hz==expected);++checks;
    }
    for (unsigned index=0;index<8;++index) {
        Model m;m.gcc[dfs]=1;
        for (unsigned i=0;i<8;++i) m.gcc[root+0x1c+4*i]=0x700;
        m.gcc[root+0x1c+4*index]=0x2601;m.gcc[root+0x5c+4*index]=384;
        m.gcc[root+0x9c+4*index]=~(15625u-384)&65535;
        assert(!m.run(result) && result.hz==7372800 && result.select==index && m.writes.empty());++checks;
    }
    {Model m;m.gcc[dfs]=1;for (unsigned i=0;i<8;++i)m.gcc[root+0x1c+4*i]=1;
     m.gcc[root+0x1c+12]=3;assert(!m.run(result) && result.select==3 && result.hz==9600000);++checks;}
    for (unsigned value:{off|1,off|0x10,off|0x20,off|0x40,off|0x80}) {
        Model m;m.cold();m.gcc[root]=value;assert(m.run(result)==-16 && m.writes.empty());++checks;
    }
    for (unsigned value:{1u,0x1000u}) {
        Model m;m.cold();m.se[SE_GENI_STATUS]=value;assert(m.run(result)==-16 && m.writes.size()==1);++checks;
    }
    const unsigned ownership[]={SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,
        SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT,
        SE_GENI_TX_FIFO_STATUS,SE_GENI_RX_FIFO_STATUS};
    for (unsigned reg:ownership) {Model m;m.cold();m.se[reg]=1;assert(m.run(result)==-16 && m.writes.size()==1);++checks;}
    {Model m;m.cold();m.se[GENI_FW_REVISION_RO]=0x200;assert(m.run(result)==-71 && m.writes.size()==1);++checks;}
    {Model m;m.cold();m.gcc[voteReg]|=1u<<26;assert(m.run(result)==-16 && m.writes.size()==1);++checks;}
    {Model m;m.cold();m.gcc[root]|=2;assert(m.run(result)==-16 && m.writes.size()==1);++checks;}
    for (unsigned reg:{0x2315cu,0x23148u,0x23140u,0x23144u,0x183ccu}) {
        Model m;m.cold();m.gcc[reg]=off;assert(m.run(result)==-110 && m.waits==200);
        assert(m.writes.size()==(reg==0x183cc?4:1));++checks;
    }
    for (unsigned reg:{0x2315cu,0x23148u,0x183ccu}) {
        Model m;m.gcc[reg]=off|2;assert(m.run(result)==-110 && m.waits==200);++checks;
    }
    for (unsigned reg:{0x23140u,0x23144u}) {Model m;m.gcc[reg]=off|2;assert(!m.run(result));++checks;}
    for (unsigned reg:{0x2315cu,0x23148u,0x183ccu}) {Model m;m.gcc[reg]=0xa0000000;assert(!m.run(result));++checks;}
    for (unsigned fault=1;fault<=4;++fault) {Model m;m.cold();m.fault=fault;assert(m.run(result)==-5 && m.writes.size()==fault);++checks;}
    {Model m;m.cold();m.updateStuck=true;assert(m.run(result)==-110 && m.waits==500 && m.writes.size()==3);++checks;}
    {Model m;m.cold();m.rootStuck=true;assert(m.run(result)==-110 && m.waits==500 && m.writes.size()==3);++checks;}
    {Model m;m.cold();m.dropEnable=true;assert(m.run(result)==-5 && m.writes.size()==3);++checks;}
    {Model m;m.cold();m.lateBusy=true;assert(m.run(result)==-16 && m.writes.size()==4);++checks;}
    for (unsigned reg:{cfg,dfs,0u,4u,0x10u,0x14u,0x18u}) {
        Model m;m.gcc[voteReg]&=~(1u<<26);if(reg!=cfg && reg!=dfs)m.gcc[cfg]=0x10b;
        m.driftReg=reg;assert(m.run(result)==-16);++checks;
    }
    for (unsigned parent:{2u,3u,4u,5u,7u}) {Model m;m.gcc[cfg]=parent<<8;assert(m.run(result)==-95 && m.writes.empty());++checks;}
    for (unsigned mode:{1u,3u}) {Model m;m.gcc[cfg]=mode<<12;assert(m.run(result)==-95);++checks;}
    for (unsigned value:{0u,4u,0x80000004u,0x80000001u}) {Model m;m.gcc[cfg]=0x10b;m.gcc[0]=value;assert(m.run(result)==-95);++checks;}
    {Model m;m.gcc[cfg]=0x10b;m.gcc[4]=0;assert(m.run(result)==-95);++checks;}
    {Model m;m.gcc[cfg]=0x10b;m.gcc[0x10]=0;assert(m.run(result)==-95);++checks;}
    {Model m;m.gcc[cfg]=0x10b;m.gcc[0x10]=65535;assert(m.run(result)==-95);++checks;}
    {Model m;m.gcc[cfg]=0x60b;m.gcc[0x18]=0;assert(m.run(result)==-95);++checks;}
    for (auto pair:std::vector<std::pair<unsigned,unsigned>>{{0,0},{1,65535},{65535,0},{5,65535}}) {
        Model m;m.gcc[cfg]=0x2001;m.gcc[root+8]=pair.first;m.gcc[root+12]=pair.second;
        assert(m.run(result)==-95);++checks;
    }
    // Every callback/pointer rejection must precede any MMIO operation.
    {Model m;peripheral_io g={&m,Model::rd,Model::wr,Model::delay},s={&m,Model::srd,Model::swr,Model::delay};
     assert(dodge_touch_clock_prepare(&g,&s,nullptr)==-22);++checks;
     assert(dodge_touch_clock_prepare(nullptr,&s,&result)==-22);++checks;
     assert(dodge_touch_clock_prepare(&g,nullptr,&result)==-22);++checks;
     for (unsigned i=0;i<3;++i) {auto invalid=g;if(i==0)invalid.read=nullptr;if(i==1)invalid.write=nullptr;if(i==2)invalid.delay=nullptr;
         assert(dodge_touch_clock_prepare(&invalid,&s,&result)==-22);++checks;}
     assert(m.writes.empty());}
    std::printf("{\"result\":\"PASS\",\"case_count\":%u,\"cold_write_failure_injections\":4,\"vendor_frequency_rows\":16,\"source_is_production_clock\":true}\n",checks);
}
