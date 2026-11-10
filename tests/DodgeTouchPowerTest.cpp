// SPDX-License-Identifier: MIT
#include "DodgeTouchPower.h"
#include "PaganiPeripherals.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>
#include <string>
struct Model {
    uint32_t version=0x70000000,count=8,status=1,writeStatus=1;
    unsigned ee=0,apid=3,ppid=PAGANI_AVDD_PPID,delays=0,commands=0;
    bool duplicate=false,wrong=false,readbackBad=false,changeOwner=false;
    uint32_t offset=0,data=0;
    uint8_t regs[256]={};
    std::vector<std::pair<uint32_t,uint32_t>> writes;
    Model() {regs[4]=0x10;regs[5]=0x10;regs[0x40]=0xa1;regs[0x44]=0x20;regs[0x41]=3;regs[0x45]=2;regs[0x46]=0x80;}
    static uint32_t core(void *p,uint32_t r) {
        auto &m=*static_cast<Model *>(p);if (!r) return m.version;if (r==4) return m.count;
        assert(r>=0x2000 && r<0x3000 && !(r&3));unsigned a=(r-0x2000)/4;
        return a==m.apid || (m.duplicate && a==m.apid+1)?m.ppid<<8|1:0;
    }
    static uint32_t config(void *p,uint32_t r) {auto &m=*static_cast<Model *>(p);assert(!(r&3) && r<0x4000);return m.wrong || (m.changeOwner && m.commands>=7)?1:m.ee;}
    static uint32_t observer(void *p,uint32_t r) {
        auto &m=*static_cast<Model *>(p);unsigned base=m.ee*0x8000+m.apid*0x20;
        if (r==base+8) return m.status;
        assert(r==base+0x18);return m.readbackBad && m.commands>7?m.regs[m.offset]^0x80:m.regs[m.offset];
    }
    static void observeWrite(void *p,uint32_t r,uint32_t v) {
        auto &m=*static_cast<Model *>(p);assert(r==m.ee*0x8000+m.apid*0x20 && v>>27==1 && !(v&15));m.offset=(v>>4)&255;++m.commands;
    }
    static uint32_t channel(void *p,uint32_t r) {auto &m=*static_cast<Model *>(p);assert(r==m.apid*0x1000+8);return m.writeStatus;}
    static void channelWrite(void *p,uint32_t r,uint32_t v) {
        auto &m=*static_cast<Model *>(p);m.writes.emplace_back(r,v);
        if (r==m.apid*0x1000+0x10) {assert(v<=255);m.data=v;return;}
        assert(r==m.apid*0x1000 && v==0x440);m.regs[0x44]=(uint8_t)m.data;
    }
    static void delay(void *p,unsigned us) {assert(us==1);++static_cast<Model *>(p)->delays;}
    int enable(DodgeAvddResult &result,unsigned bytes=PAGANI_SPMI_CHANNEL_BYTES,unsigned on=PAGANI_AVDD_ON) {
        peripheral_io c{this,core,nullptr,nullptr},f{this,config,nullptr,nullptr},o{this,observer,observeWrite,delay},w{this,channel,channelWrite,delay};
        return dodge_avdd_adopt(&c,&f,&o,&w,bytes,PAGANI_AVDD_PPID,PAGANI_SPMI_EE,on,&result);
    }
};
int main(int argc,char **argv) {
    assert(argc==2);std::string mode=argv[1];Model m;DodgeAvddResult result;int expected=0;unsigned bytes=PAGANI_SPMI_CHANNEL_BYTES,on=1;
    if (mode=="already-on") m.regs[0x44]|=0x80;
    else if (mode=="version") {m.version=0x60000000;expected=-19;}
    else if (mode=="count-zero") {m.count=0;expected=-19;}
    else if (mode=="count-large") {m.count=1025;expected=-19;}
    else if (mode=="absent") {m.ppid=1;expected=-19;}
    else if (mode=="foreign-owner") {m.wrong=true;expected=-19;}
    else if (mode=="duplicate") {m.duplicate=true;expected=-16;}
    else if (mode=="owner-changed") {m.changeOwner=true;expected=-13;}
    else if (mode=="type") {m.regs[4]=0x11;expected=-95;}
    else if (mode=="subtype") {m.regs[5]=0x14;expected=-95;}
    else if (mode=="input") {m.regs[0x40]&=0xfc;expected=-95;}
    else if (mode=="mux") {m.regs[0x44]|=1;expected=-95;}
    else if (mode=="open-drain") {m.regs[0x45]|=0x10;expected=-95;}
    else if (mode=="no-drive") {m.regs[0x45]=0;expected=-95;}
    else if (mode=="disabled") {m.regs[0x46]=0;expected=-95;}
    else if (mode=="status-error") {m.status=2;expected=-5;}
    else if (mode=="timeout") {m.status=0;expected=-110;}
    else if (mode=="write-error") {m.writeStatus=2;expected=-5;}
    else if (mode=="write-timeout") {m.writeStatus=0;expected=-110;}
    else if (mode=="readback") {m.readbackBad=true;expected=-5;}
    else if (mode=="window") {bytes=0x3000;expected=-22;}
    else if (mode=="level") {on=2;expected=-22;}
    else if (mode=="sequence" || mode=="vdd-failure" || mode=="avdd-failure") {
        std::vector<unsigned> order;
        int rc=dodge_touch_power_sequence([&]{order.push_back(1);return mode=="vdd-failure"?-71:0;},[&]{order.push_back(2);return mode=="avdd-failure"?-5:0;},[&](unsigned ms){assert(ms==200);order.push_back(3);},PAGANI_TOUCH_POWER_MS);
        if (mode=="sequence") assert(!rc && (order==std::vector<unsigned>{1,2,3}));
        if (mode=="vdd-failure") assert(rc==-71 && (order==std::vector<unsigned>{1}));
        if (mode=="avdd-failure") assert(rc==-5 && (order==std::vector<unsigned>{1,2}));
        std::printf("{\"case\":\"%s\",\"result\":\"PASS\"}\n",argv[1]);return 0;
    } else assert(mode=="enable");
    uint8_t before[256];std::memcpy(before,m.regs,sizeof before);
    int rc=m.enable(result,bytes,on);assert(rc==expected);
    bool wrote=mode=="enable" || mode=="readback" || mode=="write-error" || mode=="write-timeout";
    assert(m.writes.size()==(wrote?2u:0u));
    for (unsigned i=0;i<256;++i) assert(m.regs[i]==(wrote && i==0x44?uint8_t(before[i]|0x80):before[i]));
    if (!rc) assert(result.readback==0xa0);
    if (mode=="timeout" || mode=="write-timeout") assert(m.delays==1000);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"writes\":%zu}\n",argv[1],m.writes.size());
}
