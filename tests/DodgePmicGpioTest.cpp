// SPDX-License-Identifier: MIT
#include "DodgePmicGpio.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>
struct Model {
    uint8_t reg[256]={};unsigned offset=0,data=0,reads=0,writeFault=0,readFault=0,ownerLoss=99;
    bool foreign=false,duplicate=false;
    std::vector<std::pair<unsigned,unsigned>> writes;
    Model(){reg[4]=0x10;reg[5]=0x10;reg[0x40]=0xa0;reg[0x41]=0xa0;reg[0x42]=0x95;reg[0x44]=0x20;reg[0x45]=0xc2;reg[0x46]=0x12;}
    static uint32_t core(void *p,uint32_t r){auto &m=*static_cast<Model *>(p);if(!r)return 0x70000000;if(r==4)return 8;assert(r>=0x2000 && r<0x3000);unsigned a=(r-0x2000)/4;return a==3 || (m.duplicate && a==4)?0x98a01:0;}
    static uint32_t cnfg(void *p,uint32_t r){auto &m=*static_cast<Model *>(p);assert(r<0x4000);return m.foreign || (m.reads>=8 && m.writes.size()==m.ownerLoss)?1:0;}
    static void obswrite(void *p,uint32_t r,uint32_t v){auto &m=*static_cast<Model *>(p);assert(r==3*0x20 && v>>27==1);m.offset=(v>>4)&255;++m.reads;}
    static uint32_t obsread(void *p,uint32_t r){auto &m=*static_cast<Model *>(p);if(r==3*0x20+8)return m.readFault==m.reads?2:1;assert(r==3*0x20+0x18);return m.reg[m.offset];}
    static void channelwrite(void *p,uint32_t r,uint32_t v){auto &m=*static_cast<Model *>(p);if(r==0x3010){m.data=v;return;}assert(r==0x3000 && (v==0x440 || v==0x400 || v==0x460));unsigned offset=(v>>4)&255;m.writes.emplace_back(offset,m.data);m.reg[offset]=uint8_t(m.data);}
    static uint32_t channelread(void *p,uint32_t r){auto &m=*static_cast<Model *>(p);assert(r==0x3008);return m.writeFault==m.writes.size()?2:1;}
    static void delay(void *,unsigned){assert(false);}
    int run(DodgeGpioInitResult &out){peripheral_io c{this,core,nullptr,nullptr},f{this,cnfg,nullptr,nullptr},o{this,obsread,obswrite,delay},w{this,channelread,channelwrite,delay};return dodge_avdd_initialize(&c,&f,&o,&w,0x400000,0x98a,0,1,&out);}
};
int main(){
    unsigned cases=0;DodgeGpioInitResult result;
    for(unsigned mode=0;mode<=2;++mode)for(unsigned enabled=0;enabled<2;++enabled)for(unsigned high=0;high<2;++high){
        Model m;m.reg[0x40]|=mode;m.reg[0x46]|=enabled<<7;m.reg[0x44]|=high<<7;uint8_t before[256];std::memcpy(before,m.reg,256);
        assert(!m.run(result));assert(result.cold==(!mode || !enabled));assert(result.writes==m.writes.size());
        assert(m.reg[0x40]==(mode?0xa0|mode:0xa2) && m.reg[0x44]==0xa0 && m.reg[0x46]==0x92);
        for(unsigned i=0;i<256;++i)if(i!=0x40 && i!=0x44 && i!=0x46)assert(m.reg[i]==before[i]);
        for(unsigned i=1;i<m.writes.size();++i)assert(m.writes[i-1].first==0x44 || (m.writes[i-1].first==0x40 && m.writes[i].first==0x46));
        ++cases;
    }
    for(unsigned subtype=0;subtype<4;++subtype)for(unsigned vin=0;vin<8;++vin){
        Model m;m.reg[5]=uint8_t(0x10+subtype);m.reg[0x41]=uint8_t(0xa0|vin);const unsigned n[]={1,2,2,3};int rc=m.run(result);
        if(vin<n[subtype])assert(!rc && m.reg[0x41]==(0xa0|vin));else assert(rc==-95 && m.writes.empty());++cases;
    }
    for(auto bad:std::vector<std::pair<unsigned,unsigned>>{{4,0x11},{5,0x14},{0x40,0xa3},{0x44,0x21},{0x45,0xc0},{0x45,0xd2},{0x43,0x80}}){
        Model m;m.reg[bad.first]=uint8_t(bad.second);assert(m.run(result)<0 && m.writes.empty());++cases;
    }
    for(unsigned fault=1;fault<=14;++fault){Model m;m.readFault=fault;assert(m.run(result)==-5 && m.reads==fault);++cases;}
    for(unsigned fault=1;fault<=3;++fault){Model m;m.writeFault=fault;assert(m.run(result)==-5 && m.writes.size()==fault);++cases;}
    for(unsigned fault=0;fault<3;++fault){Model m;m.ownerLoss=fault;assert(m.run(result)==-13 && m.writes.size()==fault);++cases;}
    {Model m;m.foreign=true;assert(m.run(result)==-19 && m.writes.empty());++cases;}
    {Model m;m.duplicate=true;assert(m.run(result)==-16 && m.writes.empty());++cases;}
    std::printf("{\"result\":\"PASS\",\"case_count\":%u,\"only_output_mode_enable_writes\":true,\"electrical_fields_preserved\":true}\n",cases);
}
