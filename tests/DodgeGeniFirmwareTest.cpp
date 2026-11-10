// SPDX-License-Identifier: MIT
#include "DodgeGeniFirmware.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>
struct Model {
    std::map<unsigned,uint32_t> se,wrapper;
    struct Write {bool wrapper;unsigned reg;uint32_t value;};
    std::vector<Write> writes;
    unsigned fault=0,delays=0;
    bool mirrors=true,lateActive=false;
    Model(){wrapper[4]=0x40000000;se[SE_HW_PARAM_0]=(32u<<24)|(32u<<16);se[0xe28]=(32u<<24)|(32u<<16);}
    uint32_t get(bool wrap,unsigned r){
        uint32_t value=(wrap?wrapper:se)[r];
        if (fault && writes.size()==fault && writes.back().wrapper==wrap && writes.back().reg==r) return value^1;
        return value;
    }
    void set(bool wrap,unsigned r,uint32_t v){
        assert(r<(wrap?0x1000u:0x4000u));writes.push_back({wrap,r,v});(wrap?wrapper:se)[r]=v;
        if(!wrap && r==0x2008)se[GENI_IF_DISABLE_RO]=v&1;
        if(!wrap && r==0x2000 && (v&1) && mirrors){se[GENI_FW_REVISION_RO]=se[0x1000];se[0x6c]=se[0x1004];}
        if(!wrap && r==0x2000 && (v&1) && lateActive)se[SE_GENI_STATUS]=1;
    }
    static uint32_t rd(void *p,uint32_t r){return static_cast<Model *>(p)->get(false,r);}
    static uint32_t wrd(void *p,uint32_t r){return static_cast<Model *>(p)->get(true,r);}
    static void wr(void *p,uint32_t r,uint32_t v){static_cast<Model *>(p)->set(false,r,v);}
    static void wwr(void *p,uint32_t r,uint32_t v){static_cast<Model *>(p)->set(true,r,v);}
    static void delay(void *p,unsigned us){assert(us==1);++static_cast<Model *>(p)->delays;}
    int load(const std::vector<uint8_t> &data,DodgeGeniResult &result){
        geni_spi s={};s.se={this,rd,wr,delay};s.wrapper={this,wrd,wwr,delay};
        return dodge_geni_prepare(&s,data.data(),data.size(),&result);
    }
};
static uint32_t get32(const std::vector<uint8_t> &v,unsigned at){return uint32_t(v[at])|uint32_t(v[at+1])<<8|uint32_t(v[at+2])<<16|uint32_t(v[at+3])<<24;}
static void put16(std::vector<uint8_t> &v,unsigned at,unsigned x){v[at]=x&255;v[at+1]=x>>8;}
static void put32(std::vector<uint8_t> &v,unsigned at,uint32_t x){for(unsigned i=0;i<4;++i)v[at+i]=uint8_t(x>>(8*i));}
static std::vector<uint8_t> synthetic(){
    std::vector<uint8_t> v(2141);put32(v,0,0x57464553);put32(v,4,1);put32(v,8,0x40000000);
    for(auto item:std::vector<std::pair<unsigned,unsigned>>{{12,1},{14,2818},{16,9},{18,442},{20,28},{22,69},{24,2072},{26,1796}})put16(v,item.first,item.second);
    for(unsigned i=0;i<442;++i)put32(v,28+4*i,0x73650000u+i);
    for(unsigned i=0;i<69;++i){v[2072+i]=uint8_t(i<19?i:64+i-19);put32(v,1796+4*i,0x87500000u+i);}
    return v;
}
int main(int argc,char **argv){
    assert(argc==2);std::vector<uint8_t> data;
    if(std::string(argv[1])=="--synthetic")data=synthetic();else{std::ifstream f(argv[1],std::ios::binary);assert(f);data.assign(std::istreambuf_iterator<char>(f),{});}
    assert(data.size()==2141);DodgeGeniImage image;assert(!dodge_geni_parse(data.data(),data.size(),&image) && image.words==442 && image.configurations==69);
    unsigned checks=1;
    for(unsigned n=0;n<data.size();++n){DodgeGeniImage bad=image;assert(dodge_geni_parse(data.data(),n,&bad)<0 && !bad.bytes);++checks;}
    for(auto item:std::vector<std::pair<unsigned,unsigned>>{{0,0},{4,2},{8,0},{12,2},{14,0},{16,0},{18,0},{18,441},{18,456},{20,30},{20,65532},{22,0},{22,256},{24,0},{24,65535},{26,30},{26,65532},{24,2000},{2072,19},{2073,0}}){
        auto v=data;if(item.first<28){if(item.first<=8)put32(v,item.first,item.second);else put16(v,item.first,item.second);}else v[item.first]=uint8_t(item.second);
        assert(dodge_geni_parse(v.data(),v.size(),&image)<0 && !image.bytes);++checks;
    }
    auto trailing=data;trailing.push_back(0);assert(dodge_geni_parse(trailing.data(),trailing.size(),&image)<0);++checks;
    Model good;DodgeGeniResult result;assert(!good.load(data,result) && result.loaded && result.phase==6 && result.firmwareAfter==0x102);
    unsigned writeCount=good.writes.size();assert(writeCount>500 && result.writes==writeCount && !good.delays);
    for(unsigned i=0;i<442;++i)assert(good.se[0x1010+4*i]==get32(data,28+4*i));
    for(unsigned i=0;i<69;++i){unsigned reg=0x100+4*data[2072+i];uint32_t expected=get32(data,1796+4*i);if(reg==SE_GENI_DMA_MODE_EN)expected&=~1u;assert(good.se[reg]==expected);}
    assert(!good.se[SE_IRQ_EN] && !good.se[SE_GSI_EVENT_EN] && !(good.se[SE_GENI_DMA_MODE_EN]&1));++checks;
    for(unsigned fault=1;fault<=writeCount;++fault){Model m;m.fault=fault;assert(m.load(data,result)==GENI_ERR_IO && !result.loaded && m.writes.size()==fault && result.writes==fault);++checks;}
    for(unsigned proto:{0x200u,1u}){Model m;m.se[GENI_FW_REVISION_RO]=proto;assert(m.load(data,result)==-16 && m.writes.empty());++checks;}
    for(unsigned active:{1u,0x1000u}){Model m;m.se[SE_GENI_STATUS]=active;assert(m.load(data,result)==-16 && m.writes.empty());++checks;}
    const unsigned busyRegisters[]={0x6c,SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_GENI_M_CMD0,SE_GENI_M_IRQ_STATUS,0x630,0x640};
    for(unsigned reg:busyRegisters){
        Model m;m.se[reg]=1;assert(m.load(data,result)==-16 && m.writes.empty());++checks;
    }
    for(unsigned version:{0x300a0000u,0x40010000u}){Model m;m.wrapper[4]=version;assert(m.load(data,result)==GENI_ERR_NODEV && m.writes.empty());++checks;}
    {Model m;m.se[SE_HW_PARAM_0]=(32u<<24)|(3u<<16);assert(m.load(data,result)==GENI_ERR_NODEV && m.writes.empty());++checks;}
    {Model m;m.se[SE_HW_PARAM_0]=(16u<<24)|(32u<<16);assert(m.load(data,result)==GENI_ERR_NODEV && m.writes.empty());++checks;}
    for(unsigned value:{(32u<<24)|(3u<<16),(32u<<24)|(16u<<16),(16u<<24)|(32u<<16),(32u<<24)|(256u<<16)}){Model m;m.se[0xe28]=value;assert(m.load(data,result)==GENI_ERR_NODEV && m.writes.empty());++checks;}
    {Model m;m.mirrors=false;assert(m.load(data,result)==GENI_ERR_TIMEOUT && !result.loaded && m.delays==99);++checks;}
    {Model m;m.lateActive=true;assert(m.load(data,result)==-16 && !result.loaded);++checks;}
    {Model m;m.se[GENI_FW_REVISION_RO]=0x102;m.se[SE_GENI_DMA_MODE_EN]=1;assert(m.load({},result)==-16 && !result.loaded && m.writes.empty());++checks;}
    {Model m;m.se[GENI_FW_REVISION_RO]=0x102;assert(!m.load({},result) && !result.loaded && m.writes.empty());++checks;}
    const unsigned warmOwned[]={SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,
        SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT,
        SE_GENI_TX_FIFO_STATUS,SE_GENI_RX_FIFO_STATUS};
    for (unsigned reg:warmOwned){Model m;m.se[GENI_FW_REVISION_RO]=0x102;m.se[reg]=1;assert(m.load({},result)==-16 && m.writes.empty());++checks;}
    std::printf("{\"result\":\"PASS\",\"case_count\":%u,\"fault_injections\":%u,\"firmware_bytes\":%zu,\"source_is_production_loader\":true}\n",checks,writeCount,data.size());
}
