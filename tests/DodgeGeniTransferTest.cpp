// SPDX-License-Identifier: MIT
#include "DodgeGeniTransfer.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <deque>
#include <map>
#include <string>
#include <vector>

struct Model {
    geni_spi spi={};
    std::map<unsigned,uint32_t> regs;
    std::array<uint8_t,8192+128> memory;
    std::deque<uint8_t> received;
    std::vector<uint8_t> sent;
    std::vector<unsigned> resetWrites;
    unsigned commands=0,reads=0,writes=0,delays=0,cacheClean=0,cachePrepare=0,cacheInvalidate=0;
    unsigned txSize=0,rxSize=0,txMoved=0,rxMoved=0,commandPolls=0,commandDelay=3;
    unsigned cancelWrites=0,abortWrites=0,resetDelay=2,txResetLeft=0,rxResetLeft=0,resetAcks=0;
    unsigned idleDelay=0,idleLeft=0;
    uint32_t forcedFifo=~0u;
    bool active=false,done=false,txOps=false,rxOps=false,dataComplete=false,lastEmitted=false;
    bool noData=false,noCommand=false,dmaError=false,commandError=false;
    bool cancelFails=false,abortFails=false,cancelLeavesActive=false,resetFails=false;
    bool earlyInvalidate=false,allowEarlyInvalidate=false,postForeign=false,staleResetOnCancel=false;

    static uint8_t slave(uint8_t byte,unsigned index) {return uint8_t((byte^0xa5)+index);}
    uint32_t irq() {return regs[SE_GENI_M_IRQ_STATUS];}
    void completeCommand() {
        if (!done && !noCommand) {
            done=true;idleLeft=idleDelay;active=idleDelay!=0;
            if (regs[SE_GENI_M_IRQ_EN]&GENI_M_CMD_DONE) regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_CMD_DONE;
        }
    }
    void progress() {
        if (!active) return;
        if (commandError) {regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_CMD_FAILURE;return;}
        if (spi.use_dma) {
            if (dataComplete && ++commandPolls>=commandDelay) completeCommand();
            return;
        }
        if (noData) return;
        if (!txOps && rxOps) {
            unsigned n=std::min(112u,rxSize-rxMoved);
            for (unsigned i=0;i<n;++i) {received.push_back(slave(0,rxMoved));++rxMoved;}
        }
        if (!received.empty()) regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_RX_FIFO_WATERMARK;
        if (forcedFifo!=~0u) regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_RX_FIFO_LAST;
        if (txOps && txMoved<txSize) regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_TX_FIFO_WATERMARK;
        if ((!txOps || txMoved==txSize) && (!rxOps || rxMoved==rxSize)) {
            if (rxOps && !lastEmitted) {regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_RX_FIFO_LAST;lastEmitted=true;}
            completeCommand();
        }
    }
    void dma() {
        if (!active || noData || dataComplete || !(regs[SE_GENI_DMA_MODE_EN]&1)) return;
        if ((txOps && !regs[SE_DMA_TX_LEN]) || (rxOps && !regs[SE_DMA_RX_LEN])) return;
        if (dmaError) {
            if (txOps) regs[SE_DMA_TX_IRQ_STAT]|=GENI_DMA_AHB_ERR;
            if (rxOps) regs[SE_DMA_RX_IRQ_STAT]|=GENI_DMA_AHB_ERR;
            return;
        }
        unsigned n=txOps?txSize:rxSize;
        auto tx=reinterpret_cast<const uint8_t *>((uint64_t(regs[SE_DMA_TX_PTR_H])<<32)|regs[SE_DMA_TX_PTR_L]);
        auto rx=reinterpret_cast<uint8_t *>((uint64_t(regs[SE_DMA_RX_PTR_H])<<32)|regs[SE_DMA_RX_PTR_L]);
        if (txOps) assert(tx==spi.dma.tx_virt);
        if (rxOps) assert(rx==spi.dma.rx_virt);
        for (unsigned i=0;i<n;++i) {
            uint8_t value=txOps?tx[i]:0;
            if (txOps) sent.push_back(value);
            if (rxOps) rx[i]=slave(value,i);
        }
        dataComplete=true;txMoved=txOps?n:0;rxMoved=rxOps?n:0;
        if (txOps) regs[SE_DMA_TX_IRQ_STAT]|=GENI_DMA_DONE;
        if (rxOps) regs[SE_DMA_RX_IRQ_STAT]|=GENI_DMA_DONE;
    }
    uint32_t read(unsigned reg) {
        assert(!(reg&3) && reg<0x4000);++reads;
        if (reg==SE_GENI_M_IRQ_STATUS) progress();
        if (reg==SE_GENI_STATUS) {
            if (done && idleLeft && --idleLeft==0) active=false;
            return (regs[reg]&~1u)|(active?1u:0u);
        }
        if (reg==SE_GENI_RX_FIFO_STATUS) {
            if (commands && forcedFifo!=~0u) return forcedFifo;
            unsigned words=(received.size()+3)/4;
            return regs[reg]|words|((commands && rxMoved==rxSize)?GENI_RX_LAST|((rxSize%4)<<GENI_RX_LAST_VALID_SHIFT):0);
        }
        if (reg==SE_GENI_RX_FIFOn) {
            uint32_t value=0;assert(!received.empty());
            for (unsigned i=0;i<4 && !received.empty();++i) {value|=uint32_t(received.front())<<(8*i);received.pop_front();}
            return value;
        }
        if (reg==SE_DMA_TX_IRQ_STAT || reg==SE_DMA_RX_IRQ_STAT) {
            auto &left=reg==SE_DMA_RX_IRQ_STAT?rxResetLeft:txResetLeft;
            if (left && !resetFails && --left==0) {regs[reg]|=GENI_DMA_RESET_DONE;++resetAcks;}
        }
        if (reg==SE_GSI_EVENT_EN && postForeign && done) return 1;
        return regs[reg];
    }
    void write(unsigned reg,uint32_t value) {
        assert(!(reg&3) && reg<0x4000);++writes;
        if (reg==SE_GENI_M_IRQ_CLEAR) {regs[SE_GENI_M_IRQ_STATUS]&=~value;return;}
        if (reg==SE_DMA_TX_IRQ_CLR || reg==SE_DMA_RX_IRQ_CLR) {
            regs[reg==SE_DMA_RX_IRQ_CLR?SE_DMA_RX_IRQ_STAT:SE_DMA_TX_IRQ_STAT]&=~value;return;
        }
        if (reg==SE_DMA_TX_IRQ_EN_SET || reg==SE_DMA_RX_IRQ_EN_SET) {regs[reg]|=value;return;}
        regs[reg]=value;
        if (reg==SE_GENI_M_CMD0) {
            ++commands;unsigned opcode=value>>GENI_M_OPCODE_SHIFT;
            assert(opcode==1 || opcode==2 || opcode==3);txOps=opcode!=2;rxOps=opcode!=1;
            txSize=txOps?regs[SE_SPI_TX_TRANS_LEN]:0;rxSize=rxOps?regs[SE_SPI_RX_TRANS_LEN]:0;
            active=true;done=false;txMoved=rxMoved=commandPolls=0;dataComplete=false;lastEmitted=false;received.clear();sent.clear();
            regs[SE_DMA_TX_LEN]=regs[SE_DMA_RX_LEN]=0;return;
        }
        if (reg==SE_GENI_TX_FIFOn) {
            assert(active && txOps);unsigned n=std::min(4u,txSize-txMoved);
            for (unsigned i=0;i<n;++i) {
                auto byte=uint8_t(value>>(8*i));sent.push_back(byte);
                if (rxOps) {received.push_back(slave(byte,rxMoved));++rxMoved;}
                ++txMoved;
            }
        }
        if (reg==SE_DMA_TX_LEN || reg==SE_DMA_RX_LEN) dma();
        if (reg==SE_GENI_M_CMD_CTRL_REG) {
            if (value&GENI_M_CMD_CANCEL) {++cancelWrites;if (staleResetOnCancel) regs[SE_DMA_TX_IRQ_STAT]|=GENI_DMA_RESET_DONE;if (!cancelFails) {regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_CMD_CANCEL_DONE;if (!cancelLeavesActive) active=false;}}
            if (value&GENI_M_CMD_ABORT) {++abortWrites;if (!abortFails) {regs[SE_GENI_M_IRQ_STATUS]|=GENI_M_CMD_ABORT_DONE;active=false;}}
        }
        if (reg==SE_DMA_TX_FSM_RST || reg==SE_DMA_RX_FSM_RST) {
            assert(!active);resetWrites.push_back(reg);
            assert(regs[reg==SE_DMA_RX_FSM_RST?SE_DMA_RX_IRQ_EN_SET:SE_DMA_TX_IRQ_EN_SET]&GENI_DMA_RESET_DONE);
            (reg==SE_DMA_RX_FSM_RST?rxResetLeft:txResetLeft)=resetDelay;
        }
    }
    static uint32_t rd(void *p,uint32_t reg) {return static_cast<Model *>(p)->read(reg);}
    static void wr(void *p,uint32_t reg,uint32_t value) {static_cast<Model *>(p)->write(reg,value);}
    static void delay(void *p,unsigned us) {assert(us==1);++static_cast<Model *>(p)->delays;}
    static uint32_t wrapperRead(void *,uint32_t reg) {assert(reg==4);return 0x40000000;}
    static void wrapperWrite(void *,uint32_t,uint32_t) {assert(false);}
    static void clean(void *p,void *v,size_t n) {auto &m=*static_cast<Model *>(p);assert(v==m.spi.dma.tx_virt && n<=4096);++m.cacheClean;}
    static void prepare(void *p,void *v,size_t n) {auto &m=*static_cast<Model *>(p);assert(v==m.spi.dma.rx_virt && n<=4096);++m.cachePrepare;}
    static void invalidate(void *p,void *v,size_t n) {
        auto &m=*static_cast<Model *>(p);assert(v==m.spi.dma.rx_virt && n<=4096);++m.cacheInvalidate;
        m.earlyInvalidate=m.active || !m.done;assert(m.allowEarlyInvalidate || !m.earlyInvalidate);
    }
    explicit Model(bool dma=false) {
        memory.fill(0xa5);spi.se={this,rd,wr,delay};spi.wrapper={this,wrapperRead,wrapperWrite,delay};
        regs[GENI_FW_REVISION_RO]=0x102;regs[SE_HW_PARAM_0]=(32u<<24)|(32u<<16);regs[GENI_IF_DISABLE_RO]=dma?1:0;
        spi.poll_limit=32;spi.poll_only=dma?2:1;spi.use_dma=dma;
        spi.dma={this,clean,prepare,invalidate,memory.data()+64,memory.data()+64+4096,
                  uint64_t(uintptr_t(memory.data()+64)),uint64_t(uintptr_t(memory.data()+64+4096)),4096};
        assert(!geni_spi_init(&spi));assert(!geni_spi_setup(&spi,0,0));assert(!geni_spi_set_clock(&spi,19000000,19200000,0));
        reads=writes=0;
    }
    void canaries() {assert(std::all_of(memory.begin(),memory.begin()+64,[](uint8_t n){return n==0xa5;}));assert(std::all_of(memory.end()-64,memory.end(),[](uint8_t n){return n==0xa5;}));}
    void sticky(int terminal) {
        assert(terminal<0);unsigned before[]={reads,writes,delays,cacheClean,cachePrepare,cacheInvalidate,commands};
        uint8_t byte=0;assert(dodge_geni_transfer(&spi,&byte,&byte,1,&terminal)==terminal);
        unsigned after[]={reads,writes,delays,cacheClean,cachePrepare,cacheInvalidate,commands};
        assert(std::equal(std::begin(before),std::end(before),std::begin(after)));canaries();
    }
};

int main(int argc,char **argv) {
    assert(argc==2);std::string mode=argv[1];
    if (mode=="--original-control") {
        Model m(true);m.allowEarlyInvalidate=true;uint8_t tx[5]={1,2,3,4,5},rx[5]={};
        int rc=geni_spi_transfer(&m.spi,tx,rx,sizeof tx,0);
        assert(!rc && m.active && !m.done && m.earlyInvalidate);
        std::puts("{\"result\":\"REJECTED\",\"raw_original_return\":0,\"command_still_active\":true,\"rx_invalidated_before_command_done\":true}");return 0;
    }
    assert(mode=="--production");unsigned cases=0,transfers=0;
    const unsigned lengths[]={1,2,3,4,5,31,32,33,63,64,65,123,124,125,127,128,129,255,256,257,511,512,518,519};
    for (bool dma:{false,true}) for (unsigned direction=0;direction<3;++direction) for (unsigned n:lengths) {
        Model m(dma);std::vector<uint8_t> tx(n),rx(n+128,0xcc);for (unsigned i=0;i<n;++i) tx[i]=uint8_t(i*7+3);
        bool t=direction!=1,r=direction!=0;int terminal=0;
        assert(!dodge_geni_transfer(&m.spi,t?tx.data():nullptr,r?rx.data()+64:nullptr,n,&terminal));
        assert(!terminal && m.done && !m.active && m.commands==1);
        if (t) assert(m.sent==tx);
        if (r) for (unsigned i=0;i<n;++i) assert(rx[i+64]==Model::slave(t?tx[i]:0,i));
        assert(std::all_of(rx.begin(),rx.begin()+64,[](uint8_t v){return v==0xcc;}));assert(std::all_of(rx.end()-64,rx.end(),[](uint8_t v){return v==0xcc;}));
        if (dma) assert(m.cacheClean==(t?1u:0u) && m.cachePrepare==(r?1u:0u) && m.cacheInvalidate==(r?1u:0u));
        assert(m.resetWrites.empty() && !m.cancelWrites && !m.abortWrites);m.canaries();++cases;++transfers;
    }
    for (bool dma:{false,true}) {Model m(dma);m.idleDelay=3;uint8_t tx[7]={},rx[7];int error=0;assert(!dodge_geni_transfer(&m.spi,tx,rx,7,&error) && !m.active && m.delays>=2);++cases;}
    // Every ownership refusal precedes the first command, write and cache op.
    const unsigned busy[]={SE_GENI_STATUS,SE_GSI_EVENT_EN,SE_GENI_TX_FIFO_STATUS,SE_GENI_RX_FIFO_STATUS};
    for (bool dma:{false,true}) for (unsigned reg:busy) {Model m(dma);m.regs[reg]=reg==SE_GENI_STATUS?0x1000:1;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && !m.writes && !m.commands && !m.cacheClean);m.sticky(e);++cases;}
    for (bool dma:{false,true}) {
        Model m(dma);m.active=true;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && !m.writes);m.sticky(e);++cases;
    }
    for (bool dma:{false,true}) {Model m(dma);m.regs[GENI_FW_REVISION_RO]=0x103;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-71 && !m.writes);m.sticky(e);++cases;}
    for (bool dma:{false,true}) {Model m(dma);m.regs[SE_GENI_DMA_MODE_EN]=dma?0:1;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && !m.writes);m.sticky(e);++cases;}
    for (unsigned reg:{SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H}) {Model m(true);m.regs[reg]=1;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && !m.writes);m.sticky(e);++cases;}
    for (unsigned reg:{SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT}) {Model m;m.regs[reg]=1;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && !m.writes);m.sticky(e);++cases;}
    for (unsigned reg:{SE_GENI_M_IRQ_STATUS,SE_DMA_TX_IRQ_STAT,SE_DMA_RX_IRQ_STAT}) {Model m(true);m.regs[reg]=reg==SE_GENI_M_IRQ_STATUS?GENI_M_CMD_FAILURE:GENI_DMA_AHB_ERR;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-5 && !m.writes);m.sticky(e);++cases;}
    {Model m(true);m.regs[SE_GENI_M_IRQ_EN]&=~GENI_M_CMD_DONE;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-95 && !m.writes);m.sticky(e);++cases;}
    for (bool dma:{false,true}) for (unsigned failure=0;failure<3;++failure) {
        Model m(dma);m.spi.poll_limit=8;m.noData=failure==0;m.noCommand=failure==1;m.commandError=failure==2;
        uint8_t tx[7]={},rx[7]={};int e=0;int expected=failure==2?-5:-110;
        assert(dodge_geni_transfer(&m.spi,tx,rx,7,&e)==expected && e==expected && m.cancelWrites==1 && !m.abortWrites);
        assert(m.spi.snap_valid && m.spi.snap_status&1 && !m.active);
        assert(m.resetWrites.size()==(dma?2:0) && m.resetAcks==(dma?2u:0u));m.sticky(e);++cases;
    }
    for (unsigned direction=0;direction<3;++direction) {Model m(true);m.dmaError=true;uint8_t b=0;int e=0;
        assert(dodge_geni_transfer(&m.spi,direction!=1?&b:nullptr,direction!=0?&b:nullptr,1,&e)==-5);
        assert(m.resetWrites.size()==(direction==2?2:1) && m.resetAcks==m.resetWrites.size());m.sticky(e);++cases;}
    for (unsigned failure=0;failure<4;++failure) {
        Model m(true);m.spi.poll_limit=8;m.noCommand=true;m.cancelFails=failure!=1;m.cancelLeavesActive=failure==1;m.abortFails=failure>=2;
        if (failure==3)m.regs[SE_DMA_TX_IRQ_STAT]=GENI_DMA_RESET_DONE;
        uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-110 && m.cancelWrites==1 && m.abortWrites==1);
        assert(m.active==m.abortFails && m.resetWrites.size()==(m.abortFails?0:2));m.sticky(e);++cases;
    }
    {Model m(true);m.spi.poll_limit=8;m.noCommand=true;m.resetFails=true;m.staleResetOnCancel=true;uint8_t b=0;int e=0;
     assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-110 && m.resetWrites.size()==1 && !m.resetAcks && m.txResetLeft);m.sticky(e);++cases;}
    const uint32_t malformed[]={GENI_RX_LAST|(1u<<28),GENI_RX_LAST|(5u<<28)|1u,33u,0x1ffffffu};
    for (bool receive:{false,true}) for (uint32_t value:malformed) {Model m;m.forcedFifo=value;uint8_t tx[7]={},rx[7]={};int e=0;
        assert(dodge_geni_transfer(&m.spi,tx,receive?rx:nullptr,7,&e)==-5 && m.cancelWrites==1 && m.spi.snap_valid);m.sticky(e);++cases;}
    {Model m(true);m.postForeign=true;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,&e)==-16 && m.done && !m.cancelWrites);m.sticky(e);++cases;}
    for (unsigned invalid=0;invalid<20;++invalid) {
        Model m(true);uint8_t b=0;int e=0;auto &s=m.spi;
        if(invalid==0)s.se.rd=nullptr;
        if(invalid==1)s.se.wr=nullptr;
        if(invalid==2)s.se.delay_us=nullptr;
        if(invalid==3)s.cur_speed_hz=0;
        if(invalid==4)s.poll_limit=0;
        if(invalid==5)s.poll_limit=20001;
        if(invalid==6)s.info.tx_fifo_depth=3;
        if(invalid==7)s.info.fifo_width_bits=16;
        if(invalid==8)s.tx_wm=0;
        if(invalid==9)s.tx_wm=32;
        if(invalid==10)s.use_dma=2;
        if(invalid==11)s.dma.size=0;
        if(invalid==12)s.dma.clean=nullptr;
        if(invalid==13)s.dma.clean_inval=nullptr;
        if(invalid==14)s.dma.inval=nullptr;
        if(invalid==15)s.dma.tx_phys=0;
        if(invalid==16)s.dma.rx_phys=UINT64_MAX-1;
        if(invalid==17)s.dma.rx_phys=s.dma.tx_phys;
        if(invalid==18)s.dma.tx_virt=nullptr;
        if(invalid==19)s.dma.rx_virt=s.dma.tx_virt;
        assert(dodge_geni_transfer(&s,&b,&b,1,&e)==-22 && !m.reads && !m.writes);m.sticky(e);++cases;
    }
    for (unsigned n:{0u,520u}) {Model m;uint8_t b=0;int e=0;assert(dodge_geni_transfer(&m.spi,&b,&b,n,&e)==-22 && !m.reads && !m.writes);m.sticky(e);++cases;}
    {Model m;int e=0;assert(dodge_geni_transfer(&m.spi,nullptr,nullptr,1,&e)==-22 && !m.reads);m.sticky(e);++cases;}
    {Model m;uint8_t b=0;int e=0;assert(dodge_geni_transfer(nullptr,&b,&b,1,&e)==-22 && !m.reads);++cases;}
    {Model m;uint8_t b=0;assert(dodge_geni_transfer(&m.spi,&b,&b,1,nullptr)==-22 && !m.reads);++cases;}
    std::printf("{\"result\":\"PASS\",\"case_count\":%u,\"positive_wire_data_cases\":%u,\"terminal_reentry_checked\":true,\"actual_transport_and_guard\":true}\n",cases,transfers);
}
