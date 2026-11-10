// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independent bounded loader, using pinned upstream register/SEFW facts.
#include "DodgeGeniFirmware.h"
namespace {
uint16_t u16(const uint8_t *p) {return uint16_t(p[0])|uint16_t(p[1])<<8;}
uint32_t u32(const uint8_t *p) {return uint32_t(u16(p))|uint32_t(u16(p+2))<<16;}
bool extent(size_t n,unsigned at,size_t count,unsigned width) {
    return at>=28 && at<=n && count<=(n-at)/width;
}
uint32_t read(geni_spi *s,unsigned reg) {return s->se.rd(s->se.ctx,reg);}
int checked(geni_spi *s,unsigned reg,uint32_t value,DodgeGeniResult *r) {
    s->se.wr(s->se.ctx,reg,value);++r->writes;
    return read(s,reg)==value?0:GENI_ERR_IO;
}
int masked(geni_spi *s,unsigned reg,uint32_t clear,uint32_t set,DodgeGeniResult *r) {
    return checked(s,reg,(read(s,reg)&~clear)|set,r);
}
}
extern "C" int dodge_geni_parse(const uint8_t *data,size_t n,DodgeGeniImage *out) {
    if (!out) return GENI_ERR_PARAM;
    *out=DodgeGeniImage{};
    if (!data || n<28 || n>65535) return GENI_ERR_PARAM;
    if (u32(data)!=0x57464553 || u32(data+4)!=1 || u16(data+12)!=GENI_PROTO_SPI) return GENI_ERR_PROTO;
    DodgeGeniImage p; p.bytes=data;p.size=n;p.core=u32(data+8);
    p.firmwareVersion=u16(data+14);p.configurationVersion=u16(data+16);
    p.words=u16(data+18);p.wordOffset=u16(data+20);p.configurations=u16(data+22);
    p.indexOffset=u16(data+24);p.valueOffset=u16(data+26);
    if (p.core!=0x40000000 || !p.firmwareVersion || !p.configurationVersion || !p.words ||
        (p.words&1) || p.words>=455 || !p.configurations || p.configurations>255 ||
        (p.wordOffset&3) || (p.valueOffset&3) ||
        !extent(n,p.wordOffset,p.words,4) || !extent(n,p.indexOffset,p.configurations,1) ||
        !extent(n,p.valueOffset,p.configurations,4)) return GENI_ERR_PROTO;
    unsigned ends[]={unsigned(p.wordOffset)+unsigned(p.words)*4,unsigned(p.valueOffset)+unsigned(p.configurations)*4,
                     unsigned(p.indexOffset)+unsigned(p.configurations)};
    // Require disjoint payload tables and no unaccounted trailing bytes.
    if (p.wordOffset!=28 || ends[0]>p.valueOffset || ends[1]>p.indexOffset || ends[2]!=n) return GENI_ERR_PROTO;
    bool seen[256]={};
    for (unsigned i=0;i<p.configurations;++i) {
        unsigned index=data[p.indexOffset+i];
        if (seen[index] || !(index<=18 || (index>=64 && index<=113))) return GENI_ERR_PROTO;
        seen[index]=true;
    }
    *out=p;return 0;
}
extern "C" int dodge_geni_prepare(geni_spi *s,const uint8_t *data,size_t n,DodgeGeniResult *r) {
    if (!r) return GENI_ERR_PARAM;
    *r=DodgeGeniResult{};
    if (!s || !s->se.rd || !s->se.wr || !s->se.delay_us || !s->wrapper.rd || !s->wrapper.wr) return GENI_ERR_PARAM;
    r->phase=1;
    int rc=geni_spi_read_info(s);if (rc) return rc;
    r->firmwareBefore=s->info.fw_revision;r->firmwareAfter=r->firmwareBefore;
    if (s->info.geni_status&(GENI_STATUS_M_ACTIVE|(1u<<12))) return -16;
    uint32_t rx=read(s,0xe28),version=s->info.qup_hw_version;
    unsigned major=version>>28,minor=(version>>16)&0xfff;
    unsigned depth=(rx>>16)&((major>3 || (major==3 && minor>=10))?255u:63u);
    // The shared SPI transport uses one FIFO depth for both watermarks.
    // Refuse asymmetric/unsupported hardware before programming either path.
    if (s->info.tx_fifo_depth<4 || s->info.fifo_width_bits!=32 || ((rx>>24)&63)!=32 || depth!=s->info.tx_fifo_depth) return GENI_ERR_NODEV;
    // An idle SPI opcode alone does not prove that firmware released its
    // GPI/DMA descriptors. Apply ownership checks to warm adoption too.
    const unsigned ownership[]={SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,
        SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,
        SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT};
    for (unsigned reg:ownership) if (read(s,reg)) return -16;
    if ((read(s,SE_GENI_TX_FIFO_STATUS)&0x0fffffffu) || (read(s,SE_GENI_RX_FIFO_STATUS)&GENI_RX_WC_MASK)) return -16;
    if (s->info.protocol==GENI_PROTO_SPI) return 0;
    // Never overwrite a foreign protocol, nonempty engine or active GPI/DMA.
    if (s->info.fw_revision || read(s,0x6c)) return -16;
    DodgeGeniImage image;rc=dodge_geni_parse(data,n,&image);if (rc) return rc;
    if (s->info.qup_hw_version!=image.core || s->info.tx_fifo_depth<4 || s->info.fifo_width_bits!=32) return GENI_ERR_NODEV;
    const unsigned unused[]={SE_GENI_DMA_MODE_EN,SE_GSI_EVENT_EN,SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,
                             SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_GENI_M_CMD0,SE_GENI_M_IRQ_STATUS,0x630,0x640};
    for (unsigned reg:unused) if (read(s,reg)) return -16;
    r->phase=2;
    // Wrapper clock policy is shared: set only the documented CGC bits.
    const unsigned wrapperRegisters[]={0x118,0x120,0x21c};
    for (unsigned reg:wrapperRegisters) {
        uint32_t v=s->wrapper.rd(s->wrapper.ctx,reg)|1u;
        s->wrapper.wr(s->wrapper.ctx,reg,v);++r->writes;
        if (s->wrapper.rd(s->wrapper.ctx,reg)!=v) return GENI_ERR_IO;
    }
    auto write=[&](unsigned reg,uint32_t value) {return checked(s,reg,value,r);};
    auto change=[&](unsigned reg,uint32_t clear,uint32_t set) {return masked(s,reg,clear,set,r);};
    // Keep interrupt/GPI outputs and DMA execution disabled throughout load.
    if ((rc=write(SE_IRQ_EN,0)) || (rc=write(SE_GSI_EVENT_EN,0)) || (rc=write(GENI_OUTPUT_CTRL,0)) ||
        (rc=change(SE_GENI_CGC_CTRL,0,0x300)) || (rc=write(0x2000,0)) ||
        (rc=change(SE_GENI_CGC_CTRL,0x300,0)) || (rc=change(SE_DMA_GENERAL_CFG,0,15)) ||
        (rc=change(SE_GENI_CGC_CTRL,0x7f,0x7f)) || (rc=write(0,image.configurationVersion)) ||
        (rc=write(4,image.configurationVersion))) return rc;
    r->phase=3;
    for (unsigned i=0;i<image.configurations;++i) {
        unsigned reg=0x100+4*data[image.indexOffset+i];uint32_t value=u32(data+image.valueOffset+4*i);
        if (reg==SE_GENI_DMA_MODE_EN) value&=~1u;
        if ((rc=write(reg,value))) return rc;
    }
    if ((rc=write(SE_GENI_RX_RFR_WATERMARK_REG,s->info.tx_fifo_depth-2)) ||
        (rc=change(SE_GENI_DMA_MODE_EN,1,0))) return rc;
    r->phase=4;
    // Commit exactly the validated word extent; do not round an odd word count
    // past the input as some reference loaders do.
    for (unsigned i=0;i<image.words;++i)
        if ((rc=write(0x1010+4*i,u32(data+image.wordOffset+4*i)))) return rc;
    uint32_t revision=(GENI_PROTO_SPI<<8)|(image.firmwareVersion&255);
    if ((rc=write(0x1000,revision)) || (rc=write(0x1004,revision)) ||
        (rc=write(GENI_FORCE_DEFAULT_REG,1)) || (rc=change(GENI_OUTPUT_CTRL,0,0x7f)) ||
        (rc=change(SE_GENI_CGC_CTRL,0,0x300)) || (rc=change(0x2000,0,1)) ||
        (rc=change(SE_GENI_CGC_CTRL,0x300,0)) || (rc=change(0x2004,0,1)) ||
        (rc=change(0x2008,1,0))) return rc;
    r->phase=5;
    // Firmware read-only mirrors may settle after the clock transition.
    for (unsigned i=0;i<100;++i) {
        r->firmwareAfter=read(s,GENI_FW_REVISION_RO);
        if (r->firmwareAfter==revision && read(s,0x6c)==revision) break;
        if (i==99) return GENI_ERR_TIMEOUT;
        s->se.delay_us(s->se.ctx,1);
    }
    if (read(s,SE_GENI_STATUS)&(GENI_STATUS_M_ACTIVE|(1u<<12))) return -16;
    rc=geni_spi_read_info(s);if (rc) return rc;
    if (s->info.protocol!=GENI_PROTO_SPI || s->info.fifo_disabled) return GENI_ERR_IO;
    r->loaded=true;r->phase=6;return 0;
}
