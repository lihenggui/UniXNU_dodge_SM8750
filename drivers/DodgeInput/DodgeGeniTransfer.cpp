// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGeniTransfer.h"
namespace {
int fail(int *terminal,int error) {*terminal=error;return error;}
uint32_t load(geni_spi *s,unsigned reg) {return s->se.rd(s->se.ctx,reg);}
void snapshot(geni_spi *s) {
    if (s->snap_valid) return;
    s->snap_irq=load(s,SE_GENI_M_IRQ_STATUS);s->snap_status=load(s,SE_GENI_STATUS);
    s->snap_txfs=load(s,SE_GENI_TX_FIFO_STATUS);s->snap_rxfs=load(s,SE_GENI_RX_FIFO_STATUS);
    s->snap_dma_tx=load(s,SE_DMA_TX_IRQ_STAT);s->snap_dma_rx=load(s,SE_DMA_RX_IRQ_STAT);
    s->snap_dma_txin=load(s,SE_DMA_TX_LEN_IN);s->snap_dma_rxin=load(s,SE_DMA_RX_LEN_IN);
    s->snap_valid=1;
}
bool range(uint64_t start,uint64_t bytes) {return start && bytes && start<=UINT64_MAX-bytes;}
bool separate(uint64_t a,uint64_t b,uint64_t n) {return a+n<=b || b+n<=a;}
int ownership(geni_spi *s) {
    if (load(s,SE_GENI_STATUS)&(GENI_STATUS_M_ACTIVE|(1u<<12))) return -16;
    if (load(s,GENI_FW_REVISION_RO)!=s->info.fw_revision || s->info.protocol!=GENI_PROTO_SPI) return GENI_ERR_PROTO;
    if (load(s,SE_GENI_M_IRQ_STATUS)&GENI_M_ERRORS) return GENI_ERR_IO;
    if (load(s,SE_GSI_EVENT_EN) || (load(s,SE_GENI_DMA_MODE_EN)&1)!=(unsigned)s->use_dma) return -16;
    if ((load(s,SE_GENI_TX_FIFO_STATUS)&0x0fffffffu) || (load(s,SE_GENI_RX_FIFO_STATUS)&GENI_RX_WC_MASK)) return -16;
    if (s->use_dma) {
        uint64_t tx=load(s,SE_DMA_TX_PTR_L)|(uint64_t(load(s,SE_DMA_TX_PTR_H))<<32);
        uint64_t rx=load(s,SE_DMA_RX_PTR_L)|(uint64_t(load(s,SE_DMA_RX_PTR_H))<<32);
        if ((tx && tx!=s->dma.tx_phys) || (rx && rx!=s->dma.rx_phys)) return -16;
        if ((load(s,SE_DMA_TX_IRQ_STAT)|load(s,SE_DMA_RX_IRQ_STAT))&GENI_DMA_AHB_ERR) return GENI_ERR_IO;
        if (!(load(s,SE_GENI_M_IRQ_EN)&GENI_M_CMD_DONE)) return GENI_ERR_NOTSUP;
    } else {
        const unsigned dma[]={SE_DMA_TX_PTR_L,SE_DMA_TX_PTR_H,SE_DMA_TX_LEN,SE_DMA_TX_IRQ_STAT,
                              SE_DMA_RX_PTR_L,SE_DMA_RX_PTR_H,SE_DMA_RX_LEN,SE_DMA_RX_IRQ_STAT};
        for (unsigned reg:dma) if (load(s,reg)) return -16;
    }
    return 0;
}
}
extern "C" int dodge_geni_transfer(geni_spi *s,const uint8_t *tx,uint8_t *rx,
                                   size_t bytes,int *terminal) {
    if (!terminal) return GENI_ERR_PARAM;
    if (*terminal) return *terminal<0?*terminal:GENI_ERR_IO;
    if (!s || !s->se.rd || !s->se.wr || !s->se.delay_us || !bytes ||
        bytes>DODGE_GENI_TRANSFER_MAX || (!tx && !rx) || !s->cur_speed_hz ||
        !s->poll_limit || s->poll_limit>20000 || s->use_dma<0 || s->use_dma>1 ||
        s->info.tx_fifo_depth<4 || s->info.fifo_width_bits!=32 || !s->tx_wm || s->tx_wm>=s->info.tx_fifo_depth)
        return fail(terminal,GENI_ERR_PARAM);
    if (s->use_dma) {
        auto &d=s->dma;uint64_t tv=(uintptr_t)d.tx_virt,rv=(uintptr_t)d.rx_virt;
        if (d.size<bytes || !d.clean || !d.clean_inval || !d.inval ||
            !range(d.tx_phys,d.size) || !range(d.rx_phys,d.size) ||
            !range(tv,d.size) || !range(rv,d.size) ||
            !separate(d.tx_phys,d.rx_phys,d.size) || !separate(tv,rv,d.size)) return fail(terminal,GENI_ERR_PARAM);
    }
    int rc=ownership(s);if (rc) return fail(terminal,rc);
    s->snap_valid=0;
    rc=geni_spi_transfer(s,tx,rx,bytes,0);
    if (!rc) rc=ownership(s);
    if (rc) {snapshot(s);return fail(terminal,rc);}
    return 0;
}
