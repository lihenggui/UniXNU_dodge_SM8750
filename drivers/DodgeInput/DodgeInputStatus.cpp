// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeInputStatus.h"
namespace {
DodgeInputDiagnostics state={};
template <unsigned N> void store(uint32_t (&to)[N],const uint32_t (&from)[N]) {
    for (unsigned i=0;i<N;++i) __atomic_store_n(&to[i],from[i],__ATOMIC_RELAXED);
}
template <unsigned N> void copy(uint32_t (&to)[N],uint32_t (&from)[N]) {
    for (unsigned i=0;i<N;++i) to[i]=__atomic_load_n(&from[i],__ATOMIC_RELAXED);
}
}
extern "C" void dodge_input_observe(unsigned d,const char *s,int32_t rc,uint32_t value,uint64_t reports) {
    if (d>1 || !s) return;
    uint32_t hash=2166136261u;
    for (unsigned i=0;i<32 && s[i];++i) hash=(hash^(uint8_t)s[i])*16777619u;
    __atomic_store_n(&state.device[d].stage,hash,__ATOMIC_RELAXED);
    __atomic_store_n(&state.device[d].sample,value,__ATOMIC_RELAXED);
    __atomic_store_n(&state.device[d].result,rc,__ATOMIC_RELAXED);
    __atomic_store_n(&state.device[d].reports,reports,__ATOMIC_RELAXED);
}
extern "C" void dodge_input_touch_spi(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f) {const uint32_t v[]={a,b,c,d,e,f};store(state.spi,v);}
extern "C" void dodge_input_touch_dma(uint32_t a,uint32_t b,uint32_t c,uint32_t d) {const uint32_t v[]={a,b,c,d};store(state.dma,v);}
extern "C" void dodge_input_touch_read(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f,uint32_t g,uint32_t h) {const uint32_t v[]={a,b,c,d,e,f,g,h};store(state.read,v);}
extern "C" void dodge_input_touch_power(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f,uint32_t g) {const uint32_t v[]={a,b,c,d,e,f,g};store(state.power,v);}
extern "C" void dodge_input_touch_hid(uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f,uint64_t g,uint32_t h) {const uint32_t v[]={a,b,c,d,e,f,(uint32_t)g,h};store(state.hid,v);__atomic_store_n(&state.hidOutputXY,g,__ATOMIC_RELAXED);}
extern "C" void dodge_input_touch_smmu(uint32_t a,uint32_t b,uint32_t c,uint32_t d) {const uint32_t v[]={a,b,c,d};store(state.smmu,v);}
extern "C" void dodge_input_diagnostics(DodgeInputDiagnostics *out) {
    if (!out) return;
    for (unsigned d=0;d<2;++d) {
        out->device[d].stage=__atomic_load_n(&state.device[d].stage,__ATOMIC_RELAXED);
        out->device[d].sample=__atomic_load_n(&state.device[d].sample,__ATOMIC_RELAXED);
        out->device[d].result=__atomic_load_n(&state.device[d].result,__ATOMIC_RELAXED);
        out->device[d].reports=__atomic_load_n(&state.device[d].reports,__ATOMIC_RELAXED);
    }
    copy(out->spi,state.spi);copy(out->dma,state.dma);copy(out->read,state.read);
    copy(out->smmu,state.smmu);copy(out->power,state.power);copy(out->hid,state.hid);
    out->hidOutputXY=__atomic_load_n(&state.hidOutputXY,__ATOMIC_RELAXED);
}
