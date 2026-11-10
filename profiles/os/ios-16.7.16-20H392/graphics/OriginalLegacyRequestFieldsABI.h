// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only field snapshot for exact iPhone10,3 / 20H392, not a validator.
#pragma once
#include "OriginalLegacySwapABI.h"

struct IPhone16RequestFields {
    uint32_t primary_mask,secondary_mask,background_raw,option_110,option_134,width,height;
    uint32_t source[4],destination[4];
    uint32_t raw_layer_word,raw_float_bits,raw_transform_bits;
};
static_assert(sizeof(IPhone16RequestFields)==72,"Snapshot contains scalar words only");
namespace IPhone16Swap {
// Caller owns the real request and holds the original work-loop gate. The
// output must not overlap the request. This reads packed geometry and options;
// it neither validates color/alpha/transform semantics nor proves a producer
// fence completed. No result here authorizes copying or retiring a frame.
inline bool snapshotFields(const IOMFBSwapIORequest *request,unsigned layer,IPhone16RequestFields *output) {
    const auto begin=reinterpret_cast<uintptr_t>(request),out=reinterpret_cast<uintptr_t>(output);
    if(!request || !output || layer>=LayerCount || begin>UINTPTR_MAX-RequestBytes ||
       out>UINTPTR_MAX-sizeof(*output) || (out<begin+RequestBytes && begin<out+sizeof(*output)))return false;
    output->primary_mask=load<uint32_t>(request,792);
    output->secondary_mask=load<uint32_t>(request,796);
    output->background_raw=load<uint32_t>(request,800);
    output->option_110=load<uint32_t>(request,804);
    output->option_134=load<uint32_t>(request,812);
    output->width=load<uint32_t>(request,816);output->height=load<uint32_t>(request,820);
    for(unsigned index=0;index<4;++index) {
        output->source[index]=load<uint32_t>(request,17+layer*16+index*4);
        output->destination[index]=load<uint32_t>(request,81+layer*16+index*4);
    }
    output->raw_layer_word=load<uint32_t>(request,532+layer*4);
    output->raw_float_bits=load<uint32_t>(request,564+layer*4);
    output->raw_transform_bits=load<uint32_t>(request,580+layer*4);
    return true;
}
}
