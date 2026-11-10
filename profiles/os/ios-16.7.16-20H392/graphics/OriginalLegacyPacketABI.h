// SPDX-License-Identifier: BSD-2-Clause-Patent
// Narrow default single-layer packet accepted by the original iPhone setters.
#pragma once
#include "OriginalLegacyRequestFieldsABI.h"
#include "OriginalLegacyProducerABI.h"

class OSObject;
extern "C" uint32_t native_iphone_surface_id(const OSObject *);
// Exact original Legacy slot 178, called directly to avoid virtual recursion.
// The third argument is the original opaque submitter, not a request output.
extern "C" int32_t native_iphone_submit_default_packet(void *,const void *,void *);

namespace IPhone16Swap {
enum : unsigned {PacketBytes=1132,PacketRequestID=80,PacketSurfaceID=84,RequestID=788};
struct PacketIdentity {uint32_t request,surface;};

// Only the unmodified SwapBegin + layer-0 SetLayer defaults are accepted.
// Reject every other byte, including extra effects, pointers, timestamps,
// transformed/scaled/partial geometry, other layers and nonzero backgrounds.
// This is a deliberate bounded frontend protocol, not general IOMFB support.
inline bool defaultPacket(const void *packet,unsigned bytes,uint32_t width,uint32_t height,PacketIdentity *output) {
    const auto begin=reinterpret_cast<uintptr_t>(packet),out=reinterpret_cast<uintptr_t>(output);
    if(!packet || bytes!=PacketBytes || !output || !width || !height || width>16384 || height>16384 ||
       begin>UINTPTR_MAX-PacketBytes || out>UINTPTR_MAX-sizeof(*output) ||
       (out<begin+PacketBytes && begin<out+sizeof(*output)))return false;
    auto data=static_cast<const uint8_t *>(packet);
    for(unsigned index=0;index<PacketBytes;++index) {
        const bool variable=(index>=80 && index<88) || (index>=100 && index<116) ||
            (index>=164 && index<168) || (index>=196 && index<212) || (index>=260 && index<264);
        if(!variable && data[index])return false;
    }
    for(unsigned index=0;index<4;++index) {
        const uint32_t expected=index==2?width:index==3?height:0;
        if(load<uint32_t>(packet,100+index*4)!=expected || load<uint32_t>(packet,196+index*4)!=expected)return false;
    }
    if(load<uint32_t>(packet,164)!=1 || load<uint32_t>(packet,260)!=1 || !load<uint32_t>(packet,84))return false;
    output->request=load<uint32_t>(packet,80);output->surface=load<uint32_t>(packet,84);return true;
}

// Used only for a request bound to a previously accepted complete packet.
// The family's ready word may change between validation and submission.
// Other inherited/global display effects are not qualified by this helper.
inline bool defaultRequestGeometry(const IOMFBSwapIORequest *request,PacketIdentity identity,uint32_t width,uint32_t height) {
    IPhone16RequestFields fields{};
    if(!snapshotFields(request,0,&fields) || load<uint32_t>(request,RequestID)!=identity.request ||
       fields.primary_mask!=1 || fields.secondary_mask&~1U || fields.background_raw || fields.option_110 ||
       load<uint32_t>(request,808) || fields.option_134 || fields.width!=width || fields.height!=height ||
       fields.raw_layer_word!=1 || fields.raw_float_bits || fields.raw_transform_bits || !surface(request,0))return false;
    for(unsigned index=0;index<4;++index) {
        const uint32_t expected=index==2?width:index==3?height:0;
        if(fields.source[index]!=expected || fields.destination[index]!=expected)return false;
        if(index && surface(request,index))return false;
    }
    return !(load<uint8_t>(request,CancelledRequest)&1);
}
}
