// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only eligibility after the exact iPhone family's enqueue action.
#pragma once
#include "OriginalLegacySwapABI.h"

namespace IPhone16Swap {
enum : unsigned {
    RequestedLayers=792, ReadyLayers=796, ProducerRegistration=1349,
    CancelledRequest=1354, EffectiveSurfaces=2216
};
static_assert(EffectiveSurfaces+LayerCount*8<=RequestBytes,"Exact effective surface extent");

// The family ORs +796 on immediate IOSurface completion and from its gated
// asynchronous callback. A queued +796 is not a persistent disable mask.
// Caller holds the original work-loop gate, owns a live queued request and
// has allowed the original producer-registration/enqueue action to finish.
// This observes family bookkeeping; it neither waits nor signals any fence.
inline bool producersReady(const IOMFBSwapIORequest *request) {
    if(!request || reinterpret_cast<uintptr_t>(request)>UINTPTR_MAX-RequestBytes)return false;
    if(load<uint8_t>(request,CancelledRequest)&1)return false;
    const uint32_t requested=load<uint32_t>(request,RequestedLayers);
    const uint32_t ready=load<uint32_t>(request,ReadyLayers);
    if((requested|ready)&~0x8000000fU || requested!=ready)return false;
    bool hasSurface=false;
    for(unsigned layer=0;layer<LayerCount;++layer)if(surface(request,layer)) {
        if(!(requested&(1U<<layer)))return false;
        hasSurface=true;
    }
    return !hasSurface || (load<uint8_t>(request,ProducerRegistration)&1);
}
inline void *effectiveSurface(const IOMFBSwapIORequest *request,unsigned layer) {
    return request && layer<LayerCount ? load<void *>(request,EffectiveSurfaces+layer*8) : nullptr;
}
}
