// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3 / 20H392 startup queue shape, before client publication.
#pragma once
#include "OriginalLegacySwapABI.h"

namespace IPhone16Lifecycle {
enum : unsigned {UnsubmittedHead=4896,UnsubmittedTail=4904,NotifyHead=4912,NotifyCount=6};
static_assert(NotifyHead+NotifyCount*16<=IPhone16Swap::DisplayBytes,"Exact startup list bounds");
// Caller owns the original work-loop gate and a live complete display object.
// This checks shape only; it neither initializes nor publishes any object.
inline bool emptyStartupQueues(const void *display) {
    if(!display || reinterpret_cast<uintptr_t>(display)>UINTPTR_MAX-IPhone16Swap::DisplayBytes)return false;
    if(IPhone16Swap::load<void *>(display,IPhone16Swap::Current))return false;
    for(unsigned index=0;index<NotifyCount+2;++index) {
        const unsigned head=index==0?IPhone16Swap::Head:index==1?UnsubmittedHead:NotifyHead+(index-2)*16;
        const auto *link=static_cast<const uint8_t *>(display)+head;
        if(IPhone16Swap::load<void *>(display,head) || IPhone16Swap::load<const void *>(display,head+8)!=link)return false;
    }
    return true;
}
}
