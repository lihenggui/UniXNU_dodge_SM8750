// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3 / 20H392 notification-list access. No hardware vblank.
#pragma once
#include "OriginalLegacySwapABI.h"

extern "C" void native_iphone_refresh_notify(void *,uint64_t,uint64_t,uint64_t);
namespace IPhone16Refresh {
enum : unsigned {ClientHead=4992};
// Caller holds the original framebuffer work-loop gate and keeps the display
// and notification nodes alive under the family's registration contract.
inline bool hasClients(const void *display) {
    return display && IPhone16Swap::load<const void *>(display,ClientHead);
}
// True means the unchanged original sender was invoked. Its async transport
// may fail; this is neither delivery acknowledgement nor a scanout interrupt.
inline bool notifyIfListening(void *display,uint64_t timestamp,uint64_t continuous,uint64_t interval) {
    if(!timestamp || !continuous || !interval || !hasClients(display))return false;
    native_iphone_refresh_notify(display,timestamp,continuous,interval);
    return true;
}
}
