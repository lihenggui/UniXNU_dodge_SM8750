// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3 / 20H392 completion entry; requires original family lifetime.
#pragma once
#include "OriginalLegacySwapABI.h"
#include <libkern/c++/OSObject.h>

extern "C" void native_iphone_complete_current(void *display);

namespace IPhone16Swap {
// The exact request inherits OSObject's public retain/release slots. Release
// only an extra reference acquired here; the family's completion owns its own
// queue reference and eventually reaches the request's private free hook.
inline void retainExtraRequest(IOMFBSwapIORequest *request) {
    if (request) reinterpret_cast<OSObject *>(request)->retain();
}
inline void releaseExtraRequest(IOMFBSwapIORequest *request) {
    if (request) reinterpret_cast<OSObject *>(request)->release();
}
// Caller holds the original framebuffer work-loop gate, owns this exact Legacy instance and
// keeps expected alive. A true result means the original call was dispatched;
// it does not certify a hardware latch, producer fence or display completion.
inline bool dispatchCompletionIfCurrent(void *display, IOMFBSwapIORequest *expected) {
    if (!display || !expected || load<IOMFBSwapIORequest *>(display, Current) != expected) return false;
    native_iphone_complete_current(display);
    return true;
}
}
