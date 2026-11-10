// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact ordinary ARM64 iPhone10,3 / 20H392 bindings. No private class layout.
#pragma once
#include <stdint.h>

class OSObject;
using IPhone16SurfaceSyncCallback = void (*)(void *target,void *context,
    OSObject *surface,int32_t status);

namespace IPhone16SurfaceSync {
enum : uint32_t { Read=1, Write=2 };
}

// The caller owns a valid original IOSurface and a writable, initially-null
// ticket slot. The returned ticket is retained even when the result is false.
// true means this access is active now: its callback is not delivered for that
// immediate grant. false with a ticket means pending; keep callback inputs
// alive until the original root worker delivers its callback. A pending grant
// is not permission to submit GPU work. The supported adapter uses options=0,
// access Read or Write, and a non-null callback. It has no registration owner.
//
// Signal only after the actual producer has stopped accessing the memory and
// the required cache visibility work has completed. Then release the caller's
// ticket reference. A timeout, an absent fence or a reset is not completion.
// The original dependency walker can grant a reader after a writer signals an
// error; callers must retain their own GPU failure state. This API provides no
// GPU quiescence, CPU cache maintenance or board-specific DMA ordering.
extern "C" bool native_iphone_surface_register_sync(OSObject *surface,OSObject **ticket,
    uint32_t access,uint32_t label,IPhone16SurfaceSyncCallback callback,
    void *target,void *context,uint32_t options);
extern "C" int32_t native_iphone_surface_signal_sync(OSObject *ticket,int32_t status);
