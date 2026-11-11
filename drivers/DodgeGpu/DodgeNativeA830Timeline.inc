// SPDX-License-Identifier: MIT
#include "DodgeAdrenoTimeline.h"
#include "DodgeNativeSurface.h"
namespace { uint64_t dodge_display_epoch=1; }

extern "C" void dodge_native_display_epoch_advance()
{
    uint64_t old=__atomic_load_n(&dodge_display_epoch,__ATOMIC_ACQUIRE);
    while(old!=UINT64_MAX && !__atomic_compare_exchange_n(&dodge_display_epoch,&old,old+1,
          false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {}
}

// Ring and publication objects live for the boot after the release-store of
// published. Try-lock only: the original framebuffer may hold its work loop.
extern "C" bool dodge_adreno_display_timeline(DodgeAdrenoTimeline *out)
{
    if(!out || (reinterpret_cast<uintptr_t>(out)&7) ||
       reinterpret_cast<uintptr_t>(out)>UINTPTR_MAX-sizeof(*out) ||
       !__atomic_load_n(&g.published,__ATOMIC_ACQUIRE) || !g.ring_lock ||
       !IOLockTryLock(g.ring_lock))return false;
    bool valid=false;
    const uint64_t epoch=__atomic_load_n(&dodge_display_epoch,__ATOMIC_ACQUIRE);
    if(epoch!=UINT64_MAX && dodge_native_surface_healthy() && !lost() && !recovering() && g.ring && g.submit &&
       !g.ring->poisoned() && !g.submit->poisoned() && !g.submit->halted()) {
        const volatile uint32_t *memptrs=g.ring->memptrs();
        const uint32_t retired=memptrs?__atomic_load_n(&memptrs[1],__ATOMIC_ACQUIRE):0;
        const uint32_t submitted=g.ring->lastSubmitted();
        if(memptrs && retired<=submitted && dodge_native_surface_healthy() && !lost() && !recovering() &&
           epoch==__atomic_load_n(&dodge_display_epoch,__ATOMIC_ACQUIRE)) {
            *out={epoch,submitted,retired};valid=true;
        }
    }
    IOLockUnlock(g.ring_lock);
    return valid;
}
