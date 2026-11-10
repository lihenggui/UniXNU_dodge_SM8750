// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3 / 20H392 queue access. No display or request is constructed.
#pragma once
#include <stdint.h>

struct IOMFBSwapIORequest;
namespace IPhone16Swap {
enum : unsigned {
    DisplayBytes=5728, RequestBytes=2424,
    Current=4872, Head=4880, Tail=4888,
    Surfaces=2184, Next=2408, PreviousLink=2416, LayerCount=4
};
static_assert(sizeof(void *)==8, "Original iPhone pointer size");
static_assert(Tail+8<=DisplayBytes && Surfaces+LayerCount*8<=RequestBytes &&
              PreviousLink+8==RequestBytes, "Qualified original object extents");

template<typename T> inline T load(const void *object,unsigned offset) {
    T result;
    __builtin_memcpy(&result,static_cast<const unsigned char *>(object)+offset,sizeof(result));
    return result;
}
template<typename T> inline void store(void *object,unsigned offset,T value) {
    __builtin_memcpy(static_cast<unsigned char *>(object)+offset,&value,sizeof(value));
}
inline IOMFBSwapIORequest *pending(const void *display) {
    return display ? load<IOMFBSwapIORequest *>(display,Head) : nullptr;
}
inline void *surface(const IOMFBSwapIORequest *request,unsigned layer) {
    return request && layer<LayerCount ? load<void *>(request,Surfaces+8*layer) : nullptr;
}

// Caller must hold the original framebuffer work-loop gate. The queued
// requests must remain alive under the family's existing ownership contract.
// Check eligibility without writing any object or changing references.
inline bool canActivatePending(const void *display,const IOMFBSwapIORequest *request) {
    if(!display || !request || load<void *>(display,Current) || pending(display)!=request)return false;
    const void *headLink=static_cast<const unsigned char *>(display)+Head;
    const void *requestLink=reinterpret_cast<const unsigned char *>(request)+Next;
    auto next=load<IOMFBSwapIORequest *>(request,Next);
    void *tail=load<void *>(display,Tail);
    if(load<void *>(request,PreviousLink)!=headLink || next==request)return false;
    if(next) {
        if(!tail || tail==requestLink || load<void *>(next,PreviousLink)!=requestLink)return false;
    } else if(tail!=requestLink)return false;
    return true;
}
// Transfer the queue's reference to Current without retaining/releasing,
// completing a swap, signalling a fence or emitting a vblank.
inline bool activatePending(void *display,IOMFBSwapIORequest *request) {
    if(!canActivatePending(display,request))return false;
    void *headLink=static_cast<unsigned char *>(display)+Head;
    auto next=load<IOMFBSwapIORequest *>(request,Next);
    // Every refusal precedes the first write. Match the original TAILQ
    // removal, leaving the removed request's links for the family to own.
    store(display,Current,request);
    if(next)store(next,PreviousLink,headLink);
    else store(display,Tail,headLink);
    store(display,Head,next);
    return true;
}
}
