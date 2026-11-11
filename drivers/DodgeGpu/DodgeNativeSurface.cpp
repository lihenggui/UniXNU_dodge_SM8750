// SPDX-License-Identifier: MIT
#include "DodgeNativeSurface.h"
#include "DodgeSurfacePages.h"
#include "NativeAdrenoVm.h"
#include "NativeAdrenoSubmit.h"
#include "OriginalIOSurfaceSyncABI.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <libkern/c++/OSObject.h>
#ifndef ADRENO830_HOST_TEST
#include <kern/thread_call.h>
#endif

extern "C" void dodge_native_display_epoch_advance();

namespace {
enum State : uint32_t { Building,Waiting,Published,Completed,Cancelled,Draining,Quarantined };
struct Batch;
struct Access {
    Batch *batch;
    OSObject *surface,*ticket;
    int32_t grant; // 0 pending, 1 granted, negative original error
};
struct Batch {
    NativeAdrenoVm *vm;
    uint64_t boundary;
    size_t mappings;
    uint32_t references,state,count,dirty,failed;
    bool held;
    DodgeSurfacePages *pages[NativeAdrenoVmMaxObjects];
    Access accesses[NativeAdrenoVmMaxObjects];
    size_t page_count;
};
IOLock *batch_gate;
Batch *active;
uint32_t visibility_fault;
#ifndef ADRENO830_HOST_TEST
thread_call_t worker;
void deferred(thread_call_param_t,thread_call_param_t) {dodge_native_surface_drain();}
void schedule() {if(worker)thread_call_enter(worker);}
#else
extern "C" void dodge_native_surface_test_schedule();
void schedule() {dodge_native_surface_test_schedule();}
#endif
void put(Batch *b)
{
    if(__atomic_sub_fetch(&b->references,1u,__ATOMIC_ACQ_REL)==0)IOFree(b,sizeof *b);
}
void callback(void *target,void *,OSObject *surface,int32_t status)
{
    auto *access=static_cast<Access *>(target);
    // The ticket's callback target stays owned by the active batch. A pending
    // cancellation keeps it alive until this original worker callback arrives.
    const int32_t grant=surface==access->surface && !status?1:(status<0?status:-1);
    __atomic_store_n(&access->grant,grant,__ATOMIC_RELEASE);schedule();
}
bool granted(const Batch *b,bool *failed)
{
    *failed=false;
    const uint32_t count=__atomic_load_n(&b->count,__ATOMIC_ACQUIRE);
    for(uint32_t i=0;i<count;++i) {
        const int32_t value=__atomic_load_n(&b->accesses[i].grant,__ATOMIC_ACQUIRE);
        if(!value)return false;
        if(value<0)*failed=true;
    }
    return true;
}
bool current(const Batch *b)
{
    if(__atomic_load_n(&b->dirty,__ATOMIC_ACQUIRE))return false;
    for(size_t i=0;i<b->page_count;++i)if(dodge_surface_pages_current(b->pages[i]))return false;
    return !__atomic_load_n(&b->dirty,__ATOMIC_ACQUIRE);
}
}

extern "C" IOReturn dodge_native_surface_initialize()
{
    if(__atomic_load_n(&batch_gate,__ATOMIC_ACQUIRE))return kIOReturnSuccess;
    IOLock *fresh=IOLockAlloc();if(!fresh)return kIOReturnNoMemory;
#ifndef ADRENO830_HOST_TEST
    // The board initializes once before GPU publication. The callout is kept
    // for the boot, so a callback never frees its own scheduler object.
    worker=thread_call_allocate_with_options(deferred,nullptr,THREAD_CALL_PRIORITY_KERNEL,
                                             THREAD_CALL_OPTIONS_ONCE);
    if(!worker) {IOLockFree(fresh);return kIOReturnNoMemory;}
#endif
    __atomic_store_n(&batch_gate,fresh,__ATOMIC_RELEASE);return kIOReturnSuccess;
}

extern "C" IOReturn dodge_native_surface_prepare(NativeAdrenoVm *vm,void **owner)
{
    if(!vm || !owner || !batch_gate)return kIOReturnBadArgument;
    auto *b=static_cast<Batch *>(*owner);
    if(!b) {
        // Avoid a large allocation on the common contended retry path.
        IOLockLock(batch_gate);const bool occupied=active!=nullptr;IOLockUnlock(batch_gate);
        if(occupied)return NativeAdrenoSubmitRetry;
        b=static_cast<Batch *>(IOMallocZero(sizeof(Batch)));if(!b)return kIOReturnNoMemory;
        b->vm=vm;b->references=2;
        IOLockLock(batch_gate);
        if(active) {IOLockUnlock(batch_gate);IOFree(b,sizeof *b);return NativeAdrenoSubmitRetry;}
        active=b;IOLockUnlock(batch_gate);*owner=b;
        IOReturn result=vm->holdMapped(&b->boundary,&b->mappings);
        if(result)return result;
        b->held=true;
        b->page_count=vm->mappedSurfaces(b->pages,NativeAdrenoVmMaxObjects);
        if(b->page_count==SIZE_MAX) {b->page_count=0;return kIOReturnNotReady;}
        // Publish the complete identity set before checking backing. The
        // original mutation hooks can invalidate this batch without waiting.
        for(size_t i=0;i<b->page_count;++i) {
            OSObject *surface=b->pages[i]->identity.surface;bool duplicate=false;
            for(uint32_t j=0;j<b->count;++j)if(b->accesses[j].surface==surface) {duplicate=true;break;}
            if(duplicate)continue;
            auto &a=b->accesses[b->count];a.batch=b;a.surface=surface;a.grant=-1;
            __atomic_add_fetch(&b->count,1u,__ATOMIC_RELEASE);
        }
        if(!current(b))return kIOReturnNotReady;
        for(uint32_t i=0;i<b->count;++i) {
            Access &a=b->accesses[i];
            __atomic_store_n(&a.grant,0,__ATOMIC_RELEASE);
            const bool ready=native_iphone_surface_register_sync(a.surface,&a.ticket,IPhone16SurfaceSync::Write,
                0x444f4401,callback,&a,nullptr,0);
            if(!a.ticket) {__atomic_store_n(&a.grant,-1,__ATOMIC_RELEASE);return kIOReturnNoResources;}
            if(ready)__atomic_store_n(&a.grant,1,__ATOMIC_RELEASE);
        }
        __atomic_store_n(&b->state,uint32_t(Waiting),__ATOMIC_RELEASE);
    }
    if(b->vm!=vm || __atomic_load_n(&b->state,__ATOMIC_ACQUIRE)!=Waiting)return kIOReturnNotReady;
    bool failed=false;
    if(!granted(b,&failed))return NativeAdrenoSubmitRetry;
    return failed || !current(b)?kIOReturnNotReady:kIOReturnSuccess;
}

extern "C" bool dodge_native_surface_can_submit(void *opaque)
{
    auto *b=static_cast<Batch *>(opaque);if(!b)return true;
    bool failed=false;
    return __atomic_load_n(&b->state,__ATOMIC_ACQUIRE)==Waiting && granted(b,&failed) && !failed &&
           !__atomic_load_n(&b->dirty,__ATOMIC_ACQUIRE);
}
extern "C" void dodge_native_surface_published(void *opaque,bool uncertain)
{
    auto *b=static_cast<Batch *>(opaque);if(!b)return;
    if(uncertain)__atomic_store_n(&b->failed,1u,__ATOMIC_RELEASE);
    __atomic_store_n(&b->state,uint32_t(Published),__ATOMIC_RELEASE);
}
extern "C" void dodge_native_surface_completed(void *opaque,bool abandoned)
{
    auto *b=static_cast<Batch *>(opaque);if(!b)return;
    if(abandoned) {
        __atomic_store_n(&b->failed,1u,__ATOMIC_RELEASE);
        __atomic_store_n(&visibility_fault,1u,__ATOMIC_RELEASE);
    }
    __atomic_store_n(&b->state,uint32_t(Completed),__ATOMIC_RELEASE);schedule();
}
extern "C" void dodge_native_surface_end_call(void **owner)
{
    if(!owner || !*owner)return;
    auto *b=static_cast<Batch *>(*owner);*owner=nullptr;
    uint32_t state=__atomic_load_n(&b->state,__ATOMIC_ACQUIRE);
    while((state==Building || state==Waiting) && !__atomic_compare_exchange_n(&b->state,&state,
          uint32_t(Cancelled),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {}
    if(state==Building || state==Waiting)schedule();
    put(b);
}
extern "C" void dodge_native_surface_changed(OSObject *surface)
{
    if(!surface || !batch_gate)return;
    // Only this small registry lock is taken. No GPU or original surface lock
    // is acquired and the mutation's original caller never waits for a fence.
    IOLockLock(batch_gate);Batch *b=active;
    if(b)for(uint32_t i=0;i<__atomic_load_n(&b->count,__ATOMIC_ACQUIRE);++i)
        if(b->accesses[i].surface==surface) {
            __atomic_store_n(&b->dirty,1u,__ATOMIC_RELEASE);
            __atomic_store_n(&visibility_fault,1u,__ATOMIC_RELEASE);
            dodge_native_display_epoch_advance();break;
        }
    IOLockUnlock(batch_gate);
}
extern "C" bool dodge_native_surface_healthy()
{return !__atomic_load_n(&visibility_fault,__ATOMIC_ACQUIRE);}
extern "C" void dodge_native_surface_drain()
{
    if(!batch_gate)return;
    IOLockLock(batch_gate);Batch *b=active;
    if(b)__atomic_add_fetch(&b->references,1u,__ATOMIC_RELAXED);
    IOLockUnlock(batch_gate);if(!b)return;
    uint32_t state=__atomic_load_n(&b->state,__ATOMIC_ACQUIRE);bool failed=false;
    // A cancelled pending registration is still an original callback target.
    // Keep the whole snapshot until every registered pending grant arrives.
    if((state!=Completed && state!=Cancelled) || !granted(b,&failed)) {put(b);return;}
    if(!__atomic_compare_exchange_n(&b->state,&state,uint32_t(Draining),false,
                                   __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {put(b);return;}
    const bool completed=state==Completed;
    failed=failed || !completed || __atomic_load_n(&b->failed,__ATOMIC_ACQUIRE) || !current(b);
    if(b->held && b->vm->retireMapped(b->boundary,b->mappings,completed)) {
        __atomic_store_n(&b->state,uint32_t(Quarantined),__ATOMIC_RELEASE);
        __atomic_store_n(&visibility_fault,1u,__ATOMIC_RELEASE);
        dodge_native_display_epoch_advance();put(b);return;
    }
    // The snapshot no longer owns its page adapters. Only the independently
    // retained original tickets are accessed from this point onward.
    for(uint32_t i=0;i<b->count;++i)if(b->accesses[i].ticket) {
        native_iphone_surface_signal_sync(b->accesses[i].ticket,failed?int32_t(kIOReturnAborted):0);
        b->accesses[i].ticket->release();b->accesses[i].ticket=nullptr;
    }
    IOLockLock(batch_gate);if(active==b)active=nullptr;IOLockUnlock(batch_gate);
    put(b); // registry ownership
    put(b); // this worker's ownership
}
