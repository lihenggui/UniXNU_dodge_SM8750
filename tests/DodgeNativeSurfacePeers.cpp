// SPDX-License-Identifier: MIT
// Original sync, descriptor/identity association and callout scheduling peers.
// Actual original ARM64 sync and exact physical-page association have separate
// execution tests; this fixture isolates the new GPU protocol and lifetimes.
#include "DodgeNativeSurfacePeers.h"
#include "NativeAdrenoMemory.h"
#include <cassert>
std::vector<DodgeTestTicket *> dodge_test_tickets;
bool dodge_test_grant_immediately=true,dodge_test_pages_current=true,dodge_test_register_failure=false;
int32_t dodge_test_signal_error;
unsigned dodge_test_signal_calls;
std::atomic_uint dodge_test_schedules,dodge_test_epoch;
void (*dodge_test_signal_check)(void *);
void *dodge_test_signal_context;
void DodgeTestTicket::release() {assert(signalled && !released);released=true;}
extern "C" void dodge_native_surface_test_schedule() {++dodge_test_schedules;}
extern "C" void dodge_native_display_epoch_advance() {++dodge_test_epoch;}
extern "C" bool native_iphone_surface_register_sync(OSObject *surface,OSObject **out,uint32_t access,uint32_t,
    IPhone16SurfaceSyncCallback callback,void *target,void *context,uint32_t options)
{
    assert(surface && out && !*out && access==IPhone16SurfaceSync::Write && callback && !options);
    if(dodge_test_register_failure)return false;
    auto *ticket=new DodgeTestTicket;
    ticket->surface=surface;ticket->callback=callback;ticket->target=target;ticket->context=context;
    ticket->granted=dodge_test_grant_immediately;dodge_test_tickets.push_back(ticket);*out=ticket;
    return ticket->granted;
}
extern "C" int32_t native_iphone_surface_signal_sync(OSObject *object,int32_t result)
{
    auto *ticket=static_cast<DodgeTestTicket *>(object);
    ++dodge_test_signal_calls;if(dodge_test_signal_error)return dodge_test_signal_error;
    if(dodge_test_signal_check)dodge_test_signal_check(dodge_test_signal_context);
    assert(ticket->granted && !ticket->signalled);ticket->signalled=true;ticket->result=result;return 0;
}
void dodge_test_grant_pending(int32_t result)
{
    for(auto *ticket:dodge_test_tickets)if(!ticket->granted) {
        ticket->granted=true;ticket->callback(ticket->target,ticket->context,ticket->surface,result);
    }
}
void dodge_test_clear_tickets()
{
    for(auto *ticket:dodge_test_tickets) {assert(ticket->signalled && ticket->released);delete ticket;}
    dodge_test_tickets.clear();dodge_test_grant_immediately=dodge_test_pages_current=true;
    dodge_test_register_failure=false;
    dodge_test_signal_error=0;dodge_test_signal_calls=0;
    dodge_test_signal_check=nullptr;dodge_test_signal_context=nullptr;
}
extern "C" IOReturn dodge_surface_pages_current(const DodgeSurfacePages *)
{return dodge_test_pages_current?kIOReturnSuccess:kIOReturnNotReady;}
extern "C" IOReturn dodge_surface_pages_bind(DodgeSurfaceIdentity *identity,IOMemoryDescriptor *backing,
    NativeAdrenoMemory *memory,DodgeSurfacePages *out)
{
    if(!memory || !identity || !identity->id || !backing || !out)return kIOReturnBadArgument;
    const IOReturn held=memory->holdForDevice();if(held)return held;
    out->identity=*identity;*identity={};out->memory=memory;out->backing=backing;out->bytes=memory->bytes();out->prepared=true;
    return kIOReturnSuccess;
}
extern "C" IOReturn dodge_surface_pages_release(DodgeSurfacePages *pages)
{
    if(!pages || !pages->memory || pages->memory->deviceReferences()!=1)return kIOReturnBusy;
    const IOReturn released=pages->memory->retireAfterQuiescence();if(!released)*pages={};return released;
}
