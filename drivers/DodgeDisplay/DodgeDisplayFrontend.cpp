// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeDisplayFrontend.h"
#include "DodgeGpuSwapBridge.h"
#include "DodgeSoftwareRefresh.h"
#include "DodgeAdrenoTimeline.h"
#include "OriginalLegacyPacketABI.h"
#include "OriginalLegacyLifecycleABI.h"
#include "OriginalLegacySwapCompletionABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>

enum : unsigned {MaximumPending=16,DisplayWidth=5208,DisplayHeight=5212};
struct DodgeFrontendEntry {
    uint64_t generation;
    uint64_t gpuEpoch;
    IPhone16Swap::PacketIdentity identity;
    IOMFBSwapIORequest *request;
    OSObject *surface;
    DodgeSurfaceBacking backing;
    uint32_t gpuTarget,gpuSubmitted,gpuRetired;
    bool used,building,inflight,gpuCaptured,gpuPassed,gpuInvalid;
};
struct DodgeDisplayFrontend {
    static void *operator new(size_t,void *storage) noexcept {return storage;}
    uint32_t references;
    IOService *display;
    IOCommandGate *gate;
    IOWorkLoop *loop;
    IOTimerEventSource *timer;
    DodgeSoftwareRefresh *refresh;
    DodgeGpuSwapBridge *bridge;
    DodgeFrontendEntry entries[MaximumPending];
    DodgeFrontendEntry *active;
    uint64_t generation,submitted,validated,retired;
    uint64_t retryInterval,retryAt,retryDeadline;
    uint32_t width,height;
    IOReturn last;
    bool draining,kicking,rekick,requiresAdreno,waiting;
};

static void retainFrontend(DodgeDisplayFrontend *front) {__atomic_fetch_add(&front->references,1,__ATOMIC_RELAXED);}
static void releaseFrontend(DodgeDisplayFrontend *front) {
    if(__atomic_fetch_sub(&front->references,1,__ATOMIC_ACQ_REL)!=1)return;
    if(front->timer) {front->timer->setRefcon(nullptr);front->timer->release();}
    front->gate->release();front->loop->release();front->display->release();
    front->~DodgeDisplayFrontend();IOFree(front,sizeof(*front));
}
static bool gated(const DodgeDisplayFrontend *front) {return front && front->loop->inGate();}
static bool live(const DodgeDisplayFrontend *front) {
    return !front->draining && front->gate->isEnabled() && front->gate->getWorkLoop()==front->loop &&
        front->display->getWorkLoop()==front->loop && IPhone16Swap::load<IOCommandGate *>(front->display,5040)==front->gate &&
        IPhone16Swap::load<uint32_t>(front->display,DisplayWidth)==front->width &&
        IPhone16Swap::load<uint32_t>(front->display,DisplayHeight)==front->height;
}
static void cancelRetry(DodgeDisplayFrontend *front) {
    if(front->timer)front->timer->cancelTimeout();
    front->waiting=false;front->retryAt=front->retryDeadline=0;
}
static IOReturn retry(DodgeDisplayFrontend *front) {
    const uint64_t now=mach_absolute_time();
    if(now>UINT64_MAX-front->retryInterval)return kIOReturnBadArgument;
    const uint64_t deadline=now+front->retryInterval;
    const IOReturn status=front->timer->wakeAtTime(deadline);
    if(status!=kIOReturnSuccess)return status;
    front->retryAt=now;front->retryDeadline=deadline;front->waiting=true;
    return kIOReturnBusy;
}
static bool gpuReady(DodgeDisplayFrontend *front,DodgeFrontendEntry &entry) {
    if(entry.gpuInvalid)return false;
    if(!front->requiresAdreno || entry.gpuPassed)return true;
    DodgeAdrenoTimeline snapshot={};
    if(!dodge_adreno_display_timeline(&snapshot) || !snapshot.epoch)return false;
    const uint32_t submitted=snapshot.submitted,retired=snapshot.retired;
    if(entry.gpuCaptured && snapshot.epoch!=entry.gpuEpoch) {entry.gpuInvalid=true;return false;}
    if(retired>submitted || (entry.gpuCaptured && (submitted<entry.gpuSubmitted || retired<entry.gpuRetired))) {
        // The old request cannot be associated with a new/reset timeline.
        // Latch refusal instead of allowing a later sequence reuse to pass.
        entry.gpuInvalid=entry.gpuCaptured;return false;
    }
    if(!entry.gpuCaptured) {entry.gpuTarget=submitted;entry.gpuEpoch=snapshot.epoch;entry.gpuCaptured=true;}
    entry.gpuSubmitted=submitted;entry.gpuRetired=retired;
    // Keep the first successful snapshot across busy/query-failure retries.
    // A regressing timeline is not evidence that the old work completed.
    if(submitted<entry.gpuTarget || retired<entry.gpuTarget)return false;
    entry.gpuPassed=true;return true;
}
static void fired(OSObject *owner,IOTimerEventSource *sender) {
    auto *front=static_cast<DodgeDisplayFrontend *>(sender->getRefcon());
    if(!gated(front) || owner!=front->display || sender!=front->timer)return;
    retainFrontend(front);sender->retain();
    if(front->waiting) {
        const uint64_t now=mach_absolute_time();
        if(!live(front) || now<front->retryAt) {cancelRetry(front);front->last=kIOReturnAborted;}
        else if(now<front->retryDeadline) {
            const IOReturn status=sender->wakeAtTime(front->retryDeadline);
            if(status!=kIOReturnSuccess) {cancelRetry(front);front->last=status;}
        } else dodge_display_frontend_kick(front);
    }
    sender->release();releaseFrontend(front);
}
static void clearEntry(DodgeFrontendEntry &entry) {
    // Detach before any virtual release can reenter stop or submission. A
    // newly reserved generation in this slot must survive those releases.
    DodgeFrontendEntry retired=entry;entry={};
    dodge_release_surface_backing(&retired.backing);
    if(retired.surface)retired.surface->release();
    IPhone16Swap::releaseExtraRequest(retired.request);
}
static DodgeFrontendEntry *entryFor(DodgeDisplayFrontend *front,IOMFBSwapIORequest *request) {
    for(auto &entry:front->entries)if(entry.used && entry.request==request)return &entry;
    return nullptr;
}
static bool pendingContains(const DodgeDisplayFrontend *front,IOMFBSwapIORequest *request) {
    auto *next=IPhone16Swap::pending(front->display);
    // Only requests admitted through the bounded ledger can participate.
    // Refuse an unfamiliar link without dereferencing its request object.
    for(unsigned index=0;next && index<MaximumPending;++index) {
        if(next==request)return true;
        bool known=false;
        for(const auto &entry:front->entries)known|=entry.used && entry.request==next;
        if(!known)return false;
        next=IPhone16Swap::load<IOMFBSwapIORequest *>(next,IPhone16Swap::Next);
    }
    return false;
}
static bool reapDequeued(DodgeDisplayFrontend *front) {
    // Original cancellation can remove a request without calling our GPU
    // observer. Audit the whole bounded queue before releasing a ledger ref;
    // an unknown link, cycle or malformed tail must not look like removal.
    for(unsigned pass=0;pass<MaximumPending;++pass) {
        bool present[MaximumPending]={};
        auto *previous=reinterpret_cast<uint8_t *>(front->display)+IPhone16Swap::Head;
        auto *request=IPhone16Swap::pending(front->display);
        for(unsigned walked=0;request;++walked) {
            if(walked>=MaximumPending)return false;
            DodgeFrontendEntry *entry=entryFor(front,request);
            if(!entry || present[entry-front->entries] ||
               IPhone16Swap::load<void *>(request,IPhone16Swap::PreviousLink)!=previous)return false;
            present[entry-front->entries]=true;
            previous=reinterpret_cast<uint8_t *>(request)+IPhone16Swap::Next;
            request=IPhone16Swap::load<IOMFBSwapIORequest *>(request,IPhone16Swap::Next);
        }
        if(IPhone16Swap::load<void *>(front->display,IPhone16Swap::Tail)!=previous)return false;
        request=IPhone16Swap::load<IOMFBSwapIORequest *>(front->display,IPhone16Swap::Current);
        if(request) {
            auto *entry=entryFor(front,request);if(!entry)return false;
            present[entry-front->entries]=true;
        }
        DodgeFrontendEntry *removed=nullptr;
        for(unsigned index=0;index<MaximumPending;++index) {
            auto &entry=front->entries[index];
            if(entry.used && entry.request && !entry.building && !entry.inflight && !present[index]) {removed=&entry;break;}
        }
        if(!removed)return true;
        clearEntry(*removed);
        if(!live(front))return false;
        // Re-audit after every release: a release may have reentered IOKit
        // and changed the queue or reused the now-empty generation slot.
    }
    return true;
}
static bool matches(DodgeDisplayFrontend *front,DodgeFrontendEntry &entry,bool queued) {
    if(!entry.request || !entry.surface || !IPhone16Swap::defaultRequestGeometry(entry.request,entry.identity,front->width,front->height) ||
       IPhone16Swap::surface(entry.request,0)!=entry.surface || native_iphone_surface_id(entry.surface)!=entry.identity.surface)return false;
    if(!queued)return true;
    if(!IPhone16Swap::producersReady(entry.request) || IPhone16Swap::effectiveSurface(entry.request,0)!=entry.surface)return false;
    for(unsigned index=1;index<4;++index)if(IPhone16Swap::effectiveSurface(entry.request,index))return false;
    return true;
}
static bool admitted(IOService *display,IOMFBSwapIORequest *request,void *cookie) {
    auto *front=static_cast<DodgeDisplayFrontend *>(cookie);
    return gated(front) && live(front) && display==front->display && front->active && front->active->inflight &&
        front->active->request==request && (!front->requiresAdreno || front->active->gpuPassed) && matches(front,*front->active,true);
}

static void observed(IOService *display,IOMFBSwapIORequest *request,IOReturn status,void *cookie) {
    auto *front=static_cast<DodgeDisplayFrontend *>(cookie);
    auto *entry=front->active;
    if(gated(front) && display==front->display && entry && entry->request==request) {
        front->active=nullptr;entry->inflight=false;front->last=status;
        if(status==kIOReturnSuccess) {++front->retired;clearEntry(*entry);}
        else if(front->draining || !pendingContains(front,request))clearEntry(*entry);
        // Never spin on an unchanged failed head. A later family kick may
        // retry it; successful retirement can progress the next queued frame.
        if(status==kIOReturnSuccess && !front->draining)dodge_display_frontend_kick(front);
    }
    releaseFrontend(front); // accepted/reentrant offer's callback reference
}

static DodgeDisplayFrontend *createOnGate(IOService *display,IOService *presenter,IOMemoryMap *scanout,
    DodgeDisplayProducer producer,DodgeDisplayTransfer transfer) {
    if(producer!=DodgeDisplayProducer::CpuOnly && producer!=DodgeDisplayProducer::AdrenoTimeline)return nullptr;
    if(!display || !scanout || !display->metaCast("IOMobileFramebufferLegacy"))return nullptr;
    IOWorkLoop *loop=display->getWorkLoop();if(!loop || !loop->inGate())return nullptr;
    auto *gate=IPhone16Swap::load<IOCommandGate *>(display,5040);
    if(!gate || !gate->metaCast("IOCommandGate") || gate->getWorkLoop()!=loop || !gate->isEnabled())return nullptr;
    if(!IPhone16Lifecycle::emptyStartupQueues(display))return nullptr;
    PE_Video video={};if(PE_current_console(&video))return nullptr;
    // The original packet builder reads these exact display fields into its
    // request. A valid GOP alone does not establish the family's own mode.
    if(IPhone16Swap::load<uint32_t>(display,DisplayWidth)!=video.v_width ||
       IPhone16Swap::load<uint32_t>(display,DisplayHeight)!=video.v_height)return nullptr;
    void *storage=IOMallocZero(sizeof(DodgeDisplayFrontend));if(!storage)return nullptr;
    auto *front=new(storage) DodgeDisplayFrontend{};
    front->references=1;front->display=display;front->gate=gate;front->loop=loop;
    front->width=video.v_width;front->height=video.v_height;
    front->requiresAdreno=producer==DodgeDisplayProducer::AdrenoTimeline;
    display->retain();gate->retain();loop->retain();
    front->bridge=dodge_gpu_swap_bridge_create(display,presenter,scanout,observed,front,admitted,transfer);
    if(!front->bridge){releaseFrontend(front);return nullptr;}
    if(front->requiresAdreno) {
        nanoseconds_to_absolutetime(200000,&front->retryInterval);
        if(front->retryInterval)front->timer=IOTimerEventSource::timerEventSource(display,fired);
        if(front->timer)front->timer->setRefcon(front);
        if(!front->timer || loop->addEventSource(front->timer)!=kIOReturnSuccess) {
            dodge_gpu_swap_bridge_stop(front->bridge);front->bridge=nullptr;
            releaseFrontend(front);return nullptr;
        }
    }
    return front;
}

struct DodgeFrontendCreate {
    IOService *display,*presenter;
    IOMemoryMap *scanout;
    IOWorkLoop *loop;
    IOCommandGate *gate;
    DodgeDisplayProducer producer;
    DodgeDisplayTransfer transfer;
    DodgeDisplayFrontend *front;
};
static IOReturn createAction(OSObject *target,void *argument,void *,void *,void *) {
    auto *call=static_cast<DodgeFrontendCreate *>(argument);
    if(!call || target!=call->display || !call->loop->inGate() || call->display->getWorkLoop()!=call->loop ||
       IPhone16Swap::load<IOCommandGate *>(call->display,5040)!=call->gate)return kIOReturnNotReady;
    call->front=createOnGate(call->display,call->presenter,call->scanout,call->producer,call->transfer);
    return call->front?kIOReturnSuccess:kIOReturnNotReady;
}
DodgeDisplayFrontend *dodge_display_frontend_create(IOService *display,IOService *presenter,IOMemoryMap *scanout,
    DodgeDisplayProducer producer,DodgeDisplayTransfer transfer) {
    if(!display || !scanout || !display->metaCast("IOMobileFramebufferLegacy") ||
       (producer!=DodgeDisplayProducer::CpuOnly && producer!=DodgeDisplayProducer::AdrenoTimeline) ||
       (transfer!=DodgeDisplayTransfer::CpuCopy && transfer!=DodgeDisplayTransfer::Presenter) ||
       (transfer==DodgeDisplayTransfer::Presenter && !presenter))return nullptr;
    IOWorkLoop *loop=display->getWorkLoop();if(!loop)return nullptr;
    if(loop->inGate())return createOnGate(display,presenter,scanout,producer,transfer);
    auto *gate=IPhone16Swap::load<IOCommandGate *>(display,5040);
    if(!gate || !gate->metaCast("IOCommandGate") || gate->getWorkLoop()!=loop || !gate->isEnabled())return nullptr;
    // The original start_hardware dispatch is not itself a gated action.
    // Keep inputs alive while entering the work loop, then recheck its exact
    // identity, mode and startup lists before allocating the frontend.
    DodgeFrontendCreate call={display,presenter,scanout,loop,gate,producer,transfer,nullptr};
    display->retain();loop->retain();gate->retain();scanout->retain();if(presenter)presenter->retain();
    loop->runAction(createAction,display,&call);
    if(presenter)presenter->release();
    scanout->release();gate->release();loop->release();display->release();
    return call.front;
}

bool dodge_display_frontend_validate(DodgeDisplayFrontend *front,IOMFBSwapIORequest *request) {
    if(!gated(front) || !live(front) || !request)return false;
    const uint32_t id=IPhone16Swap::load<uint32_t>(request,IPhone16Swap::RequestID);
    DodgeFrontendEntry *selected=nullptr;
    for(auto &entry:front->entries)if(entry.used && entry.building && entry.identity.request==id && !entry.request) {
        if(selected)return false;
        selected=&entry;
    }
    if(!selected || !IPhone16Swap::defaultRequestGeometry(request,selected->identity,front->width,front->height))return false;
    const uint64_t generation=selected->generation;
    auto *surface=static_cast<OSObject *>(IPhone16Swap::surface(request,0));
    if(!surface || !surface->metaCast("IOSurface") || native_iphone_surface_id(surface)!=selected->identity.surface)return false;
    if(!live(front) || !selected->used || !selected->building || selected->request || selected->generation!=generation ||
       IPhone16Swap::surface(request,0)!=surface ||
       !IPhone16Swap::defaultRequestGeometry(request,selected->identity,front->width,front->height))return false;
    IPhone16Swap::retainExtraRequest(request);surface->retain();
    selected->request=request;selected->surface=surface;++front->validated;return true;
}

IOReturn dodge_display_frontend_kick(DodgeDisplayFrontend *front) {
    if(!gated(front))return kIOReturnNotPermitted;
    if(!live(front))return kIOReturnNotReady;
    if(front->kicking){front->rekick=true;return kIOReturnBusy;}
    if(front->active)return kIOReturnBusy;
    // Offer may call back synchronously and may reenter stop. Keep the
    // controller alive until the outer kick has stopped touching its fields.
    retainFrontend(front);front->kicking=true;cancelRetry(front);IOReturn result=kIOReturnNotReady;
    do {
        front->rekick=false;
        if(!reapDequeued(front))break;
        auto *request=IPhone16Swap::pending(front->display);
        auto *entry=entryFor(front,request);
        if(!live(front) || front->active || !entry || !matches(front,*entry,true) ||
           !IPhone16Swap::canActivatePending(front->display,request))break;
        if(!gpuReady(front,*entry)) {result=entry->gpuInvalid?kIOReturnAborted:retry(front);break;}
        if(!entry->backing.memory) {
            DodgeSurfaceBacking backing={};const uint64_t generation=entry->generation;
            auto *surface=entry->surface;surface->retain();IPhone16Swap::retainExtraRequest(request);
            result=dodge_copy_surface_backing(surface,front->width,front->height,&backing);
            const bool valid=live(front) && entry->used && entry->generation==generation && entry->request==request;
            surface->release();IPhone16Swap::releaseExtraRequest(request);
            if(result!=kIOReturnSuccess || !valid) {
                dodge_release_surface_backing(&backing);
                if(!valid)result=kIOReturnAborted;
                break;
            }
            entry->backing=backing;
        }
        // Backing construction may enter IOKit. Recheck original admission
        // and queue identity before any GPU or CPU read of the surface.
        if(!live(front) || !matches(front,*entry,true) || !IPhone16Swap::canActivatePending(front->display,request)) {
            result=kIOReturnAborted;break;
        }
        const uint64_t generation=entry->generation;
        front->active=entry;entry->inflight=true;retainFrontend(front);
        result=dodge_gpu_swap_bridge_offer(front->bridge,request,entry->backing,true);
        if(front->active==entry && entry->used && entry->generation==generation && result!=kIOReturnSuccess) {
            // Input/allocation refusals do not deliver a bridge observer.
            front->active=nullptr;entry->inflight=false;releaseFrontend(front);
        }
    } while(front->rekick && !front->active && !front->draining);
    front->last=result;front->kicking=false;releaseFrontend(front);return result;
}

struct DodgeSubmitCall {
    DodgeDisplayFrontend *front;
    void *submitter;
    IPhone16Swap::PacketIdentity identity;
    uint8_t packet[IPhone16Swap::PacketBytes];
};
static IOReturn submitGated(OSObject *,void *argument,void *,void *,void *) {
    auto *call=static_cast<DodgeSubmitCall *>(argument);auto *front=call->front;
    if(!gated(front) || !live(front))return kIOReturnNotReady;
    if(!reapDequeued(front))return kIOReturnNotReady;
    DodgeFrontendEntry *slot=nullptr;
    for(auto &entry:front->entries) {
        if(entry.used && entry.identity.request==call->identity.request)return kIOReturnBusy;
        if(!entry.used && !slot)slot=&entry;
    }
    if(!slot || front->generation==UINT64_MAX)return kIOReturnBusy;
    slot->used=slot->building=true;slot->generation=++front->generation;slot->identity=call->identity;
    gpuReady(front,*slot);
    const uint64_t generation=slot->generation;
    const IOReturn result=native_iphone_submit_default_packet(front->display,call->packet,call->submitter);
    if(slot->used && slot->generation==generation) {
        slot->building=false;
        if(!slot->inflight && (!slot->request || result!=kIOReturnSuccess || !pendingContains(front,slot->request)))clearEntry(*slot);
    }
    ++front->submitted;front->last=result;return result;
}

IOReturn dodge_display_frontend_submit(DodgeDisplayFrontend *front,const void *packet,unsigned bytes,void *submitter) {
    if(!front)return kIOReturnBadArgument;
    DodgeSubmitCall call={};call.front=front;call.submitter=submitter;
    if(!IPhone16Swap::defaultPacket(packet,bytes,front->width,front->height,&call.identity))return kIOReturnUnsupported;
    __builtin_memcpy(call.packet,packet,sizeof(call.packet));
    // Validate the actual immutable copy used by the original callee too.
    if(!IPhone16Swap::defaultPacket(call.packet,sizeof(call.packet),front->width,front->height,&call.identity))return kIOReturnUnsupported;
    retainFrontend(front);
    const IOReturn result=front->loop->runAction(submitGated,front->display,&call);
    releaseFrontend(front);return result;
}

IOReturn dodge_display_frontend_set_refresh(DodgeDisplayFrontend *front,bool enabled) {
    if(!gated(front))return kIOReturnNotPermitted;
    if(!live(front))return kIOReturnNotReady;
    if(!front->refresh) {
        if(!enabled)return kIOReturnSuccess;
        front->refresh=dodge_software_refresh_create(front->display);
        if(!front->refresh)return kIOReturnNotReady;
    }
    return dodge_software_refresh_set_enabled(front->refresh,enabled);
}

IOReturn dodge_display_frontend_stop(DodgeDisplayFrontend *front) {
    if(!gated(front))return kIOReturnNotPermitted;
    front->draining=true;cancelRetry(front);
    if(front->timer) {front->timer->setRefcon(nullptr);front->timer->disable();}
    if(front->refresh) {
        const IOReturn status=dodge_software_refresh_stop(front->refresh);
        if(status!=kIOReturnSuccess) {front->last=status;return status;}
        front->refresh=nullptr;
    }
    if(front->active)return kIOReturnBusy;
    if(front->timer) {
        const IOReturn status=front->loop->removeEventSource(front->timer);
        if(status!=kIOReturnSuccess) {front->last=status;return status;}
        OSSafeReleaseNULL(front->timer);
    }
    const IOReturn status=dodge_gpu_swap_bridge_stop(front->bridge);
    if(status!=kIOReturnSuccess)return status;
    front->bridge=nullptr;
    for(auto &entry:front->entries)if(entry.used)clearEntry(entry);
    releaseFrontend(front);return kIOReturnSuccess;
}

bool dodge_display_frontend_status(DodgeDisplayFrontend *front,DodgeDisplayFrontendStatus *output) {
    if(!gated(front) || !output)return false;
    uint32_t pending=0;for(const auto &entry:front->entries)pending+=entry.used;
    *output={front->submitted,front->validated,front->retired,pending,front->last,front->active!=nullptr,front->draining,front->waiting};return true;
}
