// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGpuSwapBridge.h"
#include "OriginalLegacySwapCompletionABI.h"
#include "OriginalLegacyProducerABI.h"
#include "NativeLegacyRequest.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>

extern "C" {
bool native_gop_gpu_offer(IOService *,void *,IOMemoryDescriptor *,uint64_t,uint32_t,uint32_t);
int boot_progress_display_handoff(void);
void boot_progress_display_failed(void);
void boot_progress_display_copy(uint64_t,uint64_t);
void boot_progress_peripheral_frame(void);
void native_legacy_overlay_rows(uint32_t *,uint32_t *);
}

struct DodgeGpuSwapFrame;
struct DodgeGpuSwapBridge {
    uint32_t references;
    IOService *display,*presenter;
    IOCommandGate *gate;
    IOWorkLoop *loop;
    IOMemoryMap *scanout;
    PE_Video video;
    DodgeGpuSwapObserver observer;
    DodgeGpuSwapAdmission admission;
    void *cookie;
    DodgeGpuSwapFrame *active;
    bool stopping,presented,gpuHandoff;
};
struct DodgeGpuSwapFrame {
    DodgeGpuSwapBridge *bridge;
    IOMFBSwapIORequest *request;
    IOMemoryDescriptor *memory;
    uint32_t stride;
    int status;
};

static void retainBridge(DodgeGpuSwapBridge *bridge) {
    __atomic_fetch_add(&bridge->references,1,__ATOMIC_RELAXED);
}
static void releaseBridge(DodgeGpuSwapBridge *bridge) {
    if(__atomic_fetch_sub(&bridge->references,1,__ATOMIC_ACQ_REL)!=1)return;
    bridge->scanout->release();if(bridge->presenter)bridge->presenter->release();bridge->gate->release();
    bridge->loop->release();bridge->display->release();
    IOFree(bridge,sizeof(*bridge));
}
static bool ownsGate(const DodgeGpuSwapBridge *bridge) {
    return bridge && bridge->loop->inGate();
}
static bool admitted(const DodgeGpuSwapBridge *bridge,IOMFBSwapIORequest *request) {
    return !bridge->admission || bridge->admission(bridge->display,request,bridge->cookie);
}
static bool liveDisplay(const DodgeGpuSwapBridge *bridge) {
    if(bridge->stopping || !bridge->gate->isEnabled() || bridge->gate->getWorkLoop()!=bridge->loop ||
       bridge->display->getWorkLoop()!=bridge->loop ||
       IPhone16Swap::load<IOCommandGate *>(bridge->display,5040)!=bridge->gate)return false;
    PE_Video current={};
    return !PE_current_console(&current) && current.v_baseAddr==bridge->video.v_baseAddr &&
        current.v_width==bridge->video.v_width && current.v_height==bridge->video.v_height &&
        current.v_rowBytes==bridge->video.v_rowBytes && current.v_depth==32 && !current.v_rotate;
}

DodgeGpuSwapBridge *dodge_gpu_swap_bridge_create(IOService *display,IOService *presenter,
    IOMemoryMap *scanout,DodgeGpuSwapObserver observer,void *cookie,DodgeGpuSwapAdmission admission,DodgeDisplayTransfer transfer) {
    if(transfer!=DodgeDisplayTransfer::CpuCopy && transfer!=DodgeDisplayTransfer::Presenter)return nullptr;
    if(!display || (transfer==DodgeDisplayTransfer::Presenter && !presenter) || !scanout || !observer ||
       !display->metaCast("IOMobileFramebufferLegacy"))return nullptr;
    IOWorkLoop *loop=display->getWorkLoop();
    if(!loop || !loop->inGate())return nullptr;
    IOCommandGate *gate=IPhone16Swap::load<IOCommandGate *>(display,5040);
    if(!gate || !gate->metaCast("IOCommandGate") || gate->getWorkLoop()!=loop || !gate->isEnabled())return nullptr;
    PE_Video video={};
    if(PE_current_console(&video) || !video.v_baseAddr || !video.v_width || !video.v_height ||
       video.v_width>16384 || video.v_height>16384 || video.v_depth!=32 || video.v_rotate ||
       video.v_rowBytes<video.v_width*4 || (video.v_rowBytes&3) || video.v_rowBytes>UINT64_MAX/video.v_height ||
       video.v_baseAddr>UINT64_MAX-video.v_rowBytes*video.v_height ||
       scanout->getPhysicalAddress()!=video.v_baseAddr || !scanout->getVirtualAddress() ||
       (scanout->getVirtualAddress()&3) ||
       scanout->getVirtualAddress()>UINTPTR_MAX-scanout->getLength() ||
       scanout->getLength()!=video.v_rowBytes*video.v_height)return nullptr;
    auto *bridge=static_cast<DodgeGpuSwapBridge *>(IOMallocZero(sizeof(DodgeGpuSwapBridge)));
    if(!bridge)return nullptr;
    bridge->references=1;bridge->display=display;bridge->presenter=presenter;
    bridge->gate=gate;bridge->loop=loop;bridge->scanout=scanout;bridge->video=video;
    bridge->observer=observer;bridge->cookie=cookie;bridge->admission=admission;
    bridge->gpuHandoff=transfer==DodgeDisplayTransfer::Presenter;
    display->retain();if(presenter)presenter->retain();gate->retain();loop->retain();scanout->retain();
    return bridge;
}

static IOReturn copyFallback(DodgeGpuSwapFrame *frame) {
    auto *bridge=frame->bridge;
    const IOReturn prepared=frame->memory->prepare(kIODirectionOut);
    if(prepared!=kIOReturnSuccess)return prepared;
    IOReturn status=kIOReturnNoMemory;
    IOMemoryMap *source=frame->memory->map(kIOMapAnywhere|kIOMapReadOnly);
    if(source && source->getVirtualAddress()) {
        uint32_t first=0,rows=0;
        native_legacy_overlay_rows(&first,&rows);
        if(liveDisplay(bridge) && IPhone16Swap::canActivatePending(bridge->display,frame->request) &&
           IPhone16Swap::producersReady(frame->request) && admitted(bridge,frame->request)) {
            // Actual bounded scalar stores into the verified GOP map. Skip
            // only the renderer's negotiated diagnostic rows.
            const uint64_t began=mach_absolute_time();
            if(native_legacy_copy_pixels(reinterpret_cast<volatile void *>(bridge->scanout->getVirtualAddress()),
                bridge->scanout->getLength(),bridge->video.v_rowBytes,
                reinterpret_cast<const void *>(source->getVirtualAddress()),source->getLength(),frame->stride,
                bridge->video.v_width,bridge->video.v_height,first,rows)) {
                OSSynchronizeIO();
                boot_progress_display_copy(mach_absolute_time()-began,
                    uint64_t(bridge->video.v_width)*(bridge->video.v_height-rows)*4);
                status=kIOReturnSuccess;
            } else status=kIOReturnBadArgument;
        } else status=kIOReturnAborted;
    }
    OSSafeReleaseNULL(source);
    const IOReturn completed=frame->memory->complete(kIODirectionOut);
    return status==kIOReturnSuccess?completed:status;
}

static IOReturn finishFrame(OSObject *,void *argument,void *,void *,void *) {
    auto *frame=static_cast<DodgeGpuSwapFrame *>(argument);
    auto *bridge=frame->bridge;
    IOReturn status=kIOReturnAborted;
    if(ownsGate(bridge) && bridge->active==frame && liveDisplay(bridge) &&
       IPhone16Swap::canActivatePending(bridge->display,frame->request) &&
       IPhone16Swap::producersReady(frame->request) && admitted(bridge,frame->request)) {
        status=frame->status==0?kIOReturnSuccess:copyFallback(frame);
        if(status==kIOReturnSuccess) {
            if(!liveDisplay(bridge) || !IPhone16Swap::producersReady(frame->request) || !admitted(bridge,frame->request) ||
               !IPhone16Swap::activatePending(bridge->display,frame->request) ||
               !IPhone16Swap::dispatchCompletionIfCurrent(bridge->display,frame->request))status=kIOReturnNotReady;
            else {bridge->presented=true;boot_progress_peripheral_frame();}
        }
    }
    if(status!=kIOReturnSuccess && !bridge->presented)boot_progress_display_failed();
    if(bridge->active==frame)bridge->active=nullptr;
    // The observer may offer the next frame or consume the controller's owner
    // reference. This pending callback still keeps the controller alive.
    if(!bridge->stopping && bridge->observer)bridge->observer(bridge->display,frame->request,status,bridge->cookie);
    frame->memory->release();IPhone16Swap::releaseExtraRequest(frame->request);
    IOFree(frame,sizeof(*frame));
    return status;
}

IOReturn dodge_gpu_swap_bridge_offer(DodgeGpuSwapBridge *bridge,IOMFBSwapIORequest *request,
    const DodgeSurfaceBacking &source,bool producerComplete) {
    if(!ownsGate(bridge))return kIOReturnNotPermitted;
    if(!liveDisplay(bridge) || bridge->active)return kIOReturnBusy;
    if(!producerComplete)return kIOReturnNotReady;
    if(!request || !source.memory || source.width!=bridge->video.v_width || source.height!=bridge->video.v_height ||
       !native_legacy_surface_bounds(source.width,source.height,source.stride,source.memory->getLength(),source.memory->getLength()) ||
       !(source.memory->getDirection()&kIODirectionOut) ||
       !IPhone16Swap::canActivatePending(bridge->display,request))return kIOReturnBadArgument;
    if(!IPhone16Swap::producersReady(request) || !admitted(bridge,request))return kIOReturnNotReady;
    if(!boot_progress_display_handoff())return kIOReturnNotReady;
    auto *frame=static_cast<DodgeGpuSwapFrame *>(IOMallocZero(sizeof(DodgeGpuSwapFrame)));
    if(!frame) {if(!bridge->presented)boot_progress_display_failed();return kIOReturnNoMemory;}
    frame->bridge=bridge;frame->request=request;frame->memory=source.memory;frame->stride=source.stride;
    frame->memory->retain();IPhone16Swap::retainExtraRequest(request);
    bridge->active=frame;
    retainBridge(bridge); // pending callback
    retainBridge(bridge); // offer may synchronously/reentrantly receive it
    const bool accepted=bridge->gpuHandoff &&
        native_gop_gpu_offer(bridge->presenter,frame,frame->memory,source.stride,source.width,source.height);
    IOReturn status=kIOReturnSuccess;
    if(!accepted) {
        // CpuCopy never hands this frame to the presenter. A real presenter
        // also never calls back on rejection. The retained context can take
        // the CPU path without a concurrent GPU scanout transfer.
        frame->status=kIOReturnNotReady;
        status=finishFrame(bridge->display,frame,nullptr,nullptr,nullptr);
        releaseBridge(bridge);
    }
    releaseBridge(bridge);
    return status;
}

IOReturn dodge_gpu_swap_bridge_stop(DodgeGpuSwapBridge *bridge) {
    if(!ownsGate(bridge))return kIOReturnNotPermitted;
    bridge->stopping=true;bridge->observer=nullptr;bridge->cookie=nullptr;
    releaseBridge(bridge);
    return kIOReturnSuccess;
}

extern "C" void native_legacy_gpu_complete(void *opaque,int status) {
    if(!opaque)return;
    auto *frame=static_cast<DodgeGpuSwapFrame *>(opaque);
    auto *bridge=frame->bridge;
    frame->status=status;
    // IOWorkLoop's gate protects the original command gate and queue too,
    // without waiting forever on a command gate disabled during teardown.
    bridge->loop->runAction(finishFrame,bridge->display,frame);
    releaseBridge(bridge);
}
