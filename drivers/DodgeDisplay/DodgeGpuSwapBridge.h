// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOMemoryDescriptor.h>
#include "DodgeSurfaceBacking.h"
#include "DodgeDisplayTransfer.h"

struct IOMFBSwapIORequest;
struct DodgeGpuSwapBridge;
// Called on the original framebuffer's work loop while an extra request
// reference is alive. Success reports memory copy/retirement, never vblank.
using DodgeGpuSwapObserver = void (*)(IOService *,IOMFBSwapIORequest *,IOReturn,void *);
// Optional extra frontend reservation/identity guard. It runs on the original
// gate and must be read-only: no callbacks, ownership changes or reentrancy.
using DodgeGpuSwapAdmission = bool (*)(IOService *,IOMFBSwapIORequest *,void *);

// All public operations require the original framebuffer's work-loop gate.
// The caller owns one controller reference, must serialize stop with offers,
// and must stop its presenter to retire any outstanding offer before shutdown.
// Only already validated one-layer BGRA frames with completed producers may
// enter this low-level bridge. Validation/composition belongs to the frontend.
// The frontend must reserve the queued request until the observer runs, and
// ensure failed/abandoned GPU work cannot continue writing before fallback.
// This component does not install an original-family queue hook or GPU reset.
// CpuCopy is the default and never offers work to the presenter; presenter may
// be null in that mode. Presenter mode requires an explicitly supplied service
// and the quiescence contract above, which is not qualified for this board.
// producerComplete is an additional caller condition. The bridge also checks
// the exact original registration/cancellation/ready words before submission,
// fallback and retirement; a caller boolean cannot bypass those observations.
DodgeGpuSwapBridge *dodge_gpu_swap_bridge_create(IOService *framebuffer,IOService *presenter,
    IOMemoryMap *scanout,DodgeGpuSwapObserver observer,void *cookie,DodgeGpuSwapAdmission admission=nullptr,
    DodgeDisplayTransfer transfer=DodgeDisplayTransfer::CpuCopy);
IOReturn dodge_gpu_swap_bridge_offer(DodgeGpuSwapBridge *,IOMFBSwapIORequest *,
    const DodgeSurfaceBacking &,bool producerComplete);
// An accepted GPU offer completes through the observer. Presenter rejection
// takes the bounded CPU path immediately and returns its result; the observer
// also runs in that case. Input/handoff/allocation refusals never notify it.
// Success consumes the caller's controller reference. Outside the gate this
// returns NotPermitted without consuming it. A pending callback retains its
// own reference; stopped controllers never copy or retire another request.
IOReturn dodge_gpu_swap_bridge_stop(DodgeGpuSwapBridge *);
