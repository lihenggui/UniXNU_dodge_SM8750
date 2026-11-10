// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "DodgeDisplayFrontend.h"

struct DodgeDisplayService;
// The caller holds the service owner reference and serializes unpublished
// create/start. All later operations enter the retained original work loop.
// Completion runs on that gate, after every display timer has been detached,
// while owner, provider and scanout are still retained. It may call parent stop.
using DodgeDisplayStopped=void (*)(IOService *owner,IOService *provider);
DodgeDisplayService *dodge_display_service_create(IOService *,IOService *provider,DodgeDisplayStopped);
IOReturn dodge_display_service_start(DodgeDisplayService *,DodgeDisplayProducer=DodgeDisplayProducer::AdrenoTimeline);
bool dodge_display_service_ready(DodgeDisplayService *);
IOReturn dodge_display_service_submit(DodgeDisplayService *,const void *packet,void *submitter);
bool dodge_display_service_validate(DodgeDisplayService *,IOMFBSwapIORequest *);
void dodge_display_service_kick(DodgeDisplayService *);
IOReturn dodge_display_service_refresh(DodgeDisplayService *,bool);
// Busy/error preserves all needed objects and schedules a gated drain retry.
// A refused wake also preserves the owner; an explicit stop call can retry.
IOReturn dodge_display_service_stop(DodgeDisplayService *);
// Consumes the caller's owner reference only after stop succeeds. Never free a
// controller that still has an attached source or an outstanding frontend.
IOReturn dodge_display_service_release(DodgeDisplayService *);

struct DodgeDisplayServiceStatus {
    bool ready,stopping,stopped,retryArmed;
    IOReturn last;
};
bool dodge_display_service_status(DodgeDisplayService *,DodgeDisplayServiceStatus *);

// The caller keeps the controller owner alive. This immutable borrowed loop
// survives original parent stop and is released only with the controller.
IOWorkLoop *dodge_display_service_workloop(DodgeDisplayService *);
// Admit a synchronous original-parent operation only while ready. Reentrant
// stop waits for the operation to return before destroying parent resources.
using DodgeDisplayOperation=IOReturn (*)(IOService *,void *);
IOReturn dodge_display_service_admit(DodgeDisplayService *,DodgeDisplayOperation,void *);
