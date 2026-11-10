// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceIdentity.h"
#include "OriginalIOSurfaceIdentityABI.h"
#include <IOKit/IOService.h>
#include <kern/task.h>

extern "C" IOReturn dodge_copy_current_surface(uint32_t id,DodgeSurfaceIdentity *out)
{
    if(!out || out->surface || out->id || !id)return kIOReturnBadArgument;
    task_t caller=current_task();
    // A worker or the optional kernel mailbox cannot impersonate a user task.
    if(!caller || caller==kernel_task)return kIOReturnNotPermitted;
    OSDictionary *matching=IOService::nameMatching("IOCoreSurfaceRoot");
    if(!matching)return kIOReturnNoMemory;
    IOService *root=IOService::copyMatchingService(matching);matching->release();
    if(!root)return kIOReturnNotReady;
    if(root->isInactive() || !root->metaCast("IOSurfaceRoot")) {
        root->release();return kIOReturnNotReady;
    }
    OSObject *surface=native_iphone_surface_copy_for_task(root,id,caller);
    IOReturn status=kIOReturnNotPermitted;
    if(surface) {
        // The original lookup returns a retained object. Always discharge
        // that ownership on refusal, using its actual virtual release.
        if(!surface->metaCast("IOSurface") || root->isInactive()) {
            surface->release();status=kIOReturnNotReady;
        } else {
            out->surface=surface;out->id=id;status=kIOReturnSuccess;
        }
    }
    root->release();return status;
}

extern "C" void dodge_release_surface_identity(DodgeSurfaceIdentity *identity)
{
    if(!identity)return;
    OSObject *surface=identity->surface;
    // Clear before virtual dispatch so an empty second release is harmless.
    *identity={};
    if(surface)surface->release();
}
