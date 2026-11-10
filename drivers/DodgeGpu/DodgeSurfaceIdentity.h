// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOTypes.h>
#include <stdint.h>
class OSObject;

struct DodgeSurfaceIdentity {
    OSObject *surface=nullptr; // Owned; never supplied by userspace.
    uint32_t id=0;
};

// Runs in the requesting user task, outside the GPU gate. Nonblocking root
// matching and the original task-aware lookup are the only resolution path.
// The result must be empty. Retaining the surface does not freeze its backing,
// authorize a GPU submission or provide cache visibility / DMA completion.
extern "C" IOReturn dodge_copy_current_surface(uint32_t,DodgeSurfaceIdentity *);
// The owner must first finish any use of this identity, including callbacks.
extern "C" void dodge_release_surface_identity(DodgeSurfaceIdentity *);
