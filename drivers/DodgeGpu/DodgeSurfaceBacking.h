// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "DodgeSurfacePages.h"

// Kernel-only. identity must own its surface reference. The returned descriptor
// owns one reference obtained from the lifecycle observer, never by retaining
// the public borrowed getter. A missing/stale observation refuses acquisition.
// No backing immutability, producer grant or DMA completion is implied.
extern "C" IOReturn dodge_copy_surface_backing(const DodgeSurfaceIdentity *,IOMemoryDescriptor **);

// Resolve the actual current task, acquire an observed descriptor reference and
// invoke the existing exact-page association. Call outside the GPU gate with an
// exclusively owned, unpublished import and empty out. On error out can retain
// quarantined owners, just as dodge_surface_pages_bind does.
extern "C" IOReturn dodge_surface_pages_acquire(uint32_t,NativeAdrenoMemory *,DodgeSurfacePages *);
