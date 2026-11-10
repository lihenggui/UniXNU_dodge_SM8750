// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOMemoryDescriptor.h>
#include "DodgeSurfaceLayout.h"

struct DodgeSurfaceBacking {
    IOMemoryDescriptor *memory=nullptr; // Owned subrange, offset normalized to zero.
    uint32_t width=0,height=0,stride=0;
};
// Caller serializes the original surface/region/mapping against mutation
// and teardown. This owns a memory subrange only; producer completion,
// cache/SMMU ownership, prepare/complete and scanout remain caller duties.
// The output must be empty. No display registration or GPU submission occurs.
IOReturn dodge_copy_surface_backing(OSObject *,uint32_t,uint32_t,DodgeSurfaceBacking *);
// Caller must finish all uses/submissions before releasing this view.
void dodge_release_surface_backing(DodgeSurfaceBacking *);
