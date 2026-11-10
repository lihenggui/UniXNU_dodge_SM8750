// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "DodgeSurfaceIdentity.h"
class IOMemoryDescriptor;
class NativeAdrenoMemory;

struct DodgeSurfacePages {
    DodgeSurfaceIdentity identity{};
    IOMemoryDescriptor *backing=nullptr; // Owned, prepared when prepared=true.
    NativeAdrenoMemory *memory=nullptr; // One explicit device reference.
    uint64_t bytes=0;
    bool prepared=false,quarantined=false;
};

// Kernel-only association. The caller already owns a valid reference to the
// exact original surface descriptor, acquired through original-component
// serialization. Never pass a user pointer or retain a borrowed getter result
// without that protection. The descriptor argument remains caller-owned.
// Serialize the NativeAdrenoMemory and this record; call outside the GPU gate.
// Memory must be an imported, currently unmapped resource with no device refs.
// The result must be empty. Once a reference is held, identity is moved to out;
// errors can retain quarantined ownership: always inspect out after failure.
extern "C" IOReturn dodge_surface_pages_bind(DodgeSurfaceIdentity *,IOMemoryDescriptor *,
    NativeAdrenoMemory *,DodgeSurfacePages *);

// Rechecks the observed descriptor identity, allocation and exact page set.
// This does not freeze future backing changes or grant producer access. The
// original producer/serialization protocol must cover check-to-submit races.
extern "C" IOReturn dodge_surface_pages_current(const DodgeSurfacePages *);

// Requires completed use and actual device quiescence. Outstanding VM/job
// references refuse release. Complete failure quarantines both owners. No
// destructor, timeout, software reset or refcount is a quiescence proof.
extern "C" IOReturn dodge_surface_pages_release(DodgeSurfacePages *);
