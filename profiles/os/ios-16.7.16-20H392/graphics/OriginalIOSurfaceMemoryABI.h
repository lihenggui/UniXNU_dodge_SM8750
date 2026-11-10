// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
class OSObject;
class IOMemoryDescriptor;

// Exact iPhone10,3 / 20H392 borrowed getter, also used by the original
// IOSurfaceClient mapping and wired-send-right prepare/complete paths.
// The result is at surface +56, distinct from the region object at +48.
// This call does not retain, prepare, lock or authorize use of its result.
extern "C" IOMemoryDescriptor *native_iphone_surface_memory(const OSObject *);
