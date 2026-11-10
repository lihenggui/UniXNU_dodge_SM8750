// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact 20H392 entry trampolines: replay the displaced stack instruction, then
// branch to the original function +4. Install all four reviewed hooks together.
#pragma once
class OSObject;
class IOMemoryDescriptor;
struct task;
extern "C" bool dodge_original_surface_init(OSObject *,OSObject *,task *,OSObject *,OSObject *);
extern "C" void dodge_original_surface_replace(OSObject *,IOMemoryDescriptor *);
extern "C" void dodge_original_surface_clear(OSObject *);
extern "C" void dodge_original_surface_free(OSObject *);
