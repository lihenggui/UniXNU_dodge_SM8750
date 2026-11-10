// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
class OSObject;
class IOService;
struct task;

// Exact iPhone10,3 / 20H392 IOSurfaceRoot entry, as called by the original
// display packet builder. The caller owns the root and task references for
// this call. The original implementation performs task/client authorization
// under its locks and try-retains the result before unlocking. Null is a
// refusal. A nonnull result owns one IOSurface reference.
extern "C" OSObject *native_iphone_surface_copy_for_task(IOService *,uint32_t,task *);

// Release successful results through OSObject's virtual release method.
// IOSurface overrides it: +12 is the surface ID, not an OSObject refcount.
// This binding does not freeze the backing or register a GPU access.
