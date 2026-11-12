// SPDX-License-Identifier: MIT
#pragma once
#include <IOKit/IOTypes.h>
class NativeAdrenoVm;
class OSObject;

// One conservative access batch for the shared address space. Preparation and
// waiting run outside connection/Ring/VM locks. Cancellation retains pending
// callbacks until their real grants arrive; it never invents a completion.
extern "C" IOReturn dodge_native_surface_initialize();
extern "C" IOReturn dodge_native_surface_prepare(NativeAdrenoVm *,void **batch);
extern "C" void dodge_native_surface_end_call(void **batch);
extern "C" bool dodge_native_surface_can_submit(void *batch);
extern "C" void dodge_native_surface_published(void *batch,bool uncertain);
extern "C" void dodge_native_surface_completed(void *batch,bool abandoned);
extern "C" void dodge_native_surface_changed(OSObject *surface);
extern "C" bool dodge_native_surface_healthy();
// A failed writer's surface stays unavailable until a later successful GPU
// writer completes for that same original identity. No object is dereferenced.
extern "C" bool dodge_native_surface_visible(OSObject *,uint32_t);
// Thread-call body. Kept callable for software-scheduler tests.
extern "C" void dodge_native_surface_drain();
