// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <IOKit/IOService.h>

// Invoke in the loader's serialized preModLoad/postModLoad context, after the
// exact original IOMobileGraphicsFamily has constructed and registered Legacy.
// The build removes this class's initializer from early native __mod_init_func.
bool dodge_iphone_framebuffer_initialize();
bool dodge_iphone_framebuffer_registered();
// Allocation only: the caller still owns init/attach/start and failure cleanup.
// No instance can be allocated before the deferred initializer AND the loader's
// postModLoad registration of this exact owned metaclass have both succeeded.
IOService *dodge_iphone_framebuffer_allocate();
