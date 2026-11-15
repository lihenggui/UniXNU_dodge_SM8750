// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "vm_map.h"
enum kma_flags_t { KMA_KOBJECT = 1, KMA_DATA = 2 };
constexpr int VM_KERN_MEMORY_SECURITY = 7;
int kmem_alloc(void *, vm_offset_t *, vm_size_t, kma_flags_t, int);
