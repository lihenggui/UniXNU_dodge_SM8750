// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
#include <stddef.h>
using vm_offset_t = uintptr_t;
using vm_size_t = size_t;
constexpr unsigned PAGE_SIZE = 4096;
constexpr int KERN_SUCCESS = 0, VM_PROT_READ = 1, TRUE = 1;
extern void *kernel_map;
inline vm_size_t round_page(vm_size_t bytes) { return (bytes + 4095) & ~vm_size_t(4095); }
int vm_map_protect(void *, vm_offset_t, vm_offset_t, int, int);
