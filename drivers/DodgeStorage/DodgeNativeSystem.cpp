// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeOwnerSystem.h"
#include <IOKit/IOLib.h>

extern "C" IOReturn dodge_native_security_start();
extern "C" {
volatile unsigned dodge_native_system_phase;
volatile IOReturn dodge_native_system_result = kIOReturnNotReady;
__attribute__((noinline)) void dodge_native_system_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

extern "C" IOReturn dodge_native_system_prepare() {
    // Refuse foreign board/identity and partial selections before storage DMA.
    if (!dodge_owner_system_allowed()) return kIOReturnNotPermitted;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_native_system_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    IOReturn result = dodge_native_security_start();
    __atomic_store_n(&dodge_native_system_result, result, __ATOMIC_RELAXED);
    __atomic_store_n(&dodge_native_system_phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_native_system_checkpoint();
    return result;
}
