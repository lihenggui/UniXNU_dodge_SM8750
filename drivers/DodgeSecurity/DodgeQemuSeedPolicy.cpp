// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <sys/types.h>

extern "C" {
extern volatile unsigned dodge_qemu_aes_phase, dodge_qemu_keystore_phase;
size_t native_aks_device_id(uint8_t *, size_t);

// Selected only by the separate VM build. The native owner guard and its
// physical-board identity checks are never replaced in native packages.
bool dodge_qemu_seed_security_ready() {
    if (__atomic_load_n(&dodge_qemu_aes_phase, __ATOMIC_ACQUIRE) != 2 ||
        __atomic_load_n(&dodge_qemu_keystore_phase, __ATOMIC_ACQUIRE) != 2) return false;
    uint8_t identity[8] = {};
    // This provider checks the explicit QEMU boot option, qemu-virt bus and
    // nonzero development identity. Successful phase counters alone are not
    // sufficient authorization.
    const bool ready = native_aks_device_id(identity, sizeof(identity)) == sizeof(identity);
    volatile uint8_t *bytes = identity;
    for (size_t index = 0; index < sizeof(identity); ++index) bytes[index] = 0;
    return ready;
}
}
