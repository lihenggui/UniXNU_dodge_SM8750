// SPDX-License-Identifier: BSD-2-Clause-Patent
#define dodge_data_mount_for_init dodge_native_data_mount_for_init_impl
#define dodge_data_mount_boot dodge_native_data_mount_impl
#include "DodgeDataMount.cpp"
#undef dodge_data_mount_boot
#undef dodge_data_mount_for_init
#include "DodgeOwnerSystem.h"

extern "C" int dodge_data_mount_for_init(proc_t process, user_addr_t scratch, size_t bytes, uint32_t flags) {
    if (!dodge_owner_security_ready()) return EPERM;
    return dodge_native_data_mount_for_init_impl(process, scratch, bytes, flags);
}
extern "C" int dodge_data_mount_boot(proc_t process, user_addr_t scratch, size_t bytes) {
    if (!dodge_owner_security_ready()) return EPERM;
    return dodge_native_data_mount_impl(process, scratch, bytes);
}
