// SPDX-License-Identifier: BSD-2-Clause-Patent
// sysproto.h is a C-only generated interface (fields include new and class).
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysproto.h>
#include <stddef.h>

int dodge_apfs_mount_syscall(proc_t process, user_addr_t type, user_addr_t path, uint32_t flags, user_addr_t data) {
    struct mount_args request = {.type = type, .path = path, .flags = (int)flags, .data = data};
    int32_t result = 0;
    return mount(process, &request, &result);
}

// Measured by the native compiler, consumed by the CPU harness. Never use a
// host syscall structure as a substitute for these generated iPhone fields.
const unsigned dodge_apfs_mount_syscall_layout[] = {
    sizeof(struct mount_args), offsetof(struct mount_args, type), offsetof(struct mount_args, path),
    offsetof(struct mount_args, flags), offsetof(struct mount_args, data)
};
