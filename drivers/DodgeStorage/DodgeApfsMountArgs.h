// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
    DodgeApfsMountBytes = 0x150,
    DodgeApfsReadOnly = 1,
    DodgeApfsUnknownPermissions = 0x200000,
};

#ifdef __cplusplus
extern "C" {
#endif
// Serializes only a fresh ordinary-volume request. The caller supplies a live
// process user address and resolved UID/GID; this helper performs no mount.
// Unsupported flags, unresolved owners or invalid sizes leave output intact.
bool dodge_apfs_ordinary_mount_args(void *output, size_t bytes, uint64_t userSpec,
                                    uint32_t flags, uint32_t uid, uint32_t gid);
uint32_t dodge_apfs_default_mount_owner(uint32_t flags, uint32_t mountpointOwner);
#ifdef __cplusplus
}
#endif
