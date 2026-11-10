// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeApfsMountArgs.h"
#include "OriginalApfsMountABI.h"

namespace {
void little(void *output, size_t offset, uint64_t value, unsigned bytes) {
    auto *data = static_cast<uint8_t *>(output);
    for (unsigned i = 0; i < bytes; ++i) data[offset + i] = uint8_t(value >> (i * 8));
}
}

extern "C" uint32_t dodge_apfs_default_mount_owner(uint32_t flags, uint32_t owner) {
    return flags & DodgeApfsUnknownPermissions ? 99 : owner;
}

extern "C" bool dodge_apfs_ordinary_mount_args(void *output, size_t bytes, uint64_t userSpec,
                                               uint32_t flags, uint32_t uid, uint32_t gid) {
    if (!output || bytes != DodgeApfsMountBytes || !userSpec ||
        (flags & ~(DodgeApfsReadOnly | DodgeApfsUnknownPermissions)) || uid == UINT32_MAX || gid == UINT32_MAX)
        return false;
    auto *data = static_cast<uint8_t *>(output);
    for (size_t i = 0; i < bytes; ++i) data[i] = 0;
    little(data, offsetof(DodgeOriginalApfsMountArgs, fspec), userSpec, 8);
    little(data, offsetof(DodgeOriginalApfsMountArgs, flags), flags, 8);
    little(data, offsetof(DodgeOriginalApfsMountArgs, mode), 1, 2);
    little(data, offsetof(DodgeOriginalApfsMountArgs, ownerUID), uid, 4);
    little(data, offsetof(DodgeOriginalApfsMountArgs, ownerGID), gid, 4);
    return true;
}
