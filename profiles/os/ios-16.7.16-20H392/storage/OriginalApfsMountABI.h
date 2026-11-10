// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded ordinary-volume request for iPhone10,3 / 20H392 APFS 2142.140.9.
// VFS removes fspec before APFS copies 0x144 bytes. Tail padding is not data.
#pragma once
#include <stddef.h>
#include <stdint.h>

struct DodgeOriginalApfsMountArgs {
    uint64_t fspec;
    uint64_t flags;
    uint16_t mode;
    uint8_t opaqueZero[0x144 - 0x12];
    uint32_t ownerUID;
    uint32_t ownerGID;
    uint32_t tailPadding;
};
#if defined(__cplusplus)
static_assert(sizeof(DodgeOriginalApfsMountArgs) == 0x150, "iPhone APFS user request");
static_assert(offsetof(DodgeOriginalApfsMountArgs, flags) == 8, "iPhone APFS flags");
static_assert(offsetof(DodgeOriginalApfsMountArgs, mode) == 16, "iPhone APFS mode");
static_assert(offsetof(DodgeOriginalApfsMountArgs, ownerUID) == 0x144, "iPhone APFS UID");
static_assert(offsetof(DodgeOriginalApfsMountArgs, ownerGID) == 0x148, "iPhone APFS GID");
static_assert(offsetof(DodgeOriginalApfsMountArgs, tailPadding) == 0x14c, "iPhone APFS padding");
#else
_Static_assert(sizeof(struct DodgeOriginalApfsMountArgs) == 0x150, "iPhone APFS user request");
_Static_assert(offsetof(struct DodgeOriginalApfsMountArgs, flags) == 8, "iPhone APFS flags");
_Static_assert(offsetof(struct DodgeOriginalApfsMountArgs, mode) == 16, "iPhone APFS mode");
_Static_assert(offsetof(struct DodgeOriginalApfsMountArgs, ownerUID) == 0x144, "iPhone APFS UID");
_Static_assert(offsetof(struct DodgeOriginalApfsMountArgs, ownerGID) == 0x148, "iPhone APFS GID");
_Static_assert(offsetof(struct DodgeOriginalApfsMountArgs, tailPadding) == 0x14c, "iPhone APFS padding");
#endif
