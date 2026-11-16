// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeDataMount.h"
#include "DodgeOwnerSystem.h"
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <pexpert/pexpert.h>

extern "C" {
unsigned dodge_seed_sync_attempts, dodge_seed_sync_completed, dodge_seed_sync_failed;
int dodge_seed_sync_last_error;
}

extern "C" int dodge_seed_sync_sysctl SYSCTL_HANDLER_ARGS {
    (void)oidp; (void)arg1;
    if (req->newptr) return EPERM;
    uint32_t value;
    switch (arg2) {
        case 0: value = __atomic_load_n(&dodge_seed_sync_attempts, __ATOMIC_ACQUIRE); break;
        case 1: value = __atomic_load_n(&dodge_seed_sync_completed, __ATOMIC_ACQUIRE); break;
        case 2: value = __atomic_load_n(&dodge_seed_sync_failed, __ATOMIC_ACQUIRE); break;
        case 3: value = uint32_t(__atomic_load_n(&dodge_seed_sync_last_error, __ATOMIC_RELAXED)); break;
        default: return EINVAL;
    }
    return SYSCTL_OUT(req, &value, sizeof(value));
}
#define DODGE_SEED_STAT(name, index, description) \
    SYSCTL_PROC(_kern, OID_AUTO, dodge_seed_sync_##name, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, \
        0, index, dodge_seed_sync_sysctl, "IU", description)
DODGE_SEED_STAT(attempts, 0, "Selected seed close synchronization attempts");
DODGE_SEED_STAT(completed, 1, "Filesystem accepted seed full synchronization; no hardware qualification");
DODGE_SEED_STAT(failed, 2, "Seed synchronization failures");
DODGE_SEED_STAT(last_error, 3, "Most recent selected seed close synchronization errno");
#undef DODGE_SEED_STAT

namespace {
int synchronize(vnode_t seed, vfs_context_t context) {
    DodgeDataMountStatus state{};
    dodge_data_mount_status(&state);
    if (state.phase != DodgeDataMountPhase::Mounted || !state.filesystemMounted || !state.resultVerified) return EAGAIN;
    vnode_t data = nullptr, directory = nullptr;
    int result = vnode_lookup("/private/var", 0, &data, context);
    if (result) return result;
    if (!data || !vnode_isvroot(data) || vnode_mount(seed) != vnode_mount(data)) result = EAUTH;
    auto *status = !result ? vfs_statfs(vnode_mount(data)) : nullptr;
    if (!result && (!status || strcmp(status->f_fstypename, "apfs") || (vfs_flags(vnode_mount(data)) & MNT_RDONLY))) result = EROFS;
    struct vnode_attr attributes;
    VATTR_INIT(&attributes);
    VATTR_WANTED(&attributes, va_uid); VATTR_WANTED(&attributes, va_gid);
    VATTR_WANTED(&attributes, va_mode); VATTR_WANTED(&attributes, va_nlink); VATTR_WANTED(&attributes, va_data_size);
    if (!result) result = vnode_getattr(seed, &attributes, context);
    if (!result && (!VATTR_IS_SUPPORTED(&attributes, va_uid) || !VATTR_IS_SUPPORTED(&attributes, va_gid) ||
        !VATTR_IS_SUPPORTED(&attributes, va_mode) || !VATTR_IS_SUPPORTED(&attributes, va_nlink) ||
        !VATTR_IS_SUPPORTED(&attributes, va_data_size))) result = ENOTSUP;
    // The original iPhone program creates a root-owned, private 32-byte seed.
    // Do not call a malformed, linked or more broadly readable file saved.
    if (!result && (attributes.va_uid || attributes.va_gid || (attributes.va_mode & 07777) != 0600 ||
        attributes.va_nlink != 1 || attributes.va_data_size != 32)) result = EAUTH;
    if (!result) result = vnode_lookup("/private/var/db", 0, &directory, context);
    if (!result && (!directory || vnode_vtype(directory) != VDIR || vnode_mount(directory) != vnode_mount(data))) result = EAUTH;
    if (!result) result = VNOP_FSYNC(seed, MNT_WAIT, context);
    if (!result) result = VNOP_FSYNC(directory, MNT_WAIT, context);
    // F_FULLFSYNC includes the backing-device flush. ENOTSUP and I/O errors
    // are returned; an ordinary fsync is not silently called a full sync.
    if (!result) result = VNOP_IOCTL(seed, F_FULLFSYNC, nullptr, 0, context);
    if (directory) vnode_put(directory);
    if (data) vnode_put(data);
    return result;
}
}

// The caller already owns a seed vnode iocount. The file's ordinary close and
// vnode_put still run exactly once, even if this extra synchronization fails.
extern "C" int dodge_seed_close_sync(vnode_t node, int flags, vfs_context_t context) {
    if (!(flags & FWRITE) || !node || vnode_vtype(node) != VREG) return 0;
    const char *name = vnode_getname(node);
    const bool candidate = name && !strcmp(name, "prng.seed");
    if (name) vnode_putname(name);
    if (!candidate || !dodge_owner_security_ready()) return 0;
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("dodge-seed-sync", &enabled, sizeof(enabled)) || enabled != 1) return 0;
    char path[MAXPATHLEN] = {}; int bytes = sizeof(path);
    int result = vn_getpath(node, path, &bytes);
    if (!result && strcmp(path, "/private/var/db/prng.seed") && strcmp(path, "/var/db/prng.seed")) return 0;
    __atomic_fetch_add(&dodge_seed_sync_attempts, 1U, __ATOMIC_RELAXED);
    if (!result) result = synchronize(node, context);
    __atomic_store_n(&dodge_seed_sync_last_error, result, __ATOMIC_RELAXED);
    __atomic_fetch_add(result ? &dodge_seed_sync_failed : &dodge_seed_sync_completed, 1U, __ATOMIC_RELEASE);
    return result;
}
