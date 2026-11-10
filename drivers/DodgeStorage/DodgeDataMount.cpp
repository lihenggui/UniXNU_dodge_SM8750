// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeDataMount.h"
#include "DodgeApfsMountArgs.h"
#include "DodgeRamBlockLifecycle.h"
#include "DodgeDataMountSeed.h"
#include <sys/errno.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <mach/vm_param.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOLib.h>

extern "C" int native_ram_block_volume_seed(const char *, dev_t *, char *, size_t, uint64_t *, uint64_t *, uint8_t *);
extern "C" int dodge_apfs_mount_syscall(proc_t, user_addr_t, user_addr_t, uint32_t, user_addr_t);

namespace {
unsigned phase = unsigned(DodgeDataMountPhase::Cold);
int last = EAGAIN;
bool entered = false, mounted = false, verified = false;
bool enabled(const char *name) {
    unsigned value = 0;
    return PE_parse_boot_argn(name, &value, sizeof(value)) && value == 1;
}
bool blockPath(const char *path) {
    if (strnlen(path, 64) == 64 || strncmp(path, "/dev/disk", 9)) return false;
    const char *cursor = path + 9;
    for (;;) {
        if (*cursor < '0' || *cursor > '9') return false;
        do { ++cursor; } while (*cursor >= '0' && *cursor <= '9');
        if (!*cursor) return true;
        if (*cursor++ != 's') return false;
    }
}
bool originalRoot(vnode_t root, mount_t filesystem) {
    vnode_t current = vfs_rootvnode();
    bool same = current && current == root;
    if (current) vnode_put(current);
    if (!same || !filesystem || vnode_mount(root) != filesystem || !vnode_isvroot(root)) return false;
    auto *status = vfs_statfs(filesystem);
    return status && (vfs_flags(filesystem) & (MNT_ROOTFS | MNT_RDONLY)) == (MNT_ROOTFS | MNT_RDONLY) &&
           !strcmp(status->f_fstypename, "apfs");
}
int attempt(proc_t process, user_addr_t scratch, uint32_t flags) {
    // Root identity is retained through the syscall and result readback.
    vnode_t root = vfs_rootvnode(), point = nullptr;
    if (!root) return EAGAIN;
    mount_t filesystem = vnode_mount(root);
    int error = EAUTH;
    if (originalRoot(root, filesystem)) {
        auto context = vfs_context_current();
        error = vnode_lookup("/private/var", 0, &point, context);
        if (!error) {
            if (!point || vnode_vtype(point) != VDIR || vnode_isvroot(point) || vnode_mount(point) != filesystem)
                error = EBUSY;
            else {
                struct vnode_attr attributes;
                VATTR_INIT(&attributes);
                VATTR_WANTED(&attributes, va_uid); VATTR_WANTED(&attributes, va_gid);
                error = vnode_getattr(point, &attributes, context);
                if (!error && (!VATTR_IS_SUPPORTED(&attributes, va_uid) || !VATTR_IS_SUPPORTED(&attributes, va_gid))) error = ENOTSUP;
                if (!error) {
                    dev_t device = NODEV;
                    char path[64] = {};
                    uint64_t base = 0, bytes = 0;
                    uint8_t digest[32] = {};
                    if (!native_ram_block_volume_seed(dodgeDataMountVolumeUUID, &device, path, sizeof(path), &base, &bytes, digest))
                        error = EAGAIN;
                    else if (device == NODEV || bytes != dodgeDataMountSeedBytes || memcmp(digest, dodgeDataMountSeedSHA256, sizeof(digest)) ||
                             !blockPath(path)) error = EINVAL;
                    else {
                        uint8_t payload[DodgeApfsMountBytes];
                        auto uid = dodge_apfs_default_mount_owner(flags, attributes.va_uid);
                        auto gid = dodge_apfs_default_mount_owner(flags, attributes.va_gid);
                        if (!dodge_apfs_ordinary_mount_args(payload, sizeof(payload), scratch + 0x80, flags, uid, gid)) error = EINVAL;
                        else {
                            error = copyout("apfs", scratch, 5);
                            if (!error) error = copyout("/private/var", scratch + 0x20, 13);
                            if (!error) error = copyout(path, scratch + 0x80, strlen(path) + 1);
                            if (!error) error = copyout(payload, scratch + 0x100, sizeof(payload));
                            if (!error && !originalRoot(root, filesystem)) error = EAUTH;
                            if (!error) {
                                // Do not hold a vnode iocount on the covered directory.
                                vnode_put(point); point = nullptr;
                                __atomic_store_n(&entered, true, __ATOMIC_RELEASE);
                                error = dodge_apfs_mount_syscall(process, scratch, scratch + 0x20, flags, scratch + 0x100);
                                if (!error) {
                                    __atomic_store_n(&mounted, true, __ATOMIC_RELAXED);
                                    error = vnode_lookup("/private/var", 0, &point, context);
                                    if (!error) {
                                        mount_t data = point ? vnode_mount(point) : nullptr;
                                        vnode_t node = data ? vfs_devvp(data) : nullptr;
                                        dev_t actual = node ? vnode_specrdev(node) : NODEV;
                                        if (node) vnode_put(node);
                                        auto *status = data ? vfs_statfs(data) : nullptr;
                                        if (!data || !status || data == filesystem || !vnode_isvroot(point) || actual != device ||
                                            (vfs_flags(data) & uint32_t(DodgeApfsReadOnly | DodgeApfsUnknownPermissions)) != flags ||
                                            strcmp(status->f_fstypename, "apfs") || !originalRoot(root, filesystem)) error = EAUTH;
                                        if (!error) __atomic_store_n(&verified, true, __ATOMIC_RELAXED);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (point) vnode_put(point);
    vnode_put(root);
    return error;
}
}

extern "C" int dodge_data_mount_for_init(proc_t process, user_addr_t scratch, size_t bytes, uint32_t flags) {
    if (!enabled("dodge-data-mount") || !enabled("dodge-data")) return EPERM;
    if (!process || current_proc() != process || proc_pid(process) != 1 || !proc_is64bit(process)) return EINVAL;
    if (bytes < 0x400 || scratch < 4096 || scratch > MACH_VM_MAX_ADDRESS - 0x400 || (flags & ~uint32_t(0x200001))) return EINVAL;
    DodgeRamBlockStatus state{}; dodge_ramblock_status(&state);
    if (state.start != DodgeRamBlockStartPhase::Started || !state.instancePinned || !state.driverRetained) return EAGAIN;
    unsigned expected = unsigned(DodgeDataMountPhase::Cold);
    if (!__atomic_compare_exchange_n(&phase, &expected, unsigned(DodgeDataMountPhase::Preparing), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == unsigned(DodgeDataMountPhase::Preparing) ? EBUSY : EALREADY;
    int error = attempt(process, scratch, flags);
    __atomic_store_n(&last, error, __ATOMIC_RELAXED);
    bool didMount = __atomic_load_n(&entered, __ATOMIC_ACQUIRE);
    __atomic_store_n(&phase, unsigned(!didMount ? DodgeDataMountPhase::Cold : error ? DodgeDataMountPhase::Failed : DodgeDataMountPhase::Mounted), __ATOMIC_RELEASE);
    return error;
}

extern "C" void dodge_data_mount_status(DodgeDataMountStatus *out) {
    if (!out) return;
    out->phase = DodgeDataMountPhase(__atomic_load_n(&phase, __ATOMIC_ACQUIRE));
    out->last = __atomic_load_n(&last, __ATOMIC_RELAXED);
    out->syscallEntered = __atomic_load_n(&entered, __ATOMIC_RELAXED);
    out->filesystemMounted = __atomic_load_n(&mounted, __ATOMIC_RELAXED);
    out->resultVerified = __atomic_load_n(&verified, __ATOMIC_RELAXED);
}

extern "C" int dodge_data_mount_boot(proc_t process, user_addr_t scratch, size_t bytes) {
    if (!enabled("dodge-data-mount")) return 0;
    int error = EAGAIN;
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        error = dodge_data_mount_for_init(process, scratch, bytes, 0);
        if (error != EAGAIN && error != EBUSY) break;
        DodgeDataMountStatus status{}; dodge_data_mount_status(&status);
        if (status.syscallEntered) break;
        if (attempt + 1 < 1000) IOSleep(10);
    }
    return error;
}
