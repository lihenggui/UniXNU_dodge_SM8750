// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#ifndef EAUTH
#define EAUTH 80
#endif
#define FWRITE 2
#define FREAD 1
#define MNT_RDONLY 1
#define MNT_WAIT 1
#define F_FULLFSYNC 51
#define MAXPATHLEN 1024
#define VREG 1
#define VDIR 2
#define FWASLOCKED 0x4000
#define FG_HAS_OFDLOCK 8
#define F_FLOCK 0x100
#define F_OFD_LOCK 0x200
#define DTYPE_VNODE 1
using proc_t = void *;
using user_addr_t = uintptr_t;
using vfs_context_t = void *;
struct SeedTestMount { char type[16]; unsigned flags; };
using mount_t = SeedTestMount *;
struct vnode { int type; mount_t mount; bool root; unsigned references; const char *name, *path; };
using SeedTestNode = vnode;
using vnode_t = vnode *;
struct vfsstatfs { char f_fstypename[16]; };
struct vnode_attr {
    uint64_t va_active, va_supported, va_nlink, va_data_size;
    uint32_t va_uid, va_gid, va_mode;
};
enum { field_va_uid, field_va_gid, field_va_mode, field_va_nlink, field_va_data_size };
#define VATTR_INIT(a) memset(a, 0, sizeof(*(a)))
#define VATTR_WANTED(a, field) ((a)->va_active |= UINT64_C(1) << field_##field)
#define VATTR_IS_SUPPORTED(a, field) (((a)->va_supported & (UINT64_C(1) << field_##field)) != 0)
int vnode_vtype(vnode_t);
mount_t vnode_mount(vnode_t);
bool vnode_isvroot(vnode_t);
int vnode_lookup(const char *, unsigned, vnode_t *, vfs_context_t);
vfsstatfs *vfs_statfs(mount_t);
unsigned vfs_flags(mount_t);
int vnode_getattr(vnode_t, vnode_attr *, vfs_context_t);
int vnode_put(vnode_t);
const char *vnode_getname(vnode_t);
void vnode_putname(const char *);
int vn_getpath(vnode_t, char *, int *);
int VNOP_FSYNC(vnode_t, int, vfs_context_t);
int VNOP_IOCTL(vnode_t, unsigned long, void *, int, vfs_context_t);
bool PE_parse_boot_argn(const char *, void *, int);
struct fileglob { vnode_t node; int fg_flag, fg_lflags; };
inline vnode_t fg_get_data(fileglob *f) { return f->node; }
#define FILEGLOB_DTYPE(f) DTYPE_VNODE
int vnode_getwithref(vnode_t);
int vn_close(vnode_t, int, vfs_context_t);
int VNOP_ADVLOCK(vnode_t, char *, int, struct flock *, int, vfs_context_t, void *);
