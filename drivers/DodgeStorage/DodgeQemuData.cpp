// SPDX-License-Identifier: BSD-2-Clause-Patent
#define dodge_data_mount_boot dodge_qemu_data_mount_impl
#include "DodgeDataMount.cpp"
#undef dodge_data_mount_boot
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>

extern "C" {
volatile unsigned dodge_qemu_data_phase, dodge_qemu_data_entered, dodge_qemu_data_mounted, dodge_qemu_data_verified;
volatile int dodge_qemu_data_result = EAGAIN;
volatile uint32_t dodge_qemu_data_device = uint32_t(NODEV), dodge_qemu_data_flags;
__attribute__((noinline)) void dodge_qemu_data_checkpoint() { __asm__ volatile("" ::: "memory"); }

int dodge_data_mount_boot(proc_t process, user_addr_t scratch, size_t bytes) {
    unsigned selected = 0;
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    OSData *type = bus ? OSDynamicCast(OSData, bus->getProperty("device_type")) : nullptr;
    bool valid = type && type->getLength() == sizeof("qemu-virt") &&
        !memcmp(type->getBytesNoCopy(), "qemu-virt", sizeof("qemu-virt"));
    if (bus) bus->release();
    if (!valid || !PE_parse_boot_argn("dodge-qemu-root", &selected, sizeof(selected)) || selected != 1) return EPERM;
    int result = dodge_qemu_data_mount_impl(process, scratch, bytes);
    DodgeDataMountStatus status{};dodge_data_mount_status(&status);
    dodge_qemu_data_phase = unsigned(status.phase);dodge_qemu_data_result = result;
    dodge_qemu_data_entered = status.syscallEntered;dodge_qemu_data_mounted = status.filesystemMounted;
    dodge_qemu_data_verified = status.resultVerified;
    if (status.resultVerified) {
        vnode_t point = nullptr;
        if (!vnode_lookup("/private/var", 0, &point, vfs_context_current())) {
            mount_t data = vnode_mount(point);
            vnode_t device = vfs_devvp(data);
            if (device) { dodge_qemu_data_device = uint32_t(vnode_specrdev(device));vnode_put(device); }
            dodge_qemu_data_flags = vfs_flags(data);vnode_put(point);
        }
    }
    dodge_qemu_data_checkpoint();
    return result;
}
}
