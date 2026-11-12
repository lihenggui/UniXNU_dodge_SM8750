// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeQemuStoreTransport.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <pexpert/pexpert.h>
#include <sys/types.h>

extern "C" {
volatile unsigned dodge_qemu_store_phase, dodge_qemu_store_error;
volatile uint64_t dodge_qemu_store_reads, dodge_qemu_store_writes, dodge_qemu_store_flushes, dodge_qemu_store_bytes;
volatile int dodge_qemu_store_result = kIOReturnNotReady;
extern volatile uint32_t native_data_persist_state;
int native_ram_block_volume_seed(const char *, dev_t *, char *, size_t, uint64_t *, uint64_t *, uint8_t *);
__attribute__((noinline)) void dodge_qemu_store_checkpoint() { __asm__ volatile("" ::: "memory"); }
}

namespace {
dodge_store::Transport transport{};
IOService *providerPin;
IOMemoryMap *mappingPin;
IOBufferMemoryDescriptor *queuePin, *transferPin;
IOLock *storeGate;
uintptr_t registers;

bool selected() {
    unsigned value = 0;
    return PE_parse_boot_argn("dodge-qemu-store", &value, sizeof(value)) && value == 1;
}
struct Operations {
    uint32_t read(uint32_t at) { return *reinterpret_cast<volatile uint32_t *>(registers + at); }
    void write(uint32_t at, uint32_t value) {
        *reinterpret_cast<volatile uint32_t *>(registers + at) = value;
        __asm__ volatile("dsb oshst" ::: "memory");
    }
    void barrier() { __asm__ volatile("dmb osh" ::: "memory"); }
    uint64_t deadline() { uint64_t value;clock_interval_to_deadline(1000, kMillisecondScale, &value);return value; }
    bool expired(uint64_t value) { return mach_absolute_time() >= value; }
    void pause() { IODelay(1); }
} operations;

void counters() {
    dodge_qemu_store_error = unsigned(transport.error);
    dodge_qemu_store_reads = transport.reads;dodge_qemu_store_writes = transport.writes;
    dodge_qemu_store_flushes = transport.flushes;dodge_qemu_store_bytes = transport.sectors * 512;
    if (transport.error == dodge_store::Error::Reset) panic("QEMU Data store DMA reset was not acknowledged");
}
bool virtualPlatform() {
    unsigned root = 0;
    if (!selected() || !PE_parse_boot_argn("dodge-qemu-root", &root, sizeof(root)) || root != 1) return false;
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    OSData *type = bus ? OSDynamicCast(OSData, bus->getProperty("device_type")) : nullptr;
    bool valid = type && type->getLength() == sizeof("qemu-virt") && !memcmp(type->getBytesNoCopy(), "qemu-virt", sizeof("qemu-virt"));
    if (bus) bus->release();
    return valid;
}
bool start() {
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_qemu_store_phase, &expected, 1U, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == 2;
    IOReturn result = kIOReturnNotPermitted;
    uint64_t bytes = 0;
    if (virtualPlatform()) {
        IOService *platform = IOService::getPlatform();
        OSIterator *iterator = platform ? platform->getChildIterator(gIOServicePlane) : nullptr;
        unsigned count = 0;
        if (iterator) {
            IOService *provider;
            while ((provider = OSDynamicCast(IOService, iterator->getNextObject()))) {
                if (!provider->getProperty("dodge,qemu-store")) continue;
                ++count;
                OSData *compatible = OSDynamicCast(OSData, provider->getProperty("compatible"));
                OSData *capacity = OSDynamicCast(OSData, provider->getProperty("dodge,qemu-store-bytes"));
                if (count != 1 || provider->isInactive() || !provider->metaCast("IOPlatformDevice") ||
                    !compatible || compatible->getLength() != sizeof("virtio,mmio") ||
                    memcmp(compatible->getBytesNoCopy(), "virtio,mmio", sizeof("virtio,mmio")) ||
                    !capacity || capacity->getLength() != sizeof(bytes) || !provider->getProperty("dma-coherent")) continue;
                memcpy(&bytes, capacity->getBytesNoCopy(), sizeof(bytes));
                provider->retain();providerPin = provider;
            }
            iterator->release();
        }
        if (count == 1 && providerPin && bytes == UINT64_C(2147553280) && providerPin->getResources() == kIOReturnSuccess) {
            mappingPin = providerPin->mapDeviceMemoryWithIndex(0, kIOMapAnywhere | kIOMapInhibitCache);
            storeGate = IOLockAlloc();
            if (mappingPin && mappingPin->getLength() >= 0x108 && storeGate) {
                registers = uintptr_t(mappingPin->getVirtualAddress());
                IOOptionBits options = IOOptionBits(kIODirectionInOut) | IOOptionBits(kIOMemoryPhysicallyContiguous);
                queuePin = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, options, 4096, 4096);
                transferPin = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, options, dodge_store::TransferBytes, 4096);
                if (queuePin && transferPin) {
                    IOByteCount queueLength = 0, transferLength = 0;
                    transport.queuePhysical = queuePin->getPhysicalSegment(0, &queueLength);
                    transport.transferPhysical = transferPin->getPhysicalSegment(0, &transferLength);
                    transport.queue = static_cast<uint8_t *>(queuePin->getBytesNoCopy());
                    transport.transfer = static_cast<uint8_t *>(transferPin->getBytesNoCopy());
                    if (queueLength >= 4096 && transferLength >= dodge_store::TransferBytes)
                        result = transport.start(operations, bytes) ? kIOReturnSuccess : kIOReturnIOError;
                }
            }
        }
    }
    counters();dodge_qemu_store_result = result;
    __atomic_store_n(&dodge_qemu_store_phase, result ? 3U : 2U, __ATOMIC_RELEASE);
    dodge_qemu_store_checkpoint();return !result;
}
bool blocks(bool write, uint64_t block, uint32_t count, void *data) {
    if (__atomic_load_n(&dodge_qemu_store_phase, __ATOMIC_ACQUIRE) != 2 || !storeGate) return false;
    IOLockLock(storeGate);
    bool result = transport.blocks(operations, write, block, count, data);
    counters();IOLockUnlock(storeGate);return result;
}
}

extern "C" unsigned dodge_qemu_store_mode() {
    if (!selected()) return 0;
    start();return 2; // Selection failures are reported by open, never converted to volatile mode.
}
extern "C" int dodge_qemu_store_open(uint64_t blocks, uint64_t *first, const char **why) {
    if (first) *first = 0;
    if (why) *why = "QEMU Data store not qualified";
    bool valid = first && why && selected() && dodge_qemu_store_phase == 2 &&
        transport.ready && !transport.poisoned && blocks == transport.sectors / 8;
    if (valid) *why = "QEMU flat-file overlay; GPT not applicable";
    return valid;
}
extern "C" int dodge_qemu_store_read(uint64_t block, uint32_t count, void *data) { return blocks(false, block, count, data); }
extern "C" int dodge_qemu_store_write(uint64_t block, uint32_t count, const void *data) {
    return blocks(true, block, count, const_cast<void *>(data));
}
extern "C" int dodge_qemu_store_sync() {
    if (dodge_qemu_store_phase != 2 || !storeGate) return 0;
    IOLockLock(storeGate);bool result = transport.sync(operations);counters();IOLockUnlock(storeGate);return result;
}
extern "C" unsigned dodge_qemu_store_gpt_check() { return 0xff; } // A flat VM file has no partition table.
extern "C" int dodge_qemu_persistent_volume_seed(const char *uuid, dev_t *device, char *path, size_t size,
    uint64_t *base, uint64_t *bytes, uint8_t digest[32]) {
    if (!native_ram_block_volume_seed(uuid, device, path, size, base, bytes, digest)) return 0;
    return native_data_persist_state == 2 || native_data_persist_state == 3;
}
