// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// VirtIO 1.2 modern MMIO, split queue, one outstanding request.
// https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html#x1-2520002
namespace dodge_store {
constexpr uint32_t QueueSize = 8, TransferBytes = 65536;
constexpr uint32_t Available = 128, Used = 256, RequestAt = 512, StatusAt = 528;
constexpr char Identifier[20] = "UNIXNU-DODGE-DATA-1";
struct Descriptor { uint64_t address; uint32_t length; uint16_t flags, next; };
struct Request { uint32_t operation, reserved; uint64_t sector; };
struct Completion { uint32_t id, length; };
static_assert(sizeof(Descriptor) == 16 && sizeof(Request) == 16 && sizeof(Completion) == 8, "VirtIO wire layout");

enum class Error : uint32_t { None, Identity, Features, Queue, Capacity, Timeout, Completion, Device, Reset, Bounds };

struct Transport {
    uint8_t *queue = nullptr, *transfer = nullptr;
    uint64_t queuePhysical = 0, transferPhysical = 0, sectors = 0;
    uint16_t available = 0, used = 0;
    bool owns = false, ready = false, poisoned = false;
    Error error = Error::None;
    uint64_t reads = 0, writes = 0, flushes = 0;

    template <class Ops> bool reset(Ops &ops) {
        ready = false;
        if (!owns) return true;
        ops.write(0x70, 0);
        uint64_t limit = ops.deadline();
        while (ops.read(0x70)) {
            if (ops.expired(limit)) { poisoned = true;error = Error::Reset;return false; }
            ops.pause();
        }
        return true;
    }
    template <class Ops> bool fail(Ops &ops, Error reason) {
        error = reason;poisoned = true;
        reset(ops); // The adapter retains DMA resources even after acknowledged reset.
        return false;
    }
    template <class Ops> void address(Ops &ops, uint32_t at, uint64_t value) {
        ops.write(at, uint32_t(value));ops.write(at + 4, uint32_t(value >> 32));
    }
    template <class Ops> bool request(Ops &ops, uint32_t operation, uint64_t sector, uint32_t bytes) {
        if (!ready || poisoned || bytes > TransferBytes ||
            (operation != 0 && operation != 1 && operation != 4 && operation != 8) ||
            ((operation == 0 || operation == 1) && (!bytes || bytes % 512 || sector >= sectors || bytes / 512 > sectors - sector)) ||
            (operation == 4 && (bytes || sector)) || (operation == 8 && (bytes != 20 || sector))) {
            error = Error::Bounds;return false;
        }
        auto *descriptors = reinterpret_cast<Descriptor *>(queue);
        auto *header = reinterpret_cast<Request *>(queue + RequestAt);
        *header = Request{operation, 0, sector};
        queue[StatusAt] = 0xff;
        descriptors[0] = Descriptor{queuePhysical + RequestAt, sizeof(Request), 1, uint16_t(bytes ? 1 : 2)};
        if (bytes) descriptors[1] = Descriptor{transferPhysical, bytes, uint16_t(1 | ((operation == 0 || operation == 8) ? 2 : 0)), 2};
        descriptors[2] = Descriptor{queuePhysical + StatusAt, 1, 2, 0};
        *reinterpret_cast<uint16_t *>(queue + Available + 4 + (available % QueueSize) * 2) = 0;
        ops.barrier();
        *reinterpret_cast<volatile uint16_t *>(queue + Available + 2) = ++available;
        ops.barrier();ops.write(0x50, 0);
        uint64_t limit = ops.deadline();
        while (*reinterpret_cast<volatile uint16_t *>(queue + Used + 2) == used) {
            if (ops.expired(limit)) return fail(ops, Error::Timeout);
            ops.pause();
        }
        ops.barrier();
        uint16_t completed = *reinterpret_cast<volatile uint16_t *>(queue + Used + 2);
        Completion entry;
        memcpy(&entry, queue + Used + 4 + (used % QueueSize) * sizeof(Completion), sizeof(entry));
        if (completed != uint16_t(used + 1) || entry.id != 0 || entry.length != 1 + ((operation == 0 || operation == 8) ? bytes : 0))
            return fail(ops, Error::Completion);
        ++used;
        uint8_t status = *reinterpret_cast<volatile uint8_t *>(queue + StatusAt);
        if (status) return fail(ops, Error::Device);
        if (operation == 0) ++reads;
        if (operation == 1) ++writes;
        if (operation == 4) ++flushes;
        return true;
    }
    template <class Ops> bool start(Ops &ops, uint64_t expectedBytes) {
        if (owns || ready || poisoned || !expectedBytes || expectedBytes % 4096 ||
            !queue || !transfer || !queuePhysical || !transferPhysical ||
            (queuePhysical & 4095) || (transferPhysical & 4095) ||
            queuePhysical > UINT64_MAX - 4096 || transferPhysical > UINT64_MAX - TransferBytes) {
            error = Error::Bounds;return false;
        }
        if (ops.read(0) != 0x74726976 || ops.read(4) != 2 || ops.read(8) != 2) {
            error = Error::Identity;poisoned = true;return false;
        }
        owns = true;
        if (!reset(ops)) return false;
        ops.write(0x70, 1);ops.write(0x70, 3);
        ops.write(0x14, 0);uint32_t low = ops.read(0x10);
        ops.write(0x14, 1);uint32_t high = ops.read(0x10);
        if ((low & (1U << 5)) || !(low & (1U << 9)) || !(high & 1U)) return fail(ops, Error::Features);
        ops.write(0x24, 0);ops.write(0x20, 1U << 9);
        ops.write(0x24, 1);ops.write(0x20, 1);
        ops.write(0x70, 11);
        if (!(ops.read(0x70) & 8)) return fail(ops, Error::Features);
        ops.write(0x30, 0);
        if (ops.read(0x44) || ops.read(0x34) < QueueSize) return fail(ops, Error::Queue);
        memset(queue, 0, 4096);available = used = 0;
        *reinterpret_cast<uint16_t *>(queue + Available) = 1; // Poll; no used-buffer interrupts.
        ops.barrier();ops.write(0x38, QueueSize);
        address(ops, 0x80, queuePhysical);address(ops, 0x90, queuePhysical + Available);address(ops, 0xa0, queuePhysical + Used);
        ops.write(0x44, 1);
        bool stable = false;
        for (unsigned index = 0; index < 8; ++index) {
            uint32_t generation = ops.read(0xfc);
            uint64_t capacity = ops.read(0x100);capacity |= uint64_t(ops.read(0x104)) << 32;
            if (generation == ops.read(0xfc)) { sectors = capacity;stable = true;break; }
        }
        if (!stable || sectors != expectedBytes / 512) return fail(ops, Error::Capacity);
        ops.write(0x70, 15);ready = (ops.read(0x70) & 15) == 15;
        if (!ready) return fail(ops, Error::Features);
        if (!request(ops, 8, 0, 20)) return false;
        if (memcmp(transfer, Identifier, sizeof(Identifier))) return fail(ops, Error::Identity);
        return true;
    }
    template <class Ops> bool sync(Ops &ops) { return request(ops, 4, 0, 0); }
    template <class Ops> bool blocks(Ops &ops, bool write, uint64_t block, uint32_t count, void *data) {
        uint64_t capacity = sectors / 8;
        if (!ready || poisoned || !data || !count || block >= capacity || count > capacity - block) {
            error = Error::Bounds;return false;
        }
        auto *cursor = static_cast<uint8_t *>(data);
        while (count) {
            uint32_t run = count < TransferBytes / 4096 ? count : TransferBytes / 4096;
            uint32_t bytes = run * 4096;
            if (write) memcpy(transfer, cursor, bytes);
            if (!request(ops, write ? 1 : 0, block * 8, bytes)) return false;
            // A page is durable before the overlay can publish its presence bit.
            if (write) { if (!sync(ops)) return false; }
            else memcpy(cursor, transfer, bytes);
            cursor += bytes;block += run;count -= run;
        }
        return true;
    }
};
} // namespace dodge_store
