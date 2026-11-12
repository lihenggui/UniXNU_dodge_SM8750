// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <cassert>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include "DodgeQemuStoreTransport.h"

using namespace dodge_store;
struct Device {
    alignas(4096) std::array<uint8_t, 4096> queue{};
    alignas(4096) std::array<uint8_t, TransferBytes> transfer{};
    std::vector<uint8_t> disk = std::vector<uint8_t>(1 << 20);
    uint32_t low = 1U << 9, high = 1, status = 15, selector = 0, queueReady = 0, queueMaximum = 8;
    uint64_t clock = 0, capacity = 2048, submittedReads = 0, submittedWrites = 0, submittedFlushes = 0;
    uint16_t used = 0;
    bool wrongMagic = false, wrongId = false, unstableCapacity = false, refuseFeatures = false;
    bool stall = false, resetStuck = false, badCompletionId = false, badLength = false, badIndex = false, deviceError = false;
    bool failFlush = false;
    uint32_t read(uint32_t at) {
        switch (at) {
        case 0: return wrongMagic ? 0 : 0x74726976;
        case 4: return 2;
        case 8: return 2;
        case 0x10: return selector ? high : low;
        case 0x34: return queueMaximum;
        case 0x44: return queueReady;
        case 0x70: return status;
        case 0xfc: return unstableCapacity ? uint32_t(++clock) : 0;
        case 0x100: return uint32_t(capacity);
        case 0x104: return uint32_t(capacity >> 32);
        default: return 0;
        }
    }
    void write(uint32_t at, uint32_t value) {
        if (at == 0x14) selector = value;
        if (at == 0x44) queueReady = value;
        if (at == 0x70) {
            if (!value && resetStuck) return;
            status = refuseFeatures && value == 11 ? 3 : value;
            if (!value) queueReady = 0;
        }
        if (at == 0x50 && !stall) complete();
    }
    void barrier() {}
    uint64_t deadline() { return clock + 20; }
    bool expired(uint64_t limit) { return clock >= limit; }
    void pause() { ++clock; }
    void complete() {
        assert(status == 15 && queueReady == 1);
        auto *descriptors = reinterpret_cast<Descriptor *>(queue.data());
        auto request = *reinterpret_cast<Request *>(queue.data() + RequestAt);
        assert(descriptors[0].address == UINT64_C(0x100000000) + RequestAt && descriptors[0].length == 16 &&
            descriptors[0].flags == 1 && request.reserved == 0);
        assert(descriptors[2].address == UINT64_C(0x100000000) + StatusAt && descriptors[2].length == 1 && descriptors[2].flags == 2);
        uint32_t written = 1;
        if (request.operation == 4) {
            assert(descriptors[0].next == 2 && request.sector == 0);++submittedFlushes;
        } else {
            assert(descriptors[0].next == 1 && descriptors[1].next == 2 && descriptors[1].address == UINT64_C(0x100010000));
            uint32_t bytes = descriptors[1].length;
            if (request.operation == 8) {
                assert(bytes == 20 && request.sector == 0 && descriptors[1].flags == 3);
                memcpy(transfer.data(), Identifier, 20);
                if (wrongId) transfer[0] ^= 1;
                written += 20;
            } else {
                assert((request.operation == 0 || request.operation == 1) && bytes && !(bytes % 512));
                assert(request.sector < capacity && bytes / 512 <= capacity - request.sector);
                if (request.operation == 0) {
                    assert(descriptors[1].flags == 3);memcpy(transfer.data(), disk.data() + request.sector * 512, bytes);
                    written += bytes;++submittedReads;
                } else {
                    assert(descriptors[1].flags == 1);memcpy(disk.data() + request.sector * 512, transfer.data(), bytes);++submittedWrites;
                }
            }
        }
        queue[StatusAt] = deviceError || (failFlush && request.operation == 4) ? 1 : 0;
        Completion completion{badCompletionId ? 1U : 0U, badLength ? written + 1 : written};
        memcpy(queue.data() + Used + 4 + (used % QueueSize) * sizeof(completion), &completion, sizeof(completion));
        used = uint16_t(used + (badIndex ? 2 : 1));
        *reinterpret_cast<uint16_t *>(queue.data() + Used + 2) = used;
    }
    Transport transport() {
        Transport result{};result.queue = queue.data();result.transfer = transfer.data();
        result.queuePhysical = UINT64_C(0x100000000);result.transferPhysical = UINT64_C(0x100010000);return result;
    }
};

int main() {
    unsigned cases = 0;
    {
        Device device;auto io = device.transport();assert(io.start(device, device.disk.size()));
        std::vector<uint8_t> data(33 * 4096), back(data.size());
        for (size_t i = 0; i < data.size(); ++i) data[i] = uint8_t(i * 17);
        assert(io.blocks(device, true, 5, 33, data.data()));
        assert(io.writes == io.flushes && io.writes == 3 && device.submittedWrites == device.submittedFlushes);
        assert(io.blocks(device, false, 5, 33, back.data()) && back == data && io.reads == 3);
        auto writes = device.submittedWrites;
        assert(!io.blocks(device, true, 256, 1, data.data()));
        assert(!io.blocks(device, true, 255, 2, data.data()));
        assert(!io.blocks(device, true, UINT64_MAX, 1, data.data()));
        assert(!io.blocks(device, true, 0, 0, data.data()));
        assert(!io.blocks(device, true, 0, 1, nullptr));
        assert(device.submittedWrites == writes);cases += 6;
    }
    for (unsigned failure = 0; failure < 9; ++failure) {
        Device device;auto io = device.transport();
        if (failure == 0) device.wrongMagic = true;
        if (failure == 1) device.low |= 1U << 5;
        if (failure == 2) device.low = 0;
        if (failure == 3) device.high = 0;
        if (failure == 4) device.wrongId = true;
        if (failure == 5) device.capacity += 8;
        if (failure == 6) device.unstableCapacity = true;
        if (failure == 7) device.refuseFeatures = true;
        if (failure == 8) device.queueMaximum = 2;
        assert(!io.start(device, device.disk.size()) && device.submittedWrites == 0 && device.submittedFlushes == 0);
        ++cases;
    }
    for (unsigned failure = 0; failure < 5; ++failure) {
        Device device;auto io = device.transport();assert(io.start(device, device.disk.size()));
        if (failure == 0) device.stall = true;
        if (failure == 1) device.badCompletionId = true;
        if (failure == 2) device.badLength = true;
        if (failure == 3) device.badIndex = true;
        if (failure == 4) device.deviceError = true;
        std::array<uint8_t, 4096> data{};data.fill(0x53);
        assert(!io.blocks(device, false, 0, 1, data.data()) && io.poisoned && !io.ready && device.status == 0);
        for (auto value : data) assert(value == 0x53);
        assert(!io.blocks(device, true, 0, 1, data.data()) && !device.submittedWrites);++cases;
    }
    {
        Device device;auto io = device.transport();assert(io.start(device, device.disk.size()));
        device.stall = device.resetStuck = true;
        std::array<uint8_t, 4096> data{};
        assert(!io.blocks(device, false, 0, 1, data.data()) && io.error == Error::Reset && io.poisoned);++cases;
    }
    {
        Device device;auto io = device.transport();assert(io.start(device, device.disk.size()));
        io.available = io.used = device.used = 65535;
        std::array<uint8_t, 4096> data{};data.fill(0x71);
        assert(io.blocks(device, true, 1, 1, data.data()) && io.available == 1 && io.used == 1);
        assert(device.disk[4096] == 0x71 && io.flushes == 1);++cases;
    }
    {
        Device device;auto io = device.transport();assert(io.start(device, device.disk.size()));
        device.failFlush = true;std::array<uint8_t, 4096> data{};
        assert(!io.blocks(device, true, 0, 1, data.data()) && io.poisoned);
        assert(io.writes == 1 && io.flushes == 0 && device.submittedFlushes == 1);
        assert(!io.blocks(device, true, 1, 1, data.data()) && io.writes == 1);++cases;
    }
    assert(cases == 23);
}
