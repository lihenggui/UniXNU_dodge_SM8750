// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "RootCommandsBridge.cpp"
#include "NativeStore.extracted.h"
#include <array>
#include <cstdlib>

static unsigned mode, reserveMiB = 1024, submitted, writeCommands;
static uint64_t now;
static std::array<uint8_t, kDmaBytes> device;
static std::array<uint32_t, 256> registers;
static int PE_parse_boot_argn(const char *name, void *value, int bytes) {
    assert(bytes == 4);
    if (!strcmp(name, "sheng-data-persist")) memcpy(value, &mode, 4);
    else if (!strcmp(name, "sheng-log-reserve")) memcpy(value, &reserveMiB, 4);
    else return 0;
    return 1;
}
static uint64_t io(unsigned operation, uint64_t address, uint64_t value, void *bytes) {
    if (operation == 0) return registers.at(address / 4);
    if (operation == 1) {
        if (address == 0x20) { registers[address / 4] &= ~uint32_t(value);return 0; }
        registers.at(address / 4) = uint32_t(value);
        if (address == 0x58) {
            ++submitted;
            auto *command = device.data() + kUcdOffset;
            auto *reply = command + kRspOffset;
            if (command[16] == 0x2a) {
                ++writeCommands;
                assert(mode == 2 && command[1] == 0x20 && command[17] == 8); // Actual FUA WRITE(10).
                const uint64_t lba = loadBe32(command + 18), count = (unsigned(command[23]) << 8) | command[24];
                assert(lba >= gStoreFirst && count && lba - gStoreFirst + count <= gStoreBlocks);
                for (unsigned i = 0; i < count * 4096; ++i) assert(device[kDataOffset + i] == 0x5a);
            } else assert(command[16] == 0x35); // Actual SYNCHRONIZE CACHE(10).
            memset(reply, 0, 512);memcpy(reply, command, 32);reply[0] = 0x21;reply[1] = 0;
            putBe32(reply + 12, 0);*reinterpret_cast<uint32_t *>(device.data() + 8) = 0;
            registers[0x58 / 4] = 0;
        }
    }
    if (operation == 2 || operation == 3) {
        assert(address >= gHost.phys && address - gHost.phys + value <= device.size());
        auto *data = device.data() + address - gHost.phys;
        if (operation == 2) memcpy(data, bytes, value);else memcpy(bytes, data, value);
    }
    if (operation == 4) return now++;
    if (operation == 5) now += value;
    return 0;
}
static void reset() {
    ufs_test_reset(io, 0x8cb5e9000);registers.fill(0);device.fill(0);
    now = 0;submitted = writeCommands = 0;gStoreRegionFirst = gStoreRegionBlocks = 0;
    gStoreGeometry = {true, 100, 1000099, 4096 * 100, 1, 0, 0, 128};
}
int main(int argc, char **argv) {
    assert(argc == 2);mode = unsigned(std::strtoul(argv[1], nullptr, 10));
    unsigned cases = 0;const char *why = nullptr;uint64_t first = 0;
    reset();gStoreGeometry.valid = false;
    assert(!native_ufs_store_open(100, &first, &why) && !submitted);++cases;
    reset();gHost.ready = false;
    assert(!native_ufs_store_open(100, &first, &why) && !submitted);++cases;
    reset();gStoreGeometry.last = UINT64_MAX;
    assert(!native_ufs_store_open(100, &first, &why) && !submitted);++cases;
    reset();gStoreGeometry.last = gStoreGeometry.first - 1;
    assert(!native_ufs_store_open(100, &first, &why) && !submitted);++cases;
    for (uint64_t blocks : {UINT64_C(0), UINT64_MAX, UINT64_C(1000000)}) {
        reset();assert(!native_ufs_store_open(blocks, &first, &why) && !submitted);++cases;
    }
    reset();gStoreGeometry.imageBytes = 1000000ULL * 4096;
    assert(!native_ufs_store_open(100, &first, &why) && !submitted);++cases;
    reset();assert(!native_ufs_store_open(250001, &first, &why) && !submitted);++cases;
    reset();
    const bool mayOpen = mode == 1 || (mode == 2 && !NATIVE_UFS_READ_ONLY);
    assert(bool(native_ufs_store_open(100, &first, &why)) == mayOpen && !submitted);++cases;
    if (mayOpen) {
        assert(first == gStoreGeometry.last + 1 - uint64_t(reserveMiB) * 256 - 100);
        assert(first >= gStoreGeometry.first + (gStoreGeometry.imageBytes + 4095) / 4096 + 1024);
        assert(!native_ufs_store_open(100, nullptr, &why));cases += 3;
    }
    std::array<uint8_t, 8192> data;data.fill(0x5a);
    const bool writable = mode == 2 && !NATIVE_UFS_READ_ONLY;
    assert(bool(native_ufs_store_write(0, 1, data.data())) == writable);++cases;
    assert(bool(native_ufs_store_write(99, 1, data.data())) == writable);++cases;
    const auto before = submitted;
    for (uint64_t relative : {UINT64_C(100), UINT64_MAX}) {
        assert(!native_ufs_store_write(relative, 1, data.data()) && submitted == before);++cases;
    }
    assert(!native_ufs_store_write(99, 2, data.data()) && submitted == before);++cases;
    assert(!native_ufs_store_write(0, 0, data.data()) && submitted == before);++cases;
    assert(!native_ufs_store_write(0, 1, nullptr) && submitted == before);++cases;
    assert(hostWrite4k(1, first, 1, data.data(), true) == kIOReturnBadArgument && submitted == before);++cases;
    assert(hostWrite4k(0, 0, 1, data.data(), true) == kIOReturnBadArgument && submitted == before);++cases;
    assert(bool(native_ufs_store_sync()) == writable);++cases;
    assert(writeCommands == (writable ? 2 : 0));++cases;
    printf("PASS: %u actual native UFS store/window cases (read-only=%u mode=%u)\n", cases, NATIVE_UFS_READ_ONLY, mode);
}
