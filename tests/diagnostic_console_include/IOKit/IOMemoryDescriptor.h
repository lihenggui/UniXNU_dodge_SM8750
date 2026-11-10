// SPDX-License-Identifier: MIT
// Software peer for the production console adapter test, not a kernel ABI.
#pragma once
#include <cassert>
#include <cstdint>
struct IOMemoryMap {
    uint64_t physical = 0xfc800000, bytes = 1440 * 3168 * 4;
    uintptr_t address = 0x100000;
    unsigned refs = 1, retains = 0, releases = 0;
    uint64_t getPhysicalAddress() const { return physical; }
    uint64_t getLength() const { return bytes; }
    uintptr_t getVirtualAddress() const { return address; }
    void retain() { assert(refs); ++refs; ++retains; }
    void release() { assert(refs > 1); --refs; ++releases; }
};
