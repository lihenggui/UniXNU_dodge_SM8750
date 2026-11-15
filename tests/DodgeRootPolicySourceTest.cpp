// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <array>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "../drivers/DodgeStorage/DodgeRootPolicySource.cpp"

uint8_t dodgeOwnerRootPolicySHA256[32];
void *kernel_map = reinterpret_cast<void *>(1);
static std::array<uint8_t, 262144> input;
static unsigned reads, allocations, protections, failRead = ~0U;
static bool failAllocation, failProtection, changeInitialHeader, changeReadPayload;
static vm_size_t mappedBytes;
static void put64(uint8_t *out, uint64_t value) { for (unsigned i = 0; i < 8; ++i) out[i] = uint8_t(value >> (8 * i)); }
int kmem_alloc(void *map, vm_offset_t *out, vm_size_t bytes, kma_flags_t flags, int tag) {
    assert(map == kernel_map && unsigned(flags) == (KMA_KOBJECT | KMA_DATA) && tag == VM_KERN_MEMORY_SECURITY);
    assert(bytes == input.size() + PAGE_SIZE);++allocations;
    if (failAllocation) return 1;
    void *memory = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);*out = reinterpret_cast<vm_offset_t>(memory);mappedBytes = bytes;return 0;
}
int vm_map_protect(void *map, vm_offset_t first, vm_offset_t last, int protection, int maximum) {
    assert(map == kernel_map && first == storage && last - first == mappedBytes && protection == VM_PROT_READ && maximum == TRUE);
    ++protections;if (failProtection) return 1;
    return mprotect(reinterpret_cast<void *>(first), last - first, PROT_READ);
}
static int read(void *, uint64_t lba, uint32_t blocks, void *out) {
    const unsigned call = reads++;
    assert(blocks && blocks <= 32 && lba >= 356 && lba - 356 + blocks <= input.size() / 4096);
    if (call == failRead) return 0;
    memcpy(out, input.data() + (lba - 356) * 4096, blocks * 4096);
    if (!call && changeInitialHeader) put64(static_cast<uint8_t *>(out) + 24, 8192);
    if (call == 2 && changeReadPayload) static_cast<uint8_t *>(out)[blocks * 4096 - 1] ^= 1;
    return 1;
}
static void reset() {
    if (storage) { assert(!munmap(reinterpret_cast<void *>(storage), mappedBytes));storage = 0; }
    table = nullptr;dodge_native_root_policy_phase = 0;dodge_native_root_policy_bytes = 0;
    reads = allocations = protections = 0;failRead = ~0U;
    failAllocation = failProtection = changeInitialHeader = changeReadPayload = false;
    input.fill(0x5a);memset(input.data(), 0, 4096);memcpy(input.data(), "DGROOTP1", 8);
    put64(input.data() + 8, UINT64_C(0x200000001));put64(input.data() + 16, input.size());
    put64(input.data() + 24, 4096);put64(input.data() + 32, 200000);put64(input.data() + 40, 8192);
    put64(input.data() + 56, 208896);put64(input.data() + 64, 40000);put64(input.data() + 72, 4096);
    SHA256(input.data(), input.size(), dodgeOwnerRootPolicySHA256);
}
int main() {
    const DodgeRootPolicyIo io{nullptr, read};unsigned cases = 0;
    for (unsigned fault = 0; fault < 10; ++fault) {
        reset();
        if (fault == 0) failRead = 0;
        if (fault == 1) input[0] ^= 1;
        if (fault == 2) put64(input.data() + 40, 12288);
        if (fault == 3) failAllocation = true;
        if (fault == 4) failRead = 1;
        if (fault == 5) failRead = 2;
        if (fault == 6) dodgeOwnerRootPolicySHA256[0] ^= 1;
        if (fault == 7) changeInitialHeader = true;
        if (fault == 8) changeReadPayload = true;
        if (fault == 9) failProtection = true;
        assert(!dodge_native_root_policies_load(&io, 100, 0x140000, 0x80000));
        assert(dodge_native_root_policy_phase == 3 && !dodge_native_root_policy_count() && !dodge_native_root_policy_table());
        const auto calls = reads;
        assert(!dodge_native_root_policies_load(&io, 100, 0x140000, 0x80000) && reads == calls);++cases;
    }
    reset();assert(!dodge_native_root_policies_load(&io, 100, 0x141000, 0x80000) && !reads && !allocations);++cases;
    reset();assert(!dodge_native_root_policy_count() && !dodge_native_root_policy_table());
    assert(dodge_native_root_policies_load(&io, 100, 0x140000, 0x80000) && reads == 3 && allocations == 1 && protections == 1);
    const auto *policies = dodge_native_root_policy_table();
    assert(dodge_native_root_policy_count() == 2 && policies && policies[0].manifestBytes == 200000 && policies[1].manifestBytes == 40000);
    assert(!memcmp(policies[0].manifest, input.data() + 4096, 200000));
    assert(!memcmp(policies[1].manifest, input.data() + 208896, 40000));
    input.fill(0);assert(policies[0].manifest[0] == 0x5a); // Retained immutable snapshot, not borrowed transport memory.
    assert(!dodge_native_root_policies_load(&io, 100, 0x140000, 0x80000) && reads == 3);++cases;
    reset();assert(!dodge_native_root_policies_load(nullptr, 100, 0x140000, 0x80000) && !reads);++cases;
    reset();printf("PASS: %u actual root-policy loader, snapshot/protection and failure-latch cases\n", cases);
}
