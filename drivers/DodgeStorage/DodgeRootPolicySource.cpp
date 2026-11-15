// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeRootPolicySource.h"
#include "DodgeRootPolicyFormat.h"
#include "DodgeOwnerIdentity.h"
#include <libkern/crypto/sha2.h>
#include <libkern/libkern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

extern "C" {
volatile unsigned dodge_native_root_policy_phase;
volatile uint64_t dodge_native_root_policy_bytes;
}
namespace {
vm_offset_t storage;
const NativeVerifiedBlockPolicy *table;
int fail() { __atomic_store_n(&dodge_native_root_policy_phase, 3U, __ATOMIC_RELEASE);return 0; }
}
extern "C" uint64_t dodge_native_root_policy_count() {
    return __atomic_load_n(&dodge_native_root_policy_phase, __ATOMIC_ACQUIRE) == 2 ? 2 : 0;
}
extern "C" const NativeVerifiedBlockPolicy *dodge_native_root_policy_table() {
    return dodge_native_root_policy_count() ? table : nullptr;
}
extern "C" int dodge_native_root_policies_load(const DodgeRootPolicyIo *io, uint64_t firstLba, uint64_t imageBytes, uint64_t volumeEnd) {
    if (!io || !io->read4k) return 0;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&dodge_native_root_policy_phase, &expected, 1U, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return 0;
    uint64_t offset = 0;
    if (!dodge_root_policy_location(firstLba, imageBytes, volumeEnd, &offset) ||
        imageBytes - offset != dodgeOwnerRootPolicyBytes) return fail();
    uint8_t header[4096];
    if (!io->read4k(io->context, firstLba + offset / 4096, 1, header)) return fail();
    DodgeRootPolicyHeader parsed{};
    if (!dodge_root_policy_header(header, sizeof(header), imageBytes - offset, &parsed)) return fail();
    for (unsigned i = 0; i < 2; ++i)
        if (parsed.records[i].imageBytes != dodgeOwnerRootImageBytes[i] || parsed.records[i].bytes != dodgeOwnerRootManifestBytes[i]) return fail();
    const vm_size_t allocation = round_page(static_cast<vm_size_t>(parsed.bytes) + PAGE_SIZE);
    if (allocation < parsed.bytes || kmem_alloc(kernel_map, &storage, allocation,
        static_cast<kma_flags_t>(KMA_KOBJECT | KMA_DATA), VM_KERN_MEMORY_SECURITY) != KERN_SUCCESS) return fail();
    // Descriptor page and policy bytes remain pinned, including on failure.
    auto *descriptors = reinterpret_cast<NativeVerifiedBlockPolicy *>(storage);
    auto *container = reinterpret_cast<uint8_t *>(storage + PAGE_SIZE);
    for (uint64_t position = 0; position < parsed.bytes;) {
        const uint32_t blocks = static_cast<uint32_t>((parsed.bytes - position > 131072 ? 131072 : parsed.bytes - position) / 4096);
        if (!blocks || !io->read4k(io->context, firstLba + (offset + position) / 4096, blocks, container + position)) return fail();
        position += uint64_t(blocks) * 4096;
    }
    uint8_t digest[32];SHA256_CTX context;
    SHA256_Init(&context);SHA256_Update(&context, container, parsed.bytes);SHA256_Final(digest, &context);
    // The expected entire container hash is compiled into this kernel. Header
    // checks alone are not a trust decision. Each vr_open still verifies its
    // owner signature and hash-table digest before any root window is published.
    if (memcmp(digest, dodgeOwnerRootPolicySHA256, sizeof(digest))) return fail();
    DodgeRootPolicyHeader stable{};
    if (!dodge_root_policy_header(container, 4096, parsed.bytes, &stable)) return fail();
    for (unsigned i = 0; i < 2; ++i) {
        if (stable.records[i].offset != parsed.records[i].offset || stable.records[i].bytes != parsed.records[i].bytes ||
            stable.records[i].imageBytes != parsed.records[i].imageBytes) return fail();
        descriptors[i] = {container + stable.records[i].offset, stable.records[i].bytes};
    }
    if (vm_map_protect(kernel_map, storage, storage + allocation, VM_PROT_READ, TRUE) != KERN_SUCCESS) return fail();
    table = descriptors;dodge_native_root_policy_bytes = parsed.bytes;
    __atomic_store_n(&dodge_native_root_policy_phase, 2U, __ATOMIC_RELEASE);return 1;
}
