// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>

struct DodgeRootPolicyRecord { uint64_t offset, bytes, imageBytes; };
struct DodgeRootPolicyHeader { uint64_t bytes; DodgeRootPolicyRecord records[2]; };
inline uint64_t dodge_root_policy_le64(const uint8_t *value) {
    uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) result |= uint64_t(value[i]) << (8 * i);
    return result;
}
inline bool dodge_root_policy_location(uint64_t firstLba, uint64_t imageBytes, uint64_t volumeEnd, uint64_t *offset) {
    if (!offset || !imageBytes || (imageBytes & 4095) || firstLba > UINT32_MAX ||
        imageBytes / 4096 > UINT32_MAX - firstLba || volumeEnd > UINT64_MAX - 0xfffff) return false;
    const uint64_t start = (volumeEnd + 0xfffff) & ~UINT64_C(0xfffff);
    if (start >= imageBytes || imageBytes - start < 8192 || imageBytes - start > (96U << 20)) return false;
    *offset = start;return true;
}
inline bool dodge_root_policy_header(const void *data, size_t bytes, uint64_t suffixBytes, DodgeRootPolicyHeader *out) {
    if (!data || bytes < 4096 || !out) return false;
    const auto *header = static_cast<const uint8_t *>(data);
    const char magic[] = "DGROOTP1";
    for (unsigned i = 0; i < 8; ++i) if (header[i] != uint8_t(magic[i])) return false;
    if (dodge_root_policy_le64(header + 8) != UINT64_C(0x200000001)) return false; // version 1, two policies
    DodgeRootPolicyHeader parsed{};parsed.bytes = dodge_root_policy_le64(header + 16);
    if (parsed.bytes != suffixBytes || parsed.bytes < 8192 || parsed.bytes > (96U << 20) || (parsed.bytes & 4095)) return false;
    uint64_t previousEnd = 4096;
    for (unsigned index = 0; index < 2; ++index) {
        const auto *record = header + 24 + index * 32;
        auto &item = parsed.records[index];
        item = {dodge_root_policy_le64(record), dodge_root_policy_le64(record + 8), dodge_root_policy_le64(record + 16)};
        if (dodge_root_policy_le64(record + 24) || (item.offset & 4095) || item.offset < previousEnd || item.bytes < 544 ||
            item.bytes > (64U << 20) || item.offset >= parsed.bytes || item.bytes > parsed.bytes - item.offset ||
            !item.imageBytes || (item.imageBytes & 4095)) return false;
        previousEnd = item.offset + item.bytes;
    }
    if (parsed.records[0].imageBytes == parsed.records[1].imageBytes) return false;
    *out = parsed;return true;
}
