// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeRootPolicyFormat.h"
#include <assert.h>
#include <initializer_list>
#include <stdio.h>
#include <string.h>

static void put64(uint8_t *out, uint64_t value) { for (unsigned i = 0; i < 8; ++i) out[i] = uint8_t(value >> (8 * i)); }
int main() {
    uint8_t header[4096] = {};memcpy(header, "DGROOTP1", 8);put64(header + 8, UINT64_C(0x200000001));put64(header + 16, 16384);
    put64(header + 24, 4096);put64(header + 32, 5000);put64(header + 40, 8192);
    put64(header + 56, 12288);put64(header + 64, 1000);put64(header + 72, 4096);
    DodgeRootPolicyHeader parsed{};assert(dodge_root_policy_header(header, sizeof(header), 16384, &parsed));unsigned cases = 1;
    for (size_t size = 0; size < 4096; ++size) { assert(!dodge_root_policy_header(header, size, 16384, &parsed));++cases; }
    for (unsigned offset : {0U, 8U, 12U, 16U, 24U, 48U, 56U, 80U}) {
        header[offset] ^= 1;assert(!dodge_root_policy_header(header, sizeof(header), 16384, &parsed));++cases;header[offset] ^= 1;
    }
    uint8_t bad[4096];
    for (uint64_t value : {UINT64_C(0), UINT64_C(4096), UINT64_MAX}) {
        memcpy(bad, header, sizeof(bad));put64(bad + 16, value);
        assert(!dodge_root_policy_header(bad, sizeof(bad), value, &parsed));++cases;
    }
    memcpy(bad, header, sizeof(bad));put64(bad + 56, 8192);
    assert(!dodge_root_policy_header(bad, sizeof(bad), 16384, &parsed));++cases; // overlapping envelopes
    memcpy(bad, header, sizeof(bad));put64(bad + 64, UINT64_MAX);
    assert(!dodge_root_policy_header(bad, sizeof(bad), 16384, &parsed));++cases;
    memcpy(bad, header, sizeof(bad));put64(bad + 72, 8192);
    assert(!dodge_root_policy_header(bad, sizeof(bad), 16384, &parsed));++cases;
    uint64_t location = 0;
    assert(dodge_root_policy_location(100, 0x104000, 0x80000, &location) && location == 0x100000);++cases;
    assert(!dodge_root_policy_location(UINT32_MAX, 0x104000, 0x80000, &location));++cases;
    assert(!dodge_root_policy_location(0, 0x104000, UINT64_MAX, &location));++cases;
    assert(!dodge_root_policy_location(0, 0x100000, 0x100000, &location));++cases;
    assert(!dodge_root_policy_location(0, 0x101000, 0x80000, &location));++cases;
    assert(!dodge_root_policy_location(0, 0x6200000, 0x80000, &location));++cases;
    printf("PASS: %u external root-policy bounds/truncation/overlap cases\n", cases);
}
