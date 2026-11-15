// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeOwnerBootPolicy.h"
#include <assert.h>
#include <initializer_list>
#include <stdio.h>

int main() {
    const uint8_t anchor[32] = {1}, identity[8] = {2}, zero[8] = {};
    const uint8_t chip[] = {0x15, 0x80, 0, 0};
    const char compatible[] = "D22AP\0iPhone10,3\0AppleARM\0oneplus,dodge\0qcom,sm8750";
    DodgeOwnerBootInputs good{1, 1, 1, {"iPhone10,3", 11}, {"D22", 4}, {compatible, sizeof(compatible)},
        {"arm-io", 7}, {chip, 4}, {"software-development", 21}, {anchor, 32}, {identity, 8}};
    assert(dodge_owner_boot_allowed(good, anchor, identity));
    unsigned cases = 1;
    for (unsigned field = 0; field < 3; ++field) for (unsigned value : {0U, 2U, ~0U}) {
        auto bad = good;
        if (field == 0) bad.system = value;
        if (field == 1) bad.development = value;
        if (field == 2) bad.ufs = value;
        assert(!dodge_owner_boot_allowed(bad, anchor, identity));++cases;
    }
    DodgeOwnerProperty *properties[] = {&good.model, &good.target, &good.compatible, &good.bus,
        &good.chip, &good.scope, &good.anchor, &good.identity};
    for (auto *property : properties) {
        const auto saved = *property;
        *property = {};assert(!dodge_owner_boot_allowed(good, anchor, identity));++cases;
        *property = saved;--property->bytes;
        assert(!dodge_owner_boot_allowed(good, anchor, identity));++cases;
        *property = saved;
    }
    const char foreign[] = "iPhone10,3\0oneplus,dodge\0qcom,sm8750\0qemu-virt";
    good.compatible = {foreign, sizeof(foreign)};
    assert(!dodge_owner_boot_allowed(good, anchor, identity));++cases;
    const char malformed[] = "iPhone10,3\0oneplus,dodge\0qcom,sm8750\0";
    good.compatible = {malformed, sizeof(malformed)};
    assert(!dodge_owner_boot_allowed(good, anchor, identity));++cases;
    good.compatible = {compatible, sizeof(compatible)};
    assert(!dodge_owner_boot_allowed(good, anchor, zero));++cases;
    uint8_t wrongAnchor[32] = {1, 3};
    assert(!dodge_owner_boot_allowed(good, wrongAnchor, identity));++cases;
    uint8_t wrongIdentity[8] = {2, 3};
    assert(!dodge_owner_boot_allowed(good, anchor, wrongIdentity));++cases;
    printf("PASS: %u owner native boot policy cases\n", cases);
}
