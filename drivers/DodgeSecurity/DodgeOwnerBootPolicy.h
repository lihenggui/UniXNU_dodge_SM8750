// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>

// Public development identity, never an Apple ECID or a hardware key.
struct DodgeOwnerProperty { const void *data; size_t bytes; };
struct DodgeOwnerBootInputs {
    unsigned system, development, ufs;
    DodgeOwnerProperty model, target, compatible, bus, chip, scope, anchor, identity;
};

inline bool dodge_owner_property_equal(DodgeOwnerProperty property, const void *wanted, size_t bytes) {
    if (!property.data || !wanted || property.bytes != bytes) return false;
    const auto *a = static_cast<const uint8_t *>(property.data);
    const auto *b = static_cast<const uint8_t *>(wanted);
    uint8_t difference = 0;
    for (size_t i = 0; i < bytes; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}

inline bool dodge_owner_compatible(DodgeOwnerProperty property) {
    if (!property.data || !property.bytes || property.bytes > 512) return false;
    const auto *text = static_cast<const char *>(property.data);
    bool board = false, soc = false, phone = false;
    for (size_t at = 0; at < property.bytes;) {
        size_t end = at;
        while (end < property.bytes && text[end]) ++end;
        if (end == property.bytes || end == at) return false;
        const DodgeOwnerProperty item{text + at, end - at + 1};
        board |= dodge_owner_property_equal(item, "oneplus,dodge", sizeof("oneplus,dodge"));
        soc |= dodge_owner_property_equal(item, "qcom,sm8750", sizeof("qcom,sm8750"));
        phone |= dodge_owner_property_equal(item, "iPhone10,3", sizeof("iPhone10,3"));
        if (dodge_owner_property_equal(item, "qemu-virt", sizeof("qemu-virt"))) return false;
        at = end + 1;
    }
    return board && soc && phone;
}

inline bool dodge_owner_boot_allowed(const DodgeOwnerBootInputs &in, const uint8_t anchor[32], const uint8_t identity[8]) {
    static const uint8_t chip[] = {0x15, 0x80, 0, 0};
    uint8_t nonzero = 0;
    for (unsigned i = 0; i < 8; ++i) nonzero |= identity[i];
    return in.system == 1 && in.development == 1 && in.ufs == 1 && nonzero &&
        dodge_owner_property_equal(in.model, "iPhone10,3", sizeof("iPhone10,3")) &&
        dodge_owner_property_equal(in.target, "D22", sizeof("D22")) && dodge_owner_compatible(in.compatible) &&
        dodge_owner_property_equal(in.bus, "arm-io", sizeof("arm-io")) &&
        dodge_owner_property_equal(in.chip, chip, sizeof(chip)) &&
        dodge_owner_property_equal(in.scope, "software-development", sizeof("software-development")) &&
        dodge_owner_property_equal(in.anchor, anchor, 32) && dodge_owner_property_equal(in.identity, identity, 8);
}
