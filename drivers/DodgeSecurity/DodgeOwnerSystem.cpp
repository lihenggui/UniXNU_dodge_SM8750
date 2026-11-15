// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeOwnerSystem.h"
#include "DodgeOwnerBootPolicy.h"
#include "DodgeOwnerIdentity.h"
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>

namespace {
DodgeOwnerProperty property(IORegistryEntry *entry, const char *name) {
    auto *value = entry ? OSDynamicCast(OSData, entry->getProperty(name)) : nullptr;
    return value ? DodgeOwnerProperty{value->getBytesNoCopy(), value->getLength()} : DodgeOwnerProperty{};
}
unsigned option(const char *name) {
    unsigned value = 0;
    return PE_parse_boot_argn(name, &value, sizeof(value)) ? value : 0;
}
}

extern "C" bool dodge_owner_system_allowed() {
    IORegistryEntry *root = IORegistryEntry::fromPath("/", gIODTPlane);
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    IORegistryEntry *bus = IORegistryEntry::fromPath("/arm-io", gIODTPlane);
    const DodgeOwnerBootInputs inputs{option("dodge-owner-system"), option("dodge-owner-development"), option("native-ufs-root"),
        property(root, "model"), property(root, "target-type"), property(root, "compatible"), property(bus, "device_type"),
        property(chosen, "chip-id"), property(chosen, "dodge-owner-security-scope"),
        property(chosen, "dodge-owner-root-anchor-sha256"), property(chosen, "unique-chip-id")};
    const bool valid = dodge_owner_boot_allowed(inputs, dodgeOwnerAnchorSHA256, dodgeOwnerDevelopmentIdentity);
    if (bus) bus->release();
    if (chosen) chosen->release();
    if (root) root->release();
    return valid;
}

extern "C" size_t dodge_owner_system_identity(uint8_t *out, size_t capacity) {
    if (!out || capacity < sizeof(dodgeOwnerDevelopmentIdentity) || !dodge_owner_system_allowed()) return 0;
    memcpy(out, dodgeOwnerDevelopmentIdentity, sizeof(dodgeOwnerDevelopmentIdentity));
    return sizeof(dodgeOwnerDevelopmentIdentity);
}
