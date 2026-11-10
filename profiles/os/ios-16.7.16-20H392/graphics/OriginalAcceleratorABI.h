// SPDX-License-Identifier: MIT
// IOAcceleratorES declaration adapted from the pinned AdrenoMetal component.
// The iPhone 20H392 class is independently identified by graphics-abi.json:
// 136 bytes, 168 IOService virtual entries, destructor/metaclass overrides only.
// Original constructors and metadata must be bound and initialized separately.
#pragma once
#include <IOKit/IOService.h>
class IOAcceleratorES : public IOService {
    OSDeclareAbstractStructors(IOAcceleratorES)
};
static_assert(sizeof(IOService) == 136 && sizeof(IOAcceleratorES) == 136,
              "Reviewed iPhone 20H392 accelerator base extent");
static_assert(sizeof(OSMetaClass) == 40, "Reviewed class metadata object extent");
