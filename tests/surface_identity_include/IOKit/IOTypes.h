// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>
using IOReturn=int32_t;
enum : IOReturn {kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotPermitted=-2,
    kIOReturnNoMemory=-3,kIOReturnNotReady=-4};
