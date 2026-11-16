// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "WifiFirmware.h"
#ifdef __cplusplus
extern "C" {
#endif
// Only after the transport/firmware consumers have stopped and released every
// borrowed pointer. Serialized with pw_fw_get. Refusal preserves ownership.
int dodge_wifi_firmware_release(PwFw *);
#ifdef __cplusplus
}
#endif
