// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "DodgeWifiFirmware.h"

static unsigned released, cases;
static void release(void *context, void *data, size_t bytes) {
    assert(context == &released);
    for (size_t i = 0; i < bytes; ++i) assert(((uint8_t *)data)[i] == 0);
    ++released;free(data);
}
int main(void) {
    PwFw firmware = {0};firmware.io.context = &released;firmware.io.free = release;
    assert(dodge_wifi_firmware_release(NULL) == PwFwArgument);++cases;
    assert(dodge_wifi_firmware_release(&firmware) == PwFwOk && !released);++cases;
    firmware.file_count = 2;
    for (unsigned i = 0; i < 2; ++i) {
        firmware.files[i].data = malloc(32);assert(firmware.files[i].data);
        memset(firmware.files[i].data, 0xa5, 32);firmware.files[i].size = firmware.files[i].allocated = 32;
    }
    firmware.io.free = NULL;assert(dodge_wifi_firmware_release(&firmware) == PwFwArgument && !released);++cases;
    firmware.io.free = release;
    uint8_t *second = firmware.files[1].data;firmware.files[1].data = firmware.files[0].data;
    assert(dodge_wifi_firmware_release(&firmware) == PwFwArgument && !released);++cases;firmware.files[1].data = second;
    firmware.files[1].size = 33;assert(dodge_wifi_firmware_release(&firmware) == PwFwArgument && !released);++cases;
    firmware.files[1].size = 32;
    firmware.files[1].allocated = PW_FW_MAX_BYTES + 2;assert(dodge_wifi_firmware_release(&firmware) == PwFwArgument && !released);++cases;
    firmware.files[1].allocated = 32;
    firmware.file_count = PW_FW_SLOTS + 1;assert(dodge_wifi_firmware_release(&firmware) == PwFwArgument && !released);++cases;
    firmware.file_count = 2;
    assert(firmware.files[0].data[0] == 0xa5 && firmware.files[1].data[0] == 0xa5);
    assert(dodge_wifi_firmware_release(&firmware) == PwFwOk && released == 2 && !firmware.file_count && firmware.cached == UINT64_MAX);++cases;
    for (unsigned i = 0; i < 2; ++i) assert(!firmware.files[i].data && !firmware.files[i].allocated);
    assert(dodge_wifi_firmware_release(&firmware) == PwFwOk && released == 2);++cases;
    printf("PASS: %u firmware cache ownership, clearing and teardown cases\n", cases);
}
