// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeWifiFirmware.h"
#include "WifiUtil.h"

int dodge_wifi_firmware_release(PwFw *firmware) {
    if (!firmware || firmware->file_count > PW_FW_SLOTS || (firmware->file_count && !firmware->io.free)) return PwFwArgument;
    // Validate all entries before releasing any of them. A malformed entry or
    // duplicate pointer cannot turn a failed teardown into a partial free.
    for (unsigned i = 0; i < firmware->file_count; ++i) {
        const PwFwFile *file = &firmware->files[i];
        if (!file->data || !file->allocated || file->size > file->allocated || file->allocated > PW_FW_MAX_BYTES + 1) return PwFwArgument;
        for (unsigned j = 0; j < i; ++j) if (file->data == firmware->files[j].data) return PwFwArgument;
    }
    for (unsigned i = 0; i < firmware->file_count; ++i) {
        PwFwFile *file = &firmware->files[i];
        // Cached join configuration can contain credentials. Make clearing
        // observable to the free callback and independent of dead-store rules.
        volatile uint8_t *bytes = file->data;
        for (uint32_t offset = 0; offset < file->allocated; ++offset) bytes[offset] = 0;
        firmware->io.free(firmware->io.context, file->data, file->allocated);
        pw_zero(file, sizeof *file);
    }
    firmware->file_count = 0;firmware->cached = UINT64_MAX;
    return PwFwOk;
}
