// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <sys/types.h>
#include <sys/proc.h>

enum class DodgeDataMountPhase : unsigned { Cold, Preparing, Mounted, Failed };
struct DodgeDataMountStatus {
    DodgeDataMountPhase phase;
    int last;
    bool syscallEntered, filesystemMounted, resultVerified;
};
// PID 1's ordinary process context, after the separately qualified original
// root boot path, with at least 0x400 bytes of exclusively owned user scratch.
// Never call this from the Data worker, a loader callback or a work-loop gate.
// Default off (dodge-data-mount=1). A mount attempt is never retried implicitly.
extern "C" int dodge_data_mount_for_init(proc_t, user_addr_t, size_t, uint32_t);
// load_init_program adapter. Disabled returns zero; selected failures are
// returned to the caller. Readiness waits are bounded to 1000 attempts/10 ms.
extern "C" int dodge_data_mount_boot(proc_t, user_addr_t, size_t);
extern "C" void dodge_data_mount_status(DodgeDataMountStatus *);
