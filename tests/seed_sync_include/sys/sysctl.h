// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "../SeedPeers.h"
struct sysctl_req { uintptr_t newptr; uint32_t value; size_t bytes; int result; };
#define SYSCTL_HANDLER_ARGS (void *oidp, void *arg1, int arg2, struct sysctl_req *req)
inline int seed_test_sysctl_out(sysctl_req *request, const void *value, size_t bytes) {
    if (request->result) return request->result;
    request->bytes = bytes;
    if (bytes == 4) memcpy(&request->value, value, bytes);
    return 0;
}
#define SYSCTL_OUT seed_test_sysctl_out
#define OID_AUTO 0
#define CTLFLAG_RD 1
#define CTLFLAG_LOCKED 2
#define CTLTYPE_INT 4
struct SeedTestOid { int index; unsigned flags; };
#define SYSCTL_PROC(parent, id, name, flags, arg1, arg2, handler, format, description) \
    SeedTestOid test_oid_##name = {arg2, flags}
