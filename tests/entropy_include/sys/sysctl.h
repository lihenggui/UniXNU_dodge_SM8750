// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <string.h>
struct sysctl_req { uint64_t value; size_t bytes; int result; };
#define SYSCTL_HANDLER_ARGS (void *oidp, void *arg1, int arg2, struct sysctl_req *req)
inline int entropy_test_out(sysctl_req *req, const void *data, size_t bytes) {
    if (req->result) return req->result;
    req->bytes = bytes;
    if (bytes == sizeof(req->value)) memcpy(&req->value, data, bytes);
    return 0;
}
#define SYSCTL_OUT entropy_test_out
#define OID_AUTO 0
#define CTLFLAG_RD 1
#define CTLFLAG_LOCKED 2
#define CTLTYPE_QUAD 4
#define SYSCTL_NODE(parent, id, name, flags, arg, description)
#define SYSCTL_DECL(name)
struct entropy_test_oid { int (*handler) SYSCTL_HANDLER_ARGS; unsigned flags; const char *format; };
#define SYSCTL_PROC(parent, id, name, flags, arg1, arg2, handler, format, description) \
    entropy_test_oid entropy_test_registration = {handler, flags, format}
