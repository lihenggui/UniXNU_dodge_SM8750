// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <sys/types.h>
#include <sys/random.h>
#include <sys/sysctl.h>
#include <sys/errno.h>

// The existing Darwin 22 implementation hashes the supplied bytes, calls the
// registered original iPhone PRNG reseed callback and clears the temporary seed.
extern int dodge_write_random_original(void *, u_int);
uint64_t dodge_user_entropy_reseeds;
uint64_t dodge_user_entropy_bytes;

int write_random(void *buffer, u_int bytes) {
    if (!bytes) return 0;
    if (!buffer) return EINVAL;
    int result = dodge_write_random_original(buffer, bytes);
    if (!result) {
        __atomic_fetch_add(&dodge_user_entropy_bytes, (uint64_t)bytes, __ATOMIC_RELAXED);
        __atomic_fetch_add(&dodge_user_entropy_reseeds, UINT64_C(1), __ATOMIC_RELEASE);
    }
    return result;
}

static int sysctl_dodge_user_reseed_count SYSCTL_HANDLER_ARGS {
    (void)oidp;(void)arg1;(void)arg2;
    const uint64_t value = __atomic_load_n(&dodge_user_entropy_reseeds, __ATOMIC_ACQUIRE);
    return SYSCTL_OUT(req, &value, sizeof(value));
}
// corecrypto registers the original iPhone PRNG tree during its bootstrap.
// The native linker binds this child-list declaration to that measured tree.
// A second node named "prng" hides one tree from sysctl name lookup.
SYSCTL_DECL(_kern_prng);
SYSCTL_PROC(_kern_prng, OID_AUTO, user_reseed_count, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_dodge_user_reseed_count, "QU", "Completed nonempty user entropy reseeds");
