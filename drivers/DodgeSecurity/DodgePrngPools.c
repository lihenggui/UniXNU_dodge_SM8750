// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <sys/sysctl.h>

// This iPhone user program queries pool0, while its original corecrypto exports
// pool_0. Both names must reach the same original counter list. No private PRNG
// state or replacement counters are defined here.
SYSCTL_DECL(_kern_prng);
extern struct sysctl_oid_list dodge_original_prng_pool_children[32];
#define DODGE_PRNG_POOL(number) \
    SYSCTL_OID(_kern_prng, OID_AUTO, pool##number, CTLTYPE_NODE | CTLFLAG_RD | CTLFLAG_LOCKED, \
        &dodge_original_prng_pool_children[number], 0, 0, "N", "Original iPhone PRNG pool observations")
DODGE_PRNG_POOL(0);
DODGE_PRNG_POOL(1);
DODGE_PRNG_POOL(2);
DODGE_PRNG_POOL(3);
DODGE_PRNG_POOL(4);
DODGE_PRNG_POOL(5);
DODGE_PRNG_POOL(6);
DODGE_PRNG_POOL(7);
DODGE_PRNG_POOL(8);
DODGE_PRNG_POOL(9);
DODGE_PRNG_POOL(10);
DODGE_PRNG_POOL(11);
DODGE_PRNG_POOL(12);
DODGE_PRNG_POOL(13);
DODGE_PRNG_POOL(14);
DODGE_PRNG_POOL(15);
DODGE_PRNG_POOL(16);
DODGE_PRNG_POOL(17);
DODGE_PRNG_POOL(18);
DODGE_PRNG_POOL(19);
DODGE_PRNG_POOL(20);
DODGE_PRNG_POOL(21);
DODGE_PRNG_POOL(22);
DODGE_PRNG_POOL(23);
DODGE_PRNG_POOL(24);
DODGE_PRNG_POOL(25);
DODGE_PRNG_POOL(26);
DODGE_PRNG_POOL(27);
DODGE_PRNG_POOL(28);
DODGE_PRNG_POOL(29);
DODGE_PRNG_POOL(30);
DODGE_PRNG_POOL(31);
#undef DODGE_PRNG_POOL
