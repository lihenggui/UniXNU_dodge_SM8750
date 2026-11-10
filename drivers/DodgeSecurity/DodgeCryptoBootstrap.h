// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <mach/kmod.h>

#ifdef __cplusplus
extern "C" {
#endif
struct DodgeCryptoStatus {
    unsigned phase, attempts;
    kern_return_t last;
    unsigned providerOwned;
};
int dodge_crypto_is_original(kmod_info_t *);
kern_return_t dodge_crypto_start_once(kmod_info_t *, void *);
kern_return_t dodge_crypto_bootstrap(void);
void dodge_crypto_status(struct DodgeCryptoStatus *);

// Implemented in the isolated, compiled prng_random.c overlay; no guessed
// offsets or writes to the private PRNG state are used here.
int dodge_crypto_prng_ready(void);
int dodge_crypto_prng_matches(const void *);
#ifdef __cplusplus
}
#endif
