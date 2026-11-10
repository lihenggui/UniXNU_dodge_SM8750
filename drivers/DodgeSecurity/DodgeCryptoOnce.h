// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

enum DodgeCryptoPhase { DodgeCryptoCold, DodgeCryptoStarting, DodgeCryptoReady, DodgeCryptoFailed };
struct DodgeCryptoOnce {
    unsigned phase;
    int last;
    unsigned attempts;
};
struct DodgeCryptoOperations {
    void *context;
    int success, failure, invalid;
    int (*validModule)(void *, void *);
    int (*providerEmpty)(void *);
    int (*providerOwned)(void *);
    int (*startOriginal)(void *, void *, void *);
};

// The first initialization owns both the crypto table and the kernel PRNG.
// There is no retry, provider replacement or fallback after entering it.
static inline int dodge_crypto_once_call(struct DodgeCryptoOnce *state, const struct DodgeCryptoOperations *ops,
                                        void *module, void *data) {
    if (!ops->validModule(ops->context, module)) return ops->invalid;
    unsigned expected = DodgeCryptoCold;
    if (!__atomic_compare_exchange_n(&state->phase, &expected, DodgeCryptoStarting, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (expected == DodgeCryptoStarting) return ops->failure;
        int result = __atomic_load_n(&state->last, __ATOMIC_RELAXED);
        return expected == DodgeCryptoReady && !ops->providerOwned(ops->context) ? ops->failure : result;
    }
    int result = ops->failure;
    if (ops->providerEmpty(ops->context)) {
        __atomic_fetch_add(&state->attempts, 1, __ATOMIC_RELAXED);
        result = ops->startOriginal(ops->context, module, data);
        if (result == ops->success && !ops->providerOwned(ops->context)) result = ops->failure;
    }
    __atomic_store_n(&state->last, result, __ATOMIC_RELAXED);
    __atomic_store_n(&state->phase, result == ops->success ? DodgeCryptoReady : DodgeCryptoFailed, __ATOMIC_RELEASE);
    return result;
}
