// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeCryptoBootstrap.h"
#include "DodgeCryptoOnce.h"
#include "OriginalCryptoABI.h"
#include <libkern/crypto/crypto_internal.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

static struct DodgeCryptoOnce state = { DodgeCryptoCold, KERN_FAILURE, 0 };

static int valid_module(void *context, void *value) {
    (void)context;
    kmod_info_t *module = value;
    return module == &dodge_original_crypto_kmod && module->info_version == KMOD_INFO_VERSION &&
           !memcmp(module->name, DodgeOriginalCryptoName, sizeof(DodgeOriginalCryptoName)) &&
           (!memcmp(module->version, DodgeOriginalCryptoRecordVersion, sizeof(DodgeOriginalCryptoRecordVersion)) ||
            !memcmp(module->version, DodgeOriginalCryptoBundleVersion, sizeof(DodgeOriginalCryptoBundleVersion))) &&
           module->address == (vm_address_t)dodge_original_crypto_header && module->size == DodgeOriginalCryptoModuleBytes &&
           module->start == dodge_original_crypto_entry &&
           dodge_original_crypto_entry_slot == dodge_original_crypto_real_entry;
}
static int provider_empty(void *context) {
    (void)context;
    return !g_crypto_funcs && !dodge_crypto_prng_ready();
}
static int provider_owned(void *context) {
    (void)context;
    return (const void *)g_crypto_funcs == (const void *)dodge_original_crypto_functions &&
           dodge_crypto_prng_matches(dodge_original_crypto_prng_context);
}
static int start_original(void *context, void *module, void *data) {
    (void)context;
    return dodge_original_crypto_entry(module, data);
}
static const struct DodgeCryptoOperations operations = {
    0, KERN_SUCCESS, KERN_FAILURE, KERN_INVALID_ARGUMENT,
    valid_module, provider_empty, provider_owned, start_original
};

int dodge_crypto_is_original(kmod_info_t *module) { return module == &dodge_original_crypto_kmod; }
kern_return_t dodge_crypto_start_once(kmod_info_t *module, void *data) {
    return dodge_crypto_once_call(&state, &operations, module, data);
}
kern_return_t dodge_crypto_bootstrap(void) {
    unsigned mode = 0;
    if (PE_parse_boot_argn("fips_mode", &mode, sizeof(mode)) && mode) return KERN_INVALID_ARGUMENT;
    return dodge_crypto_start_once(&dodge_original_crypto_kmod, 0);
}
void dodge_crypto_status(struct DodgeCryptoStatus *out) {
    if (!out) return;
    out->phase = __atomic_load_n(&state.phase, __ATOMIC_ACQUIRE);
    out->attempts = __atomic_load_n(&state.attempts, __ATOMIC_RELAXED);
    out->last = __atomic_load_n(&state.last, __ATOMIC_RELAXED);
    out->providerOwned = provider_owned(0);
}
