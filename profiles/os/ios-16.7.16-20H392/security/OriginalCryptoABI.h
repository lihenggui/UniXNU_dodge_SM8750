// SPDX-License-Identifier: BSD-2-Clause-Patent
// Measured iPhone10,3 / 20H392 corecrypto owner; ordinary arm64 only.
#pragma once
#include <mach/kmod.h>
#ifdef __cplusplus
extern "C" {
#endif
extern kmod_info_t dodge_original_crypto_kmod;
extern const unsigned char dodge_original_crypto_header[], dodge_original_crypto_functions[], dodge_original_crypto_prng_context[];
extern kmod_start_func_t dodge_original_crypto_entry, dodge_original_crypto_real_entry;
extern kmod_start_func_t *const dodge_original_crypto_entry_slot;
#ifdef __cplusplus
}
#endif
static const char DodgeOriginalCryptoName[]="com.apple.kec.corecrypto";
static const char DodgeOriginalCryptoRecordVersion[]="1.0.0d1";
static const char DodgeOriginalCryptoBundleVersion[]="12.0";
static const vm_size_t DodgeOriginalCryptoModuleBytes=788012;
