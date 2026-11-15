// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "VerifiedBlockPolicy.h"
struct DodgeRootPolicyIo {
    void *context;
    int (*read4k)(void *, uint64_t, uint32_t, void *);
};
extern "C" int dodge_native_root_policies_load(const DodgeRootPolicyIo *, uint64_t, uint64_t, uint64_t);
extern "C" uint64_t dodge_native_root_policy_count();
extern "C" const NativeVerifiedBlockPolicy *dodge_native_root_policy_table();
