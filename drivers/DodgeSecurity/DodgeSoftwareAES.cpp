// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "NativeAES.cpp"

static_assert(sizeof(NativeAES) == 0x120, "iPhone AES instance size changed");
extern "C" const OSMetaClass *dodge_aes_driver_meta() { return NativeAES::metaClass; }
extern "C" IOService *dodge_aes_allocate() { return new NativeAES; }
