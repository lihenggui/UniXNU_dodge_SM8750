// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "NativeKeyStoreEvents.cpp"

extern "C" const OSMetaClass *dodge_keystore_driver_meta() { return AppleKeyStore::metaClass; }
extern "C" const OSMetaClass *dodge_keystore_client_meta() { return AppleKeyStoreUserClient::metaClass; }
extern "C" const unsigned dodge_keystore_layout[] = {
    sizeof(IOService), sizeof(IOUserClient), sizeof(AppleKeyStore), sizeof(AppleKeyStoreUserClient),
    sizeof(IOExternalMethodArguments),
    __builtin_offsetof(IOExternalMethodArguments, scalarInput),
    __builtin_offsetof(IOExternalMethodArguments, scalarInputCount),
    __builtin_offsetof(IOExternalMethodArguments, scalarOutput),
    __builtin_offsetof(IOExternalMethodArguments, scalarOutputCount),
    __builtin_offsetof(IOExternalMethodArguments, structureInput),
    __builtin_offsetof(IOExternalMethodArguments, structureInputSize),
    __builtin_offsetof(IOExternalMethodArguments, structureOutput),
    __builtin_offsetof(IOExternalMethodArguments, structureOutputSize)
};
