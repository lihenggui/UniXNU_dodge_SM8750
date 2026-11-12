// SPDX-License-Identifier: BSD-2-Clause-Patent
// Use the pinned transport with the measured iPhone storage base.
// Its class constructor runs only after IOStorageFamily has loaded.
#include "NativeVirtioBlock.cpp"
static_assert(sizeof(IOBlockStorageDevice) == 144, "iPhone storage base size");
extern "C" const unsigned dodge_virtio_driver_bytes = sizeof(NativeVirtioBlock);
extern "C" const OSMetaClass *dodge_virtio_driver_meta() { return &NativeVirtioBlock::gMetaClass; }
extern "C" IOService *dodge_virtio_allocate() { return new NativeVirtioBlock; }
