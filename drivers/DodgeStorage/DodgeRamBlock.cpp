// SPDX-License-Identifier: BSD-2-Clause-Patent
// Compile the unchanged pinned RamBlock with the measured iPhone storage ABI.
// Its module constructor is deferred by build_data_source.py; this file does
// not register a personality or start a device.
#include "NativeRamBlock.cpp"
static_assert(sizeof(IOBlockStorageDevice) == 144, "iPhone storage base size");
extern "C" unsigned dodge_ramblock_driver_bytes() { return sizeof(NativeRamBlock); }
extern "C" const OSMetaClass *dodge_ramblock_driver_meta() { return &NativeRamBlock::gMetaClass; }
extern "C" IOService *dodge_ramblock_allocate() { return new NativeRamBlock; }
