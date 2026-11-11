// SPDX-License-Identifier: MIT
#pragma once
#include "NativeAdrenoABI.h"

// Optional selectors used by the pinned Metal/Turnip frontend. Keep the
// upstream ABI header unchanged. A single FIFO ring has no priority control;
// these optional calls return Unsupported after validating their records.
enum : uint32_t { NativeAdrenoMethodSetPriority=17, NativeAdrenoMethodNote=18,
                  NativeAdrenoMethodSurfaceImport=19 };
enum : uint32_t { NativeAdrenoParamsOwnedCoherent=2, NativeAdrenoParamsMemoryPressure=4,
                  NativeAdrenoParamsSurfaceImport=8 };
struct NativeAdrenoAbiPriority { uint32_t foreground,background; };
enum : uint32_t { NativeAdrenoNoteWords=30, NativeAdrenoNotePass=1, NativeAdrenoNotePipeline=2 };
struct NativeAdrenoAbiNote { uint32_t kind,count,words[NativeAdrenoNoteWords]; };
struct NativeAdrenoAbiSurfaceImport { uint64_t address,bytes;uint32_t id,reserved; };
static_assert(sizeof(NativeAdrenoAbiPriority)==8,"Priority wire record");
static_assert(sizeof(NativeAdrenoAbiNote)==128,"Note wire record");
static_assert(sizeof(NativeAdrenoAbiSurfaceImport)==24,"Surface import wire record");
