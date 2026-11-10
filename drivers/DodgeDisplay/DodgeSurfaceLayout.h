// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

struct DodgeSurfaceGeometry {
    uint32_t width,height,stride,offset,allocation,format,planes;
    uint32_t bytes_per_element,element_width,element_height,tile_format,tile_mode;
};
struct DodgeSurfaceRange {
    uint64_t offset,length;
};
// IOSurfaceAllocSize includes IOSurfaceOffset. Map offset is relative to
// its parent descriptor. Keep both offsets when producing a GPU-readable
// subrange; no physical or virtual contiguity is assumed here.
inline bool dodge_surface_range(const DodgeSurfaceGeometry &surface,
    uint32_t width,uint32_t height,uint64_t mapOffset,uint64_t mapBytes,
    uint64_t descriptorBytes,DodgeSurfaceRange *result) {
    if(!result || !width || !height || width>16384 || height>16384 ||
       surface.width<width || surface.height<height ||
       surface.format!=0x42475241U || surface.planes || surface.tile_format || surface.tile_mode ||
       surface.bytes_per_element!=4 || surface.element_width!=1 || surface.element_height!=1 ||
       surface.stride<(uint64_t)width*4 || surface.allocation<surface.offset)return false;
    const uint64_t span=(uint64_t)surface.stride*height;
    if(span>(uint64_t)surface.allocation-surface.offset ||
       surface.allocation>mapBytes || mapOffset>descriptorBytes ||
       surface.allocation>descriptorBytes-mapOffset)return false;
    *result={mapOffset+surface.offset,span};
    return true;
}
