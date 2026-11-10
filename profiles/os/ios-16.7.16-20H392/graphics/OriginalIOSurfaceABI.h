// SPDX-License-Identifier: BSD-2-Clause-Patent
// Borrowed getters from exact iPhone10,3 / 20H392 IOSurface 336.60.1.
#pragma once
#include <stdint.h>
class OSObject;
// Region is an IOSurfaceMemoryRegion object. It is not a memory descriptor.
extern "C" OSObject *native_iphone_surface_region(const OSObject *);
extern "C" uint32_t native_iphone_surface_width(const OSObject *);
extern "C" uint32_t native_iphone_surface_height(const OSObject *);
extern "C" uint32_t native_iphone_surface_stride(const OSObject *);
extern "C" uint32_t native_iphone_surface_offset(const OSObject *);
extern "C" uint32_t native_iphone_surface_format(const OSObject *);
extern "C" uint32_t native_iphone_surface_allocation(const OSObject *);
extern "C" uint32_t native_iphone_surface_planes(const OSObject *);
extern "C" uint16_t native_iphone_surface_bytes_per_element(const OSObject *);
extern "C" uint8_t native_iphone_surface_element_width(const OSObject *);
extern "C" uint8_t native_iphone_surface_element_height(const OSObject *);
extern "C" uint32_t native_iphone_surface_tile_format(const OSObject *);
extern "C" uint8_t native_iphone_surface_tile_mode(const OSObject *);
