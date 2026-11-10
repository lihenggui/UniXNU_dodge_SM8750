// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceBacking.h"
#include "OriginalIOSurfaceABI.h"
#include <IOKit/IOSubMemoryDescriptor.h>

IOReturn dodge_copy_surface_backing(OSObject *surface,uint32_t width,uint32_t height,
    DodgeSurfaceBacking *result) {
    if(!surface || !result || result->memory)return kIOReturnBadArgument;
    if(!surface->metaCast("IOSurface"))return kIOReturnBadArgument;
    OSObject *region=native_iphone_surface_region(surface);
    if(!region || !region->metaCast("IOSurfaceDeviceMemoryRegion"))return kIOReturnUnsupported;
    // Qualified by the exact original device-region physical-address
    // method: +64 is an IOMemoryMap, whose address method it calls.
    IOMemoryMap *mapping=nullptr;
    __builtin_memcpy(&mapping,reinterpret_cast<const unsigned char *>(region)+64,sizeof(mapping));
    if(!mapping || !mapping->metaCast("IOMemoryMap"))return kIOReturnNotReady;
    mapping->retain();
    IOMemoryDescriptor *parent=mapping->getMemoryDescriptor();
    if(!parent || !parent->metaCast("IOMemoryDescriptor")) {
        mapping->release();return kIOReturnNotReady;
    }
    const DodgeSurfaceGeometry geometry={native_iphone_surface_width(surface),
        native_iphone_surface_height(surface),native_iphone_surface_stride(surface),
        native_iphone_surface_offset(surface),native_iphone_surface_allocation(surface),
        native_iphone_surface_format(surface),native_iphone_surface_planes(surface),
        native_iphone_surface_bytes_per_element(surface),native_iphone_surface_element_width(surface),
        native_iphone_surface_element_height(surface),native_iphone_surface_tile_format(surface),native_iphone_surface_tile_mode(surface)};
    DodgeSurfaceRange range{};
    // The actual Darwin 22 private header field is checked against the
    // original IOMemoryMap::getPhysicalSegment +offset dataflow in the build.
    if(!dodge_surface_range(geometry,width,height,mapping->fOffset,mapping->getLength(),parent->getLength(),&range)) {
        mapping->release();return kIOReturnUnsupported;
    }
    const IODirection direction=parent->getDirection();
    if(!(direction & kIODirectionOut)) {mapping->release();return kIOReturnNotPermitted;}
    IOSubMemoryDescriptor *subrange=IOSubMemoryDescriptor::withSubRange(parent,range.offset,range.length,
        direction|kIOMemoryThreadSafe);
    mapping->release();
    if(!subrange)return kIOReturnNoMemory;
    result->memory=subrange;
    result->width=width;result->height=height;result->stride=geometry.stride;
    return kIOReturnSuccess;
}

void dodge_release_surface_backing(DodgeSurfaceBacking *view) {
    if(!view)return;
    if(view->memory)view->memory->release();
    *view={};
}
