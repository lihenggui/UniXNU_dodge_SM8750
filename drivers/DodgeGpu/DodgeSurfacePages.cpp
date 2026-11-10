// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfacePages.h"
#include "NativeAdrenoMemory.h"
#include "OriginalIOSurfaceABI.h"
#include "OriginalIOSurfaceMemoryABI.h"
#include <IOKit/IOMemoryDescriptor.h>

static bool empty(const DodgeSurfacePages &p)
{
    return !p.identity.surface && !p.identity.id && !p.backing && !p.memory &&
        !p.bytes && !p.prepared && !p.quarantined;
}
static bool extent(const DodgeSurfaceIdentity &identity,uint64_t bytes)
{
    const uint64_t allocation=native_iphone_surface_allocation(identity.surface);
    return allocation && bytes==((allocation+4095)&~UINT64_C(4095));
}
static IOReturn comparePages(const DodgeSurfacePages &p)
{
    const auto *spans=p.memory->spans();const size_t count=p.memory->spanCount();
    if(!spans || !count || count>p.bytes/4096)return kIOReturnBadArgument;
    uint64_t end=0;
    for(size_t i=0;i<count;++i) {
        const auto &span=spans[i];
        if(span.offset!=end || !span.bytes || ((span.offset|span.bytes|span.physical)&4095) ||
            !span.physical || span.bytes>p.bytes-end || span.physical>UINT64_MAX-span.bytes)
            return kIOReturnBadArgument;
        for(uint64_t offset=0;offset<span.bytes;offset+=4096) {
            IOByteCount run=0;
            const addr64_t physical=p.backing->getPhysicalSegment(end+offset,&run,kIOMemoryMapperNone);
            if(run<4096 || physical!=span.physical+offset)return kIOReturnNotPermitted;
        }
        end+=span.bytes;
    }
    return end==p.bytes?kIOReturnSuccess:kIOReturnBadArgument;
}
extern "C" IOReturn dodge_surface_pages_current(const DodgeSurfacePages *p)
{
    if(!p || !p->identity.surface || !p->identity.id || !p->backing || !p->memory ||
        !p->bytes || !p->prepared)return kIOReturnBadArgument;
    if(p->quarantined || p->memory->quarantined() || !p->memory->deviceReferences())return kIOReturnNotReady;
    // A borrowed value is compared only. It is never dereferenced or retained:
    // the backing argument was independently owned before entering this API.
    if(native_iphone_surface_memory(p->identity.surface)!=p->backing ||
        !extent(p->identity,p->bytes) || p->memory->bytes()!=p->bytes || p->backing->getLength()!=p->bytes)
        return kIOReturnNotReady;
    const IOReturn status=comparePages(*p);if(status)return status;
    // Observe replacement during prepare/page walking as well. These two
    // observations still require producer serialization before publication.
    if(native_iphone_surface_memory(p->identity.surface)!=p->backing ||
        !extent(p->identity,p->bytes) || p->backing->getLength()!=p->bytes)return kIOReturnNotReady;
    return kIOReturnSuccess;
}
extern "C" IOReturn dodge_surface_pages_release(DodgeSurfacePages *p)
{
    if(!p)return kIOReturnBadArgument;
    if(empty(*p))return kIOReturnSuccess;
    if(!p->memory || !p->backing || !p->identity.surface)return kIOReturnBadArgument;
    if(p->quarantined || p->memory->quarantined())return kIOReturnNotReady;
    if(p->memory->deviceReferences()!=1)return kIOReturnBusy;
    if(p->prepared) {
        const IOReturn status=p->backing->complete();
        if(status) {p->quarantined=true;p->memory->quarantine();return status;}
        p->prepared=false;
    }
    const IOReturn status=p->memory->retireAfterQuiescence();
    if(status) {p->quarantined=true;p->memory->quarantine();return status;}
    IOMemoryDescriptor *backing=p->backing;DodgeSurfaceIdentity identity=p->identity;
    *p={};backing->release();dodge_release_surface_identity(&identity);
    return kIOReturnSuccess;
}
extern "C" IOReturn dodge_surface_pages_bind(DodgeSurfaceIdentity *identity,IOMemoryDescriptor *backing,
    NativeAdrenoMemory *memory,DodgeSurfacePages *out)
{
    if(!identity || !identity->surface || !identity->id || !backing || !memory || !out || !empty(*out))
        return kIOReturnBadArgument;
    if(!identity->surface->metaCast("IOSurface") || !backing->metaCast("IOMemoryDescriptor"))return kIOReturnBadArgument;
    if(!memory->imported() || memory->quarantined())return kIOReturnNotReady;
    if(memory->deviceReferences())return kIOReturnBusy;
    const uint64_t bytes=memory->bytes();
    if(!bytes || (bytes&4095) || !extent(*identity,bytes) || backing->getLength()!=bytes)return kIOReturnBadArgument;
    if(native_iphone_surface_memory(identity->surface)!=backing)return kIOReturnNotPermitted;
    const IODirection direction=backing->getDirection();
    if(!(direction&kIODirectionOut) || (!memory->readOnly() && !(direction&kIODirectionIn)))return kIOReturnNotPermitted;
    IOReturn status=memory->holdForDevice();if(status)return status;
    backing->retain();out->identity=*identity;*identity={};out->backing=backing;out->memory=memory;out->bytes=bytes;
    status=backing->prepare();
    if(!status) {out->prepared=true;status=dodge_surface_pages_current(out);}
    if(!status)return kIOReturnSuccess;
    const IOReturn cleanup=dodge_surface_pages_release(out);
    return cleanup?cleanup:status;
}
