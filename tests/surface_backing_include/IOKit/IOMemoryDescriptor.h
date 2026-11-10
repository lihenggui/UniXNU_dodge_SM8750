// SPDX-License-Identifier: BSD-2-Clause-Patent
// Software IOKit peers for ownership/control-flow tests, not an original ABI.
#pragma once
#include <stdint.h>
#include <string.h>
#include <cassert>

using IOReturn=int32_t;
using IODirection=uint32_t;
using IOOptionBits=uint32_t;
enum : IOReturn {
    kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnUnsupported=-2,
    kIOReturnNotReady=-3,kIOReturnNotPermitted=-4,kIOReturnNoMemory=-5
};
enum : uint32_t {kIODirectionIn=1,kIODirectionOut=2,kIODirectionInOut=3,kIOMemoryThreadSafe=0x00100000};
enum class DodgeTestKind : uint32_t {Other,Surface,DeviceRegion,MemoryMap,Descriptor,SubMemory};
class OSObject {
public:
    unsigned references=1;
    DodgeTestKind kind;
    explicit OSObject(DodgeTestKind type):kind(type) {}
    virtual ~OSObject()=default;
    virtual const OSObject *metaCast(const char *name) const {
        const bool descriptor=kind==DodgeTestKind::Descriptor || kind==DodgeTestKind::SubMemory;
        if((kind==DodgeTestKind::Surface && !strcmp(name,"IOSurface")) ||
           (kind==DodgeTestKind::DeviceRegion && !strcmp(name,"IOSurfaceDeviceMemoryRegion")) ||
           (kind==DodgeTestKind::MemoryMap && !strcmp(name,"IOMemoryMap")) ||
           (descriptor && !strcmp(name,"IOMemoryDescriptor")))return this;
        return nullptr;
    }
    virtual void retain() {assert(references);++references;}
    virtual void release() {assert(references);if(!--references)delete this;}
};
class IOMemoryDescriptor : public OSObject {
public:
    uint64_t bytes;
    IODirection direction;
    IOMemoryDescriptor(uint64_t n,IODirection d):OSObject(DodgeTestKind::Descriptor),bytes(n),direction(d) {}
    virtual uint64_t getLength() {return bytes;}
    virtual IODirection getDirection() {return direction;}
};
class IOMemoryMap : public OSObject {
public:
    IOMemoryDescriptor *memory=nullptr;
    void *super=nullptr;
    uint64_t fOffset=0,address=0,bytes=0;
    IOMemoryMap():OSObject(DodgeTestKind::MemoryMap) {}
    virtual IOMemoryDescriptor *getMemoryDescriptor() {return memory;}
    virtual uint64_t getLength() {return bytes;}
};
