// SPDX-License-Identifier: BSD-2-Clause-Patent
// Explicit provider peers; native kernel checks use the actual target layout.
#pragma once
#include "IOTypes.h"
#include <cassert>
#include <cstring>
#include <cstddef>
using IOByteCount=uint64_t;
using addr64_t=uint64_t;
using IODirection=uint32_t;
enum : uint32_t {kIODirectionIn=1,kIODirectionOut=2,kIODirectionInOut=3,kIOMemoryMapperNone=0x800};
class OSObject {
public:
    const char *type;unsigned refs=1;
    explicit OSObject(const char *name):type(name) {}
    virtual ~OSObject()=default;
    virtual const OSObject *metaCast(const char *name) const {return !std::strcmp(type,name)?this:nullptr;}
    virtual void retain() {assert(refs);++refs;}
    virtual void release() {assert(refs>1);--refs;}
};
class IOMemoryDescriptor:public OSObject {
public:
    uint64_t bytes=12288,physical[3]={0x40000000,0x40001000,0x40002000},run=4096;
    IODirection direction=kIODirectionInOut;
    bool prepareFails=false,completeFails=false,prepared=false;
    unsigned prepares=0,completes=0,segments=0;
    void (*onPrepare)()=nullptr;void (*onSegment)()=nullptr;
    IOMemoryDescriptor():OSObject("IOMemoryDescriptor") {}
    virtual uint64_t getLength() {return bytes;}
    virtual IODirection getDirection() {return direction;}
    virtual IOReturn prepare() {++prepares;if(onPrepare)onPrepare();if(prepareFails)return kIOReturnIOError;prepared=true;return 0;}
    virtual IOReturn complete() {++completes;if(completeFails)return kIOReturnIOError;prepared=false;return 0;}
    virtual addr64_t getPhysicalSegment(uint64_t offset,IOByteCount *length,unsigned options) {
        assert(prepared && offset<bytes && !(offset&4095) && offset/4096<3 && options==kIOMemoryMapperNone);
        ++segments;if(onSegment)onSegment();*length=run;return physical[offset/4096];
    }
};
