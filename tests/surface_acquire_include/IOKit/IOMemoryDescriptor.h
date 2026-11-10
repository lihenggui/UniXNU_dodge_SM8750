// SPDX-License-Identifier: BSD-2-Clause-Patent
// Explicit host IOKit primitives; the native checks use the actual target ABI.
#pragma once
#include "IOTypes.h"
#include <atomic>
#include <cassert>
#include <cstring>
using IOByteCount=uint64_t;
using addr64_t=uint64_t;
using IODirection=uint32_t;
enum : unsigned {kIODirectionIn=1,kIODirectionOut=2,kIODirectionInOut=3,kIOMemoryMapperNone=0x800};
extern std::atomic<unsigned> descriptorDeletes;
class OSObject {
public:
    const char *type;
    std::atomic<unsigned> refs{1};
    explicit OSObject(const char *name):type(name) {}
    virtual ~OSObject()=default;
    virtual const OSObject *metaCast(const char *name) const {return !std::strcmp(type,name)?this:nullptr;}
    virtual void retain() {assert(refs.fetch_add(1));}
    virtual void release() {const unsigned old=refs.fetch_sub(1);assert(old);if(old==1)delete this;}
};
class IOMemoryDescriptor:public OSObject {
public:
    uint64_t bytes=12288,physical[3]={0x40000000,0x40001000,0x40002000};
    bool prepareFails=false,completeFails=false,prepared=false;
    unsigned prepares=0,completes=0;
    IOMemoryDescriptor():OSObject("IOMemoryDescriptor") {}
    ~IOMemoryDescriptor() override {++descriptorDeletes;}
    virtual uint64_t getLength() {return bytes;}
    virtual IODirection getDirection() {return kIODirectionInOut;}
    virtual IOReturn prepare() {++prepares;if(prepareFails)return kIOReturnIOError;prepared=true;return 0;}
    virtual IOReturn complete() {++completes;if(completeFails)return kIOReturnIOError;prepared=false;return 0;}
    virtual addr64_t getPhysicalSegment(uint64_t offset,IOByteCount *length,unsigned options) {
        assert(prepared && offset<bytes && !(offset&4095) && offset/4096<3 && options==kIOMemoryMapperNone);
        *length=4096;return physical[offset/4096];
    }
};
