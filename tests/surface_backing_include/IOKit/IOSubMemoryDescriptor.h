// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include "IOMemoryDescriptor.h"

extern bool dodge_test_subrange_failure;
extern unsigned dodge_test_live_subranges;
class IOSubMemoryDescriptor : public IOMemoryDescriptor {
public:
    IOMemoryDescriptor *parent;
    uint64_t start;
    IOOptionBits options;
    IOSubMemoryDescriptor(IOMemoryDescriptor *p,uint64_t offset,uint64_t length,IOOptionBits flags):
        IOMemoryDescriptor(length,flags&3),parent(p),start(offset),options(flags) {
        kind=DodgeTestKind::SubMemory;parent->retain();++dodge_test_live_subranges;
    }
    ~IOSubMemoryDescriptor() override {parent->release();--dodge_test_live_subranges;}
    static IOSubMemoryDescriptor *withSubRange(IOMemoryDescriptor *parent,uint64_t offset,uint64_t length,IOOptionBits options) {
        assert(parent && offset<=parent->bytes && length<=parent->bytes-offset);
        if(dodge_test_subrange_failure)return nullptr;
        return new IOSubMemoryDescriptor(parent,offset,length,options);
    }
};
