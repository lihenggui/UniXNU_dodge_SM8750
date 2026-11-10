// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host reference/count peers. Native ARM64 cases execute the real methods.
#pragma once
#include <IOKit/IOMemoryDescriptor.h>
struct NativeAdrenoPhysicalSpan {uint64_t offset,physical,bytes;};
class NativeAdrenoMemory {
public:
    NativeAdrenoPhysicalSpan pages[3]={{0,0x40000000,12288},{},{}};
    size_t length=12288,count=1;uint32_t references=0;
    bool isImported=true,readOnlyFlag=false,isQuarantined=false,isPrepared=true;
    bool imported() const {return isImported;}
    bool readOnly() const {return readOnlyFlag;}
    bool quarantined() const {return isQuarantined;}
    void quarantine() {isQuarantined=true;}
    uint32_t deviceReferences() const {return references;}
    size_t bytes() const {return length;}
    size_t spanCount() const {return count;}
    const NativeAdrenoPhysicalSpan *spans() const {return pages;}
    IOReturn holdForDevice() {if(!isPrepared || isQuarantined)return kIOReturnNotReady;++references;return 0;}
    IOReturn retireAfterQuiescence() {if(isQuarantined)return kIOReturnNotReady;assert(references);--references;return 0;}
};
