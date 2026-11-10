// SPDX-License-Identifier: MIT
// Scheduling/ownership peers only, not an IOKit object layout.
#pragma once
#include <atomic>
#include <cstdint>
using IOReturn=int32_t;
enum : IOReturn {kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnNotPermitted=-3,
    kIOReturnNoMemory=-4,kIOReturnNoResources=-5,kIOReturnBusy=-6,kIOReturnUnsupported=-8,kIOReturnError=-9};
class IOPlatformExpert;
class IOService {
public:
    std::atomic<unsigned> references{1};
    bool inactive=false;
    virtual ~IOService()=default;
    virtual void retain() {references.fetch_add(1);}
    virtual void release() {if(references.fetch_sub(1)==1)delete this;}
    bool isInactive() const {return inactive;}
    static IOPlatformExpert *getPlatform();
    static void publishResource(const char *);
};
