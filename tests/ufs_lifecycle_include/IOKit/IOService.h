// SPDX-License-Identifier: MIT
// Orchestration peers, not native object layouts.
#pragma once
#include <cstdint>
using IOReturn=int32_t;
enum : IOReturn {kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnNotPermitted=-3,
    kIOReturnNoMemory=-4,kIOReturnNoResources=-5,kIOReturnBusy=-6,kIOReturnUnsupported=-8,kIOReturnError=-9};
class IOPlatformExpert;
class IOService {
public:
    unsigned references=1;
    bool inactive=false;
    IOService *parent=nullptr;
    virtual ~IOService()=default;
    virtual void retain() {++references;}
    virtual void release() {if(!--references)delete this;}
    virtual bool init() {return true;}
    virtual bool attach(IOService *) {return true;}
    virtual bool start(IOService *) {return true;}
    virtual const IOService *metaCast(const char *) const {return nullptr;}
    bool isInactive() const {return inactive;}
    IOService *getProvider() const {return parent;}
    static IOPlatformExpert *getPlatform();
};
