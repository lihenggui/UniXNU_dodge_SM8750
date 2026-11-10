// SPDX-License-Identifier: MIT
// Module orchestration peer only; this is not an IOKit layout or ABI.
#pragma once
#include <cstdint>
using IOReturn=int32_t;
enum : IOReturn {kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnNotPermitted=-3,
    kIOReturnNoMemory=-4,kIOReturnBusy=-6,kIOReturnUnsupported=-8,kIOReturnError=-9};
class IOService {
public:
    unsigned references=1;
    virtual ~IOService()=default;
    virtual void retain() {++references;}
    virtual void release() {if(!--references)delete this;}
    virtual bool init()=0;
    virtual bool attach(IOService *)=0;
    virtual bool start(IOService *)=0;
    virtual void stop(IOService *)=0;
    virtual void detach(IOService *)=0;
    virtual bool isInactive() const {return false;}
    virtual const IOService *metaCast(const char *) const {return nullptr;}
    class Dictionary {
    public:
        const char *name;
        explicit Dictionary(const char *value):name(value) {}
        void release();
    };
    static Dictionary *nameMatching(const char *);
    static IOService *copyMatchingService(Dictionary *);
};
