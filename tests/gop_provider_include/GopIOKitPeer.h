// SPDX-License-Identifier: MIT
// Ownership/orchestration peers. These classes do not describe the XNU ABI.
#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>
using IOReturn=int32_t;
enum : IOReturn {kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnNotReady=-2,kIOReturnNotPermitted=-3,
    kIOReturnNoMemory=-4,kIOReturnBusy=-6,kIOReturnUnsupported=-8,kIOReturnError=-9};
class OSMetaClass;
class OSObject {
public:
    std::atomic<unsigned> references{1};
    virtual ~OSObject()=default;
    virtual void retain() {references.fetch_add(1);}
    virtual void release() {if(references.fetch_sub(1)==1)delete this;}
    virtual const OSMetaClass *getMetaClass() const {return nullptr;}
};
class OSSymbol {
public:
    const char *name;
    static const OSSymbol *withCStringNoCopy(const char *);
    void release() const;
};
class OSMetaClass {
public:
    unsigned size;
    const OSMetaClass *super;
    mutable unsigned pins=0;
    explicit OSMetaClass(unsigned bytes,const OSMetaClass *parent=nullptr):size(bytes),super(parent) {}
    static const OSMetaClass *copyMetaClassWithName(const OSSymbol *);
    void releaseMetaClass() const;
    unsigned getClassSize() const {return size;}
    const OSMetaClass *getSuperClass() const {return super;}
    OSObject *alloc() const;
};
class IODeviceMemory : public OSObject {
public:
    uint64_t address,length;
    IODeviceMemory(uint64_t,uint64_t);
    ~IODeviceMemory() override;
    static IODeviceMemory *withRange(uint64_t,uint64_t);
    uint64_t getPhysicalAddress() const {return address;}
    uint64_t getLength() const {return length;}
};
class OSArray : public OSObject {
public:
    std::vector<OSObject *> values;
    OSArray();
    ~OSArray() override;
    static OSArray *withCapacity(unsigned);
    bool setObject(OSObject *);
};
class IOPlatformExpert;
class IOService : public OSObject {
public:
    static const OSMetaClass *metaClass;
    bool inactive=false,attached=false,registered=false;
    IOService *parent=nullptr;
    OSArray *memory=nullptr;
    const char *name="IOService";
    bool isProvider=false;
    explicit IOService(bool provider=false);
    ~IOService() override;
    const OSMetaClass *getMetaClass() const override;
    virtual const IOService *metaCast(const char *) const;
    virtual bool init();
    virtual bool attach(IOService *);
    virtual void detach(IOService *);
    virtual void registerService();
    virtual IOReturn getResources();
    virtual void setDeviceMemory(OSArray *);
    virtual unsigned getDeviceMemoryCount();
    virtual IODeviceMemory *getDeviceMemoryWithIndex(unsigned);
    virtual void setName(const char *);
    const char *getName() const {return name;}
    bool isInactive() const {return inactive;}
    static IOPlatformExpert *getPlatform();
};
class IOPlatformExpert : public IOService {
public:
    bool hierarchy=true;
    const IOService *metaCast(const char *value) const override {
        return hierarchy && !std::strcmp("IODTPlatformExpert",value)?this:IOService::metaCast(value);
    }
};
#define OSDynamicCast(type,object) dynamic_cast<type *>(object)
struct PE_Video {
    uint64_t v_baseAddr,v_width,v_height,v_rowBytes,v_depth,v_rotate;
};
int PE_current_console(PE_Video *);
