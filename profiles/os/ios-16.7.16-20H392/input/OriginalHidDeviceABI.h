// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3/20H392 table shape. Opaque declarations describe slot
// positions only: their original prototypes are NOT asserted and source
// calls are a compile error. Every inherited pointer is checked at link time.
#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/hid/IOHIDDeviceTypes.h>
#include <libkern/c++/OSString.h>
class IOHIDDevice : public IOService {
    OSDeclareAbstractStructors(IOHIDDevice)
    unsigned char originalPrivate[208-sizeof(IOService)];
public:
    using IOService::setProperty;
    IOReturn Dispatch(IORPC) override;
    void free() override;
    bool init(OSDictionary *properties=nullptr) override;
    bool setProperty(const OSSymbol *,OSObject *) override;
    bool willTerminate(IOService *,IOOptionBits) override;
    IOReturn configureReport(IOReportChannelList *,IOReportConfigureAction,void *,void *) override;
    IOReturn updateReport(IOReportChannelList *,IOReportUpdateAction,void *,void *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    bool handleOpen(IOService *,IOOptionBits,void *) override;
    void handleClose(IOService *,IOOptionBits) override;
    bool handleIsOpen(const IOService *) const override;
    bool matchPropertyTable(OSDictionary *,SInt32 *) override;
    IOReturn message(UInt32,IOService *,void *) override;
    IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) override;
    virtual void dodgeOpaque168() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque169() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque170() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual OSString *newTransportString() const;
    virtual void dodgeOpaque172() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual OSString *newProductString() const;
    virtual void dodgeOpaque174() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque175() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque176() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque177() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque178() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque179() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual IOReturn newReportDescriptor(IOMemoryDescriptor **) const=0;
    virtual IOReturn handleReport(IOMemoryDescriptor *,IOHIDReportType,IOOptionBits);
    virtual void dodgeOpaque182() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque183() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque184() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque185() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque186() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque187() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque188() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque189() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque190() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque191() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque192() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque193() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque194() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque195() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque196() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque197() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque198() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque199() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque200() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque201() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque202() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque203() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque204() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque205() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
    virtual void dodgeOpaque206() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));
};
static_assert(sizeof(IOHIDDevice)==208,"Exact original iPhone HID storage");
