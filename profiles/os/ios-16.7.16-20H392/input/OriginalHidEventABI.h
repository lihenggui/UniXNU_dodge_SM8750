// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded iPhone10,3 / 20H392 declarations. Unqualified slots preserve
// original pointers only; the compiler forbids calls to their placeholders.
#pragma once
#include <IOKit/IOService.h>
class OSArray;
class IOHIDEvent : public OSObject {
    OSDeclareAbstractStructors(IOHIDEvent)
    unsigned char originalPrivate[80-sizeof(OSObject)];
public:
    void free() override;
    OSArray *getChildren();
    virtual void dodgeEventOpaque15() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque16() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque17() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual uint32_t getType();
    virtual void dodgeEventOpaque19() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque20() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque21() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque22() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual int32_t getIntegerValue(uint32_t,IOOptionBits=0);
    virtual void setIntegerValue(uint32_t,int32_t,IOOptionBits=0);
    virtual IOFixed getFixedValue(uint32_t,IOOptionBits=0);
    virtual void dodgeEventOpaque26() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque27() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque28() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque29() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque30() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque31() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque32() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque33() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque34() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque35() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
    virtual void dodgeEventOpaque36() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));
};
static_assert(sizeof(IOHIDEvent)==80,"Original iPhone event instance");
class IOHIDEventDriver : public IOService {
    OSDeclareDefaultStructors(IOHIDEventDriver)
    unsigned char originalPrivate[264-sizeof(IOService)];
public:
    IOReturn Dispatch(IORPC) override;
    void free() override;
    bool init(OSDictionary *properties=nullptr) override;
    IOReturn setProperties(OSObject *) override;
    bool didTerminate(IOService *,IOOptionBits,bool *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    void close(IOService *,IOOptionBits=0) override;
    bool handleOpen(IOService *,IOOptionBits,void *) override;
    void handleClose(IOService *,IOOptionBits) override;
    bool handleIsOpen(const IOService *) const override;
    bool matchPropertyTable(OSDictionary *,SInt32 *) override;
    IOReturn message(UInt32,IOService *,void *) override;
    IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) override;
    virtual void dodgeEventDriverOpaque168() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque169() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque170() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque171() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque172() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque173() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque174() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque175() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque176() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque177() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque178() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque179() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque180() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque181() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque182() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque183() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque184() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque185() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque186() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque187() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque188() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque189() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque190() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque191() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque192() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque193() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque194() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque195() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque196() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque197() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dispatchEvent(IOHIDEvent *,IOOptionBits=0);
    virtual void dodgeEventDriverOpaque199() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque200() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque201() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque202() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque203() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque204() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque205() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque206() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque207() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque208() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque209() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque210() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque211() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque212() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque213() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque214() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque215() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque216() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque217() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
    virtual void dodgeEventDriverOpaque218() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));
};
static_assert(sizeof(IOHIDEventDriver)==264,"Original iPhone event driver instance");
