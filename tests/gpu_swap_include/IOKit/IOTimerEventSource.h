// SPDX-License-Identifier: MIT
// Software scheduler peer. It does not create a kernel timer or a vblank.
#pragma once
#include "DodgeSwapPeer.h"

extern bool dodge_test_timer_failure;
extern IOReturn dodge_test_timer_wake_result;
extern unsigned dodge_test_timer_objects;
extern IOTimerEventSource *dodge_test_last_timer;
class IOTimerEventSource : public OSObject {
    void *refcon=nullptr;
public:
    using Action=void (*)(OSObject *,IOTimerEventSource *);
    OSObject *owner;
    Action action;
    IOWorkLoop *loop=nullptr;
    bool enabled=true,armed=false;
    uint64_t deadline=0;
    unsigned wakes=0,cancels=0;
    IOTimerEventSource(OSObject *object,Action function):OSObject(DodgeSwapKind::Timer),owner(object),action(function) {
        ++dodge_test_timer_objects;dodge_test_last_timer=this;
    }
    ~IOTimerEventSource() override {
        assert(!loop && !armed);--dodge_test_timer_objects;
        if(dodge_test_last_timer==this)dodge_test_last_timer=nullptr;
    }
    static IOTimerEventSource *timerEventSource(OSObject *object,Action function) {
        assert(object && function);return dodge_test_timer_failure?nullptr:new IOTimerEventSource(object,function);
    }
    void setRefcon(void *value) {refcon=value;}
    void *getRefcon() const {return refcon;}
    void cancelTimeout() {armed=false;++cancels;}
    void disable() {enabled=false;cancelTimeout();}
    IOReturn wakeAtTime(uint64_t time) {
        assert(loop && loop->inGate() && enabled && time);++wakes;
        if(dodge_test_timer_wake_result)return dodge_test_timer_wake_result;
        deadline=time;armed=true;return kIOReturnSuccess;
    }
    void fire() {
        assert(loop && armed && enabled);
        fireQueued(loop);
    }
    void fireQueued(IOWorkLoop *capturedLoop) {
        retain();capturedLoop->retain();
        capturedLoop->withGate([&] {
            if(loop==capturedLoop && armed && enabled) {armed=false;action(owner,this);}
        });
        capturedLoop->release();release();
    }
    void forceStaleAction() {action(owner,this);}
};
