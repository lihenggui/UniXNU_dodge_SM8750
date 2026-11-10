// SPDX-License-Identifier: MIT
// Actual timer-controller source, explicit software scheduling/IOKit/sender peers.
#include "DodgeSoftwareRefresh.h"
#include "OriginalLegacyRefreshABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

bool dodge_test_timer_failure=false;
IOReturn dodge_test_timer_wake_result=kIOReturnSuccess;
unsigned dodge_test_timer_objects=0;
IOTimerEventSource *dodge_test_last_timer=nullptr;
static IOReturn addResult=kIOReturnSuccess,removeResult=kIOReturnSuccess;
static int allocationFailure=-1;
static uint64_t now=1000,continuous=3000,conversionDivisor=1000;
static std::unordered_map<void *,size_t> allocations;
static std::function<void()> senderHook;
struct Sent {void *display;uint64_t timestamp,continuous,interval;};
static std::vector<Sent> sent;
static std::vector<std::string> cases;
void *IOMallocZero(size_t bytes) {
    if(allocationFailure==0)return nullptr;
    if(allocationFailure>0)--allocationFailure;
    void *result=std::calloc(1,bytes);assert(result);allocations[result]=bytes;return result;
}
void IOFree(void *pointer,size_t bytes) {
    auto found=allocations.find(pointer);assert(found!=allocations.end() && found->second==bytes);
    allocations.erase(found);std::free(pointer);
}
extern "C" uint64_t mach_absolute_time(void) {return now;}
extern "C" uint64_t mach_continuous_time(void) {return continuous;}
extern "C" void nanoseconds_to_absolutetime(uint64_t ns,uint64_t *out) {*out=conversionDivisor?ns/conversionDivisor:0;}
extern "C" void native_iphone_refresh_notify(void *display,uint64_t timestamp,uint64_t stamp,uint64_t interval) {
    auto *object=static_cast<IOService *>(display);assert(object->loop->inGate());
    assert(timestamp && stamp && interval);sent.push_back({display,timestamp,stamp,interval});
    if(senderHook)senderHook();
}
IOReturn IOWorkLoop::addEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && !source->loop);
    if(addResult)return addResult;
    source->loop=this;source->retain();return kIOReturnSuccess;
}
IOReturn IOWorkLoop::removeEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && source->loop==this);
    if(removeResult)return removeResult;
    source->loop=nullptr;source->enabled=source->armed=false;source->release();return kIOReturnSuccess;
}
struct Display : IOService {
    unsigned char opaque[5728-sizeof(IOService)]{};
    Display():IOService(DodgeSwapKind::Display) {}
};
static_assert(sizeof(Display)==5728,"Exact display storage extent, not original implementation");
struct Fixture {
    IOWorkLoop loop;
    IOCommandGate gate;
    Display display;
    DodgeSoftwareRefresh *controller=nullptr;
    bool owner=true;
    uint64_t sentBase,missBase;
    Fixture() {
        assert(allocations.empty() && !dodge_test_timer_objects && !native_gop_vsync[0]);
        sentBase=native_gop_vsync[1];missBase=native_gop_vsync[2];
        allocationFailure=-1;dodge_test_timer_failure=false;dodge_test_timer_wake_result=kIOReturnSuccess;
        addResult=removeResult=kIOReturnSuccess;now=1000;continuous=3000;conversionDivisor=1000;sent.clear();senderHook={};
        display.loop=&loop;gate.loop=&loop;IPhone16Swap::store(&display,5040,&gate);
        clients(true);
    }
    void clients(bool value) {IPhone16Swap::store<void *>(&display,IPhone16Refresh::ClientHead,value?reinterpret_cast<void *>(0x10203040):nullptr);}
    void create() {controller=loop.withGate([&]{return dodge_software_refresh_create(&display);});assert(controller);}
    IOReturn enable(bool value=true) {return loop.withGate([&]{return dodge_software_refresh_set_enabled(controller,value);});}
    IOReturn status() {return loop.withGate([&]{return dodge_software_refresh_status(controller);});}
    IOReturn stop() {
        assert(owner && controller);auto result=loop.withGate([&]{return dodge_software_refresh_stop(controller);});
        if(!result)owner=false;
        return result;
    }
    void tick(int64_t offset=0) {assert(dodge_test_last_timer);now=dodge_test_last_timer->deadline+offset;continuous=now+700;dodge_test_last_timer->fire();}
    void counts(unsigned attempts,unsigned misses) const {assert(native_gop_vsync[1]==sentBase+attempts && native_gop_vsync[2]==missBase+misses && sent.size()==attempts);}
    ~Fixture() {
        if(controller && owner) {removeResult=kIOReturnSuccess;assert(!stop());}
        assert(allocations.empty() && !dodge_test_timer_objects && !native_gop_vsync[0]);
        assert(display.references==1 && gate.references==1 && loop.references==1);senderHook={};
    }
};
static void run(const char *name,const std::function<void()> &test) {test();cases.emplace_back(name);}
int main() {
    const char *createFailures[]={"null-display","wrong-display-class","no-workloop","create-outside-gate","no-command-gate",
        "wrong-command-gate-class","different-command-workloop","disabled-command-gate","controller-allocation-failure",
        "zero-converted-interval","timer-allocation-failure","add-event-source-failure"};
    for(unsigned defect=0;defect<sizeof(createFailures)/sizeof(*createFailures);++defect)run(createFailures[defect],[&]{
        Fixture f;IOWorkLoop other;IOService *display=&f.display;
        switch(defect) {
            case 0:display=nullptr;break;case 1:f.display.kind=DodgeSwapKind::Other;break;case 2:f.display.loop=nullptr;break;
            case 3:break;case 4:IPhone16Swap::store<void *>(&f.display,5040,nullptr);break;case 5:f.gate.kind=DodgeSwapKind::Other;break;
            case 6:f.gate.loop=&other;break;case 7:f.gate.enabled=false;break;case 8:allocationFailure=0;break;
            case 9:conversionDivisor=0;break;case 10:dodge_test_timer_failure=true;break;case 11:addResult=kIOReturnError;break;
            default:assert(false);
        }
        auto create=[&]{return dodge_software_refresh_create(display);};
        assert(!(defect==3?create():f.loop.withGate(create)));f.counts(0,0);
    });
    run("creation-is-disabled-and-silent",[]{
        Fixture f;f.create();assert(!dodge_test_last_timer->armed && !native_gop_vsync[0] && !f.status());f.counts(0,0);
        assert(f.display.references==2 && f.gate.references==2 && f.loop.references==2);
    });
    run("only-one-controller-reserves-diagnostics",[]{
        Fixture f;f.create();auto *timer=dodge_test_last_timer;
        assert(!f.loop.withGate([&]{return dodge_software_refresh_create(&f.display);}));
        assert(timer==dodge_test_last_timer && dodge_test_timer_objects==1 && f.display.references==2);
        assert(!f.enable());f.tick();f.counts(1,0);
    });
    run("outside-gate-operations-keep-owner-alive",[]{
        Fixture f;f.create();assert(dodge_software_refresh_set_enabled(f.controller,true)==kIOReturnNotPermitted);
        assert(dodge_software_refresh_status(f.controller)==kIOReturnNotPermitted);
        assert(dodge_software_refresh_stop(f.controller)==kIOReturnNotPermitted);assert(!f.enable());f.tick();f.counts(1,0);
    });
    run("null-operations-refused",[]{
        assert(dodge_software_refresh_set_enabled(nullptr,true)==kIOReturnNotPermitted);
        assert(dodge_software_refresh_status(nullptr)==kIOReturnNotPermitted && dodge_software_refresh_stop(nullptr)==kIOReturnNotPermitted);
    });
    run("exact-deadline-uses-converted-ticks-and-continuous-time",[]{
        Fixture f;f.create();const auto start=now;assert(!f.enable());const auto interval=16666666/1000;
        auto *timer=dodge_test_last_timer;assert(timer->deadline==start+interval && native_gop_vsync[0]==60);
        f.tick();assert(sent[0].display==&f.display && sent[0].timestamp==now && sent[0].continuous==continuous && sent[0].interval==interval);
        assert(timer->deadline==start+2*interval && timer->armed);f.counts(1,0);
    });
    run("repeated-enable-preserves-phase",[]{
        Fixture f;f.create();assert(!f.enable());const auto first=dodge_test_last_timer->deadline;const auto wakes=dodge_test_last_timer->wakes;
        now+=31;assert(!f.enable());assert(dodge_test_last_timer->deadline==first && dodge_test_last_timer->wakes==wakes);f.counts(0,0);
    });
    run("early-timer-does-not-invent-notification",[]{
        Fixture f;f.create();assert(!f.enable());auto *timer=dodge_test_last_timer;const auto deadline=timer->deadline;
        f.tick(-1);assert(timer->deadline==deadline && timer->armed);f.counts(0,0);f.tick();f.counts(1,0);
    });
    run("idle-client-list-can-start-listening-later",[]{
        Fixture f;f.clients(false);f.create();assert(!f.enable());f.tick();f.counts(0,0);assert(dodge_test_last_timer->armed);
        f.loop.withGate([&]{f.clients(true);});f.tick();f.counts(1,0);
        f.loop.withGate([&]{f.clients(false);});f.tick();f.counts(1,0);
    });
    run("reference-head-is-not-an-interest-signal",[]{
        Fixture f;f.clients(false);IPhone16Swap::store<void *>(&f.display,5592,reinterpret_cast<void *>(0x1234));
        f.create();assert(!f.enable());f.tick();f.counts(0,0);
    });
    run("small-lateness-keeps-phase",[]{
        Fixture f;f.create();assert(!f.enable());const auto first=dodge_test_last_timer->deadline;
        f.tick(17);assert(dodge_test_last_timer->deadline==first+16666);f.counts(1,0);
    });
    run("late-deadline-is-counted-once-and-restarted",[]{
        Fixture f;f.create();assert(!f.enable());f.tick(4*16666);assert(dodge_test_last_timer->deadline==now+16666);f.counts(1,1);
    });
    run("slow-real-sender-time-counts-as-late",[]{
        Fixture f;f.create();assert(!f.enable());senderHook=[]{now+=5*16666;};f.tick();
        assert(dodge_test_last_timer->deadline==now+16666);f.counts(1,1);
    });
    run("disable-cancels-and-resume-starts-new-phase",[]{
        Fixture f;f.create();assert(!f.enable());f.tick();assert(!f.enable(false));
        assert(!dodge_test_last_timer->armed && !native_gop_vsync[0]);f.counts(1,0);
        now+=90000;const auto resumed=now;assert(!f.enable());assert(dodge_test_last_timer->deadline==resumed+16666);f.tick();f.counts(2,0);
    });
    run("initial-wake-error-is-reported-without-rate-or-attempt",[]{
        Fixture f;f.create();dodge_test_timer_wake_result=kIOReturnError;
        assert(f.enable()==kIOReturnError && f.status()==kIOReturnError && !native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(0,0);
        dodge_test_timer_wake_result=kIOReturnSuccess;assert(!f.enable());f.tick();f.counts(1,0);
    });
    run("rearm-error-keeps-only-the-actual-attempt",[]{
        Fixture f;f.create();assert(!f.enable());dodge_test_timer_wake_result=kIOReturnError;f.tick();
        assert(f.status()==kIOReturnError && !native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(1,0);
    });
    run("early-rearm-error-generates-no-attempt",[]{
        Fixture f;f.create();assert(!f.enable());dodge_test_timer_wake_result=kIOReturnError;f.tick(-1);
        assert(f.status()==kIOReturnError && !native_gop_vsync[0]);f.counts(0,0);
    });
    const char *invalidations[]={"gate-disabled-before-tick","original-gate-replaced-before-tick","display-workloop-replaced-before-tick","command-workloop-replaced-before-tick"};
    for(unsigned defect=0;defect<4;++defect)run(invalidations[defect],[&]{
        Fixture f;f.create();assert(!f.enable());IOWorkLoop other;
        if(defect==0)f.gate.enabled=false;
        if(defect==1)IPhone16Swap::store<void *>(&f.display,5040,nullptr);
        if(defect==2)f.display.loop=&other;
        if(defect==3)f.gate.loop=&other;
        f.tick();assert(f.status()==kIOReturnAborted && !native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(0,0);
    });
    run("invalid-display-enable-aborts-without-scheduling",[]{
        Fixture f;f.create();f.gate.enabled=false;assert(f.enable()==kIOReturnAborted && f.status()==kIOReturnAborted);
        assert(!dodge_test_last_timer->armed && !native_gop_vsync[0]);f.counts(0,0);
    });
    run("sender-can-disable-reentrantly",[]{
        Fixture f;f.create();assert(!f.enable());senderHook=[&]{assert(!f.enable(false));};f.tick();
        assert(!native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(1,0);
    });
    run("sender-can-stop-and-release-owner-reentrantly",[]{
        Fixture f;f.create();assert(!f.enable());senderHook=[&]{assert(!f.stop());};f.tick();
        assert(!dodge_test_timer_objects && allocations.empty() && f.display.references==1);f.counts(1,0);
    });
    run("reentrant-disable-enable-preserves-new-generation-and-phase",[]{
        Fixture f;f.create();assert(!f.enable());uint64_t restarted=0;unsigned wakes=0;
        senderHook=[&]{assert(!f.enable(false));now+=3*16666;assert(!f.enable());restarted=dodge_test_last_timer->deadline;wakes=dodge_test_last_timer->wakes;};
        f.tick();assert(dodge_test_last_timer->deadline==restarted && dodge_test_last_timer->wakes==wakes);
        assert(native_gop_vsync[0]==60);f.counts(1,0);
    });
    run("display-invalidated-by-sender-is-not-rearmed",[]{
        Fixture f;f.create();assert(!f.enable());senderHook=[&]{f.gate.enabled=false;};f.tick();
        assert(f.status()==kIOReturnAborted && !dodge_test_last_timer->armed && !native_gop_vsync[0]);f.counts(1,0);
    });
    run("stale-queued-action-after-stop-has-no-controller",[]{
        Fixture f;f.create();assert(!f.enable());auto *timer=dodge_test_last_timer;timer->retain();
        assert(!f.stop());assert(!timer->getRefcon());f.loop.withGate([&]{timer->forceStaleAction();});timer->release();f.counts(0,0);
    });
    run("queued-tick-and-stop-serialize-with-retained-source",[]{
        for(unsigned iteration=0;iteration<32;++iteration) {
            Fixture f;f.create();assert(!f.enable());auto *timer=dodge_test_last_timer;timer->retain();
            now=timer->deadline;continuous=now+700;
            std::thread worker([&]{timer->fireQueued(&f.loop);});assert(!f.stop());worker.join();
            timer->release();assert(sent.size()<=1);f.counts(unsigned(sent.size()),0);
            assert(allocations.empty() && !dodge_test_timer_objects && f.display.references==1);
        }
    });
    run("disabled-controller-ignores-stale-action",[]{
        Fixture f;f.create();assert(!f.enable());assert(!f.enable(false));
        f.loop.withGate([&]{dodge_test_last_timer->forceStaleAction();});
        assert(!dodge_test_last_timer->armed && !native_gop_vsync[0]);f.counts(0,0);
    });
    run("failed-removal-keeps-disabled-owner-for-cleanup-retry",[]{
        Fixture f;f.create();assert(!f.enable());removeResult=kIOReturnError;
        assert(f.stop()==kIOReturnError && f.owner && f.status()==kIOReturnError);
        assert(!dodge_test_last_timer->armed && !dodge_test_last_timer->getRefcon() && !native_gop_vsync[0]);
        assert(f.enable()==kIOReturnNotReady);removeResult=kIOReturnSuccess;assert(!f.stop());f.counts(0,0);
    });
    run("initial-clock-overflow-refuses-deadline",[]{
        Fixture f;f.create();now=UINT64_MAX-10;assert(f.enable()==kIOReturnBadArgument && f.status()==kIOReturnBadArgument);
        assert(!native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(0,0);
    });
    run("next-phase-overflow-does-not-wrap-clock",[]{
        Fixture f;f.create();now=UINT64_MAX-16666-10;assert(!f.enable());continuous=1;
        now=dodge_test_last_timer->deadline;dodge_test_last_timer->fire();
        assert(f.status()==kIOReturnBadArgument && !native_gop_vsync[0] && !dodge_test_last_timer->armed);f.counts(1,0);
    });
    run("late-restart-overflow-does-not-wrap-clock",[]{
        Fixture f;f.create();assert(!f.enable());now=UINT64_MAX-10;continuous=1;dodge_test_last_timer->fire();
        assert(f.status()==kIOReturnBadArgument && !native_gop_vsync[0]);f.counts(1,1);
    });
    run("clock-regression-during-sender-aborts-rearm",[]{
        Fixture f;f.create();assert(!f.enable());senderHook=[]{--now;};f.tick();
        assert(f.status()==kIOReturnAborted && !native_gop_vsync[0]);f.counts(1,0);
    });
    run("zero-continuous-clock-does-not-count-invocation",[]{
        Fixture f;f.create();assert(!f.enable());now=dodge_test_last_timer->deadline;continuous=0;dodge_test_last_timer->fire();
        assert(dodge_test_last_timer->armed);f.counts(0,0);
    });
    std::printf("{\"result\":\"PASS\",\"cases\":[");
    for(size_t index=0;index<cases.size();++index)std::printf("%s\"%s\"",index?",":"",cases[index].c_str());
    std::puts("],\"original_sender_executed\":false,\"kernel_timers_executed\":false,\"software_iokit_peers\":true}");
}
