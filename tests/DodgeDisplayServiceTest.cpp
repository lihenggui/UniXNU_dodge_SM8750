// SPDX-License-Identifier: MIT
// Production service coordinator; frontend, original parent, maps and scheduler
// are explicit peers here. The actual frontend has a separate sanitizer suite.
#include "DodgeDisplayService.h"
#include "OriginalLegacyLifecycleABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <pexpert/pexpert.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

bool dodge_test_timer_failure=false;
IOReturn dodge_test_timer_wake_result=0;
unsigned dodge_test_timer_objects=0;
IOTimerEventSource *dodge_test_last_timer=nullptr;
static std::unordered_map<void *,size_t> allocations;
static bool allocationFailure=false,consoleFailure=false,frontFailure=false;
static IOReturn addResult=0,removeResult=0,frontStopResult=0;
static unsigned attached=0,frontObjects=0,frontCreates=0,frontStops=0,submits=0,validates=0,kicks=0,refreshes=0;
static uint64_t now=1000,conversionDivisor=1;
static PE_Video video;
static std::function<void()> mapHook,addHook,createHook,submitHook,stopHook,consoleHook;
void *IOMallocZero(size_t bytes) {
    if(allocationFailure)return nullptr;
    void *value=std::calloc(1,bytes);assert(value);allocations[value]=bytes;return value;
}
void IOFree(void *value,size_t bytes) {
    auto found=allocations.find(value);assert(found!=allocations.end() && found->second==bytes);
    allocations.erase(found);std::free(value);
}
extern "C" int PE_current_console(PE_Video *out) {
    auto hook=consoleHook;consoleHook={};if(hook)hook();*out=video;return consoleFailure;
}
extern "C" uint64_t mach_absolute_time() {return now;}
extern "C" void nanoseconds_to_absolutetime(uint64_t ns,uint64_t *out) {*out=conversionDivisor?ns/conversionDivisor:0;}
IOReturn IOWorkLoop::addEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && !source->loop);
    auto hook=addHook;addHook={};if(hook)hook();
    if(addResult)return addResult;
    source->loop=this;source->retain();++attached;return 0;
}
IOReturn IOWorkLoop::removeEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && source->loop==this);
    if(removeResult)return removeResult;
    source->loop=nullptr;source->armed=false;source->enabled=false;source->release();--attached;return 0;
}
struct DodgeDisplayFrontend {IOService *display;IOMemoryMap *map;};
DodgeDisplayFrontend *dodge_display_frontend_create(IOService *display,IOService *presenter,IOMemoryMap *map,
        DodgeDisplayProducer producer,DodgeDisplayTransfer transfer) {
    assert(display->getWorkLoop()->inGate() && !presenter && transfer==DodgeDisplayTransfer::CpuCopy);
    assert(producer==DodgeDisplayProducer::AdrenoTimeline || producer==DodgeDisplayProducer::CpuOnly);
    assert(IPhone16Swap::load<uint32_t>(display,5208)==video.v_width && IPhone16Swap::load<uint32_t>(display,5212)==video.v_height);
    ++frontCreates;auto hook=createHook;createHook={};if(hook)hook();
    if(frontFailure)return nullptr;
    display->retain();map->retain();++frontObjects;return new DodgeDisplayFrontend{display,map};
}
IOReturn dodge_display_frontend_submit(DodgeDisplayFrontend *front,const void *packet,unsigned bytes,void *submitter) {
    assert(front && front->display->getWorkLoop()->inGate() && packet && bytes==1132 && submitter==packet);
    ++submits;auto hook=submitHook;submitHook={};if(hook)hook();return 0;
}
bool dodge_display_frontend_validate(DodgeDisplayFrontend *front,IOMFBSwapIORequest *request) {
    assert(front && front->display->getWorkLoop()->inGate());++validates;return request!=nullptr;
}
IOReturn dodge_display_frontend_kick(DodgeDisplayFrontend *front) {
    assert(front && front->display->getWorkLoop()->inGate());++kicks;return 0;
}
IOReturn dodge_display_frontend_set_refresh(DodgeDisplayFrontend *front,bool) {
    assert(front && front->display->getWorkLoop()->inGate());++refreshes;return 0;
}
IOReturn dodge_display_frontend_stop(DodgeDisplayFrontend *front) {
    assert(front && front->display->getWorkLoop()->inGate());++frontStops;
    auto hook=stopHook;stopHook={};if(hook)hook();
    if(frontStopResult)return frontStopResult;
    front->map->release();front->display->release();delete front;--frontObjects;return 0;
}
struct Display : IOService {
    uint8_t storage[IPhone16Swap::DisplayBytes-sizeof(IOService)]{};
    Display():IOService(DodgeSwapKind::Display) {}
};
struct Provider : IOService {
    bool mapped=false;
    Provider():IOService(DodgeSwapKind::Other) {}
    IOMemoryMap *mapDeviceMemoryWithIndex(unsigned index,uint32_t options) override {
        auto hook=mapHook;mapHook={};if(hook)hook();mapped=deviceMap!=nullptr;
        return IOService::mapDeviceMemoryWithIndex(index,options);
    }
};
static_assert(sizeof(Display)==5728,"Peer storage boundary only");
struct Fixture;
static Fixture *active=nullptr;
struct Fixture {
    IOWorkLoop loop;
    IOCommandGate gate;
    Display display;
    Provider provider;
    IOMemoryMap map;
    DodgeDisplayService *service=nullptr;
    unsigned completions=0;
    std::function<void()> completionHook;
    Fixture() {
        assert(!active && allocations.empty() && !frontObjects && !dodge_test_timer_objects && !attached);active=this;
        allocationFailure=consoleFailure=frontFailure=dodge_test_timer_failure=false;
        addResult=removeResult=frontStopResult=dodge_test_timer_wake_result=0;now=1000;conversionDivisor=1;
        frontCreates=frontStops=submits=validates=kicks=refreshes=0;
        mapHook={};addHook={};createHook={};submitHook={};stopHook={};consoleHook={};video={};
        display.loop=gate.loop=&loop;provider.deviceMap=&map;
        map.physical=video.v_baseAddr;map.bytes=video.v_height*video.v_rowBytes;map.address=0x100000;
        IPhone16Swap::store(&display,5040,&gate);
        for(unsigned i=0;i<8;++i) {
            unsigned head=i==0?4880:i==1?4896:4912+(i-2)*16;
            IPhone16Swap::store(&display,head+8,reinterpret_cast<uint8_t *>(&display)+head);
        }
    }
    static void completed(IOService *display,IOService *provider) {
        auto &f=*active;assert(display==&f.display && provider==&f.provider && f.loop.inGate());
        assert(!attached && !frontObjects && f.map.references==unsigned(f.provider.mapped?2:1) && f.gate.references==2);
        // The detached sender can still be retained by a running timer call.
        if(dodge_test_timer_objects)assert(dodge_test_timer_objects==1 && dodge_test_last_timer &&
            !dodge_test_last_timer->loop && !dodge_test_last_timer->armed && !dodge_test_last_timer->getRefcon());
        assert(f.display.references==2 && f.provider.references==2);++f.completions;
        if(f.completionHook)f.completionHook();
    }
    bool create() {service=dodge_display_service_create(&display,&provider,completed);return service;}
    IOReturn start(DodgeDisplayProducer p=DodgeDisplayProducer::AdrenoTimeline) {assert(create());return dodge_display_service_start(service,p);}
    DodgeDisplayServiceStatus status() {
        DodgeDisplayServiceStatus s={};assert(dodge_display_service_status(service,&s));return s;
    }
    ~Fixture() {
        completionHook={};frontStopResult=removeResult=dodge_test_timer_wake_result=0;conversionDivisor=1;now=1000;
        if(service) {assert(dodge_display_service_release(service)==0);service=nullptr;}
        assert(allocations.empty() && !frontObjects && !attached && !dodge_test_timer_objects);
        for(auto *object:std::array<OSObject *,5>{&loop,&gate,&display,&provider,&map})assert(object->references==1);
        active=nullptr;
    }
};
int main() {
    std::vector<std::string> cases;
    auto test=[&](const char *name,auto function) {Fixture f;function(f);cases.emplace_back(name);};
    test("zero-mode-GOP-connected-before-ready",[](Fixture &f) {
        assert(f.start()==0 && dodge_display_service_ready(f.service));
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==17 && IPhone16Swap::load<uint32_t>(&f.display,5212)==5);
        assert(frontCreates==1 && attached==1 && f.map.references==3);
        std::array<uint8_t,1132> packet{};assert(dodge_display_service_submit(f.service,packet.data(),packet.data())==0);
        assert(dodge_display_service_validate(f.service,reinterpret_cast<IOMFBSwapIORequest *>(uintptr_t(0x1234))));
        dodge_display_service_kick(f.service);assert(dodge_display_service_refresh(f.service,true)==0);
        assert(submits==1 && validates==1 && kicks==1 && refreshes==1);
        assert(dodge_display_service_stop(f.service)==0 && f.completions==1 && !dodge_display_service_ready(f.service));
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==17 && dodge_display_service_stop(f.service)==0 && f.completions==1);
    });
    test("matching-existing-mode-CPU-producer",[](Fixture &f) {
        IPhone16Swap::store(&f.display,5208,17U);IPhone16Swap::store(&f.display,5212,5U);
        assert(f.start(DodgeDisplayProducer::CpuOnly)==0);
    });
    test("conflicting-existing-mode-untouched",[](Fixture &f) {
        IPhone16Swap::store(&f.display,5208,99U);assert(f.start()==kIOReturnUnsupported);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==99 && !frontCreates && f.completions==1);
    });
    test("repeated-start-preserves-running-service",[](Fixture &f) {
        assert(f.start()==0 && dodge_display_service_start(f.service)==kIOReturnNotPermitted);
        assert(dodge_display_service_ready(f.service) && !frontStops && !f.completions);
    });
    test("stopped-service-cannot-restart",[](Fixture &f) {
        assert(f.start()==0 && dodge_display_service_stop(f.service)==0);
        assert(dodge_display_service_start(f.service)==kIOReturnNotPermitted && f.completions==1);
    });
    test("allocation-failure-no-retains",[](Fixture &f) {allocationFailure=true;assert(!f.create());});
    test("missing-loop-refused",[](Fixture &f) {f.display.loop=nullptr;assert(!f.create());});
    test("missing-gate-refused",[](Fixture &f) {IPhone16Swap::store<IOCommandGate *>(&f.display,5040,nullptr);assert(!f.create());});
    test("disabled-gate-refused",[](Fixture &f) {f.gate.enabled=false;assert(!f.create());});
    test("detached-gate-refused",[](Fixture &f) {f.gate.loop=nullptr;assert(!f.create());});
    test("queued-before-start-refused",[](Fixture &f) {IPhone16Swap::store(&f.display,4872,uintptr_t(1));assert(f.start()==kIOReturnNotReady && !frontCreates);});
    test("bad-startup-tail-refused",[](Fixture &f) {IPhone16Swap::store(&f.display,4888,uintptr_t(1));assert(f.start()==kIOReturnNotReady && !frontCreates);});
    test("bad-notification-tail-refused",[](Fixture &f) {IPhone16Swap::store(&f.display,5000,uintptr_t(1));assert(f.start()==kIOReturnNotReady && !frontCreates);});
    test("invalid-producer-refused",[](Fixture &f) {assert(f.start(static_cast<DodgeDisplayProducer>(99))==kIOReturnNotReady && !frontCreates);});
    test("console-query-failure",[](Fixture &f) {consoleFailure=true;assert(f.start()==kIOReturnNotReady);});
    for(const auto &defect:std::vector<std::string>{"zero-physical","zero-width","zero-height","wide","tall","depth","rotation","short-stride","large-stride","physical-wrap","map-missing","map-physical","map-length","map-null-VA","map-VA-wrap"}) {
        const std::string name="GOP-refuses-"+defect;
        test(name.c_str(),[&](Fixture &f) {
            if(defect=="zero-physical")video.v_baseAddr=0;
            if(defect=="zero-width")video.v_width=0;
            if(defect=="zero-height")video.v_height=0;
            if(defect=="wide")video.v_width=8193;
            if(defect=="tall")video.v_height=8193;
            if(defect=="depth")video.v_depth=16;
            if(defect=="rotation")video.v_rotate=1;
            if(defect=="short-stride")video.v_rowBytes=67;
            if(defect=="large-stride")video.v_rowBytes=32769;
            if(defect=="physical-wrap")video.v_baseAddr=UINT64_MAX-10;
            if(defect=="map-missing")f.provider.deviceMap=nullptr;
            if(defect=="map-physical")++f.map.physical;
            if(defect=="map-length")++f.map.bytes;
            if(defect=="map-null-VA")f.map.address=0;
            if(defect=="map-VA-wrap")f.map.address=UINTPTR_MAX-10;
            assert(f.start()==kIOReturnNotReady && !frontCreates && f.completions==1);
            assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0);
        });
    }
    test("timer-factory-failure-unwinds-map",[](Fixture &f) {dodge_test_timer_failure=true;assert(f.start()==kIOReturnNoMemory && f.completions==1);});
    test("timer-add-failure-unwinds-map",[](Fixture &f) {addResult=kIOReturnError;assert(f.start()==kIOReturnError && f.completions==1);});
    test("frontend-create-failure-rolls-back-mode",[](Fixture &f) {
        frontFailure=true;assert(f.start()==kIOReturnNotReady && f.completions==1);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0 && IPhone16Swap::load<uint32_t>(&f.display,5212)==0);
    });
    test("failed-start-detach-failure-retains-for-retry",[](Fixture &f) {
        frontFailure=true;removeResult=kIOReturnError;assert(f.start()==kIOReturnNotReady);
        assert(f.status().stopping && !f.status().stopped && f.status().retryArmed && !f.completions && f.map.references==2);
        removeResult=0;dodge_test_last_timer->fire();assert(f.completions==1 && f.status().stopped);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0);
    });
    test("busy-front-keeps-map-and-retries",[](Fixture &f) {
        assert(f.start()==0);frontStopResult=kIOReturnBusy;
        assert(dodge_display_service_stop(f.service)==kIOReturnBusy && f.status().retryArmed && !f.status().ready);
        dodge_test_last_timer->fire();assert(!f.completions && f.map.references==3 && frontStops==2);
        frontStopResult=0;dodge_test_last_timer->fire();assert(f.completions==1 && frontStops==3);
    });
    test("detach-error-does-not-repeat-consumed-front-stop",[](Fixture &f) {
        assert(f.start()==0);removeResult=kIOReturnError;
        assert(dodge_display_service_stop(f.service)==kIOReturnError && frontStops==1 && !frontObjects);
        removeResult=0;dodge_test_last_timer->fire();assert(f.completions==1 && frontStops==1);
    });
    test("refused-wake-preserves-explicit-retry",[](Fixture &f) {
        assert(f.start()==0);frontStopResult=kIOReturnBusy;dodge_test_timer_wake_result=kIOReturnError;
        assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.status().retryArmed && f.status().last==kIOReturnError);
        frontStopResult=dodge_test_timer_wake_result=0;assert(dodge_display_service_stop(f.service)==0 && f.completions==1);
    });
    test("deadline-overflow-keeps-owner",[](Fixture &f) {
        assert(f.start()==0);frontStopResult=kIOReturnBusy;now=UINT64_MAX;
        assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.status().retryArmed);
        frontStopResult=0;assert(dodge_display_service_stop(f.service)==0);
    });
    test("zero-time-conversion-keeps-owner",[](Fixture &f) {
        assert(f.start()==0);frontStopResult=kIOReturnBusy;conversionDivisor=0;
        assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.status().retryArmed);
        frontStopResult=0;assert(dodge_display_service_stop(f.service)==0);
    });
    test("release-busy-preserves-owner-reference",[](Fixture &f) {
        assert(f.start()==0);frontStopResult=kIOReturnBusy;
        assert(dodge_display_service_release(f.service)==kIOReturnBusy);
        frontStopResult=0;dodge_test_last_timer->fire();assert(dodge_display_service_release(f.service)==0);f.service=nullptr;
    });
    test("submit-reentrant-stop-defers-parent-and-mapping-release",[](Fixture &f) {
        assert(f.start()==0);submitHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.completions && f.map.references==3);};
        std::array<uint8_t,1132> packet{};assert(dodge_display_service_submit(f.service,packet.data(),packet.data())==0);
        assert(dodge_display_service_submit(f.service,packet.data(),packet.data())==kIOReturnNotReady && submits==1);
        dodge_test_last_timer->fire();assert(f.completions==1);
    });
    test("frontend-stop-reentrancy-is-not-double-retirement",[](Fixture &f) {
        assert(f.start()==0);stopHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy);};
        assert(dodge_display_service_stop(f.service)==0 && frontStops==1 && f.completions==1);
    });
    test("completion-reentrant-stop-is-idempotent",[](Fixture &f) {
        assert(f.start()==0);f.completionHook=[&] {assert(dodge_display_service_stop(f.service)==0);};
        assert(dodge_display_service_stop(f.service)==0 && f.completions==1);
    });
    test("completion-reentrant-owner-release-is-consumed-once",[](Fixture &f) {
        assert(f.start()==0);f.completionHook=[&] {assert(dodge_display_service_release(f.service)==0);f.service=nullptr;};
        auto *owned=f.service;assert(dodge_display_service_release(owned)==0 && !f.service && allocations.empty());
    });
    test("map-reentrant-stop-aborts-unpublished-start",[](Fixture &f) {
        assert(f.create());mapHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.completions);};
        assert(dodge_display_service_start(f.service)==kIOReturnAborted && f.completions==1 && !frontCreates);
    });
    test("add-source-reentrant-stop-aborts-unpublished-start",[](Fixture &f) {
        assert(f.create());addHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy);};
        assert(dodge_display_service_start(f.service)==kIOReturnAborted && f.completions==1 && !frontCreates);
    });
    test("frontend-create-reentrant-stop-drains-returned-owner",[](Fixture &f) {
        assert(f.create());createHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy);};
        assert(dodge_display_service_start(f.service)==kIOReturnAborted && frontStops==1 && f.completions==1);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0);
    });
    test("add-source-mode-change-refuses-write",[](Fixture &f) {
        addHook=[&] {IPhone16Swap::store(&f.display,5208,99U);};assert(f.start()==kIOReturnNotReady && !frontCreates);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==99);
    });
    test("add-source-queue-change-refuses-write",[](Fixture &f) {
        addHook=[&] {IPhone16Swap::store(&f.display,4872,uintptr_t(1));};assert(f.start()==kIOReturnNotReady && !frontCreates);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0);
    });
    test("creation-console-change-refuses-publication",[](Fixture &f) {
        createHook=[] {video.v_rotate=1;};assert(f.start()==kIOReturnNotReady && frontStops==1 && f.completions==1);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0);
    });
    test("readiness-query-reentrant-stop-keeps-inputs-live",[](Fixture &f) {
        assert(f.start()==0);consoleHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.completions);};
        assert(!dodge_display_service_ready(f.service));dodge_test_last_timer->fire();assert(f.completions==1);
    });
    test("live-mode-change-blocks-all-front-entrypoints",[](Fixture &f) {
        assert(f.start()==0);IPhone16Swap::store(&f.display,5208,99U);
        std::array<uint8_t,1132> packet{};assert(!dodge_display_service_ready(f.service));
        assert(dodge_display_service_submit(f.service,packet.data(),packet.data())==kIOReturnNotReady);
        assert(!dodge_display_service_validate(f.service,reinterpret_cast<IOMFBSwapIORequest *>(uintptr_t(1))));
        dodge_display_service_kick(f.service);assert(dodge_display_service_refresh(f.service,true)==kIOReturnNotReady);
        assert(!submits && !validates && !kicks && !refreshes);
    });
    test("stale-timer-action-after-detach-is-empty",[](Fixture &f) {
        assert(f.start()==0);auto *timer=dodge_test_last_timer;timer->retain();
        // A saved sender is allowed to outlive removal. No refcon survives.
        f.completionHook=[&] {assert(timer->getRefcon()==nullptr);};
        assert(dodge_display_service_stop(f.service)==0);timer->forceStaleAction();
        assert(f.completions==1);timer->release();
    });
    test("null-status-and-null-controller-refused",[](Fixture &f) {
        assert(f.create());assert(!dodge_display_service_status(f.service,nullptr));
        assert(!dodge_display_service_ready(nullptr) && dodge_display_service_stop(nullptr)==kIOReturnBadArgument);
    });
    test("admission-requires-ready-and-preserves-result",[](Fixture &f) {
        assert(f.create());unsigned calls=0;
        const auto action=[](IOService *owner,void *context)->IOReturn {
            assert(owner==&active->display && active->loop.inGate());++*static_cast<unsigned *>(context);return kIOReturnUnsupported;
        };
        assert(dodge_display_service_admit(f.service,action,&calls)==kIOReturnNotReady && !calls);
        assert(dodge_display_service_start(f.service)==0);
        assert(dodge_display_service_admit(f.service,action,&calls)==kIOReturnUnsupported && calls==1);
    });
    test("admission-null-action-refused",[](Fixture &f) {
        assert(f.start()==0 && dodge_display_service_admit(f.service,nullptr,nullptr)==kIOReturnBadArgument);
    });
    test("admission-reentrant-stop-defers-parent-completion",[](Fixture &f) {
        assert(f.start()==0);unsigned calls=0;
        const auto action=[](IOService *,void *context)->IOReturn {
            auto &f=*active;++*static_cast<unsigned *>(context);
            assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !f.completions && !frontStops && f.map.references==3);
            return kIOReturnSuccess;
        };
        assert(dodge_display_service_admit(f.service,action,&calls)==0 && calls==1 && !f.completions);
        assert(dodge_display_service_admit(f.service,action,&calls)==kIOReturnNotReady && calls==1);
        dodge_test_last_timer->fire();assert(f.completions==1);
    });
    test("admission-live-mode-change-refused",[](Fixture &f) {
        assert(f.start()==0);IPhone16Swap::store(&f.display,5208,99U);
        assert(dodge_display_service_admit(f.service,[](IOService *,void *)->IOReturn {assert(false);return 0;},nullptr)==kIOReturnNotReady);
    });
    test("admission-after-stop-refused",[](Fixture &f) {
        assert(f.start()==0 && dodge_display_service_stop(f.service)==0);
        assert(dodge_display_service_admit(f.service,[](IOService *,void *)->IOReturn {assert(false);return 0;},nullptr)==kIOReturnNotReady);
    });
    test("borrowed-loop-survives-original-parent-stop",[](Fixture &f) {
        assert(!dodge_display_service_workloop(nullptr));assert(f.start()==0);
        assert(dodge_display_service_workloop(f.service)==&f.loop);
        assert(dodge_display_service_stop(f.service)==0);
        f.display.loop=nullptr;IPhone16Swap::store<IOCommandGate *>(&f.display,5040,nullptr);
        assert(dodge_display_service_workloop(f.service)==&f.loop && f.loop.references==2);
    });
    std::printf("{\"result\":\"PASS\",\"frontend_is_peer\":true,\"cases\":[");
    for(size_t i=0;i<cases.size();++i)std::printf("%s\"%s\"",i?",":"",cases[i].c_str());
    std::puts("]}");
}
