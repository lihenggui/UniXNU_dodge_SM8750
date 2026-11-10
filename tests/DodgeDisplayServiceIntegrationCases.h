// SPDX-License-Identifier: MIT
// Included by the actual frontend fixture's separate integration build only.
#pragma once
static unsigned serviceCompletions;
struct ServiceFixture : Fixture {
    DodgeDisplayService *service=nullptr;
    static void completed(IOService *display,IOService *provider) {
        auto &f=*activeFixture;
        assert(display==&f.display && provider==&f.presenter && f.loop.inGate());++serviceCompletions;
        assert(!f.memory.prepared && !native_gop_vsync[0]);
    }
    ServiceFixture() {
        assert(!serviceUnderTest);serviceCompletions=0;presenter.deviceMap=&scanout;
        service=dodge_display_service_create(&display,&presenter,completed);assert(service);serviceUnderTest=service;
    }
    IOReturn start(DodgeDisplayProducer producer=DodgeDisplayProducer::AdrenoTimeline) {return dodge_display_service_start(service,producer);}
    IOReturn send(uint32_t id=1) {auto data=packet(id);return dodge_display_service_submit(service,data.data(),this);}
    ~ServiceFixture() {
        removeResult=0;assert(dodge_display_service_release(service)==0);serviceUnderTest=nullptr;
        assert(serviceCompletions==1);
    }
};
int main() {
    run("actual-coordinator-frontend-bridge-default-first-frame",[]{
        ServiceFixture f;assert(f.start()==0 && dodge_display_service_ready(f.service));
        assert(f.send()==0 && builderCalls==1 && completionCalls==1 && !presentOffers);f.copied();
    });
    run("actual-zero-mode-initialized-before-packet-builder",[]{
        ServiceFixture f;IPhone16Swap::store(&f.display,5208,0U);IPhone16Swap::store(&f.display,5212,0U);
        assert(f.start()==0 && f.send()==0 && completionCalls==1);f.copied();
    });
    run("actual-Adreno-producer-target-waits-and-retires",[]{
        ServiceFixture f;gpuSubmitted=7;gpuRetired=6;assert(f.start()==0 && f.send()==0);
        assert(!completionCalls && !pixelCopies && gpuQueries);f.unchanged();
        gpuRetired=7;f.tick();assert(completionCalls==1 && pixelCopies==1);f.copied();
    });
    run("actual-Adreno-recovery-change-refuses-old-frame",[]{
        ServiceFixture f;gpuSubmitted=7;gpuRetired=6;assert(f.start()==0 && f.send()==0);
        gpuEpoch=2;gpuRetired=7;f.tick();assert(!completionCalls && !pixelCopies);f.unchanged();
        assert(dodge_display_service_stop(f.service)==0 && serviceCompletions==1);
    });
    run("actual-CPU-producer-explicit-mode",[]{
        ServiceFixture f;gpuKnown=false;assert(f.start(DodgeDisplayProducer::CpuOnly)==0 && f.send()==0);
        assert(!gpuQueries && completionCalls==1 && !presentOffers);f.copied();
    });
    run("actual-backing-reentrant-stop-keeps-copy-inputs-live",[]{
        ServiceFixture f;assert(f.start()==0);
        backingHook=[&] {assert(dodge_display_service_stop(f.service)==kIOReturnBusy && !serviceCompletions);};
        assert(f.send()==0 && completionCalls==1 && !serviceCompletions);f.copied();
        assert(f.send(2)==kIOReturnNotReady && builderCalls==1);
        assert(dodge_display_service_stop(f.service)==0 && serviceCompletions==1);
    });
    run("actual-software-refresh-stops-before-parent-callback",[]{
        ServiceFixture f;assert(f.start()==0);f.listeners();
        assert(dodge_display_service_refresh(f.service,true)==0 && native_gop_vsync[0]==60);
        f.tick();assert(refreshCalls==1);assert(dodge_display_service_stop(f.service)==0 && !native_gop_vsync[0] && serviceCompletions==1);
    });
    run("actual-remove-failure-keeps-whole-service-for-retry",[]{
        ServiceFixture f;assert(f.start()==0);removeResult=kIOReturnError;
        assert(dodge_display_service_stop(f.service)==kIOReturnError && !serviceCompletions && !dodge_display_service_ready(f.service));
        removeResult=0;assert(dodge_display_service_stop(f.service)==0 && serviceCompletions==1);
    });
    run("actual-frontend-allocation-failure-restores-mode",[]{
        ServiceFixture f;IPhone16Swap::store(&f.display,5208,0U);IPhone16Swap::store(&f.display,5212,0U);
        allocationFailure=0;assert(f.start()==kIOReturnNotReady && serviceCompletions==1);
        assert(IPhone16Swap::load<uint32_t>(&f.display,5208)==0 && !dodge_test_timer_objects && !builderCalls);
    });
    run("actual-live-mode-change-refuses-copy-and-builder",[]{
        ServiceFixture f;assert(f.start()==0);IPhone16Swap::store(&f.display,5208,99U);
        assert(f.send()==kIOReturnNotReady && !builderCalls && !completionCalls && !pixelCopies);f.unchanged();
    });
    std::printf("{\"result\":\"PASS\",\"frontend_bridge_refresh_are_actual_source\":true,\"cases\":[");
    for(unsigned i=0;i<cases.size();++i)std::printf("%s\"%s\"",i?",":"",cases[i].c_str());
    std::puts("],\"original_builder_completion_and_IOKit_are_peers\":true}");
}
