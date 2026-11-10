// SPDX-License-Identifier: MIT
// Actual pinned VM/memory/ring/submit code; only allocation/cache/MMIO are
// fixture peers. Expose the private scheduler check for a dependency refusal.
#include "XnuMemoryFixture.h"
#define private public
#include "NativeAdrenoSubmit.h"
#undef private
#define main pinned_submit_main
#include "test_submit.cpp"
#undef main

static unsigned cases;
static void passed(const char *name) {++cases;std::printf("PASS: %s\n",name);}
static uint64_t mapResource(Path &p,NativeAdrenoMemory &memory,uint64_t address,bool imported=false,unsigned permissions=3)
{
    CHECK((imported?memory.importTask(reinterpret_cast<void *>(2),0x10000000,4096,40,4096):
        memory.allocate(4096,40,false,4096))==kIOReturnSuccess);
    uint64_t handle=0;
    CHECK(p.vm.map(&memory,0,address,permissions,0,2,&handle)==kIOReturnSuccess);
    return handle;
}
static uint32_t commit(Path &p)
{
    NativeAdrenoSubmitBuffer ib{p.handle,0x800000,4096};uint32_t fence=0;
    CHECK(p.submit.submit(&ib,1,0,&fence)==kIOReturnSuccess && fence);
    return fence;
}
static void complete(Path &p,uint32_t fence)
{fencemem[1]=fence;CHECK(p.submit.wait(fence,&ringclock,1000)==kIOReturnSuccess);}

int main()
{
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        const uint64_t handle=mapResource(p,target,0x802000,true);const uint32_t fence=commit(p);
        CHECK(target.deviceReferences()==2 && p.submit.stats().references_held==2);
        CHECK(p.vm.unmap(handle)==kIOReturnBusy && target.release()==kIOReturnBusy);
        CHECK(p.submit.wait(fence,&ringclock,1000)==kIOReturnTimeout && target.deviceReferences()==2);
        const unsigned calls=fixture.physical_calls;complete(p,fence);
        CHECK(fixture.physical_calls>calls && target.deviceReferences()==1);
        CHECK(p.submit.stats().references_retired==2 && !p.vm.unmap(handle) && !target.release());
        passed("imported-render-target-not-in-IB-list-held-through-timeout-and-fence");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        const uint64_t handle=mapResource(p,target,0x802000);const uint32_t fence=commit(p);
        CHECK(p.vm.unmap(handle)==kIOReturnBusy);
        const unsigned calls=fixture.cache_calls;complete(p,fence);
        CHECK(fixture.cache_calls==calls+2 && target.deviceReferences()==1);
        CHECK(!p.vm.unmap(handle) && !target.release());
        passed("owned-cacheable-target-acquired-before-lease-release");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory old,later;
        const uint64_t old_handle=mapResource(p,old,0x802000,true);
        const uint32_t fence=commit(p);CHECK(!later.importTask(reinterpret_cast<void *>(2),0x11000000,4096,40,4096));
        uint64_t later_handle=123;const unsigned accesses=mf.calls,calls=fixture.physical_calls;
        CHECK(p.vm.map(&later,0,0x803000,3,0,2,&later_handle)==kIOReturnBusy && !later_handle);
        CHECK(!later.deviceReferences() && old.deviceReferences()==2 && mf.calls==accesses && fixture.physical_calls==calls);
        complete(p,fence);CHECK(!p.vm.map(&later,0,0x803000,3,0,2,&later_handle));
        const unsigned after=fixture.physical_calls;CHECK(!p.submit.wait(fence,&ringclock,1000));
        CHECK(fixture.physical_calls==after && later.deviceReferences()==1 && old.deviceReferences()==1);
        CHECK(!p.vm.unmap(later_handle) && !later.release() && !p.vm.unmap(old_handle) && !old.release());
        passed("late-import-refused-without-mutation-then-mapped-after-completion");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory later;
        const uint32_t fence=commit(p);CHECK(!later.allocate(4096,40,false,4096));uint64_t handle=123;
        CHECK(p.vm.map(&later,0,0x802000,3,0,2,&handle)==kIOReturnBusy && !handle);
        CHECK(!later.release());complete(p,fence);
        passed("refused-late-map-does-not-pin-unpublished-allocation");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory removed,reused;
        const uint64_t first=mapResource(p,removed,0x802000,true);
        CHECK(!p.vm.unmap(first) && !removed.release());const uint32_t fence=commit(p);
        CHECK(!reused.importTask(reinterpret_cast<void *>(2),0x12000000,4096,40,4096));uint64_t second=123;
        CHECK(p.vm.map(&reused,0,0x802000,3,0,2,&second)==kIOReturnBusy && !second);
        const unsigned calls=fixture.physical_calls;complete(p,fence);CHECK(fixture.physical_calls==calls);
        CHECK(!p.vm.map(&reused,0,0x802000,3,0,2,&second) && second>first && reused.deviceReferences()==1);
        CHECK(!p.vm.unmap(second) && !reused.release());
        passed("vacated-IOVA-cannot-be-reused-until-prior-job-completes");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        const uint64_t handle=mapResource(p,target,0x802000,true);
        const uint32_t first=commit(p),second=commit(p);CHECK(target.deviceReferences()==3);
        complete(p,first);CHECK(target.deviceReferences()==2 && p.vm.unmap(handle)==kIOReturnBusy);
        complete(p,second);CHECK(target.deviceReferences()==1 && !p.vm.unmap(handle) && !target.release());
        passed("two-submissions-retire-only-their-own-mapping-holds");
    }
    {
        Path p;CHECK(!exposed(p));std::vector<NativeAdrenoMemory *> resources;std::vector<uint64_t> handles;
        for(unsigned i=0;i<160;++i) {
            auto *memory=new NativeAdrenoMemory;resources.push_back(memory);
            handles.push_back(mapResource(p,*memory,0x802000+i*4096));
        }
        const uint32_t fence=commit(p);CHECK(p.submit.stats().references_held==161);
        for(auto *memory:resources)CHECK(memory->deviceReferences()==2);
        CHECK(p.vm.unmap(handles.back())==kIOReturnBusy);complete(p,fence);
        CHECK(p.submit.stats().references_retired==161);
        for(size_t i=0;i<resources.size();++i) {CHECK(!p.vm.unmap(handles[i]) && !resources[i]->release());delete resources[i];}
        passed("mapping-table-growth-and-more-than-128-indirect-resources");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory late;
        mapResource(p,late,0x802000);late.quarantine();
        const uint32_t wptr=cp.regs[0x0807];NativeAdrenoSubmitBuffer ib{p.handle,0x800000,4096};uint32_t fence=123;
        CHECK(p.submit.submit(&ib,1,0,&fence)==kIOReturnNotReady && !fence);
        CHECK(p.object.deviceReferences()==1 && late.deviceReferences()==1 && !p.submit.outstanding());
        CHECK(cp.regs[0x0807]==wptr && !p.submit.stats().references_held);
        passed("partial-hold-failure-rolls-back-earlier-holds-before-publication");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        mapResource(p,target,0x802000);cp.fail_publish=cp.publish+1;
        NativeAdrenoSubmitBuffer ib{p.handle,0x800000,4096};uint32_t fence=123;
        CHECK(p.submit.submit(&ib,1,0,&fence)==kIOReturnIOError && !fence && p.submit.poisoned());
        CHECK(target.deviceReferences()==2 && p.object.deviceReferences()==2 && p.submit.outstanding()==1);
        // CPU ring bookkeeping alone supplies no quiescence proof for the
        // unknown publication and must not turn fence zero into completion.
        CHECK(!p.ring.restart(0));
        static unsigned restarts;restarts=0;NativeAdrenoRecovery result{};
        CHECK(p.submit.recover([](void *,NativeAdrenoRing *,uint32_t)->IOReturn {++restarts;return kIOReturnSuccess;},
            nullptr,&ringclock,&result)==kIOReturnIOError && !restarts);
        CHECK(target.deviceReferences()==2 && !p.submit.stats().references_retired);
        passed("uncertain-ring-publication-pins-target-and-zero-fence-never-retires");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        mapResource(p,target,0x802000);const uint32_t fence=commit(p);
        fixture.cache_fail_call=fixture.cache_calls+2;fencemem[1]=fence;
        CHECK(p.submit.wait(fence,&ringclock,1000)==kIOReturnIOError);
        CHECK(p.submit.poisoned() && p.vm.poisoned() && p.submit.outstanding()==1);
        CHECK(target.deviceReferences()==2 && p.object.deviceReferences()==2 && !p.submit.stats().references_retired);
        CHECK(target.quarantined() && p.object.quarantined());fixture.cache_fail_call=0;
        passed("second-completion-cache-failure-keeps-entire-lease");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        mapResource(p,target,0x802000);fixture.cache_fail_call=fixture.cache_calls+1;
        NativeAdrenoSubmitBuffer ib{p.handle,0x800000,4096};uint32_t fence=123;
        const uint32_t wptr=cp.regs[0x0807];CHECK(p.submit.submit(&ib,1,0,&fence)==kIOReturnIOError && !fence);
        CHECK(p.vm.poisoned() && p.submit.poisoned() && p.submit.outstanding()==1);
        CHECK(target.deviceReferences()==2 && p.object.deviceReferences()==2 && cp.regs[0x0807]==wptr);
        fixture.cache_fail_call=0;passed("failed-publication-cache-and-rollback-retains-quarantined-set");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;
        mapResource(p,target,0x802000,true,ArmSmmu4KRead);const uint32_t fence=commit(p);
        const unsigned calls=fixture.physical_calls;complete(p,fence);
        CHECK(target.deviceReferences()==1 && fixture.physical_calls==calls);
        passed("read-only-resource-held-without-device-write-acquisition");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;mapResource(p,target,0x802000);
        uint64_t before=0;size_t count=0;CHECK(!p.vm.holdMapped(&before,&count) && count==2);
        const unsigned calls=fixture.cache_calls;
        CHECK(p.vm.retireMapped(before,count+1,true)==kIOReturnBadArgument);
        CHECK(p.vm.retireMapped(before+1,count,true)==kIOReturnBadArgument);
        CHECK(p.object.deviceReferences()==2 && target.deviceReferences()==2 && fixture.cache_calls==calls);
        CHECK(!p.vm.retireMapped(before,count,false) && target.deviceReferences()==1);
        passed("invalid-snapshot-boundary-or-count-never-partially-releases");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;mapResource(p,target,0x802000);
        commit(p);const uint64_t unrelated=999;
        CHECK(!p.submit.ringDisjoint(0,&unrelated,1) && p.submit.ringDisjoint(1,&unrelated,1));
        passed("distinct-IBs-cannot-prove-resource-disjointness");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;const uint64_t handle=mapResource(p,target,0x802000,true);
        commit(p);const uint32_t last=commit(p);
        NativeAdrenoRecovery result{};
        CHECK(!p.submit.recover([](void *,NativeAdrenoRing *ring,uint32_t done)->IOReturn {return ring->restart(done);},
            nullptr,&ringclock,&result));
        CHECK(result.replayed==1 && target.deviceReferences()==2 && p.vm.unmap(handle)==kIOReturnBusy);
        complete(p,last);CHECK(target.deviceReferences()==1 && !p.vm.unmap(handle) && !target.release());
        passed("successful-reset-retires-guilty-hold-and-preserves-replay-resource");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoMemory target;mapResource(p,target,0x802000,true);commit(p);
        NativeAdrenoRecovery result{};
        CHECK(p.submit.recover([](void *,NativeAdrenoRing *,uint32_t)->IOReturn {return kIOReturnIOError;},
            nullptr,&ringclock,&result)==kIOReturnIOError);
        CHECK(target.deviceReferences()==2 && p.object.deviceReferences()==2 && !p.submit.stats().references_retired);
        passed("failed-reset-cannot-release-render-target");
    }
    CHECK(cases==16);std::printf("PASS: %u mapped-resource regression cases\n",cases);
    return 0;
}
