// SPDX-License-Identifier: MIT
// Production VM, scheduler and user-client through the upstream MMIO/page peers.
#define main pinned_userclient_main
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type"
#include "test_userclient.cpp"
#pragma clang diagnostic pop
#undef main
#include "DodgeMapWait.inc"
#include "DodgeNativeSurface.h"
#include "DodgeNativeSurfacePeers.h"
#include "DodgeSurfaceImportHint.h"
#include "Adreno830Status.h"
#include <mutex>
#include <thread>

static unsigned cases;
extern "C" int pagani_gpu_status(char [7][80]);
static void passed(const char *name) {++cases;std::printf("PASS: %s\n",name);}
static uint64_t importMapped(Path &p,uint64_t address,unsigned permissions=3)
{
    NativeAdrenoAbiBoImport request{0x10000000,4096};NativeAdrenoAbiBoAllocReply bo{};
    CHECK(!p.client.importBo(&request,reinterpret_cast<void *>(2),&bo));
    NativeAdrenoAbiBoMap map{bo.handle,address,permissions,0,2,0};NativeAdrenoAbiBoMapReply reply{};
    CHECK(!p.client.mapBo(&map,&reply));return bo.handle;
}
static uint32_t commit(Path &p,uint64_t handle,uint32_t queue=0)
{
    NativeAdrenoAbiSubmit request{};request.buffer_count=1;request.queue=queue;
    request.buffers[0]={handle,Base,256};NativeAdrenoAbiSubmitReply reply{};
    CHECK(!p.client.submit(&request,&reply,&ringclock) && reply.fence);return uint32_t(reply.fence);
}
static void finished(Path &p,uint32_t fence)
{complete(fence);CHECK(!p.execbuf.wait(fence,&ringclock,0));}
static void freed(Path &p,uint64_t handle)
{NativeAdrenoAbiBoFree request{handle};CHECK(!p.client.freeBo(&request));}

int main()
{
    {
        Path p;CHECK(!exposed(p));NativeAdrenoStatus counters;uint32_t lost=0,recovering=0;
        counters.attachLifecycle(&lost,&recovering);CHECK(!p.client.attachStatus(&counters));
        NativeAdrenoAbiStatus status{};CHECK(!p.client.status(&status) && !status.faults);
        __atomic_store_n(&recovering,1u,__ATOMIC_RELEASE);counters.noteFault();
        CHECK(p.client.status(&status)==kIOReturnBusy && !status.faults && !status.suspends);
        counters.noteSuspend();__atomic_store_n(&recovering,0u,__ATOMIC_RELEASE);
        CHECK(!p.client.status(&status) && status.faults==1 && status.suspends==1);
        const auto ib=allocMapped(p.client,4096,Base);const auto fence=commit(p,ib);finished(p,fence);freed(p,ib);
        __atomic_store_n(&lost,1u,__ATOMIC_RELEASE);__atomic_store_n(&recovering,1u,__ATOMIC_RELEASE);
        CHECK(p.client.status(&status)==NativeAdrenoReturnNotResponding && !status.faults && !status.suspends);
        passed("status-distinguishes-recovery-terminal-loss-and-recovered-resource-use");
    }
    {
        struct Output {char rows[7][80];uint64_t canary=0x123456789abcdef;};Output out{};
        CHECK(!pagani_gpu_status(out.rows));char input[Adreno830StatusRows][Adreno830StatusRowBytes];
        memset(input,'x',sizeof input);boot_progress_gpu_rows(input,Adreno830StatusRows);
        CHECK(pagani_gpu_status(out.rows)==1 && out.canary==0x123456789abcdef);
        for(unsigned i=0;i<7;++i)for(unsigned j=0;j<80;++j)
            CHECK(out.rows[i][j]==(i<4 && j<Adreno830StatusRowMax?'x':0));
        boot_progress_gpu_rows(nullptr,1);CHECK(pagani_gpu_status(out.rows)==1);
        passed("native-diagnostic-rows-bridge-with-bounded-padding-and-output-canary");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=importMapped(p,Base+4096);auto *memory=p.client.memoryOf(target);
        const uint32_t fence=commit(p,ib);CHECK(memory->deviceReferences()==2);
        NativeAdrenoAbiBoFree request{target};CHECK(p.client.freeBo(&request)==kIOReturnBusy);
        CHECK(p.execbuf.wait(fence,&ringclock,0)==kIOReturnTimeout && memory->deviceReferences()==2);
        const unsigned cache=fixture.physical_calls;finished(p,fence);
        CHECK(memory->deviceReferences()==1 && fixture.physical_calls>cache);freed(p,target);freed(p,ib);
        passed("indirect-import-held-through-timeout-and-acquired-before-release");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=allocMapped(p.client,4096,Base+4096);auto *memory=p.client.memoryOf(target);
        const uint32_t first=commit(p,ib),second=commit(p,ib);CHECK(memory->deviceReferences()==3);
        finished(p,first);CHECK(memory->deviceReferences()==2 && p.vm.hasMappedJobs());
        finished(p,second);CHECK(memory->deviceReferences()==1 && !p.vm.hasMappedJobs());
        freed(p,target);freed(p,ib);passed("overlapping-jobs-retire-only-their-own-holds");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto fence=commit(p,ib);NativeAdrenoAbiBoAlloc request{4096,12,0};NativeAdrenoAbiBoAllocReply bo{};
        CHECK(!p.client.allocBo(&request,&bo));NativeAdrenoAbiBoMap map{bo.handle,Base+4096,3,0,2,0};
        NativeAdrenoAbiBoMapReply reply{};const unsigned accesses=mf.calls;
        CHECK(p.client.mapBo(&map,&reply)==kIOReturnBusy && !reply.iova && p.client.mapMayWait(bo.handle));
        CHECK(mf.calls==accesses && !p.client.memoryOf(bo.handle)->deviceReferences());
        complete(fence);CHECK(!p.client.mapBo(&map,&reply) && !p.vm.hasMappedJobs());
        freed(p,bo.handle);freed(p,ib);passed("new-map-waits-without-touching-pages-or-tables-then-reaps-fence");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=allocMapped(p.client,4096,Base+4096);p.client.memoryOf(target)->quarantine();
        const auto wptr=cp.regs[0x0807];NativeAdrenoAbiSubmit request{};request.buffer_count=1;
        request.buffers[0]={ib,Base,256};NativeAdrenoAbiSubmitReply reply{99};
        CHECK(p.client.submit(&request,&reply,&ringclock)==kIOReturnNotReady && !reply.fence);
        CHECK(p.client.memoryOf(ib)->deviceReferences()==1 && cp.regs[0x0807]==wptr && !p.execbuf.outstanding());
        passed("quarantined-indirect-resource-refuses-before-publication");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=importMapped(p,Base+4096);cp.fail_publish=cp.publish+1;
        NativeAdrenoAbiSubmit request{};request.buffer_count=1;request.buffers[0]={ib,Base,256};
        NativeAdrenoAbiSubmitReply reply{};CHECK(p.client.submit(&request,&reply,&ringclock)==kIOReturnIOError);
        CHECK(!reply.fence && p.execbuf.poisoned() && p.client.memoryOf(target)->deviceReferences()==2);
        complete(1);CHECK(p.execbuf.retireCompleted()==kIOReturnNotReady && p.execbuf.outstanding()==1);
        // This fixture represents the caller's successful quiescing reset.
        // A software fence observation above could not retire the unknown job.
        uint32_t last=0;CHECK(!p.ring.recover(&last));
        uint32_t abandoned=0;CHECK(!p.execbuf.recover(&abandoned) && abandoned==1);
        CHECK(p.client.memoryOf(target)->deviceReferences()==1 && !p.vm.hasMappedJobs());
        passed("uncertain-commit-kept-until-explicit-quiescing-recovery");
    }
    {
        native_adreno_wc_enabled=0;
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=allocMapped(p.client,4096,Base+4096);const auto fence=commit(p,ib);
        fixture.cache_fail_call=fixture.cache_calls+2;complete(fence);
        CHECK(p.execbuf.wait(fence,&ringclock,0)==kIOReturnIOError && p.vm.poisoned() && p.execbuf.poisoned());
        CHECK(p.client.memoryOf(ib)->deviceReferences()==2 && p.client.memoryOf(target)->deviceReferences()==2);
        CHECK(!p.execbuf.stats().references_retired && p.execbuf.outstanding()==1);
        fixture.cache_fail_call=0;native_adreno_wc_enabled=1;
        passed("completion-cache-failure-keeps-the-entire-resource-set");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        const auto target=importMapped(p,Base+4096,ArmSmmu4KRead);const auto fence=commit(p,ib);
        const auto cache=fixture.physical_calls;finished(p,fence);CHECK(fixture.physical_calls==cache);
        freed(p,target);freed(p,ib);passed("read-only-import-has-no-device-write-acquisition");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        uint64_t before=0;size_t count=0;CHECK(!p.vm.holdMapped(&before,&count) && count==1);
        CHECK(p.vm.retireMapped(before,count+1,true)==kIOReturnBadArgument);
        CHECK(p.vm.retireMapped(before+1,count,true)==kIOReturnBadArgument && p.client.memoryOf(ib)->deviceReferences()==2);
        CHECK(!p.vm.retireMapped(before,count,false) && !p.vm.hasMappedJobs());
        CHECK(p.vm.retireMapped(before,count,false)==kIOReturnBadArgument);freed(p,ib);
        passed("invalid-and-duplicate-retirement-cannot-release-a-lease");
    }
    {
        Path p;CHECK(!exposed(p));NativeAdrenoAbiPriority priority{1,3};NativeAdrenoAbiNote note{};
        CHECK(p.client.dispatch(17,&priority,sizeof priority,nullptr,0,&ringclock)==kIOReturnUnsupported);
        CHECK(p.client.dispatch(17,&priority,sizeof priority-1,nullptr,0,&ringclock)==kIOReturnBadArgument);
        CHECK(p.client.dispatch(18,&note,sizeof note,nullptr,0,&ringclock)==kIOReturnUnsupported);
        CHECK(p.client.dispatch(18,nullptr,sizeof note,nullptr,0,&ringclock)==kIOReturnBadArgument);
        NativeAdrenoAbiParams params{};CHECK(!p.client.query(&params) &&
            params.flags==(uint32_t(NativeAdrenoParamsHostImport)|uint32_t(NativeAdrenoParamsSurfaceImport)));
        passed("optional-frontend-records-validated-without-false-capability-flags");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);
        uint64_t boundary=0;size_t count=0;CHECK(!p.vm.holdMapped(&boundary,&count));
        std::thread worker([&] {
            uint64_t next=0;size_t held=0;CHECK(!p.vm.holdMapped(&next,&held));
            CHECK(next==boundary && held==count && p.vm.hasMappedJobs());
            CHECK(!p.vm.retireMapped(next,held,false));
        });worker.join();
        CHECK(p.client.memoryOf(ib)->deviceReferences()==2 && !p.vm.retireMapped(boundary,count,false));
        freed(p,ib);passed("VM-lock-serializes-concurrent-snapshot-leases");
    }
    CHECK(!dodge_native_surface_initialize());
    {
        DodgeSurfaceImportHint hint;const auto *pointer=reinterpret_cast<const void *>(0x10000000);
        CHECK(!hint.begin(0,pointer,4096) && !hint.begin(1,pointer,0) && !hint.begin(1,pointer,4095));
        CHECK(!hint.begin(1,reinterpret_cast<const void *>(UINTPTR_MAX-4095),8192));
        CHECK(hint.begin(42,pointer,4096) && !hint.begin(43,pointer,4096));
        CHECK(!hint.matches(pointer,8192) && hint.matches(pointer,4096) && !hint.end() && !hint.id);
        CHECK(hint.begin(43,pointer,4096));hint.used=true;CHECK(!hint.matches(pointer,4096) && hint.end() && !hint.id);
        passed("surface-hint-rejects-invalid-nested-mismatched-and-unconsumed-imports");
    }
    auto surfaceImport=[](Path &p,OSObject &surface,uint64_t address,uint32_t id=42)->uint64_t {
        DodgeSurfaceIdentity identity{&surface,id};NativeAdrenoAbiSurfaceImport request{0x10000000,4096,id,0};
        NativeAdrenoAbiBoAllocReply bo{};
        CHECK(!p.client.importSurface(&request,reinterpret_cast<void *>(2),&identity,
            reinterpret_cast<IOMemoryDescriptor *>(2),&bo) && !identity.surface);
        CHECK(p.client.memoryOf(bo.handle)->deviceReferences()==1);
        NativeAdrenoAbiBoMap map{bo.handle,address,3,0,2,0};NativeAdrenoAbiBoMapReply mapped{};
        CHECK(!p.client.mapBo(&map,&mapped));return bo.handle;
    };
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto ib=allocMapped(p.client,4096,Base);
        const auto target=surfaceImport(p,surface,Base+4096);void *batch=nullptr;
        struct SignalCheck {
            NativeAdrenoMemory *memory;unsigned cache;bool called=false;
            std::mutex ring,allocation;unsigned depth=0;
        };
        SignalCheck check{p.client.memoryOf(target),fixture.physical_calls};
        const NativeAdrenoSubmitLocks locks{&check,
            [](void *opaque,NativeAdrenoSubmitLock which) {
                auto &c=*static_cast<SignalCheck *>(opaque);
                (which==NativeAdrenoSubmitLockRing?c.ring:c.allocation).lock();++c.depth;
            },
            [](void *opaque,NativeAdrenoSubmitLock which) {
                auto &c=*static_cast<SignalCheck *>(opaque);--c.depth;
                (which==NativeAdrenoSubmitLockRing?c.ring:c.allocation).unlock();
            }};
        CHECK(!p.execbuf.attachLocks(&locks));
        dodge_test_signal_context=&check;
        dodge_test_signal_check=[](void *opaque) {
            auto &check=*static_cast<SignalCheck *>(opaque);
            CHECK(!check.depth && check.memory->deviceReferences()==2 && fixture.physical_calls>check.cache);check.called=true;
        };
        CHECK(!dodge_native_surface_prepare(&p.vm,&batch) && dodge_test_tickets.size()==1);
        CHECK(!dodge_test_tickets[0]->signalled && p.client.memoryOf(target)->deviceReferences()==3);
        p.client.setSubmissionOwner(batch);const auto fence=commit(p,ib);p.client.setSubmissionOwner(nullptr);
        dodge_native_surface_end_call(&batch);CHECK(!batch && !dodge_test_tickets[0]->signalled);
        CHECK(p.client.memoryOf(target)->deviceReferences()==4);
        const auto cache=fixture.physical_calls;check.cache=cache;
        finished(p,fence);CHECK(!dodge_test_tickets[0]->signalled);
        dodge_native_surface_drain();CHECK(dodge_test_tickets[0]->signalled && !dodge_test_tickets[0]->result);
        CHECK(fixture.physical_calls>cache && p.client.memoryOf(target)->deviceReferences()==2 && check.called);
        freed(p,target);freed(p,ib);dodge_test_clear_tickets();
        passed("surface-ID-import-producer-grant-submit-fence-cache-signal-and-free");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto ib=allocMapped(p.client,4096,Base);
        const auto target=surfaceImport(p,surface,Base+4096);void *batch=nullptr;
        dodge_test_grant_immediately=false;CHECK(dodge_native_surface_prepare(&p.vm,&batch)==NativeAdrenoSubmitRetry);
        p.client.setSubmissionOwner(batch);NativeAdrenoAbiSubmit request{};request.buffer_count=1;request.buffers[0]={ib,Base,256};
        NativeAdrenoAbiSubmitReply reply{};const auto wptr=cp.regs[0x0807];
        CHECK(p.client.submit(&request,&reply,&ringclock)==kIOReturnNotReady && cp.regs[0x0807]==wptr);
        p.client.setSubmissionOwner(nullptr);dodge_test_grant_pending();
        CHECK(!dodge_native_surface_prepare(&p.vm,&batch));
        dodge_native_surface_end_call(&batch);dodge_native_surface_drain();
        CHECK(dodge_test_tickets[0]->result==kIOReturnAborted && !p.vm.hasMappedJobs());
        freed(p,target);freed(p,ib);dodge_test_clear_tickets();
        passed("pending-original-grant-refuses-GPU-publication-and-can-be-cancelled-after-grant");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto target=surfaceImport(p,surface,Base);void *batch=nullptr;
        dodge_test_grant_immediately=false;CHECK(dodge_native_surface_prepare(&p.vm,&batch)==NativeAdrenoSubmitRetry);
        dodge_native_surface_end_call(&batch);dodge_native_surface_drain();
        CHECK(!dodge_test_tickets[0]->signalled && p.client.memoryOf(target)->deviceReferences()==3);
        dodge_test_grant_pending();dodge_native_surface_drain();
        CHECK(dodge_test_tickets[0]->signalled && dodge_test_tickets[0]->result==kIOReturnAborted && !p.vm.hasMappedJobs());
        freed(p,target);dodge_test_clear_tickets();
        passed("cancelled-pending-callback-context-and-pages-retained-until-real-grant");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto target=surfaceImport(p,surface,Base);void *batch=nullptr;
        dodge_test_grant_immediately=false;CHECK(dodge_native_surface_prepare(&p.vm,&batch)==NativeAdrenoSubmitRetry);
        std::thread worker([] {dodge_test_grant_pending();dodge_native_surface_drain();});
        dodge_native_surface_end_call(&batch);worker.join();dodge_native_surface_drain();
        CHECK(dodge_test_tickets[0]->signalled && !p.vm.hasMappedJobs());freed(p,target);dodge_test_clear_tickets();
        passed("grant-and-cancellation-on-different-threads-preserve-callback-ownership");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;
        const auto first=surfaceImport(p,surface,Base),second=surfaceImport(p,surface,Base+4096);
        void *batch=nullptr;CHECK(!dodge_native_surface_prepare(&p.vm,&batch) && dodge_test_tickets.size()==1);
        dodge_native_surface_end_call(&batch);dodge_native_surface_drain();
        CHECK(p.client.memoryOf(first)->deviceReferences()==2 && p.client.memoryOf(second)->deviceReferences()==2);
        freed(p,second);freed(p,first);dodge_test_clear_tickets();passed("aliased-surface-imports-share-one-original-producer-ticket");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto target=surfaceImport(p,surface,Base);void *batch=nullptr;
        dodge_test_pages_current=false;CHECK(dodge_native_surface_prepare(&p.vm,&batch)==kIOReturnNotReady);
        dodge_native_surface_end_call(&batch);dodge_native_surface_drain();CHECK(!p.vm.hasMappedJobs() && dodge_test_tickets.empty());
        dodge_test_pages_current=true;freed(p,target);passed("stale-backing-before-registration-rolls-back-without-a-ticket");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto target=surfaceImport(p,surface,Base);void *batch=nullptr;
        dodge_test_register_failure=true;CHECK(dodge_native_surface_prepare(&p.vm,&batch)==kIOReturnNoResources);
        dodge_native_surface_end_call(&batch);dodge_native_surface_drain();CHECK(!p.vm.hasMappedJobs());
        dodge_test_register_failure=false;freed(p,target);passed("original-registration-failure-releases-unpublished-snapshot");
    }
    {
        Path p;CHECK(!exposed(p));const auto ib=allocMapped(p.client,4096,Base);void *batch=nullptr;
        CHECK(!dodge_native_surface_prepare(&p.vm,&batch));p.client.setSubmissionOwner(batch);
        const auto fence=commit(p,ib);p.client.setSubmissionOwner(nullptr);finished(p,fence);
        dodge_native_surface_drain(); // Registry drops its reference before the caller returns.
        dodge_native_surface_end_call(&batch);CHECK(!batch && !p.vm.hasMappedJobs());freed(p,ib);
        passed("completion-before-submit-caller-returns-keeps-owner-reference-valid");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface,other;const auto ib=allocMapped(p.client,4096,Base);
        const auto target=surfaceImport(p,surface,Base+4096,4101);
        for(unsigned repeat=0;repeat<2;++repeat) {
            void *batch=nullptr;CHECK(dodge_native_surface_visible(&surface,4101));
            CHECK(!dodge_native_surface_prepare(&p.vm,&batch));p.client.setSubmissionOwner(batch);
            const auto fence=commit(p,ib);p.client.setSubmissionOwner(nullptr);dodge_native_surface_end_call(&batch);
            uint32_t ranges=0;CHECK(!p.execbuf.halt(&ranges));uint32_t last=0;
            CHECK(!p.ring.recover(&last) && last==fence);
            uint32_t abandoned=0;const auto epoch=dodge_test_epoch.load();
            CHECK(!p.execbuf.recover(&abandoned) && abandoned==1 && dodge_test_epoch>epoch);
            p.execbuf.resume();
            CHECK(!dodge_native_surface_healthy() && !dodge_test_tickets[0]->signalled);
            dodge_native_surface_drain();CHECK(dodge_test_tickets[0]->result==kIOReturnAborted);
            CHECK(dodge_native_surface_healthy() && !dodge_native_surface_visible(&surface,4101));
            CHECK(dodge_native_surface_visible(&other,4102) && dodge_native_surface_visible(&surface,4102));
            dodge_test_clear_tickets();
            CHECK(!dodge_native_surface_prepare(&p.vm,&batch));
            dodge_native_surface_end_call(&batch);dodge_native_surface_drain();
            CHECK(!dodge_native_surface_visible(&surface,4101));dodge_test_clear_tickets();
            CHECK(!dodge_native_surface_prepare(&p.vm,&batch));p.client.setSubmissionOwner(batch);
            const auto repair=commit(p,ib);p.client.setSubmissionOwner(nullptr);dodge_native_surface_end_call(&batch);
            CHECK(repair>fence && !dodge_native_surface_visible(&surface,4101));
            finished(p,repair);CHECK(!dodge_native_surface_visible(&surface,4101));
            dodge_native_surface_drain();CHECK(dodge_native_surface_visible(&surface,4101));
            CHECK(dodge_test_tickets[0]->signalled && !dodge_test_tickets[0]->result);dodge_test_clear_tickets();
        }
        freed(p,target);freed(p,ib);
        passed("reset-invalidates-failed-surface-until-its-own-successful-writer-and-supports-repeated-recovery");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto ib=allocMapped(p.client,4096,Base);
        const auto target=surfaceImport(p,surface,Base+4096);void *batch=nullptr;
        CHECK(!dodge_native_surface_prepare(&p.vm,&batch));p.client.setSubmissionOwner(batch);
        const auto fence=commit(p,ib);p.client.setSubmissionOwner(nullptr);dodge_native_surface_end_call(&batch);
        const auto epoch=dodge_test_epoch.load();dodge_native_surface_changed(&surface);
        CHECK(dodge_test_epoch==epoch+1 && !dodge_native_surface_healthy());
        CHECK(p.client.memoryOf(target)->deviceReferences()==4 && !dodge_test_tickets[0]->signalled);
        finished(p,fence);dodge_native_surface_drain();CHECK(dodge_test_tickets[0]->result==kIOReturnAborted);
        freed(p,target);freed(p,ib);dodge_test_clear_tickets();
        passed("inflight-backing-mutation-latches-display-failure-and-waits-for-GPU-fence");
    }
    {
        Path p;CHECK(!exposed(p));OSObject surface;const auto ib=allocMapped(p.client,4096,Base);
        const auto target=surfaceImport(p,surface,Base+4096,9801);void *batch=nullptr;
        CHECK(!dodge_native_surface_prepare(&p.vm,&batch));p.client.setSubmissionOwner(batch);
        const auto fence=commit(p,ib);p.client.setSubmissionOwner(nullptr);dodge_native_surface_end_call(&batch);
        finished(p,fence);dodge_test_signal_error=kIOReturnNotReady;const auto epoch=dodge_test_epoch.load();
        dodge_native_surface_drain();CHECK(!dodge_native_surface_healthy() && dodge_test_epoch>epoch);
        CHECK(!dodge_test_tickets[0]->released && !dodge_test_tickets[0]->signalled && dodge_test_signal_calls==1);
        CHECK(!p.vm.hasMappedJobs());dodge_native_surface_drain();CHECK(dodge_test_signal_calls==1);
        CHECK(dodge_native_surface_prepare(&p.vm,&batch)==NativeAdrenoSubmitRetry && !batch);
        freed(p,target);freed(p,ib);
        passed("unconfirmed-original-signal-keeps-callback-context-and-tickets-quarantined");
    }
    std::printf("PASS: %u native iPhone resource and protocol cases\n",cases);
}
