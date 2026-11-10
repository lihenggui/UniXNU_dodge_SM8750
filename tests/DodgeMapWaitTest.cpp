// SPDX-License-Identifier: MIT
// Actual wait helper and core map/fence code over the pinned software peers.
#define main pinned_userclient_main
#include "test_userclient.cpp"
#undef main
#include "DodgeMapWait.inc"
extern "C" volatile uint32_t native_adreno_wc_enabled;

struct WaitFixture {
    Path path;
    NativeAdrenoAbiBoMap request{};
    NativeAdrenoAbiBoMapReply reply{};
    uint64_t first=0,target=0,now=0;
    unsigned attempts=0,idles=0,clocks=0;
    bool held=false,finish=true,live=true,close=false,frozen=false,regress=false,fail_idle=false,fail_cache=false;
    WaitFixture(bool pending=true) {
        CHECK(!exposed(path));NativeAdrenoAbiBoAlloc alloc{4096,12,1};NativeAdrenoAbiBoAllocReply bo{};
        CHECK(!path.client.allocBo(&alloc,&bo));first=bo.handle;
        NativeAdrenoAbiBoMap initial{first,0x800000,3,0,2,0};CHECK(!path.client.mapBo(&initial,&reply));
        CHECK(!path.client.allocBo(&alloc,&bo));target=bo.handle;request={target,0x802000,3,0,2,0};reply={};
        if(pending) {
            NativeAdrenoAbiSubmit submit{};submit.buffer_count=1;submit.buffers[0]={first,0x800000,256};
            NativeAdrenoAbiSubmitReply fence{};CHECK(!path.client.submit(&submit,&fence,&ringclock) && fence.fence==1);
        }
    }
    static IOReturn attempt(void *opaque,bool *pending) {
        auto &f=*static_cast<WaitFixture *>(opaque);CHECK(!f.held);f.held=true;++f.attempts;
        const IOReturn value=f.live?f.path.client.dispatch(NativeAdrenoMethodBoMap,&f.request,sizeof(f.request),
            &f.reply,sizeof(f.reply),&ringclock):kIOReturnNotReady;
        *pending=value==kIOReturnBusy && f.live && f.path.client.mapMayWait(f.request.handle);
        f.held=false;return value;
    }
    static uint64_t clock(void *opaque) {
        auto &f=*static_cast<WaitFixture *>(opaque);CHECK(!f.held);++f.clocks;
        return f.regress && f.clocks>1?9:f.now;
    }
    static int idle(void *opaque) {
        auto &f=*static_cast<WaitFixture *>(opaque);CHECK(!f.held);++f.idles;
        if(f.fail_idle)return 1;
        if(!f.frozen)f.now+=1000;
        if(f.close)f.live=false;
        if(f.finish)fencemem[1]=1;
        if(f.fail_cache)fixture.cache_fail_call=fixture.cache_calls+1;
        return 0;
    }
    IOReturn run(uint64_t budget=1000000,uint32_t polls=16384) {
        const DodgeMapWaitOps ops{this,attempt,clock,idle};return dodge_adreno_wait_map(&ops,budget,polls);
    }
    void retained() {
        CHECK(path.client.memoryOf(first)->deviceReferences()==2 && !path.client.memoryOf(target)->deviceReferences());
    }
};

int main()
{
    // Keep owned memory cacheable to exercise the actual completion-acquire
    // error path, rather than a later SMMU-table maintenance failure.
    native_adreno_wc_enabled=0;
    unsigned cases=0;
    {
        WaitFixture f;CHECK(!f.run() && f.attempts==2 && f.idles==1 && f.reply.iova==0x802000);
        CHECK(!f.path.execbuf.outstanding() && f.path.client.mapped(f.target));++cases;
    }
    {
        WaitFixture f;f.finish=false;CHECK(f.run(1000)==kIOReturnTimeout && f.attempts==2 && f.idles==1);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.fail_idle=true;CHECK(f.run()==kIOReturnIOError && f.attempts==1 && f.idles==1);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.now=10;f.regress=true;CHECK(f.run()==kIOReturnIOError && f.attempts==1 && !f.idles);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.finish=false;f.close=true;CHECK(f.run()==kIOReturnNotReady && f.attempts==2 && f.idles==1);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.request.handle=99999;CHECK(f.run()==kIOReturnBadArgument && f.attempts==1 && !f.idles);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.request.handle=f.first;f.request.iova=0x800000;
        CHECK(f.run()==kIOReturnBusy && f.attempts==1 && !f.idles);f.retained();++cases;
    }
    {
        WaitFixture f;DodgeMapWaitOps ops{&f,WaitFixture::attempt,WaitFixture::clock,WaitFixture::idle};
        CHECK(dodge_adreno_wait_map(nullptr,1000,1)==kIOReturnBadArgument);
        CHECK(dodge_adreno_wait_map(&ops,0,1)==kIOReturnBadArgument && dodge_adreno_wait_map(&ops,1,0)==kIOReturnBadArgument);
        ops.attempt=nullptr;CHECK(dodge_adreno_wait_map(&ops,1,1)==kIOReturnBadArgument);
        ops.attempt=WaitFixture::attempt;ops.now=nullptr;CHECK(dodge_adreno_wait_map(&ops,1,1)==kIOReturnBadArgument);
        ops.now=WaitFixture::clock;ops.idle=nullptr;CHECK(dodge_adreno_wait_map(&ops,1,1)==kIOReturnBadArgument);
        CHECK(!f.attempts && !f.idles && !f.clocks);++cases;
    }
    {
        WaitFixture f(false);CHECK(!f.run() && f.attempts==1 && !f.idles && f.reply.iova==0x802000);++cases;
    }
    {
        WaitFixture f;f.finish=false;f.frozen=true;CHECK(f.run(1000,4)==kIOReturnTimeout && f.attempts==4 && f.idles==3);
        f.retained();++cases;
    }
    {
        WaitFixture f;f.fail_cache=true;CHECK(f.run()==kIOReturnIOError && f.attempts==2 && f.idles==1);
        CHECK(f.path.execbuf.poisoned() && !f.path.client.mapped(f.target));f.retained();fixture.cache_fail_call=0;++cases;
    }
    {
        WaitFixture f;f.finish=false;CHECK(f.run(1000,1)==kIOReturnTimeout && f.attempts==1 && !f.idles);
        f.retained();++cases;
    }
    CHECK(cases==12);std::printf("PASS: %u bounded map-wait integration cases; clock/idle always outside fixture lock\n",cases);
    return 0;
}
