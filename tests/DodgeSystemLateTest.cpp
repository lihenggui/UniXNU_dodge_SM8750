// SPDX-License-Identifier: MIT
#include "DodgeSystemLate.h"
#include "DodgeUfsLifecycle.h"
#include <IOKit/IOPlatformExpert.h>
#include <kern/thread.h>
#include <cassert>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

static std::string mode;
static IOPlatformExpert platform;
static IOService root;
static thread_continue_t continuation=nullptr;
static unsigned starts=0,deallocations=0,terminations=0,rootCalls=0,graphicsCalls=0,sleeps=0,released=0,reentries=0;
static bool hardware=false,failed=false;
static void *const threadPeer=reinterpret_cast<void *>(uintptr_t(0x12345678));
static void reenter(const char *stage) {
    if(mode!=std::string("reentry-")+stage)return;
    assert(dodge_system_schedule()==kIOReturnBusy);++reentries;
}
IOPlatformExpert *IOService::getPlatform() {return mode=="no-platform"?nullptr:&platform;}
bool PE_parse_boot_argn(const char *name,void *out,int bytes) {
    assert(!std::strcmp(name,"native-ufs-root") && bytes==4);
    *static_cast<unsigned *>(out)=mode=="root-zero"?0:mode=="root-other"?2:1;return mode!="root-absent";
}
kern_return_t kernel_thread_start(thread_continue_t entry,void *arg,thread_t *out) {
    assert(entry && !arg && out && *out==THREAD_NULL);++starts;reenter("queue");
    if(mode=="thread-failure" || (mode=="thread-retry" && starts==1))return -1;
    continuation=entry;*out=threadPeer;
    if(mode=="eager-worker")continuation(nullptr,0);
    return 0;
}
void thread_deallocate(thread_t t) {assert(t==threadPeer);++deallocations;}
thread_t current_thread() {return threadPeer;}
kern_return_t thread_terminate(thread_t t) {assert(t==threadPeer);++terminations;return 0;}
void IOSleep(unsigned ms) {assert(ms==10 && !hardware && !failed);++sleeps;reenter("sleep");}
struct OwnedDriver final : IOService {~OwnedDriver() override {++released;reenter("release");}};
extern "C" IOReturn dodge_ufs_start(IOService *p,IOService **out) {
    assert(p==&root && out && !*out);++rootCalls;reenter("root");
    if((mode=="delayed" || mode=="reentry-sleep") && rootCalls<3)return kIOReturnNotReady;
    if(mode=="timeout")return kIOReturnBusy;
    if(mode=="unsupported")return kIOReturnUnsupported;
    if(mode=="metadata-failed") {failed=true;return kIOReturnNotReady;}
    if(mode=="hardware-failed") {hardware=true;return kIOReturnNotReady;}
    if(mode=="null-driver")return 0;
    if(mode=="driver-with-error") {*out=new OwnedDriver;return kIOReturnError;}
    *out=new OwnedDriver;return 0;
}
extern "C" void dodge_ufs_status(DodgeUfsStatus *out) {
    *out={};out->phase=failed?DodgeUfsPhase::Failed:DodgeUfsPhase::Cold;out->startAttempted=hardware;
}
extern "C" IOReturn dodge_graphics_schedule() {
    ++graphicsCalls;reenter("graphics");
    if(mode!="root-zero" && mode!="root-other" && mode!="root-absent")assert(rootCalls && released==1 && !failed && !hardware);
    return mode=="graphics-disabled"?kIOReturnNotPermitted:mode=="graphics-queue-failed"?kIOReturnNoResources:kIOReturnSuccess;
}
int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];platform.parent=mode=="no-root"?nullptr:&root;
    if(mode=="inactive-platform")platform.inactive=true;
    IOReturn result=0;
    if(mode=="concurrent-queue") {
        unsigned successes=0,busy=0;std::vector<std::thread> threads;
        // Serial ownership of result counters; the real CAS itself races.
        std::atomic<unsigned> ok{0},blocked{0};
        for(unsigned i=0;i<16;++i)threads.emplace_back([&] {const auto r=dodge_system_schedule();if(!r)++ok;else {assert(r==kIOReturnBusy);++blocked;}});
        for(auto &t:threads)t.join();
        successes=ok;busy=blocked;assert(successes==1 && busy==15);
    } else result=dodge_system_schedule();
    DodgeSystemLateStatus status={};dodge_system_late_status(&status);
    if(mode=="root-zero" || mode=="root-other" || mode=="root-absent") {
        assert(!result && graphicsCalls==1 && !starts && !rootCalls && status.phase==DodgeSystemLatePhase::Cold);goto done;
    }
    if(mode=="thread-failure" || mode=="thread-retry") {
        assert(result==kIOReturnNoResources && !continuation && status.phase==DodgeSystemLatePhase::Cold && !graphicsCalls);
        if(mode=="thread-failure")goto done;
        assert(!dodge_system_schedule());
    } else assert(!result);
    if(mode!="eager-worker") {assert(continuation && !rootCalls);std::thread worker([] {continuation(nullptr,0);});worker.join();}
    dodge_system_late_status(&status);assert(status.phase==DodgeSystemLatePhase::Finished && deallocations==1 && terminations==1);
    assert(dodge_system_schedule()==kIOReturnNotPermitted);
    if(mode=="no-platform" || mode=="inactive-platform" || mode=="no-root" || mode=="timeout") {
        assert(status.attempts==200 && sleeps==199 && !graphicsCalls && !status.storageStarted && status.storageLast);
    } else if(mode=="metadata-failed" || mode=="hardware-failed" || mode=="unsupported" || mode=="null-driver" || mode=="driver-with-error") {
        assert(rootCalls==1 && !sleeps && !graphicsCalls && !status.storageStarted && status.storageLast);
    } else {
        assert(graphicsCalls==1 && released==1 && status.storageStarted && !status.storageLast);
        if(mode=="delayed" || mode=="reentry-sleep")assert(rootCalls==3 && sleeps==2);
        else assert(rootCalls==1 && !sleeps);
        if(mode=="graphics-disabled")assert(status.graphicsScheduleLast==kIOReturnNotPermitted);
        if(mode=="graphics-queue-failed")assert(status.graphicsScheduleLast==kIOReturnNoResources);
    }
    if(mode.rfind("reentry-",0)==0)assert(reentries==(mode=="reentry-sleep"?2:1));
done:
    dodge_system_late_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"root_calls\":%u,\"graphics_calls\":%u,\"sleeps\":%u}\n",
        mode.c_str(),rootCalls,graphicsCalls,sleeps);
}
