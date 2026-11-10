// SPDX-License-Identifier: MIT
#include "DodgeGraphicsLate.h"
#include "DodgeGopProvider.h"
#include "DodgeGraphicsBoot.h"
#include <IOKit/IOPlatformExpert.h>
#include <kern/thread.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

kern_return_t IOKitBSDInit(void);
static std::string mode;
static IOPlatformExpert platform;
static IOService *displayPeer=nullptr;
static thread_continue_t queued=nullptr;
static unsigned starts=0,deallocations=0,terminations=0,bootCalls=0,sleeps=0,reentries=0;
static bool resourcePublished=false,bootHardware=false,bootFailed=false;
static std::thread::id caller;
static void *const threadPeer=reinterpret_cast<void *>(uintptr_t(0x12345678));

static void reenter(const char *stage) {
    if(mode!=std::string("reentry-")+stage)return;
    assert(dodge_graphics_schedule()==(std::strcmp(stage,"terminate")?kIOReturnBusy:kIOReturnNotPermitted));++reentries;
}
IOPlatformExpert *IOService::getPlatform() {return mode=="platform-missing"?nullptr:&platform;}
void IOService::publishResource(const char *name) {assert(!std::strcmp(name,"IOBSD"));resourcePublished=true;}
bool PE_parse_boot_argn(const char *name,void *out,int size) {
    assert(!std::strcmp(name,"dodge-graphics") && size==4);
    *static_cast<unsigned *>(out)=mode=="flag-zero"?0:mode=="flag-other"?2:1;
    return mode!="flag-absent";
}
kern_return_t kernel_thread_start(thread_continue_t continuation,void *arg,thread_t *out) {
    assert(resourcePublished && !arg && continuation && out && *out==THREAD_NULL);++starts;reenter("queue");
    if(mode=="thread-failure" || (mode=="thread-failure-retry" && starts==1))return -1;
    assert(!queued);queued=continuation;*out=threadPeer;
    if(mode=="eager-worker")queued(nullptr,0);
    return KERN_SUCCESS;
}
void thread_deallocate(thread_t thread) {assert(thread==threadPeer);++deallocations;reenter("deallocate");}
thread_t current_thread() {return threadPeer;}
kern_return_t thread_terminate(thread_t thread) {assert(thread==threadPeer);++terminations;reenter("terminate");return 0;}
void IOSleep(unsigned milliseconds) {assert(milliseconds==10 && !bootHardware && !bootFailed);++sleeps;reenter("sleep");}
extern "C" IOReturn dodge_graphics_boot_gop(IOService *p,IOService **out) {
    assert(resourcePublished && p==&platform && out && !*out);++bootCalls;reenter("boot");
    if(mode!="eager-worker")assert(std::this_thread::get_id()!=caller);
    if(mode=="root-delay" && bootCalls<3)return kIOReturnNotReady;
    if((mode=="busy-delay" || mode=="reentry-sleep") && bootCalls<3)return kIOReturnBusy;
    if(mode=="root-timeout")return kIOReturnNotReady;
    if(mode=="unsupported")return kIOReturnUnsupported;
    if(mode=="latched-failure") {bootFailed=true;return kIOReturnNotReady;}
    if(mode=="hardware-failure" || mode=="hardware-busy") {bootHardware=true;return mode=="hardware-busy"?kIOReturnBusy:kIOReturnNotReady;}
    if(mode=="null-display")return kIOReturnSuccess;
    if(mode=="display-with-error") {*out=new IOService;return kIOReturnError;}
    displayPeer=new IOService;*out=displayPeer;return kIOReturnSuccess;
}
extern "C" void dodge_graphics_boot_status(DodgeGraphicsBootStatus *out) {
    *out={};out->phase=bootFailed?DodgeGraphicsBootPhase::Failed:DodgeGraphicsBootPhase::Cold;out->hardwareAttempted=bootHardware;
}

int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];caller=std::this_thread::get_id();
    if(mode=="platform-inactive")platform.inactive=true;
    if(mode=="concurrent-queue") {
        resourcePublished=true;std::atomic<unsigned> successes{0},busy{0};std::vector<std::thread> threads;
        for(unsigned i=0;i<16;++i)threads.emplace_back([&] {
            const IOReturn result=dodge_graphics_schedule();
            if(result==kIOReturnSuccess)++successes;else {assert(result==kIOReturnBusy);++busy;}
        });
        for(auto &thread:threads)thread.join();
        assert(successes==1 && busy==15 && starts==1 && deallocations==1);
    } else assert(IOKitBSDInit()==kIOReturnSuccess);
    DodgeGraphicsLateStatus status={};dodge_graphics_late_status(&status);
    if(mode=="flag-absent" || mode=="flag-zero" || mode=="flag-other") {
        assert(resourcePublished && !starts && !deallocations && !queued && !bootCalls && !sleeps);
        assert(status.phase==DodgeGraphicsLatePhase::Cold && !status.attempts && !status.displayRetained);goto done;
    }
    if(mode=="thread-failure" || mode=="thread-failure-retry") {
        assert(starts==1 && !queued && !deallocations && status.phase==DodgeGraphicsLatePhase::Cold && status.last==kIOReturnNoResources);
        if(mode=="thread-failure")goto done;
        assert(dodge_graphics_schedule()==kIOReturnSuccess);dodge_graphics_late_status(&status);
    }
    if(mode!="eager-worker") {
        assert(status.phase==DodgeGraphicsLatePhase::Queued && !status.attempts && !status.displayRetained && !bootCalls);
        assert(dodge_graphics_schedule()==kIOReturnBusy);
        std::thread worker([] {queued(nullptr,0);});worker.join();
    }
    dodge_graphics_late_status(&status);
    assert(status.phase==DodgeGraphicsLatePhase::Finished && terminations==1 && deallocations==1);
    assert(dodge_graphics_schedule()==kIOReturnNotPermitted);
    if(mode=="platform-missing" || mode=="platform-inactive" || mode=="root-timeout") {
        assert(status.attempts==200 && sleeps==199 && status.last==kIOReturnNotReady && !status.displayRetained);
        assert(bootCalls==(mode=="root-timeout"?200:0));
    } else if(mode=="unsupported" || mode=="latched-failure" || mode=="hardware-failure" || mode=="hardware-busy" ||
              mode=="null-display" || mode=="display-with-error") {
        assert(status.attempts==1 && bootCalls==1 && !sleeps && !status.displayRetained && status.last!=kIOReturnSuccess);
    } else {
        const bool delayed=mode=="root-delay" || mode=="busy-delay" || mode=="reentry-sleep";
        assert(status.attempts==(delayed?3:1) && bootCalls==status.attempts && sleeps==(delayed?2:0));
        assert(status.last==kIOReturnSuccess && status.displayRetained && displayPeer && displayPeer->references==1);
    }
    if(mode.rfind("reentry-",0)==0)assert(reentries==(mode=="reentry-sleep"?2:1));
done:
    dodge_graphics_late_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"thread_starts\":%u,\"boot_calls\":%u,\"retry_sleeps\":%u}\n",
        mode.c_str(),starts,bootCalls,sleeps);return 0;
}
