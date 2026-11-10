// SPDX-License-Identifier: MIT
#include "DodgeInputLate.h"
#include "DodgeInputLifecycle.h"
#include "DodgeSystemLate.h"
#include "DodgeGraphicsLate.h"
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
static unsigned queues=0,deallocations=0,terminations=0,sleeps=0,calls[2]={},released=0,reentries=0;
static bool attempted[2]={};
static void *const peer=reinterpret_cast<void *>(uintptr_t(0x12345678));
static void reenter(const char *stage) {if(mode==std::string("reentry-")+stage){assert(dodge_input_schedule()==kIOReturnBusy);++reentries;}}
IOPlatformExpert *IOService::getPlatform() {return mode=="no-platform"?nullptr:&platform;}
bool PE_parse_boot_argn(const char *name,void *out,int bytes) {
    assert(bytes==4);bool on=false;
    if(!std::strcmp(name,"dodge-input")) {on=mode!="disabled" && mode!="missing";if(mode=="other") {*static_cast<unsigned *>(out)=2;return true;}}
    else if(!std::strcmp(name,"native-ufs-root"))on=mode=="wait-storage" || mode=="storage-timeout";
    else if(!std::strcmp(name,"dodge-graphics"))on=mode=="wait-graphics" || mode=="graphics-timeout";
    else assert(false);
    *static_cast<unsigned *>(out)=on;return mode!="missing";
}
kern_return_t kernel_thread_start(thread_continue_t entry,void *arg,thread_t *out) {
    assert(entry && !arg && *out==THREAD_NULL);++queues;reenter("queue");
    if(mode=="thread-failure" || (mode=="thread-retry" && queues==1))return -1;
    continuation=entry;*out=peer;if(mode=="eager")entry(nullptr,0);return 0;
}
void thread_deallocate(thread_t t){assert(t==peer);++deallocations;}
thread_t current_thread(){return peer;}
kern_return_t thread_terminate(thread_t t){assert(t==peer);++terminations;return 0;}
void IOSleep(unsigned ms){assert(ms==10);++sleeps;reenter("sleep");}
extern "C" void dodge_system_late_status(DodgeSystemLateStatus *s){*s={};s->phase=mode=="wait-storage" && sleeps>=3?DodgeSystemLatePhase::Finished:DodgeSystemLatePhase::Running;}
extern "C" void dodge_graphics_late_status(DodgeGraphicsLateStatus *s){*s={};s->phase=mode=="wait-graphics" && sleeps>=4?DodgeGraphicsLatePhase::Finished:DodgeGraphicsLatePhase::Running;}
struct Driver final:IOService{~Driver() override{++released;reenter("release");}};
extern "C" IOReturn dodge_input_start(IOService *p,bool touch,IOService **out){
    assert(p==&root && out && !*out);unsigned d=touch?1:0;++calls[d];reenter("start");
    if(mode=="wait-storage")assert(sleeps>=3);
    if(mode=="wait-graphics")assert(sleeps>=4);
    if((mode=="busy" || mode=="reentry-sleep") && calls[d]<3)return kIOReturnBusy;
    if(mode=="prestart-timeout")return kIOReturnNotReady;
    if(mode=="unsupported")return kIOReturnUnsupported;
    if(mode=="metadata-failed" || mode=="init-failed")return kIOReturnNotReady;
    attempted[d]=true;
    if(mode=="keys-failed" && !touch)return kIOReturnNotReady;
    if(mode=="touch-failed" && touch)return kIOReturnNotReady;
    if(mode=="null-driver")return 0;
    *out=new Driver;return mode=="driver-with-error"?kIOReturnError:kIOReturnSuccess;
}
extern "C" void dodge_input_status(DodgeInputStatus *s){*s={};s->phase=mode=="metadata-failed"?DodgeInputPhase::Failed:DodgeInputPhase::Ready;for(unsigned d=0;d<2;++d){s->attempted[d]=attempted[d];if(mode=="init-failed")s->start[d]=DodgeInputStart::Failed;}}
int main(int argc,char **argv){
    assert(argc==2);mode=argv[1];platform.parent=mode=="no-root"?nullptr:&root;
    if(mode=="inactive-platform")platform.inactive=true;
    IOReturn rc=0;
    if(mode=="concurrent"){
        std::atomic<unsigned> ok{0},busy{0};std::vector<std::thread> threads;
        for(unsigned i=0;i<16;++i)threads.emplace_back([&]{auto r=dodge_input_schedule();if(!r)++ok;else{assert(r==kIOReturnBusy);++busy;}});
        for(auto &t:threads)t.join();
        assert(ok==1 && busy==15);
    } else rc=dodge_input_schedule();
    DodgeInputLateStatus s={};dodge_input_late_status(&s);
    if(mode=="disabled" || mode=="missing" || mode=="other"){assert(rc==kIOReturnNotPermitted && !queues && !continuation);goto done;}
    if(mode=="thread-failure" || mode=="thread-retry"){
        assert(rc==kIOReturnNoResources && s.phase==DodgeInputLatePhase::Cold && !continuation);
        if(mode=="thread-failure")goto done;
        assert(!dodge_input_schedule());
    } else assert(!rc);
    if(mode!="eager"){assert(continuation && !calls[0] && !calls[1]);std::thread work([]{continuation(nullptr,0);});work.join();}
    dodge_input_late_status(&s);assert(s.phase==DodgeInputLatePhase::Finished && deallocations==1 && terminations==1);
    assert(dodge_input_schedule()==kIOReturnNotPermitted);
    if(mode=="no-platform" || mode=="inactive-platform" || mode=="no-root" || mode=="storage-timeout" || mode=="graphics-timeout"){
        assert(s.attempts==1000 && sleeps==999 && !calls[0] && !calls[1]);
    } else if(mode=="prestart-timeout")assert(calls[0]==1000 && calls[1]==1000 && sleeps==999);
    else {
        assert(calls[0]==((mode=="busy" || mode=="reentry-sleep")?3u:1u) && calls[1]==calls[0]);
        if(mode=="keys-failed")assert(s.keys && !s.touch && released==1);
        else if(mode=="touch-failed")assert(!s.keys && s.touch && released==1);
        else if(mode=="unsupported" || mode=="metadata-failed" || mode=="init-failed" || mode=="null-driver" || mode=="driver-with-error")assert(s.keys && s.touch);
        else assert(!s.keys && !s.touch && released==2);
    }
    if(mode.rfind("reentry-",0)==0)assert(reentries>0);
done:
    dodge_input_late_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"keys_calls\":%u,\"touch_calls\":%u,\"sleeps\":%u}\n",argv[1],calls[0],calls[1],sleeps);
}
