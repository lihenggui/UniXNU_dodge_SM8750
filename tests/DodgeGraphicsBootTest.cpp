// SPDX-License-Identifier: BSD-2-Clause-Patent
// Actual startup coordinator; module, hardware and display APIs are peers.
#include "DodgeGraphicsBoot.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static std::string mode;
static std::vector<std::string> events;
static unsigned prepares,roots,hardware,attaches,reentries;
static DodgeGraphicsPhase modulePhase=DodgeGraphicsPhase::Cold;
static bool rootActive=true;
static DodgeGraphicsBootStatus status() {DodgeGraphicsBootStatus value={};dodge_graphics_boot_status(&value);return value;}
static IOService *providerPointer;
static void busyProbe() {
    IOService *value=reinterpret_cast<IOService *>(uintptr_t(1));
    assert(dodge_graphics_boot(providerPointer,&value)==kIOReturnBusy && !value);++reentries;
}
struct Peer final : IOService {
    bool owner=false;
    IOService *provider=nullptr,*root=nullptr;
    explicit Peer(bool owned=false):owner(owned) {}
    ~Peer() override {if(provider)provider->release();if(root)root->release();}
    bool init() override {assert(false);return false;}
    bool attach(IOService *) override {assert(false);return false;}
    bool start(IOService *) override {assert(false);return false;}
    void stop(IOService *) override {assert(false);}
    void detach(IOService *) override {assert(false);}
    void retain() override {
        IOService::retain();
        if(mode=="reentry-retain")busyProbe();
    }
    void release() override {
        const auto phase=status().phase;
        if(mode=="reentry-release" && phase!=DodgeGraphicsBootPhase::Cold && phase!=DodgeGraphicsBootPhase::Started && phase!=DodgeGraphicsBootPhase::Failed)busyProbe();
        IOService::release();
    }
};
static Peer provider,root;
extern "C" IOReturn dodge_graphics_prepare() {
    assert(status().phase==DodgeGraphicsBootPhase::Preparing && provider.references==2 && root.references==1);
    ++prepares;events.emplace_back("prepare");
    if(mode=="reentry-prepare")busyProbe();
    if(mode=="prepare-cold-error" || mode=="retry-prepare") {modulePhase=DodgeGraphicsPhase::Cold;return -31;}
    if(mode=="prepare-loading-busy") {modulePhase=DodgeGraphicsPhase::Loading;return kIOReturnBusy;}
    if(mode=="prepare-latched-error") {modulePhase=DodgeGraphicsPhase::Failed;return -32;}
    modulePhase=DodgeGraphicsPhase::Ready;return kIOReturnSuccess;
}
extern "C" void dodge_graphics_status(DodgeGraphicsStatus *out) {assert(out);out->phase=modulePhase;}
extern "C" IOReturn dodge_graphics_acquire_root(IOService *p,IOService **out) {
    assert(p==&provider && out && status().phase==DodgeGraphicsBootPhase::Prerequisites && modulePhase==DodgeGraphicsPhase::Ready);
    assert(provider.references==2 && root.references==1);*out=nullptr;++roots;events.emplace_back("root");
    if(mode=="reentry-root")busyProbe();
    if(mode=="root-missing" || mode=="retry-root")return kIOReturnNotReady;
    if(mode=="root-wrong-provider")return kIOReturnUnsupported;
    if(mode=="root-allocation-fail")return kIOReturnNoMemory;
    if(mode=="root-null-on-success")return kIOReturnSuccess;
    root.retain();*out=&root;return kIOReturnSuccess;
}
extern "C" int dodge_gpu_start() {
    assert(status().phase==DodgeGraphicsBootPhase::Hardware && status().hardwareAttempted);
    assert(provider.references==2 && root.references==2);++hardware;events.emplace_back("hardware");
    if(mode=="reentry-gpu")busyProbe();
    if(mode=="concurrent-gpu") {std::thread other(busyProbe);other.join();}
    if(mode=="gpu-failure")return -33;
    if(mode=="gpu-refused")return kIOReturnBusy;
    if(mode=="root-disappears-after-gpu")rootActive=false;
    return 0;
}
extern "C" IOReturn dodge_graphics_attach(IOService *p,IOService **out) {
    assert(p==&provider && out && status().phase==DodgeGraphicsBootPhase::Display && hardware==1);
    assert(provider.references==2 && root.references==2);*out=nullptr;++attaches;events.emplace_back("display");
    if(mode=="reentry-attach")busyProbe();
    if(mode=="attach-failure" || !rootActive)return kIOReturnNotReady;
    if(mode=="display-null-on-success")return kIOReturnSuccess;
    auto *display=new Peer(true);display->provider=p;display->root=&root;p->retain();root.retain();*out=display;return 0;
}

int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];providerPointer=&provider;const std::string original=mode;
    assert(status().phase==DodgeGraphicsBootPhase::Cold && status().last==kIOReturnNotReady && !status().hardwareAttempted);
    dodge_graphics_boot_status(nullptr);IOService *display=reinterpret_cast<IOService *>(uintptr_t(1));
    if(mode=="null-out")assert(dodge_graphics_boot(&provider,nullptr)==kIOReturnBadArgument);
    else if(mode=="null-provider")assert(dodge_graphics_boot(nullptr,&display)==kIOReturnBadArgument && !display);
    else {
        const IOReturn result=dodge_graphics_boot(&provider,&display);
        const bool beforeHardware=mode=="prepare-cold-error" || mode=="prepare-loading-busy" || mode=="retry-prepare" || mode=="root-missing" || mode=="retry-root" || mode=="root-wrong-provider" || mode=="root-allocation-fail";
        const bool failed=beforeHardware || mode=="prepare-latched-error" || mode=="root-null-on-success" || mode=="gpu-failure" || mode=="gpu-refused" || mode=="attach-failure" || mode=="display-null-on-success" || mode=="root-disappears-after-gpu";
        assert((result!=0)==failed && status().last==result);
        if(failed) {
            assert(!display && provider.references==1 && root.references==1);
            assert(status().phase==(beforeHardware?DodgeGraphicsBootPhase::Cold:DodgeGraphicsBootPhase::Failed));
            assert(status().hardwareAttempted==bool(hardware));
            if(beforeHardware)assert(!hardware && !attaches);
            else {
                const auto saved=events;assert(dodge_graphics_boot(&provider,&display)==result && !display && events==saved);
            }
        } else {
            assert(display && status().phase==DodgeGraphicsBootPhase::Started && status().hardwareAttempted);
            assert(events==std::vector<std::string>({"prepare","root","hardware","display"}));
        }
        if(mode=="retry-root" || mode=="retry-prepare") {
            mode="success";assert(dodge_graphics_boot(&provider,&display)==0 && display && hardware==1 && attaches==1);
            assert(prepares==2 && roots==unsigned(original=="retry-root"?2:1));
        }
        if(display) {
            assert(provider.references==2 && root.references==2 && display->references==1);
            const auto saved=events;IOService *second=reinterpret_cast<IOService *>(uintptr_t(1));
            assert(dodge_graphics_boot(&provider,&second)==kIOReturnNotPermitted && !second && saved==events);
            display->release();
        }
        if(original.rfind("reentry-",0)==0 || original=="concurrent-gpu")assert(reentries);
    }
    assert(provider.references==1 && root.references==1 && hardware<=1);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"hardware_calls\":%u,\"display_calls\":%u}\n",original.c_str(),hardware,attaches);
}
