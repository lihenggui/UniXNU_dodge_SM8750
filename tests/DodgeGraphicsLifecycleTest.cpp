// SPDX-License-Identifier: MIT
// Compile the actual orchestration. OSKext, metadata and the concrete service
// are explicit peers; actual compiled concrete hooks have separate CPU tests.
#include "DodgeGraphicsLifecycle.h"
#include "DodgeIPhoneFramebuffer.h"
#include "OriginalGraphicsModulesABI.h"
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

extern "C" {
kmod_info_t g_kernel_kmod_info={"com.apple.kernel"};
OSMetaClass dodge_test_surface(1168),dodge_test_accelerator(136),dodge_test_legacy(5728);
// Aliases name actual peer metadata objects. Only pointer equality is tested;
// production has N_ABS aliases to the independently derived original objects.
extern const unsigned char dodge_original_graphics_surface_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_surface")));
extern const unsigned char dodge_original_graphics_accelerator_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_accelerator")));
extern const unsigned char dodge_original_graphics_legacy_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_legacy")));
}
static OSMetaClass wrong(5728);
static OSMetaClass *metas[]={&dodge_test_surface,&dodge_test_accelerator,&dodge_test_legacy};
static std::string mode;
static std::vector<std::string> events;
static unsigned symbols=0,loads=0,pre=0,post=0,constructed=0,allocations=0,displayObjects=0;
static bool initialized=false,registered=false,loadFailed=false,preEntered=false;
static int failureIndex=-1;
static IOReturn busyObserved=0;
static unsigned dictionaries=0;
static void event(const char *text) {events.emplace_back(text);}
static unsigned classIndex(const char *name) {
    for(unsigned i=0;i<3;++i)if(!strcmp(name,DodgeOriginalGraphicsModules[i].className))return i;
    assert(false);return 0;
}
IOReturn OSKext::loadKextWithIdentifier(const char *name,bool defer,bool delay,OSKextExcludeLevel start,OSKextExcludeLevel matching,void *personalities) {
    assert(!defer && delay && start==kOSKextExcludeNone && !personalities && !preEntered);
    const unsigned i=loads++%3;assert(matching==(i==0?kOSKextExcludeNone:kOSKextExcludeAll));
    assert(!strcmp(name,DodgeOriginalGraphicsModules[i].bundle));event(name);
    if(mode=="concurrent-prepare" && loads==1) {
        std::thread second([] {busyObserved=dodge_graphics_prepare();});second.join();assert(busyObserved==kIOReturnBusy);
    }
    if(mode=="reentrant-prepare" && loads==1)assert(dodge_graphics_prepare()==kIOReturnBusy);
    if(mode=="loader-failure" && int(i)==failureIndex && !loadFailed) {loadFailed=true;return -90-int(i);}
    return 0;
}
const OSSymbol *OSSymbol::withCStringNoCopy(const char *name) {
    const unsigned i=classIndex(name);
    if(mode=="symbol-failure" && int(i)==failureIndex)return nullptr;
    ++symbols;return new OSSymbol{name};
}
void OSSymbol::release() const {assert(symbols);--symbols;delete this;}
const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *name) {
    const unsigned i=classIndex(name->name);assert(loads>i);
    if(mode=="metadata-missing" && int(i)==failureIndex)return nullptr;
    auto *meta=mode=="metadata-wrong" && int(i)==failureIndex?&wrong:metas[i];++meta->pins;return meta;
}
void OSMetaClass::releaseMetaClass() const {assert(pins);--pins;}
void *OSMetaClass::preModLoad(const char *name) {
    assert(!strcmp(name,g_kernel_kmod_info.name) && loads==3 && !symbols && !preEntered);
    for(auto *meta:metas)assert(meta->pins==1);
    ++pre;event("pre");preEntered=true;
    if(mode=="pre-failure")return nullptr;
    return &pre;
}
IOReturn OSMetaClass::postModLoad(void *handle) {
    assert(handle==&pre && preEntered && pre==1);++post;event("post");preEntered=false;
    if(mode=="post-failure")return -91;
    registered=initialized && mode!="registration-missing";return 0;
}
bool dodge_iphone_framebuffer_initialize() {
    assert(preEntered && pre==1 && !post);++constructed;event("construct");
    assert(dodge_graphics_prepare()==kIOReturnBusy);
    if(mode=="constructor-refused")return false;
    initialized=true;return true;
}
bool dodge_iphone_framebuffer_registered() {return registered;}

struct DisplayPeer final : IOService {
    IOService *provider=nullptr;
    bool drained=false,pendingDetach=false,controller=false;
    DisplayPeer() {++displayObjects;}
    ~DisplayPeer() override {assert(!provider && !controller);--displayObjects;event("free");}
    bool init() override {event("init");return mode!="init-failure";}
    bool attach(IOService *p) override {
        event("attach");if(mode=="attach-failure")return false;
        provider=p;p->retain();retain();return true;
    }
    bool start(IOService *p) override {
        assert(provider==p);event("start");controller=true;retain();
        if(mode=="reentrant-attach") {
            IOService *value=reinterpret_cast<IOService *>(uintptr_t(1));
            assert(dodge_graphics_attach(p,&value)==kIOReturnBusy && !value);
        }
        return mode!="start-failure" && mode!="deferred-start-failure";
    }
    void stop(IOService *p) override {
        assert(provider==p);event("stop");
        if(mode!="deferred-start-failure")drain();
    }
    void detach(IOService *p) override {
        assert(provider==p);event("detach");pendingDetach=true;if(drained)unlink();
    }
    void unlink() {
        assert(provider && pendingDetach && drained);auto *p=provider;provider=nullptr;pendingDetach=false;
        event("unlink");p->release();release();
    }
    void drain() {
        assert(controller);drained=true;controller=false;
        if(pendingDetach)unlink();
        release();
    }
};
static DisplayPeer *lastDisplay=nullptr;
IOService *dodge_iphone_framebuffer_allocate() {
    assert(registered);++allocations;event("allocate");
    if(mode=="allocate-failure")return nullptr;
    lastDisplay=new DisplayPeer;return lastDisplay;
}
struct ProviderPeer final : IOService {
    bool init() override {return false;}
    bool attach(IOService *) override {assert(false);return false;}
    bool start(IOService *) override {assert(false);return false;}
    void stop(IOService *) override {assert(false);}
    void detach(IOService *) override {assert(false);}
    bool isInactive() const override {return mode=="surface-root-inactive";}
    const IOService *metaCast(const char *name) const override {
        if(!strcmp(name,"AppleARMIODevice"))return mode=="provider-wrong-class"?nullptr:this;
        assert(!strcmp(name,"IOSurfaceRoot"));return mode=="surface-root-wrong-class"?nullptr:this;
    }
};
static ProviderPeer surfaceRoot;
IOService::Dictionary *IOService::nameMatching(const char *name) {
    assert(!strcmp(name,"IOCoreSurfaceRoot"));event("root-matching");
    if(mode=="matching-allocation-failed")return nullptr;
    ++dictionaries;return new Dictionary(name);
}
void IOService::Dictionary::release() {assert(dictionaries);--dictionaries;delete this;}
IOService *IOService::copyMatchingService(Dictionary *matching) {
    assert(matching && !strcmp(matching->name,"IOCoreSurfaceRoot"));event("root-copy");
    if(mode=="surface-root-missing")return nullptr;
    surfaceRoot.retain();return &surfaceRoot;
}
static DodgeGraphicsStatus status() {DodgeGraphicsStatus result={};dodge_graphics_status(&result);return result;}
static void noPins() {for(auto *meta:metas)assert(!meta->pins);assert(!wrong.pins && !symbols);}
int main(int argc,char **argv) {
    assert(argc>=2);mode=argv[1];if(argc==3)failureIndex=std::stoi(argv[2]);
    assert(status().phase==DodgeGraphicsPhase::Cold && status().last==kIOReturnNotReady && !status().attachment);
    ProviderPeer provider;IOService *display=reinterpret_cast<IOService *>(uintptr_t(1));
    assert(dodge_graphics_attach(&provider,&display)==kIOReturnNotReady && !display && !loads);
    assert(dodge_graphics_acquire_root(&provider,&display)==kIOReturnNotReady && !display && !loads);
    assert(dodge_graphics_acquire_root(nullptr,&display)==kIOReturnBadArgument && !display);
    assert(dodge_graphics_acquire_root(&provider,nullptr)==kIOReturnBadArgument);
    assert(dodge_graphics_attach(nullptr,&display)==kIOReturnBadArgument && !display);
    assert(dodge_graphics_attach(&provider,nullptr)==kIOReturnBadArgument);
    dodge_graphics_status(nullptr);
    if(mode=="metadata-size")metas[failureIndex]->size++;
    const IOReturn prepared=dodge_graphics_prepare();
    if(mode=="loader-failure" || mode=="symbol-failure" || mode=="metadata-missing" || mode=="metadata-wrong" || mode=="metadata-size") {
        assert(prepared!=0 && status().phase==DodgeGraphicsPhase::Cold && status().last==prepared && !pre && !post && !constructed);noPins();
        if(mode=="loader-failure") {
            // OSKext itself owns already started dependencies; retries must not
            // invoke the deferred source constructor twice or keep stale pins.
            assert(prepared==-90-failureIndex);loads=0;mode="retry-success";
            assert(dodge_graphics_prepare()==0 && constructed==1 && post==1 && status().phase==DodgeGraphicsPhase::Ready);
        }
    } else if(mode=="pre-failure" || mode=="constructor-refused" || mode=="post-failure" || mode=="registration-missing") {
        assert(prepared!=0 && status().phase==DodgeGraphicsPhase::Failed && pre==1);
        assert(post==unsigned(mode!="pre-failure") && constructed==unsigned(mode!="pre-failure"));
        const auto saved=events;assert(dodge_graphics_prepare()==prepared && events==saved);
        assert(dodge_graphics_attach(&provider,&display)==kIOReturnNotReady && !display && !allocations);
        if(mode=="pre-failure" || mode=="constructor-refused")noPins();
        else for(auto *meta:metas)assert(meta->pins==1);
    } else {
        assert(prepared==0 && status().phase==DodgeGraphicsPhase::Ready && loads==3 && pre==1 && post==1 && constructed==1 && !symbols);
        for(auto *meta:metas)assert(meta->pins==1);
        if(mode=="success") {
            IOService *held=nullptr;
            assert(dodge_graphics_acquire_root(&provider,&held)==0 && held==&surfaceRoot && surfaceRoot.references==2);
            assert(!allocations && !status().attachment);held->release();assert(surfaceRoot.references==1);
        }
        const auto saved=events;assert(dodge_graphics_prepare()==0 && events==saved);
        const IOReturn result=dodge_graphics_attach(&provider,&display);
        if(mode=="surface-root-missing" || mode=="surface-root-inactive" || mode=="surface-root-wrong-class" || mode=="matching-allocation-failed" || mode=="provider-wrong-class") {
            assert(result==(mode=="matching-allocation-failed"?kIOReturnNoMemory:mode=="provider-wrong-class"?kIOReturnUnsupported:kIOReturnNotReady) && !display && !allocations && !displayObjects && !status().attachment);
            assert(surfaceRoot.references==1 && !dictionaries);
            mode="retry-success";assert(dodge_graphics_attach(&provider,&display)==0 && display);
        } else if(mode=="allocate-failure" || mode=="init-failure" || mode=="attach-failure") {
            assert(result!=0 && !display && !displayObjects && !status().attachment && provider.references==1);
            mode="retry-success";assert(dodge_graphics_attach(&provider,&display)==0 && display);
        } else if(mode=="start-failure" || mode=="deferred-start-failure") {
            assert(result==kIOReturnNotReady && !display && status().attachment==3);
            assert(dodge_graphics_attach(&provider,&display)==kIOReturnNotPermitted && !display && allocations==1);
            if(mode=="deferred-start-failure") {
                assert(displayObjects==1 && provider.references==2 && lastDisplay->references==2 && lastDisplay->pendingDetach);
                lastDisplay->drain();
            }
            assert(!displayObjects && provider.references==1);
        } else assert(result==0 && display);
        if(display) {
            assert(status().attachment==2 && provider.references==2 && displayObjects==1);
            IOService *second=reinterpret_cast<IOService *>(uintptr_t(1));
            assert(dodge_graphics_attach(&provider,&second)==kIOReturnNotPermitted && !second);
            display->stop(&provider);display->detach(&provider);display->release();assert(!displayObjects && provider.references==1);
        }
    }
    assert(!symbols && !displayObjects && provider.references==1 && surfaceRoot.references==1 && !dictionaries);
    std::printf("{\"case\":\"%s%s%s\",\"result\":\"PASS\",\"loads\":%u,\"constructors\":%u,\"post_calls\":%u}\n",argv[1],argc==3?"-":"",argc==3?argv[2]:"",loads,constructed,post);
}
