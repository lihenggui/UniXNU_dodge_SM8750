// SPDX-License-Identifier: MIT
#include "DodgeInputLifecycle.h"
#include "OriginalHidDeviceABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSKext.h>
#include <mach/kmod.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

static std::string mode;
static OSMetaClass driverMeta(4096),wrong(208);
extern "C" {
kmod_info_t g_kernel_kmod_info={"com.apple.kernel"};
OSMetaClass dodge_test_hid_meta(208);
extern const unsigned char dodge_original_hid_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_hid_meta")));
}
struct Root final : IOService {
    const IOService *metaCast(const char *name) const override {return mode!="wrong-provider" && !std::strcmp(name,"IOPlatformExpertDevice")?this:nullptr;}
};
static Root *root=nullptr;
static IOPlatformExpert *platform=nullptr;
static unsigned loads=0,pre=0,post=0,initializers=0,symbols=0,allocations=0,objects=0,starts=0,freed=0,reentries=0;
static bool registeredClasses=false,insideLoader=false;
static void reenter(const char *stage) {
    if(mode!=std::string("reentry-")+stage)return;
    IOService *out=nullptr;assert(dodge_input_start(root,false,&out)==kIOReturnBusy && !out);++reentries;
}
IOPlatformExpert *IOService::getPlatform() {return mode=="no-platform"?nullptr:platform;}
bool PE_parse_boot_argn(const char *name,void *value,int bytes) {
    assert(!std::strcmp(name,"dodge-input") && bytes==4);
    *static_cast<unsigned *>(value)=mode=="flag-zero"?0:1;return mode!="flag-missing";
}
IOReturn OSKext::loadKextWithIdentifier(const char *name,bool defer,bool delay,OSKextExcludeLevel start,OSKextExcludeLevel match,void *p) {
    assert(!std::strcmp(name,"com.apple.iokit.IOHIDFamily") && !defer && delay && !start && !match && !p);++loads;
    if(mode=="reentry-prepare") {assert(dodge_input_prepare()==kIOReturnBusy);++reentries;}
    return mode=="load-failure"?-90:kIOReturnSuccess;
}
const OSSymbol *OSSymbol::withCStringNoCopy(const char *name) {
    if(mode=="symbol-failure" && !std::strcmp(name,"IOHIDDevice"))return nullptr;
    ++symbols;return new OSSymbol{name};
}
void OSSymbol::release() const {assert(symbols);--symbols;delete this;}
const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *name) {
    OSMetaClass *value=nullptr;
    if(!std::strcmp(name->name,"IOHIDDevice")) {
        if(mode=="parent-missing")return nullptr;
        value=mode=="parent-identity"?&wrong:&dodge_test_hid_meta;
        if(mode=="parent-size")value->size=209;
    } else {
        assert(registeredClasses && post==1);
        assert(!std::strcmp(name->name,"DodgeInput"));
        if(mode=="driver-missing")return nullptr;
        value=mode=="driver-identity"?&wrong:&driverMeta;
        if(mode=="driver-size")++value->size;
    }
    ++value->pins;return value;
}
void OSMetaClass::releaseMetaClass() const {assert(pins);--pins;}
void *OSMetaClass::preModLoad(const char *name) {
    assert(!std::strcmp(name,"com.apple.kernel") && dodge_test_hid_meta.pins==1 && !insideLoader);++pre;insideLoader=true;
    return mode=="pre-failure"?nullptr:&pre;
}
IOReturn OSMetaClass::postModLoad(void *handle) {
    assert(handle==&pre && insideLoader && initializers==1);insideLoader=false;++post;registeredClasses=true;
    return mode=="post-failure"?-91:0;
}
extern "C" void dodge_input_cpp_initializer() asm("__GLOBAL__sub_I_DodgeInput.cpp");
extern "C" void dodge_input_cpp_initializer() {
    assert(insideLoader && pre==1 && !initializers);++initializers;assert(dodge_input_prepare()==kIOReturnBusy);
}
extern "C" unsigned dodge_input_driver_bytes() {return 4096;}
extern "C" const OSMetaClass *dodge_input_driver_meta() {return &driverMeta;}
struct Driver final : IOService {
    Driver() {++objects;}
    ~Driver() override {assert(objects);--objects;++freed;reenter("release");}
    bool init() override {reenter("init");return mode!="init-failure" && !(mode=="dual-init-failure" && allocations==1);}
    bool attach(IOService *p) override {
        assert(p==root);reenter("attach");if(mode=="attach-failure")return false;
        parent=p;p->retain();retain();return true;
    }
    bool start(IOService *p) override {
        assert(p==parent && p==root && root->references==3+2*starts+(mode=="dual-init-failure"?1:0));++starts;reenter("start");
        if(mode=="concurrent-start") {
            std::thread second([] {IOService *out=nullptr;assert(dodge_input_start(root,false,&out)==kIOReturnBusy && !out);});second.join();
        }
        return mode!="start-failure";
    }
};
extern "C" IOService *dodge_input_allocate(bool) {
    assert(registeredClasses && !insideLoader && !driverMeta.pins);++allocations;
    return mode=="allocation-failure"?nullptr:new Driver;
}
int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];root=new Root;platform=new IOPlatformExpert;platform->parent=root;
    if(mode=="null-out") {assert(dodge_input_start(root,false,nullptr)==kIOReturnBadArgument);goto done;}
    if(mode=="null-provider") {IOService *out=root;assert(dodge_input_start(nullptr,false,&out)==kIOReturnBadArgument && !out);goto done;}
    if(mode=="inactive-provider")root->inactive=true;
    if(mode=="inactive-platform")platform->inactive=true;
    {
        IOService *out=reinterpret_cast<IOService *>(uintptr_t(1));const IOReturn result=dodge_input_start(root,false,&out);
        DodgeInputStatus status={};dodge_input_status(&status);
        if(mode=="flag-zero" || mode=="flag-missing") {assert(result==kIOReturnNotPermitted && !loads && !out);goto done;}
        if(mode=="wrong-provider" || mode=="no-platform" || mode=="inactive-provider" || mode=="inactive-platform") {assert(result==kIOReturnUnsupported && !loads && !out);goto done;}
        if(status.phase==DodgeInputPhase::Cold || status.phase==DodgeInputPhase::Failed) {
            assert(result && !out && !allocations && !objects && !starts && root->references==1 && !symbols && !wrong.pins);
            assert(dodge_test_hid_meta.pins==(status.phase==DodgeInputPhase::Failed?1u:0u));
            if(status.phase==DodgeInputPhase::Failed) {
                assert(dodge_input_prepare()==result && initializers<=1);
                if(mode!="pre-failure")assert(initializers==1 && post==1);
            }
        } else if(starts) {
            assert(starts==1 && allocations==1 && objects==1 && !freed && status.attempted[0] && status.driverRetained[0]);
            assert(root->references==3 && dodge_test_hid_meta.pins==1);
            IOService *again=nullptr;
            if(mode=="start-failure") {
                assert(result==kIOReturnNotReady && !out && status.start[0]==DodgeInputStart::Failed);
                assert(dodge_input_start(root,false,&again)==result && !again && starts==1 && !freed);
            } else {
                assert(result==0 && out && out->references==3 && status.start[0]==DodgeInputStart::Started);out->release();
                assert(dodge_input_start(root,false,&again)==kIOReturnNotPermitted && !again && starts==1);
                if(mode=="dual") {
                    assert(dodge_input_start(root,true,&again)==0 && again);again->release();
                    assert(starts==2 && loads==1 && initializers==1 && root->references==5);
                    dodge_input_status(&status);
                    assert(status.attempted[1] && status.driverRetained[1] && status.providerRetained[1]);
                }
            }
        } else if(status.initializationAttempted[0]) {
            assert(result==kIOReturnNotReady && !out && objects==1 && !freed && status.start[0]==DodgeInputStart::Failed);
            assert(!status.attempted[0] && status.driverRetained[0] && status.providerRetained[0]);
            assert(root->references==2 && dodge_test_hid_meta.pins==1);
            IOService *again=nullptr;assert(dodge_input_start(root,false,&again)==result && !again && allocations==1 && !starts && !freed);
            if(mode=="dual-init-failure") {
                assert(dodge_input_start(root,true,&again)==0 && again);again->release();
                dodge_input_status(&status);
                assert(objects==2 && allocations==2 && starts==1 && loads==1 && initializers==1 && root->references==4 && !freed);
                assert(status.start[0]==DodgeInputStart::Failed && status.start[1]==DodgeInputStart::Started);
                assert(status.initializationAttempted[0] && status.initializationAttempted[1] && !status.attempted[0] && status.attempted[1]);
            }
        } else {
            assert(result && !out && !objects && status.start[0]==DodgeInputStart::Idle && !status.attempted[0] && !status.driverRetained[0]);
            assert(root->references==1 && dodge_test_hid_meta.pins==1);
        }
        if(mode.rfind("reentry-",0)==0)assert(reentries==1);
    }
done:
    dodge_input_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"initializers\":%u,\"start_calls\":%u,\"objects_retained\":%u}\n",
        mode.c_str(),initializers,starts,objects);return 0;
}
