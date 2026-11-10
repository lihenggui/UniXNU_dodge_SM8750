// SPDX-License-Identifier: MIT
#include "DodgeUfsLifecycle.h"
#include "OriginalStorageABI.h"
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
static OSMetaClass driverMeta(152),blockMeta(216),wrong(144);
extern "C" {
kmod_info_t g_kernel_kmod_info={"com.apple.kernel"};
OSMetaClass dodge_test_storage_meta(144);
extern const unsigned char dodge_original_storage_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_storage_meta")));
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
    IOService *out=nullptr;assert(dodge_ufs_start(root,&out)==kIOReturnBusy && !out);++reentries;
}
IOPlatformExpert *IOService::getPlatform() {return mode=="no-platform"?nullptr:platform;}
bool PE_parse_boot_argn(const char *name,void *value,int bytes) {
    assert(!std::strcmp(name,"native-ufs-root") && bytes==4);
    *static_cast<unsigned *>(value)=mode=="flag-zero"?0:1;return mode!="flag-missing";
}
IOReturn OSKext::loadKextWithIdentifier(const char *name,bool defer,bool delay,OSKextExcludeLevel start,OSKextExcludeLevel match,void *p) {
    assert(!std::strcmp(name,"com.apple.iokit.IOStorageFamily") && !defer && delay && !start && !match && !p);++loads;
    if(mode=="reentry-prepare") {assert(dodge_ufs_prepare()==kIOReturnBusy);++reentries;}
    return mode=="load-failure"?-90:kIOReturnSuccess;
}
const OSSymbol *OSSymbol::withCStringNoCopy(const char *name) {
    if(mode=="symbol-failure" && !std::strcmp(name,DodgeOriginalStorageClass))return nullptr;
    ++symbols;return new OSSymbol{name};
}
void OSSymbol::release() const {assert(symbols);--symbols;delete this;}
const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *name) {
    OSMetaClass *value=nullptr;
    if(!std::strcmp(name->name,DodgeOriginalStorageClass)) {
        if(mode=="parent-missing")return nullptr;
        value=mode=="parent-identity"?&wrong:&dodge_test_storage_meta;
        if(mode=="parent-size")value->size=145;
    } else {
        assert(registeredClasses && post==1);
        const bool driver=!std::strcmp(name->name,"NativeUfs");
        assert(driver || !std::strcmp(name->name,"NativeUfsBlock"));
        if(mode==(driver?"driver-missing":"block-missing"))return nullptr;
        value=mode==(driver?"driver-identity":"block-identity")?&wrong:driver?&driverMeta:&blockMeta;
        if(mode==(driver?"driver-size":"block-size"))++value->size;
    }
    ++value->pins;return value;
}
void OSMetaClass::releaseMetaClass() const {assert(pins);--pins;}
void *OSMetaClass::preModLoad(const char *name) {
    assert(!std::strcmp(name,"com.apple.kernel") && dodge_test_storage_meta.pins==1 && !insideLoader);++pre;insideLoader=true;
    return mode=="pre-failure"?nullptr:&pre;
}
IOReturn OSMetaClass::postModLoad(void *handle) {
    assert(handle==&pre && insideLoader && initializers==1);insideLoader=false;++post;registeredClasses=true;
    return mode=="post-failure"?-91:0;
}
extern "C" void dodge_ufs_cpp_initializer() asm("__GLOBAL__sub_I_NativeUfs.cpp");
extern "C" void dodge_ufs_cpp_initializer() {
    assert(insideLoader && pre==1 && !initializers);++initializers;assert(dodge_ufs_prepare()==kIOReturnBusy);
}
extern "C" unsigned dodge_ufs_driver_bytes() {return 152;}
extern "C" unsigned dodge_ufs_block_bytes() {return 216;}
extern "C" const OSMetaClass *dodge_ufs_driver_meta() {return &driverMeta;}
extern "C" const OSMetaClass *dodge_ufs_block_meta() {return &blockMeta;}
struct Driver final : IOService {
    Driver() {++objects;}
    ~Driver() override {assert(objects);--objects;++freed;reenter("release");}
    bool init() override {reenter("init");return mode!="init-failure" && mode!="reentry-release";}
    bool attach(IOService *p) override {
        assert(p==root);reenter("attach");if(mode=="attach-failure")return false;
        parent=p;p->retain();retain();return true;
    }
    bool start(IOService *p) override {
        assert(p==parent && p==root && root->references==3);++starts;reenter("start");
        if(mode=="concurrent-start") {
            std::thread second([] {IOService *out=nullptr;assert(dodge_ufs_start(root,&out)==kIOReturnBusy && !out);});second.join();
        }
        return mode!="start-failure";
    }
};
extern "C" IOService *dodge_ufs_allocate() {
    assert(registeredClasses && !insideLoader && !driverMeta.pins && !blockMeta.pins);++allocations;
    return mode=="allocation-failure"?nullptr:new Driver;
}
int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];root=new Root;platform=new IOPlatformExpert;platform->parent=root;
    if(mode=="null-out") {assert(dodge_ufs_start(root,nullptr)==kIOReturnBadArgument);goto done;}
    if(mode=="null-provider") {IOService *out=root;assert(dodge_ufs_start(nullptr,&out)==kIOReturnBadArgument && !out);goto done;}
    if(mode=="inactive-provider")root->inactive=true;
    if(mode=="inactive-platform")platform->inactive=true;
    {
        IOService *out=reinterpret_cast<IOService *>(uintptr_t(1));const IOReturn result=dodge_ufs_start(root,&out);
        DodgeUfsStatus status={};dodge_ufs_status(&status);
        if(mode=="flag-zero" || mode=="flag-missing") {assert(result==kIOReturnNotPermitted && !loads && !out);goto done;}
        if(mode=="wrong-provider" || mode=="no-platform" || mode=="inactive-provider" || mode=="inactive-platform") {assert(result==kIOReturnUnsupported && !loads && !out);goto done;}
        if(status.phase==DodgeUfsPhase::Cold || status.phase==DodgeUfsPhase::Failed) {
            assert(result && !out && !allocations && !objects && !starts && root->references==1 && !symbols && !wrong.pins);
            assert(dodge_test_storage_meta.pins==(status.phase==DodgeUfsPhase::Failed?1u:0u));
            if(status.phase==DodgeUfsPhase::Failed) {
                assert(dodge_ufs_prepare()==result && initializers<=1);
                if(mode!="pre-failure")assert(initializers==1 && post==1);
            }
        } else if(starts) {
            assert(starts==1 && allocations==1 && objects==1 && !freed && status.startAttempted && status.driverRetained);
            assert(root->references==2 && dodge_test_storage_meta.pins==1);
            IOService *again=nullptr;
            if(mode=="start-failure") {
                assert(result==kIOReturnNotReady && !out && status.start==DodgeUfsStartPhase::Failed);
                assert(dodge_ufs_start(root,&again)==result && !again && starts==1 && !freed);
            } else {
                assert(result==0 && out && out->references==3 && status.start==DodgeUfsStartPhase::Started);out->release();
                assert(dodge_ufs_start(root,&again)==kIOReturnNotPermitted && !again && starts==1);
            }
        } else {
            assert(result && !out && !objects && status.start==DodgeUfsStartPhase::Idle && !status.startAttempted && !status.driverRetained);
            assert(root->references==1 && dodge_test_storage_meta.pins==1);
        }
        if(mode.rfind("reentry-",0)==0)assert(reentries==1);
    }
done:
    dodge_ufs_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"initializers\":%u,\"start_calls\":%u,\"objects_retained\":%u}\n",
        mode.c_str(),initializers,starts,objects);return 0;
}
