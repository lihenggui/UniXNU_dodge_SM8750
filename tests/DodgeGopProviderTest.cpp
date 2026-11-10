// SPDX-License-Identifier: MIT
// Actual factory/wrapper source with explicit allocation, registry and PE peers.
#include "DodgeGopProvider.h"
#include "DodgeGraphicsBoot.h"
#include "OriginalGopProviderABI.h"
#include <GopIOKitPeer.h>
#include <cassert>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static std::string mode;
static OSMetaClass serviceMeta(136),otherMeta(216);
const OSMetaClass *IOService::metaClass=&serviceMeta;
extern "C" {
OSMetaClass dodge_test_gop_meta(216,&serviceMeta);
extern const unsigned char dodge_original_gop_provider_meta[sizeof(OSMetaClass)] __attribute__((alias("dodge_test_gop_meta")));
}
static IOPlatformExpert *platform=nullptr,*currentPlatform=nullptr;
static IOService *allocated=nullptr;
static PE_Video video={0x123400000,1440,3168,5760,32,0};
static unsigned providerObjects=0,memoryObjects=0,arrayObjects=0,symbols=0,allocations=0,attachCalls=0,detachCalls=0;
static unsigned registrations=0,initCalls=0,resources=0,prepareCalls=0,bootCalls=0,reentries=0;
static std::atomic<unsigned> consoleCalls{0};
static bool modulesReady=true;
static IOReturn prepareResult=0,bootResult=0;
static std::vector<std::string> events;

static void reenter(const char *step) {
    if(mode!=std::string("reentry-")+step)return;
    DodgeGopProviderStatus status={};dodge_gop_provider_status(&status);
    assert(status.phase==DodgeGopProviderPhase::Creating);
    IOService *value=reinterpret_cast<IOService *>(uintptr_t(1));
    assert(dodge_gop_provider_publish(platform,&value)==kIOReturnBusy && !value);++reentries;
}
IOService::IOService(bool provider):isProvider(provider) {if(provider)++providerObjects;}
IOService::~IOService() {
    assert(!attached && !parent && !registered);
    if(memory)memory->release();
    if(isProvider) {assert(providerObjects);--providerObjects;events.emplace_back("free-provider");reenter("release");}
}
const OSMetaClass *IOService::getMetaClass() const {
    return isProvider?(mode=="object-wrong-metadata"?&otherMeta:&dodge_test_gop_meta):&serviceMeta;
}
const IOService *IOService::metaCast(const char *value) const {
    return !std::strcmp(value,"IOService") || (isProvider && !std::strcmp(value,"AppleARMIODevice"))?this:nullptr;
}
bool IOService::init() {
    assert(isProvider && !attached && !memory);++initCalls;events.emplace_back("init");reenter("init");
    return mode!="init-failure" && mode!="reentry-release";
}
bool IOService::attach(IOService *p) {
    assert(isProvider && !attached && !parent && memory && p==platform && p->references==2);
    ++attachCalls;events.emplace_back("attach");reenter("attach");
    if(mode=="attach-failure")return false;
    attached=true;parent=p;p->retain();retain();
    if(mode=="platform-dies-at-attach")p->inactive=true;
    if(mode=="mode-change-at-attach") {video.v_width=1280;video.v_rowBytes=5120;}
    return true;
}
void IOService::detach(IOService *p) {
    assert(attached && p==parent && !registered);++detachCalls;attached=false;parent=nullptr;p->release();release();
}
void IOService::registerService() {
    assert(attached && !registered && memory && resources==1 && parent==platform);
    assert(dodge_test_gop_meta.pins==1 && memoryObjects==1 && arrayObjects==1);
    ++registrations;events.emplace_back("register");registered=true;reenter("register");
    if(mode=="mode-change-at-register")video.v_baseAddr+=4096;
    if(mode=="provider-dies-at-register")inactive=true;
    if(mode=="memory-change-at-register")dynamic_cast<IODeviceMemory *>(memory->values[0])->address+=4096;
}
IOReturn IOService::getResources() {
    assert(memory && memory->values.size()==1 && !attached);++resources;events.emplace_back("resources");
    return mode=="resources-failure"?kIOReturnError:kIOReturnSuccess;
}
void IOService::setDeviceMemory(OSArray *value) {
    assert(!memory && value && value->values.size()==1);events.emplace_back("memory");
    if(mode=="memory-install-failure")return;
    value->retain();memory=value;
}
unsigned IOService::getDeviceMemoryCount() {
    return mode=="memory-count-mismatch"?2:memory?unsigned(memory->values.size()):0;
}
IODeviceMemory *IOService::getDeviceMemoryWithIndex(unsigned index) {
    assert(index==0);
    return mode=="memory-index-mismatch"?nullptr:memory?dynamic_cast<IODeviceMemory *>(memory->values.at(index)):nullptr;
}
void IOService::setName(const char *value) {if(mode!="name-failure")name=value;}
IOPlatformExpert *IOService::getPlatform() {return currentPlatform;}
const OSSymbol *OSSymbol::withCStringNoCopy(const char *name) {
    assert(!std::strcmp(name,"AppleARMIODevice"));
    if(mode=="symbol-failure")return nullptr;
    ++symbols;return new OSSymbol{name};
}
void OSSymbol::release() const {assert(symbols);--symbols;delete this;}
const OSMetaClass *OSMetaClass::copyMetaClassWithName(const OSSymbol *name) {
    assert(!std::strcmp(name->name,"AppleARMIODevice"));reenter("metadata");
    if(mode=="metadata-missing")return nullptr;
    auto *value=mode=="metadata-identity"?&otherMeta:&dodge_test_gop_meta;
    if(mode=="metadata-size")value->size=217;
    if(mode=="metadata-parent")value->super=&otherMeta;
    ++value->pins;return value;
}
void OSMetaClass::releaseMetaClass() const {assert(pins);--pins;}
OSObject *OSMetaClass::alloc() const {
    assert(this==&dodge_test_gop_meta && pins==1);++allocations;events.emplace_back("allocate");
    if(mode=="allocation-failure")return nullptr;
    if(mode=="allocation-wrong-class")return new OSObject;
    if(mode=="concurrent-create") {
        std::vector<std::thread> threads;
        for(unsigned i=0;i<16;++i)threads.emplace_back([] {
            IOService *out=reinterpret_cast<IOService *>(uintptr_t(1));
            assert(dodge_gop_provider_publish(platform,&out)==kIOReturnBusy && !out);
        });
        for(auto &thread:threads)thread.join();
    }
    allocated=new IOService(true);return allocated;
}
IODeviceMemory::IODeviceMemory(uint64_t a,uint64_t n):address(a),length(n) {++memoryObjects;}
IODeviceMemory::~IODeviceMemory() {assert(memoryObjects);--memoryObjects;}
IODeviceMemory *IODeviceMemory::withRange(uint64_t address,uint64_t length) {
    assert(address==video.v_baseAddr && length==video.v_rowBytes*video.v_height);
    if(mode=="memory-allocation-failure")return nullptr;
    return new IODeviceMemory(address+(mode=="memory-address-mismatch"?4096:0),length+(mode=="memory-length-mismatch"?4096:0));
}
OSArray::OSArray() {++arrayObjects;}
OSArray::~OSArray() {for(auto *v:values)v->release();assert(arrayObjects);--arrayObjects;}
OSArray *OSArray::withCapacity(unsigned capacity) {
    assert(capacity==1);return mode=="array-allocation-failure"?nullptr:new OSArray;
}
bool OSArray::setObject(OSObject *value) {
    assert(value && values.empty());if(mode=="array-insert-failure")return false;
    value->retain();values.push_back(value);return true;
}
int PE_current_console(PE_Video *out) {++consoleCalls;*out=video;return mode=="console-failure"?1:0;}
extern "C" void dodge_graphics_status(DodgeGraphicsStatus *out) {
    *out={};out->phase=modulesReady?DodgeGraphicsPhase::Ready:DodgeGraphicsPhase::Cold;
}
extern "C" IOReturn dodge_graphics_prepare() {++prepareCalls;events.emplace_back("prepare");return prepareResult;}
extern "C" IOReturn dodge_graphics_boot(IOService *provider,IOService **out) {
    assert(provider && provider==allocated && provider->registered && registrations==1 && provider->references==3);
    ++bootCalls;events.emplace_back("boot");*out=nullptr;
    if(bootResult==kIOReturnSuccess)*out=new IOService;
    return bootResult;
}

int main(int argc,char **argv) {
    assert(argc==2);mode=argv[1];platform=new IOPlatformExpert;currentPlatform=platform;
    IOReturn expected=kIOReturnSuccess;
    if(mode=="null-out") {assert(dodge_gop_provider_publish(platform,nullptr)==kIOReturnBadArgument);goto complete;}
    if(mode=="null-platform") {
        IOService *out=platform;assert(dodge_gop_provider_publish(nullptr,&out)==kIOReturnBadArgument && !out);goto complete;
    }
    if(mode=="concurrent-cold-start") {
        std::atomic<unsigned> successes{0},busy{0};std::vector<std::thread> threads;
        for(unsigned i=0;i<16;++i)threads.emplace_back([&] {
            IOService *value=nullptr;const IOReturn result=dodge_gop_provider_publish(platform,&value);
            if(result==kIOReturnSuccess) {assert(value);++successes;value->release();}
            else {assert(result==kIOReturnBusy && !value);++busy;}
        });
        for(auto &thread:threads)thread.join();
        assert(successes && successes+busy==16 && allocations==1 && registrations==1 && allocated->references==2);
        goto complete;
    }
    if(mode=="modules-not-ready") {modulesReady=false;expected=kIOReturnNotReady;}
    if(mode=="wrong-platform") {currentPlatform=nullptr;expected=kIOReturnUnsupported;}
    if(mode=="platform-inactive") {platform->inactive=true;expected=kIOReturnUnsupported;}
    if(mode=="platform-hierarchy") {platform->hierarchy=false;expected=kIOReturnUnsupported;}
    if(mode=="console-failure")expected=kIOReturnUnsupported;
    if(mode=="zero-base") {video.v_baseAddr=0;expected=kIOReturnUnsupported;}
    if(mode=="zero-width") {video.v_width=0;expected=kIOReturnUnsupported;}
    if(mode=="zero-height") {video.v_height=0;expected=kIOReturnUnsupported;}
    if(mode=="oversize-width") {video.v_width=8193;expected=kIOReturnUnsupported;}
    if(mode=="oversize-height") {video.v_height=8193;expected=kIOReturnUnsupported;}
    if(mode=="depth") {video.v_depth=24;expected=kIOReturnUnsupported;}
    if(mode=="rotation") {video.v_rotate=1;expected=kIOReturnUnsupported;}
    if(mode=="short-stride") {video.v_rowBytes=5759;expected=kIOReturnUnsupported;}
    if(mode=="long-stride") {video.v_rowBytes=32769;expected=kIOReturnUnsupported;}
    if(mode=="physical-overflow") {video.v_baseAddr=UINT64_MAX-4096;expected=kIOReturnUnsupported;}
    if(mode=="symbol-failure" || mode=="allocation-failure" || mode=="name-failure" || mode=="memory-allocation-failure" ||
       mode=="array-allocation-failure" || mode=="array-insert-failure" || mode=="memory-install-failure" ||
       mode=="memory-count-mismatch" || mode=="memory-index-mismatch")expected=kIOReturnNoMemory;
    if(mode=="metadata-missing" || mode=="metadata-identity" || mode=="metadata-size" || mode=="metadata-parent" ||
       mode=="allocation-wrong-class" || mode=="object-wrong-metadata" || mode=="memory-address-mismatch" ||
       mode=="memory-length-mismatch")expected=kIOReturnUnsupported;
    if(mode=="init-failure" || mode=="attach-failure" || mode=="platform-dies-at-attach" || mode=="mode-change-at-attach" ||
       mode=="reentry-release")expected=kIOReturnNotReady;
    if(mode=="mode-change-at-register" || mode=="provider-dies-at-register" || mode=="memory-change-at-register")expected=kIOReturnNotReady;
    if(mode=="resources-failure")expected=kIOReturnError;
    {
        IOService *out=reinterpret_cast<IOService *>(uintptr_t(1));
        const bool wrapper=mode.rfind("wrapper-",0)==0;
        if(mode=="wrapper-prepare-failure") {prepareResult=kIOReturnError;expected=kIOReturnError;}
        if(mode=="wrapper-publish-failure") {video.v_depth=16;expected=kIOReturnUnsupported;}
        if(mode=="wrapper-boot-failure" || mode=="wrapper-retry") {bootResult=kIOReturnNotReady;expected=kIOReturnNotReady;}
        const IOReturn result=wrapper?dodge_graphics_boot_gop(platform,&out):dodge_gop_provider_publish(platform,&out);
        assert(result==expected);
        if(result!=kIOReturnSuccess)assert(!out);
        else {assert(out);out->release();}
        if(registrations) {
            assert(registrations==1 && providerObjects==1 && memoryObjects==1 && arrayObjects==1);
            assert(dodge_test_gop_meta.pins==1 && platform->references==2 && allocated->references==2 && !detachCalls);
            DodgeGopProviderStatus status={};dodge_gop_provider_status(&status);
            assert(status.phase==DodgeGopProviderPhase::Published && status.physicalAddress==0x123400000 &&
                   status.width==1440 && status.height==3168 && status.rowBytes==5760 && status.length==5760*3168);
            if(mode=="cache-mode-change")video.v_baseAddr+=4096;
            if(mode=="cache-provider-inactive")allocated->inactive=true;
            if(mode=="cache-platform-inactive")platform->inactive=true;
            if(mode=="cache-memory-change")dynamic_cast<IODeviceMemory *>(allocated->memory->values[0])->length+=4096;
            IOService *again=nullptr;
            if(mode=="cache-wrong-platform") {
                auto *other=new IOPlatformExpert;
                assert(dodge_gop_provider_publish(other,&again)==kIOReturnNotReady && !again);other->release();
            } else if(mode.rfind("cache-",0)==0 || mode=="mode-change-at-register" || mode=="provider-dies-at-register" ||
                      mode=="memory-change-at-register")assert(dodge_gop_provider_publish(platform,&again)==kIOReturnNotReady && !again);
            else {
                assert(dodge_gop_provider_publish(platform,&again)==kIOReturnSuccess && again==allocated);again->release();
                assert(allocations==1 && registrations==1 && allocated->references==2);
            }
            if(mode=="wrapper-retry") {
                bootResult=0;IOService *display=nullptr;
                assert(dodge_graphics_boot_gop(platform,&display)==kIOReturnSuccess && display);display->release();
                assert(prepareCalls==2 && bootCalls==2 && allocations==1 && registrations==1);
            }
        } else {
            assert(!providerObjects && !memoryObjects && !arrayObjects && !symbols && !registrations);
            assert(!dodge_test_gop_meta.pins && !otherMeta.pins && platform->references==1);
            DodgeGopProviderStatus status={};dodge_gop_provider_status(&status);
            assert(status.phase==DodgeGopProviderPhase::Cold && !status.width && !status.physicalAddress);
            if(mode=="platform-dies-at-attach" || mode=="mode-change-at-attach")assert(detachCalls==1);
            if(mode=="reentry-release")assert(reentries==1);
            if(mode=="modules-not-ready") {
                modulesReady=true;
                assert(dodge_gop_provider_publish(platform,&out)==kIOReturnSuccess && out);out->release();
            }
            if(mode=="wrapper-prepare-failure")assert(prepareCalls==1 && !allocations && !bootCalls);
            if(mode=="wrapper-publish-failure")assert(prepareCalls==1 && !allocations && !bootCalls);
        }
        if(mode.rfind("reentry-",0)==0)assert(reentries==1);
        if(wrapper && registrations)assert(bootCalls && events.front()=="prepare" && events.back()=="boot");
    }
complete:
    dodge_gop_provider_status(nullptr);
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"allocations\":%u,\"publications\":%u,\"detach_calls\":%u,\"reentries\":%u}\n",
        mode.c_str(),allocations,registrations,detachCalls,reentries);
    return 0;
}
