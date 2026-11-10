// SPDX-License-Identifier: MIT
// Actual frontend + actual bridge/copy. The original builder/completion,
// surface-backing provider, presenter and IOKit objects are software peers.
#include "DodgeDisplayFrontend.h"
#include "DodgeGpuSwapBridge.h"
#include "DodgeSoftwareRefresh.h"
#include "DodgeAdrenoTimeline.h"
#include "OriginalLegacyPacketABI.h"
#include "OriginalLegacyLifecycleABI.h"
#include "OriginalLegacyRefreshABI.h"
#include "OriginalLegacySwapCompletionABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <pexpert/pexpert.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#ifdef DODGE_DISPLAY_SERVICE_INTEGRATION
#include "DodgeDisplayService.h"
static DodgeDisplayService *serviceUnderTest=nullptr;
#endif

static std::unordered_map<void *,size_t> allocations;
static int allocationFailure=-1;
bool dodge_test_timer_failure=false;
IOReturn dodge_test_timer_wake_result=kIOReturnSuccess;
unsigned dodge_test_timer_objects=0;
IOTimerEventSource *dodge_test_last_timer=nullptr;
static IOReturn addResult=kIOReturnSuccess,removeResult=kIOReturnSuccess;
static uint64_t now=1000,conversionDivisor=1;
static bool gpuKnown=true;
static uint32_t gpuSubmitted=0,gpuRetired=0;
static uint64_t gpuEpoch=1;
static unsigned gpuQueries=0;
static std::function<void()> surfaceReleaseHook;
void *IOMallocZero(size_t bytes) {
    if(allocationFailure==0)return nullptr;
    if(allocationFailure>0)--allocationFailure;
    void *pointer=std::calloc(1,bytes);assert(pointer);allocations[pointer]=bytes;return pointer;
}
void IOFree(void *pointer,size_t bytes) {
    auto found=allocations.find(pointer);assert(found!=allocations.end() && found->second==bytes);
    allocations.erase(found);std::free(pointer);
}
struct Display : IOService {
    uint8_t storage[IPhone16Swap::DisplayBytes-sizeof(IOService)]{};
    Display():IOService(DodgeSwapKind::Display) {}
};
struct IOMFBSwapIORequest : OSObject {
    uint8_t storage[IPhone16Swap::RequestBytes-sizeof(OSObject)]{};
    IOMFBSwapIORequest():OSObject(DodgeSwapKind::Request) {}
};
static_assert(sizeof(Display)==5728 && sizeof(IOMFBSwapIORequest)==2424,"Synthetic storage extents only");
struct Surface : OSObject {
    uint32_t id=0x42424242;
    bool valid=true;
    Surface():OSObject(DodgeSwapKind::Other) {}
    const OSObject *metaCast(const char *name) const override {return valid && !strcmp(name,"IOSurface")?this:nullptr;}
    void release() const override {
        auto callback=surfaceReleaseHook;surfaceReleaseHook={};OSObject::release();if(callback)callback();
    }
};
static PE_Video video;
static bool consoleError=false,presenterAccept=true,synchronous=false,producerDone=true,enqueue=true;
static int gpuStatus=0;
static IOReturn originalStatus=0,backingStatus=0;
static unsigned builderCalls=0,completionCalls=0,backingCalls=0,presentOffers=0,pixelCopies=0,barriers=0;
static unsigned refreshCalls=0;
static std::function<void()> backingHook,completionHook,refreshHook;
static std::function<void(IOMFBSwapIORequest &)> requestHook;
struct Offered {void *context=nullptr;IOMemoryDescriptor *memory=nullptr;};
static Offered offered;
extern "C" void native_legacy_gpu_complete(void *,int);
extern "C" int PE_current_console(PE_Video *out){*out=video;return consoleError;}
extern "C" uint32_t native_iphone_surface_id(const OSObject *object){return static_cast<const Surface *>(object)->id;}
extern "C" int boot_progress_display_handoff(void){return 1;}
extern "C" void boot_progress_display_failed(void){}
extern "C" void boot_progress_display_copy(uint64_t,uint64_t){++pixelCopies;}
extern "C" void boot_progress_peripheral_frame(void){}
extern "C" void native_legacy_overlay_rows(uint32_t *first,uint32_t *rows){*first=0;*rows=0;}
extern "C" void OSSynchronizeIO(void){++barriers;}
extern "C" uint64_t mach_absolute_time(void){return now;}
extern "C" uint64_t mach_continuous_time(void){return now+700;}
extern "C" void nanoseconds_to_absolutetime(uint64_t ns,uint64_t *out){*out=conversionDivisor?ns/conversionDivisor:0;}
extern "C" bool dodge_adreno_display_timeline(DodgeAdrenoTimeline *out) {
    ++gpuQueries;if(!gpuKnown)return false;
    *out={gpuEpoch,gpuSubmitted,gpuRetired};return true;
}
IOReturn IOWorkLoop::addEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && !source->loop);
    if(addResult)return addResult;
    source->loop=this;source->retain();return kIOReturnSuccess;
}
IOReturn IOWorkLoop::removeEventSource(IOTimerEventSource *source) {
    assert(inGate() && source && source->loop==this);
    if(removeResult)return removeResult;
    source->loop=nullptr;source->enabled=source->armed=false;source->release();return kIOReturnSuccess;
}
static void completeOffer(int status=0) {
    assert(offered.context);const auto done=offered;offered={};done.memory->release();native_legacy_gpu_complete(done.context,status);
}
extern "C" bool native_gop_gpu_offer(IOService *,void *context,IOMemoryDescriptor *memory,uint64_t,uint32_t,uint32_t) {
    ++presentOffers;if(!presenterAccept)return false;
    assert(!offered.context);memory->retain();offered={context,memory};
    if(synchronous)completeOffer(gpuStatus);
    return true;
}

struct Fixture;
static Fixture *activeFixture=nullptr;
struct Fixture {
    IOWorkLoop loop;
    IOCommandGate gate;
    Display display;
    IOService presenter{DodgeSwapKind::Presenter};
    IOMemoryMap scanout,sourceMap;
    IOMemoryDescriptor memory;
    Surface surface;
    std::array<IOMFBSwapIORequest,32> requests;
    std::array<bool,32> queued{},familySurface{};
    unsigned nextRequest=0;
    DodgeDisplayFrontend *front=nullptr;
    std::vector<uint8_t> destination,input;
    Fixture() {
        assert(!activeFixture && allocations.empty() && !offered.context && !dodge_test_timer_objects && !native_gop_vsync[0]);activeFixture=this;
        allocationFailure=-1;consoleError=false;presenterAccept=producerDone=enqueue=true;synchronous=false;gpuStatus=0;
        dodge_test_timer_failure=false;dodge_test_timer_wake_result=addResult=removeResult=kIOReturnSuccess;
        now=1000;conversionDivisor=1;gpuKnown=true;gpuSubmitted=gpuRetired=gpuQueries=0;gpuEpoch=1;
        originalStatus=backingStatus=0;builderCalls=completionCalls=backingCalls=presentOffers=pixelCopies=barriers=0;
        backingHook={};completionHook={};refreshHook={};surfaceReleaseHook={};requestHook={};refreshCalls=0;video={};video.v_width=17;video.v_rowBytes=80;
        destination.assign(64+video.v_height*video.v_rowBytes+64,0xcd);input.resize(64+84*video.v_height+64);
        for(size_t index=0;index<input.size();++index)input[index]=uint8_t(index*37+19);
        scanout.physical=video.v_baseAddr;scanout.bytes=video.v_height*video.v_rowBytes;
        scanout.address=reinterpret_cast<uintptr_t>(destination.data()+64);
        sourceMap.bytes=84*video.v_height;sourceMap.address=reinterpret_cast<uintptr_t>(input.data()+64);
        memory.bytes=sourceMap.bytes;memory.mapping=&sourceMap;display.loop=presenter.loop=gate.loop=&loop;
        IPhone16Swap::store(&display,5040,&gate);
        IPhone16Swap::store(&display,5208,uint32_t(video.v_width));IPhone16Swap::store(&display,5212,uint32_t(video.v_height));
        IPhone16Swap::store(&display,IPhone16Swap::Tail,reinterpret_cast<uint8_t *>(&display)+IPhone16Swap::Head);
        IPhone16Swap::store(&display,IPhone16Lifecycle::UnsubmittedTail,reinterpret_cast<uint8_t *>(&display)+IPhone16Lifecycle::UnsubmittedHead);
        for(unsigned index=0;index<IPhone16Lifecycle::NotifyCount;++index) {
            const unsigned head=IPhone16Lifecycle::NotifyHead+index*16;
            IPhone16Swap::store(&display,head+8,reinterpret_cast<uint8_t *>(&display)+head);
        }
    }
    std::array<uint8_t,IPhone16Swap::PacketBytes> packet(uint32_t id=1) const {
        std::array<uint8_t,IPhone16Swap::PacketBytes> data{};
        IPhone16Swap::store(data.data(),80,id);IPhone16Swap::store(data.data(),84,surface.id);
        IPhone16Swap::store(data.data(),164,1U);IPhone16Swap::store(data.data(),260,1U);
        for(unsigned base:{100U,196U}) {
            IPhone16Swap::store(data.data(),base+8,uint32_t(video.v_width));
            IPhone16Swap::store(data.data(),base+12,uint32_t(video.v_height));
        }
        return data;
    }
    bool tryCreate(DodgeDisplayProducer producer=DodgeDisplayProducer::AdrenoTimeline,
        DodgeDisplayTransfer transfer=DodgeDisplayTransfer::Presenter) {
        front=loop.withGate([&]{return dodge_display_frontend_create(&display,&presenter,&scanout,producer,transfer);});return front;
    }
    void create(DodgeDisplayProducer producer=DodgeDisplayProducer::AdrenoTimeline,
        DodgeDisplayTransfer transfer=DodgeDisplayTransfer::Presenter) {assert(tryCreate(producer,transfer));}
    IOReturn submit(uint32_t id=1) {auto data=packet(id);return dodge_display_frontend_submit(front,data.data(),data.size(),this);}
    IOReturn kick(){return loop.withGate([&]{return dodge_display_frontend_kick(front);});}
    void fire(IOTimerEventSource *timer,int64_t offset=0) {assert(timer);now=std::max(now,timer->deadline+offset);timer->fire();}
    void tick(int64_t offset=0) {fire(dodge_test_last_timer,offset);}
    IOReturn refresh(bool enabled=true) {return loop.withGate([&]{return dodge_display_frontend_set_refresh(front,enabled);});}
    void listeners(bool present=true) {IPhone16Swap::store<void *>(&display,IPhone16Refresh::ClientHead,present?reinterpret_cast<void *>(0x12345678):nullptr);}
    IOReturn stop() {
        assert(front);auto *object=front;const auto result=loop.withGate([&]{return dodge_display_frontend_stop(object);});
        if(!result)front=nullptr;
        return result;
    }
    DodgeDisplayFrontendStatus status() {
        DodgeDisplayFrontendStatus status{};assert(loop.withGate([&]{return dodge_display_frontend_status(front,&status);}));return status;
    }
    unsigned indexOf(IOMFBSwapIORequest *request) const {
        for(unsigned index=0;index<requests.size();++index)if(&requests[index]==request)return index;
        assert(false);return 0;
    }
    void cancel(unsigned index) {
        // Software peer for an original family dequeue, not GPU completion.
        loop.withGate([&]{
            auto &request=requests[index];assert(queued[index] && familySurface[index]);
            assert(IPhone16Swap::load<void *>(&display,IPhone16Swap::Current)!=&request);
            auto *previous=IPhone16Swap::load<IOMFBSwapIORequest **>(&request,IPhone16Swap::PreviousLink);
            auto *next=IPhone16Swap::load<IOMFBSwapIORequest *>(&request,IPhone16Swap::Next);
            assert(previous && *previous==&request);*previous=next;
            if(next)IPhone16Swap::store(next,IPhone16Swap::PreviousLink,previous);
            else IPhone16Swap::store(&display,IPhone16Swap::Tail,previous);
            IPhone16Swap::store<void *>(&request,IPhone16Swap::Next,nullptr);IPhone16Swap::store<void *>(&request,IPhone16Swap::PreviousLink,nullptr);
            queued[index]=familySurface[index]=false;request.release();surface.release();
        });
    }
    void unchanged()const{assert(std::all_of(destination.begin(),destination.end(),[](uint8_t value){return value==0xcd;}));}
    void copied()const {
        for(size_t index=0;index<destination.size();++index) {
            uint8_t expected=0xcd;
            if(index>=64 && index<64+scanout.bytes) {
                const auto row=(index-64)/video.v_rowBytes,column=(index-64)%video.v_rowBytes;
                if(column<video.v_width*4)expected=input[64+row*84+column];
            }
            assert(destination[index]==expected);
        }
    }
    ~Fixture() {
        assert(!offered.context);
        if(front)assert(!stop());
        for(unsigned index=0;index<requests.size();++index) {
            if(queued[index])requests[index].release();
            if(familySurface[index])surface.release();
            assert(requests[index].references==1);
        }
        assert(allocations.empty() && !dodge_test_timer_objects && !native_gop_vsync[0] && surface.references==1 && memory.references==1 && sourceMap.references==1 &&
            display.references==1 && gate.references==1 && loop.references==1 && presenter.references==1 && scanout.references==1 && !memory.prepared);
        activeFixture=nullptr;backingHook={};completionHook={};refreshHook={};surfaceReleaseHook={};requestHook={};
    }
};

extern "C" void native_iphone_refresh_notify(void *display,uint64_t stamp,uint64_t continuous,uint64_t interval) {
    auto &f=*activeFixture;assert(display==&f.display && f.loop.inGate() && stamp==now && continuous==now+700 && interval==1000000000ULL/60);
    ++refreshCalls;if(refreshHook)refreshHook();
}

IOReturn dodge_copy_surface_backing(OSObject *surface,uint32_t width,uint32_t height,DodgeSurfaceBacking *output) {
    auto &f=*activeFixture;++backingCalls;assert(surface==&f.surface && width==video.v_width && height==video.v_height && !output->memory);
    if(backingHook)backingHook();
    if(backingStatus)return backingStatus;
    f.memory.retain();*output={&f.memory,width,height,84};return 0;
}
void dodge_release_surface_backing(DodgeSurfaceBacking *output) {
    if(output->memory)output->memory->release();
    *output={};
}
extern "C" int32_t native_iphone_submit_default_packet(void *object,const void *packet,void *submitter) {
    auto &f=*activeFixture;assert(object==&f.display && submitter==&f && f.loop.inGate());++builderCalls;
    assert(f.nextRequest<f.requests.size());const unsigned index=f.nextRequest++;auto &request=f.requests[index];
    std::memset(request.storage,0,sizeof(request.storage));request.retain();f.surface.retain();f.familySurface[index]=true;
    IPhone16Swap::store(&request,788,IPhone16Swap::load<uint32_t>(packet,80));
    IPhone16Swap::store(&request,792,1U);IPhone16Swap::store(&request,816,uint32_t(video.v_width));
    IPhone16Swap::store(&request,820,uint32_t(video.v_height));IPhone16Swap::store(&request,532,1U);
    for(unsigned base:{17U,81U}) {
        IPhone16Swap::store(&request,base+8,uint32_t(video.v_width));IPhone16Swap::store(&request,base+12,uint32_t(video.v_height));
    }
    IPhone16Swap::store(&request,IPhone16Swap::Surfaces,&f.surface);
    if(requestHook)requestHook(request);
    IOReturn result=originalStatus;
    bool valid=false;
    if(!result) {
#ifdef DODGE_DISPLAY_SERVICE_INTEGRATION
        valid=dodge_display_service_validate(serviceUnderTest,&request);
#else
        valid=dodge_display_frontend_validate(f.front,&request);
#endif
    }
    if(!result && !valid)result=kIOReturnBadArgument;
    if(!result && enqueue) {
        IPhone16Swap::store<uint8_t>(&request,IPhone16Swap::ProducerRegistration,1);
        IPhone16Swap::store(&request,IPhone16Swap::ReadyLayers,producerDone?1U:0U);
        IPhone16Swap::store(&request,IPhone16Swap::EffectiveSurfaces,&f.surface);
        auto *tail=IPhone16Swap::load<IOMFBSwapIORequest **>(&f.display,IPhone16Swap::Tail);
        *tail=&request;IPhone16Swap::store(&request,IPhone16Swap::PreviousLink,tail);
        IPhone16Swap::store(&f.display,IPhone16Swap::Tail,reinterpret_cast<uint8_t *>(&request)+IPhone16Swap::Next);
        request.retain();f.queued[index]=true;
#ifdef DODGE_DISPLAY_SERVICE_INTEGRATION
        dodge_display_service_kick(serviceUnderTest);
#else
        dodge_display_frontend_kick(f.front);
#endif
    } else {f.familySurface[index]=false;f.surface.release();}
    request.release();return result;
}
extern "C" void native_iphone_complete_current(void *object) {
    auto &f=*activeFixture;assert(object==&f.display && f.loop.inGate());++completionCalls;
    auto *request=IPhone16Swap::load<IOMFBSwapIORequest *>(object,IPhone16Swap::Current);assert(request);
    const unsigned index=f.indexOf(request);assert(f.queued[index] && f.familySurface[index] && f.surface.references>=3);
    f.queued[index]=f.familySurface[index]=false;request->release();f.surface.release();
    IPhone16Swap::store<void *>(object,IPhone16Swap::Current,nullptr);
    if(completionHook)completionHook();
}

static std::vector<std::string> cases;
static void run(const std::string &name,const std::function<void()> &test){test();cases.push_back(name);}
#ifdef DODGE_DISPLAY_SERVICE_INTEGRATION
#include "DodgeDisplayServiceIntegrationCases.h"
#else
int main() {
    run("unpublished-start-enters-workloop-before-frontend-construction",[]{
        Fixture f;assert(!f.loop.inGate());
        f.front=dodge_display_frontend_create(&f.display,nullptr,&f.scanout);
        assert(f.front && f.loop.actions==1 && !f.loop.inGate() && dodge_test_timer_objects==1 && !builderCalls);
    });
    run("ungated-cpu-only-start-can-present-default-packet",[]{
        Fixture f;f.front=dodge_display_frontend_create(&f.display,nullptr,&f.scanout,DodgeDisplayProducer::CpuOnly);
        assert(f.front && f.loop.actions==1 && !dodge_test_timer_objects);
        assert(!f.submit() && !presentOffers && f.status().retired==1);f.copied();
    });
    run("already-gated-create-does-not-queue-a-second-action",[]{
        Fixture f;f.create();assert(!f.loop.actions);
    });
    run("ungated-create-refuses-missing-workloop",[]{
        Fixture f;f.display.loop=nullptr;assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && !f.loop.actions);
        f.display.loop=&f.loop;
    });
    run("ungated-create-refuses-disabled-command-gate",[]{
        Fixture f;f.gate.enabled=false;assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && !f.loop.actions);
    });
    run("ungated-create-refuses-detached-command-gate",[]{
        Fixture f;f.gate.loop=nullptr;assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && !f.loop.actions);
        f.gate.loop=&f.loop;
    });
    run("create-inputs-held-until-mode-is-rechecked-under-gate",[]{
        Fixture f;f.loop.beforeAction=[] {
            auto &state=*activeFixture;assert(state.loop.inGate() && !state.front);
            assert(state.display.references==2 && state.loop.references==2 && state.gate.references==2 &&
                   state.scanout.references==2 && state.presenter.references==2);
            IPhone16Swap::store(&state.display,5208,999U);
        };
        assert(!dodge_display_frontend_create(&f.display,&f.presenter,&f.scanout) && f.loop.actions==1 && allocations.empty());
    });
    run("create-rechecks-startup-queue-after-entering-gate",[]{
        Fixture f;f.loop.beforeAction=[] {
            IPhone16Swap::store<void *>(&activeFixture->display,IPhone16Lifecycle::UnsubmittedHead,reinterpret_cast<void *>(0x1234));
        };
        assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && f.loop.actions==1 && allocations.empty());
        IPhone16Swap::store<void *>(&f.display,IPhone16Lifecycle::UnsubmittedHead,nullptr);
    });
    run("create-refuses-loop-replacement-before-action",[]{
        Fixture f;IOWorkLoop other;f.presenter.loop=&other;
        f.loop.beforeAction=[] {activeFixture->display.loop=activeFixture->presenter.loop;};
        assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && f.loop.actions==1 && allocations.empty());
        f.display.loop=f.presenter.loop=&f.loop;
    });
    run("create-refuses-command-gate-replacement-before-action",[]{
        Fixture f;IOCommandGate other;static IOCommandGate *replacement;replacement=&other;
        f.loop.beforeAction=[] {
            IPhone16Swap::store(&activeFixture->display,5040,replacement);
        };
        assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && f.loop.actions==1 && allocations.empty());
        IPhone16Swap::store(&f.display,5040,&f.gate);replacement=nullptr;
    });
    run("create-refuses-command-gate-disabled-before-action",[]{
        Fixture f;f.loop.beforeAction=[] {activeFixture->gate.enabled=false;};
        assert(!dodge_display_frontend_create(&f.display,nullptr,&f.scanout) && f.loop.actions==1 && allocations.empty());
    });
    run("ungated-create-allocation-failure-releases-temporary-inputs",[]{
        Fixture f;allocationFailure=0;assert(!dodge_display_frontend_create(&f.display,&f.presenter,&f.scanout));
        assert(f.loop.actions==1 && allocations.empty() && !dodge_test_timer_objects);
    });
    run("ungated-create-timer-failure-releases-temporary-inputs",[]{
        Fixture f;dodge_test_timer_failure=true;assert(!dodge_display_frontend_create(&f.display,&f.presenter,&f.scanout));
        assert(f.loop.actions==1 && allocations.empty() && !dodge_test_timer_objects);
    });
    run("ungated-create-source-add-failure-releases-temporary-inputs",[]{
        Fixture f;addResult=kIOReturnError;assert(!dodge_display_frontend_create(&f.display,&f.presenter,&f.scanout));
        assert(f.loop.actions==1 && allocations.empty() && !dodge_test_timer_objects);
    });
    for(unsigned field:{unsigned(IPhone16Lifecycle::UnsubmittedHead),unsigned(IPhone16Refresh::ClientHead)})run("existing-family-work-refuses-frontend-create-"+std::to_string(field),[&]{
        Fixture f;IPhone16Swap::store<void *>(&f.display,field,reinterpret_cast<void *>(0x1234));
        assert(!f.tryCreate() && allocations.empty() && !dodge_test_timer_objects && !backingCalls);
    });
    for(unsigned field:{5208U,5212U})run("original-display-mode-mismatch-at-create-"+std::to_string(field),[&]{
        Fixture f;IPhone16Swap::store(&f.display,field,999U);assert(!f.tryCreate() && allocations.empty() && !dodge_test_timer_objects);
    });
    run("mode-change-cancels-producer-wait-without-surface-read",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        IPhone16Swap::store(&f.display,5208,1U);gpuRetired=7;f.tick();
        assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !backingCalls && !presentOffers && !completionCalls);f.unchanged();
    });
    run("mode-change-during-gpu-offer-prevents-copy-and-retirement",[]{
        Fixture f;f.create();assert(!f.submit());IPhone16Swap::store(&f.display,5212,1U);completeOffer(kIOReturnError);
        assert(!pixelCopies && !completionCalls && !f.status().active && f.status().pending==1);f.unchanged();
    });
    run("mode-change-during-backing-releases-unpublished-output",[]{
        Fixture f;f.create();backingHook=[&]{IPhone16Swap::store(&f.display,5208,1U);};assert(!f.submit());
        assert(!presentOffers && !completionCalls && f.memory.references==1 && !f.status().active && f.status().pending==1);f.unchanged();
    });
    run("recovery-epoch-change-refuses-reused-fence-number",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        gpuEpoch=2;gpuRetired=7;f.tick();assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !backingCalls && !presentOffers);
        gpuSubmitted=gpuRetired=100;assert(f.kick()==kIOReturnAborted && !completionCalls);f.unchanged();
    });
    run("unavailable-query-during-recovery-never-adopts-new-epoch",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        gpuEpoch=2;gpuRetired=7;gpuKnown=false;f.tick();assert(f.status().producerWaiting && !backingCalls);
        gpuKnown=true;f.tick();assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !presentOffers && !completionCalls);f.unchanged();
    });
    run("new-epoch-request-progresses-only-after-old-request-is-dequeued",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit(1));
        gpuEpoch=2;gpuSubmitted=9;gpuRetired=8;assert(!f.submit(2) && !presentOffers);
        assert(!f.status().producerWaiting && f.status().pending==2);f.cancel(0);
        gpuRetired=9;assert(!f.kick() && offered.context);completeOffer();
        assert(completionCalls==1 && f.status().retired==1 && !f.status().pending);
    });
    run("first-available-query-captures-current-epoch-once",[]{
        Fixture f;f.create();gpuKnown=false;assert(!f.submit());
        gpuKnown=true;gpuEpoch=3;gpuSubmitted=8;gpuRetired=7;f.tick();assert(f.status().producerWaiting && !backingCalls);
        gpuSubmitted=100;gpuRetired=8;f.tick();assert(offered.context);completeOffer();assert(f.status().retired==1);
    });
    run("default-cpu-scanout-does-not-copy-reset-producer",[]{
        Fixture f;f.front=f.loop.withGate([&]{return dodge_display_frontend_create(&f.display,nullptr,&f.scanout);});assert(f.front);
        gpuSubmitted=7;gpuRetired=6;assert(!f.submit());gpuEpoch=2;gpuRetired=7;f.tick();
        assert(!backingCalls && !presentOffers && !pixelCopies && !completionCalls && f.status().last==kIOReturnAborted);f.unchanged();
    });
    run("original-cancellations-reuse-bounded-ledger-and-request-id",[]{
        Fixture f;f.create();producerDone=false;
        for(unsigned index=0;index<f.requests.size();++index) {assert(!f.submit(9));f.cancel(index);}
        f.kick();assert(f.status().submitted==32 && !f.status().pending && !presentOffers && !completionCalls && !backingCalls);f.unchanged();
    });
    run("all-sixteen-dequeued-reservations-can-be-reclaimed-before-submit",[]{
        Fixture f;f.create();producerDone=false;
        for(unsigned index=0;index<16;++index)assert(!f.submit(index));
        for(unsigned index=0;index<16;++index)f.cancel(index);
        assert(!f.submit(100) && f.status().pending==1 && builderCalls==17);
        for(unsigned index=0;index<16;++index)assert(f.requests[index].references==1);
        assert(!backingCalls && !completionCalls && !presentOffers);f.unchanged();
    });
    run("family-current-request-is-not-reaped-as-dequeued",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit());
        assert(f.loop.withGate([&]{return IPhone16Swap::activatePending(&f.display,&f.requests[0]);}));
        f.kick();assert(f.status().pending==1 && f.requests[0].references==3 && !completionCalls && !presentOffers);
        f.loop.withGate([&]{native_iphone_complete_current(&f.display);});
        f.kick();assert(!f.status().pending && f.requests[0].references==1 && f.status().retired==0 && completionCalls==1);
    });
    run("dequeued-middle-request-releases-only-its-ledger-references",[]{
        Fixture f;f.create();producerDone=false;for(unsigned id=1;id<=3;++id)assert(!f.submit(id));
        f.cancel(1);f.kick();assert(f.status().pending==2 && f.requests[1].references==1);
        for(unsigned index:{0U,2U})IPhone16Swap::store(&f.requests[index],IPhone16Swap::ReadyLayers,1U);
        assert(!f.kick());completeOffer();assert(offered.context);completeOffer();assert(f.status().retired==2 && !f.status().pending);
    });
    run("unknown-queue-head-does-not-release-held-requests",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit());
        IPhone16Swap::store<void *>(&f.display,IPhone16Swap::Head,reinterpret_cast<void *>(0x1234));
        assert(f.kick()==kIOReturnNotReady && f.submit(2)==kIOReturnNotReady && builderCalls==1 && f.status().pending==1 && f.requests[0].references==3);
        IPhone16Swap::store(&f.display,IPhone16Swap::Head,&f.requests[0]);
        IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);assert(!f.kick());completeOffer();
    });
    for(unsigned defect=0;defect<4;++defect)run("malformed-original-queue-refuses-reaping-"+std::to_string(defect),[&]{
        Fixture f;f.create();producerDone=false;assert(!f.submit());
        if(defect==0)IPhone16Swap::store(&f.requests[0],IPhone16Swap::Next,&f.requests[0]);
        if(defect==1)IPhone16Swap::store<void *>(&f.display,IPhone16Swap::Tail,nullptr);
        if(defect==2)IPhone16Swap::store<void *>(&f.requests[0],IPhone16Swap::PreviousLink,nullptr);
        if(defect==3)IPhone16Swap::store<void *>(&f.display,IPhone16Swap::Current,reinterpret_cast<void *>(0x1234));
        assert(f.kick()==kIOReturnNotReady && f.submit(2)==kIOReturnNotReady && builderCalls==1 && f.status().pending==1 && f.requests[0].references==3);
    });
    run("dequeued-release-can-stop-frontend-without-double-release",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit());f.cancel(0);
        surfaceReleaseHook=[&]{assert(!f.stop());};f.kick();
        assert(!f.front && !dodge_test_timer_objects && f.requests[0].references==1 && f.surface.references==1 && !completionCalls);f.unchanged();
    });
    run("dequeued-release-can-reserve-new-generation-in-same-slot",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit(1));f.cancel(0);
        surfaceReleaseHook=[&]{assert(!f.submit(2));};f.kick();
        assert(f.front && f.status().pending==1 && f.requests[0].references==1 && f.requests[1].references==3 && builderCalls==2);
        IPhone16Swap::store(&f.requests[1],IPhone16Swap::ReadyLayers,1U);assert(!f.kick());completeOffer();assert(f.status().retired==1);
    });
    run("software-refresh-defaults-off-and-explicitly-notifies-original-clients",[]{
        Fixture f;f.create();assert(!native_gop_vsync[0] && dodge_test_timer_objects==1 && !f.refresh(false));
        assert(dodge_test_timer_objects==1 && !f.refresh());auto *timer=dodge_test_last_timer;
        assert(dodge_test_timer_objects==2 && native_gop_vsync[0]==60);f.fire(timer);assert(!refreshCalls);
        f.listeners();f.fire(timer);assert(refreshCalls==1 && !pixelCopies && !completionCalls);
        assert(!f.refresh(false) && !timer->armed && !native_gop_vsync[0]);
        assert(!f.refresh() && dodge_test_timer_objects==2);f.fire(timer);assert(refreshCalls==2);
    });
    run("gpu-wait-and-software-refresh-use-independent-timers-on-original-loop",[]{
        Fixture f;f.create();auto *producer=dodge_test_last_timer;gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        f.listeners();assert(!f.refresh());auto *refresh=dodge_test_last_timer;assert(producer!=refresh);
        f.fire(refresh);assert(refreshCalls==1 && f.status().producerWaiting && !backingCalls && !presentOffers);
        gpuRetired=7;f.fire(producer);assert(offered.context && !f.status().producerWaiting);completeOffer();
        f.fire(refresh);assert(refreshCalls==2 && f.status().retired==1);
    });
    run("refresh-sender-can-stop-entire-frontend-reentrantly",[]{
        Fixture f;f.create();f.listeners();assert(!f.refresh());auto *timer=dodge_test_last_timer;
        refreshHook=[&]{assert(!f.stop());};f.fire(timer);
        assert(!f.front && refreshCalls==1 && !dodge_test_timer_objects && !native_gop_vsync[0] && !pixelCopies && !completionCalls);
    });
    run("busy-stop-disables-refresh-before-active-frame-drains",[]{
        Fixture f;f.create();assert(!f.submit());f.listeners();assert(!f.refresh());
        auto *timer=dodge_test_last_timer;timer->retain();assert(f.stop()==kIOReturnBusy && f.front && !native_gop_vsync[0]);
        f.loop.withGate([&]{timer->forceStaleAction();});assert(!refreshCalls && !timer->armed && !timer->getRefcon());timer->release();
        assert(f.refresh()==kIOReturnNotReady);completeOffer();assert(!completionCalls && !f.stop());
    });
    run("refresh-removal-failure-retains-frontend-owner-for-retry",[]{
        Fixture f;f.create();f.listeners();assert(!f.refresh());auto *timer=dodge_test_last_timer;
        removeResult=kIOReturnError;assert(f.stop()==kIOReturnError && f.front && f.status().draining && !native_gop_vsync[0]);
        assert(!timer->armed && !timer->enabled && !timer->getRefcon());f.loop.withGate([&]{timer->forceStaleAction();});
        assert(!refreshCalls && !pixelCopies && !completionCalls);removeResult=0;assert(!f.stop());
    });
    for(unsigned failure=0;failure<4;++failure)run("refresh-creation-unwind-"+std::to_string(failure),[&]{
        Fixture f;f.create();
        switch(failure) {
            case 0:allocationFailure=0;break;
            case 1:dodge_test_timer_failure=true;break;
            case 2:addResult=kIOReturnError;break;
            default:conversionDivisor=0;break;
        }
        assert(f.refresh()==kIOReturnNotReady && dodge_test_timer_objects==1 && !native_gop_vsync[0]);
    });
    run("refresh-enable-failure-can-be-disabled-and-retried",[]{
        Fixture f;f.create();dodge_test_timer_wake_result=kIOReturnError;
        assert(f.refresh()==kIOReturnError && !native_gop_vsync[0]);assert(!f.refresh(false));
        dodge_test_timer_wake_result=0;f.listeners();assert(!f.refresh());f.tick();assert(refreshCalls==1);
    });
    run("frontend-never-consumes-another-refresh-controller-owner",[]{
        Fixture f;f.create();auto *other=f.loop.withGate([&]{return dodge_software_refresh_create(&f.display);});assert(other);
        assert(f.refresh()==kIOReturnNotReady);assert(!f.stop());
        assert(!f.loop.withGate([&]{return dodge_software_refresh_stop(other);}));
    });
    run("refresh-setting-requires-original-workloop-gate",[]{
        Fixture f;f.create();assert(dodge_display_frontend_set_refresh(f.front,true)==kIOReturnNotPermitted && dodge_test_timer_objects==1);
    });
    run("default-front-waits-for-adreno-then-cpu-copies-without-presenter",[]{
        Fixture f;f.front=f.loop.withGate([&]{return dodge_display_frontend_create(&f.display,nullptr,&f.scanout);});assert(f.front);
        gpuSubmitted=7;gpuRetired=6;assert(!f.submit() && f.status().producerWaiting && !presentOffers && !backingCalls);
        gpuRetired=7;f.tick();assert(!presentOffers && pixelCopies==1 && completionCalls==1 && f.status().retired==1);f.copied();
    });
    run("explicit-cpu-copy-does-not-offer-to-available-presenter",[]{
        Fixture f;f.create(DodgeDisplayProducer::CpuOnly,DodgeDisplayTransfer::CpuCopy);
        assert(!f.submit() && !gpuQueries && !presentOffers && pixelCopies==1 && completionCalls==1);f.copied();
    });
    run("presenter-transfer-without-presenter-is-refused",[]{
        Fixture f;assert(!f.loop.withGate([&]{return dodge_display_frontend_create(&f.display,nullptr,&f.scanout,
            DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::Presenter);}) && allocations.empty());
    });
    run("unknown-transfer-policy-is-refused",[]{
        Fixture f;assert(!f.tryCreate(DodgeDisplayProducer::AdrenoTimeline,static_cast<DodgeDisplayTransfer>(-1)) && allocations.empty());
    });
    run("gpu-pending-waits-before-backing-and-offer",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;
        assert(!f.submit() && !backingCalls && !presentOffers && f.status().producerWaiting);
        assert(dodge_test_last_timer->deadline==now+200000);f.tick();
        assert(!backingCalls && !presentOffers && f.status().producerWaiting);f.unchanged();
        gpuRetired=7;f.tick();assert(backingCalls==1 && presentOffers==1 && !f.status().producerWaiting);
        completeOffer();assert(f.status().retired==1);
    });
    run("first-gpu-target-survives-unavailable-query-and-new-submission",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        gpuKnown=false;gpuSubmitted=gpuRetired=30;f.tick();assert(!backingCalls && f.status().producerWaiting);
        gpuKnown=true;gpuSubmitted=40;gpuRetired=7;f.tick();
        assert(offered.context && !f.status().producerWaiting);completeOffer();assert(f.status().retired==1);
    });
    run("unpublished-gpu-never-becomes-a-cpu-fallback",[]{
        Fixture f;f.create();gpuKnown=false;presenterAccept=false;assert(!f.submit());
        for(unsigned index=0;index<10;++index)f.tick();
        assert(!backingCalls && !presentOffers && !completionCalls && !pixelCopies && f.status().producerWaiting);f.unchanged();
        gpuKnown=true;gpuSubmitted=4;gpuRetired=3;f.tick();assert(!backingCalls);
        gpuSubmitted=8;gpuRetired=4;f.tick();assert(pixelCopies==1 && completionCalls==1);f.copied();
    });
    run("each-queued-request-keeps-its-own-gpu-target",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit(1));
        gpuSubmitted=9;assert(!f.submit(2));gpuSubmitted=100;gpuRetired=7;f.tick();
        assert(presentOffers==1);completeOffer();assert(f.status().retired==1 && f.status().producerWaiting && !offered.context);
        gpuRetired=9;f.tick();assert(presentOffers==2);completeOffer();assert(f.status().retired==2);
    });
    run("gpu-target-captured-before-original-builder",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;
        requestHook=[](IOMFBSwapIORequest &){gpuSubmitted=100;gpuRetired=7;};
        assert(!f.submit() && offered.context);completeOffer();assert(f.status().retired==1);
    });
    run("passed-gpu-target-is-not-queried-again-after-producer-callback",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && gpuQueries==1);
        gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
        assert(!f.kick() && offered.context && gpuQueries==1);completeOffer();
    });
    run("long-gpu-wait-does-not-release-or-retire-frame",[]{
        Fixture f;f.create();gpuSubmitted=5;gpuRetired=4;assert(!f.submit());
        for(unsigned index=0;index<1500;++index)f.tick();
        assert(now>300000000 && !backingCalls && !presentOffers && !completionCalls && f.status().pending==1 && f.status().producerWaiting);
        f.unchanged();assert(!f.stop());assert(!completionCalls);
    });
    run("regressing-gpu-timeline-does-not-complete-old-target",[]{
        Fixture f;f.create();gpuSubmitted=9;gpuRetired=8;assert(!f.submit());
        gpuSubmitted=gpuRetired=1;f.tick();assert(!backingCalls && !f.status().producerWaiting && f.status().last==kIOReturnAborted);
        gpuSubmitted=gpuRetired=9;assert(f.kick()==kIOReturnAborted && !offered.context && !completionCalls);f.unchanged();
    });
    for(unsigned defect=0;defect<3;++defect)run("captured-gpu-timeline-invalidation-"+std::to_string(defect),[&]{
        Fixture f;f.create();gpuSubmitted=9;gpuRetired=8;assert(!f.submit());
        if(defect==0) {gpuSubmitted=100;f.tick();gpuSubmitted=50;}
        if(defect==1) {gpuSubmitted=10;gpuRetired=7;}
        if(defect==2)gpuRetired=10;
        f.tick();const auto queries=gpuQueries;
        assert(!f.status().producerWaiting && f.status().last==kIOReturnAborted && !backingCalls && !presentOffers && !completionCalls);
        gpuSubmitted=gpuRetired=200;
        assert(f.kick()==kIOReturnAborted && gpuQueries==queries && !offered.context && f.status().pending==1);f.unchanged();
    });
    run("retired-beyond-submitted-is-not-a-valid-gpu-snapshot",[]{
        Fixture f;f.create();gpuSubmitted=4;gpuRetired=5;assert(!f.submit() && !backingCalls);
        gpuSubmitted=9;gpuRetired=8;f.tick();assert(!backingCalls);
        gpuSubmitted=20;gpuRetired=9;f.tick();assert(offered.context);completeOffer();
    });
    run("explicit-cpu-producer-does-not-wait-for-unpublished-adreno",[]{
        Fixture f;gpuKnown=false;f.create(DodgeDisplayProducer::CpuOnly);assert(!dodge_test_timer_objects);
        presenterAccept=false;assert(!f.submit() && !gpuQueries && pixelCopies==1 && completionCalls==1);f.copied();
    });
    run("cancelled-request-cancels-gpu-retry-without-retirement",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        IPhone16Swap::store<uint8_t>(&f.requests[0],IPhone16Swap::CancelledRequest,1);f.tick();
        assert(!f.status().producerWaiting && !dodge_test_last_timer->armed && !backingCalls && !completionCalls);f.unchanged();
    });
    run("producer-state-regression-stops-polling-until-original-kick",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,0U);gpuRetired=7;f.tick();
        assert(!f.status().producerWaiting && !backingCalls);
        IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);assert(!f.kick());completeOffer();
    });
    run("early-gpu-timer-preserves-deadline-without-query",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        const auto deadline=dodge_test_last_timer->deadline;const auto queries=gpuQueries;
        gpuRetired=7;f.tick(-1);assert(dodge_test_last_timer->armed && dodge_test_last_timer->deadline==deadline && gpuQueries==queries && !backingCalls);
        f.tick();assert(offered.context);completeOffer();
    });
    run("timer-callback-can-reenter-stop-during-backing",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        backingHook=[&]{assert(!f.stop());};gpuRetired=7;f.tick();
        assert(!f.front && !dodge_test_timer_objects && !presentOffers && !completionCalls);f.unchanged();
    });
    run("stop-drops-pending-timer-and-stale-action-is-safe",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        auto *timer=dodge_test_last_timer;timer->retain();assert(!f.stop());
        f.loop.withGate([&]{timer->forceStaleAction();});assert(!timer->armed && !backingCalls && !completionCalls);timer->release();
    });
    run("timer-removal-failure-keeps-owner-for-retry",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());removeResult=kIOReturnError;
        assert(f.stop()==kIOReturnError && f.front && f.status().draining && !f.status().producerWaiting);
        auto *timer=dodge_test_last_timer;assert(!timer->armed && !timer->enabled && !timer->getRefcon());
        f.loop.withGate([&]{timer->forceStaleAction();});assert(!backingCalls && !completionCalls);
        removeResult=0;assert(!f.stop());
    });
    run("timer-wake-failure-holds-request-for-explicit-retry",[]{
        Fixture f;f.create();dodge_test_timer_wake_result=kIOReturnError;gpuSubmitted=7;gpuRetired=6;
        assert(!f.submit() && !f.status().producerWaiting && f.status().pending==1 && !backingCalls);
        assert(f.kick()==kIOReturnError && !dodge_test_last_timer->armed);
        dodge_test_timer_wake_result=0;assert(f.kick()==kIOReturnBusy);gpuRetired=7;f.tick();completeOffer();
    });
    run("early-timer-rearm-failure-holds-frame",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());
        dodge_test_timer_wake_result=kIOReturnError;f.tick(-1);
        assert(f.status().last==kIOReturnError && !f.status().producerWaiting && !backingCalls && !completionCalls);
    });
    run("gpu-retry-deadline-overflow-is-refused",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;now=UINT64_MAX-100;
        assert(!f.submit() && f.kick()==kIOReturnBadArgument && !f.status().producerWaiting && !backingCalls);
    });
    run("gpu-retry-clock-regression-is-refused",[]{
        Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit());now=999;dodge_test_last_timer->fire();
        assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !backingCalls && !completionCalls);
    });
    for(unsigned failure=0;failure<6;++failure)run("frontend-create-unwind-"+std::to_string(failure),[&]{
        Fixture f;
        switch(failure) {
            case 0:allocationFailure=0;break;
            case 1:allocationFailure=1;break;
            case 2:conversionDivisor=0;break;
            case 3:dodge_test_timer_failure=true;break;
            case 4:addResult=kIOReturnError;break;
            default:break;
        }
        const auto mode=failure==5?static_cast<DodgeDisplayProducer>(-1):DodgeDisplayProducer::AdrenoTimeline;
        assert(!f.tryCreate(mode) && !dodge_test_timer_objects && allocations.empty());
    });
    run("canonical-packet-enters-real-gated-builder-and-retires",[]{
        Fixture f;f.create();assert(!f.submit() && offered.context && builderCalls==1 && backingCalls==1);
        auto before=f.status();assert(before.active && before.pending==1 && before.validated==1 && !before.retired);
        completeOffer();auto after=f.status();assert(!after.active && !after.pending && after.retired==1 && completionCalls==1);f.unchanged();
    });
    run("producer-pending-does-not-map-or-offer",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && !offered.context && !backingCalls && !presentOffers);
        f.unchanged();f.loop.withGate([&]{IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);});
        assert(!f.kick() && offered.context && backingCalls==1);completeOffer();assert(f.status().retired==1);
    });
    run("second-submission-progresses-after-first-completion",[]{
        Fixture f;f.create();assert(!f.submit(1) && !f.submit(2) && presentOffers==1 && f.status().pending==2);
        completeOffer();assert(offered.context && presentOffers==2 && f.status().retired==1);
        completeOffer();assert(f.status().retired==2 && !f.status().pending);
    });
    run("presenter-rejection-takes-actual-pixel-fallback",[]{
        Fixture f;f.create();presenterAccept=false;assert(!f.submit() && !offered.context);
        assert(pixelCopies==1 && barriers==1 && completionCalls==1 && f.status().retired==1);f.copied();
    });
    run("failed-gpu-takes-actual-pixel-fallback",[]{
        Fixture f;f.create();assert(!f.submit());completeOffer(kIOReturnError);
        assert(pixelCopies==1 && barriers==1 && completionCalls==1);f.copied();
    });
    run("synchronous-completion-does-not-retain-a-dead-entry",[]{
        Fixture f;f.create();synchronous=true;assert(!f.submit(1) && !f.submit(2));
        assert(f.status().retired==2 && !f.status().pending && completionCalls==2);
    });
    run("duplicate-pending-id-refused-before-original-call",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit(9));assert(f.submit(9)==kIOReturnBusy && builderCalls==1 && f.status().pending==1);
    });
    run("bounded-pending-ledger-refuses-seventeenth-frame",[]{
        Fixture f;f.create();producerDone=false;
        for(unsigned index=0;index<16;++index)assert(!f.submit(index));
        assert(f.submit(17)==kIOReturnBusy && builderCalls==16 && f.status().pending==16 && !backingCalls && !offered.context);
    });
    run("every-noncanonical-packet-byte-refused-before-builder",[]{
        Fixture f;f.create();const auto original=f.packet();
        for(unsigned at=0;at<original.size();++at) {
            if(at>=80 && at<88)continue;
            auto changed=original;changed[at]^=1;
            assert(dodge_display_frontend_submit(f.front,changed.data(),changed.size(),&f)==kIOReturnUnsupported);
        }
        assert(!builderCalls && !backingCalls && !f.status().pending);f.unchanged();
    });
    for(unsigned bytes:{0U,1131U,1133U,0xffffffffU})run("wrong-packet-size-"+std::to_string(bytes),[&]{
        Fixture f;f.create();auto data=f.packet();assert(dodge_display_frontend_submit(f.front,data.data(),bytes,&f)==kIOReturnUnsupported && !builderCalls);
    });
    run("null-and-wrapping-packet-refused",[]{
        Fixture f;f.create();assert(dodge_display_frontend_submit(f.front,nullptr,1132,&f)==kIOReturnUnsupported);
        assert(dodge_display_frontend_submit(f.front,reinterpret_cast<void *>(UINTPTR_MAX-100),1132,&f)==kIOReturnUnsupported && !builderCalls);
    });
    const char *geometryDefects[]={"wrong-id","extra-layer","scaled-source","offset-destination","layer-scalar-not-default","extra-float-bits","transform","unknown-option","dimensions","surface-id","surface-type"};
    for(unsigned defect=0;defect<11;++defect)run(geometryDefects[defect],[&]{
        Fixture f;f.create();requestHook=[&](IOMFBSwapIORequest &request){
            switch(defect) {
                case 0:IPhone16Swap::store(&request,788,2U);break;
                case 1:IPhone16Swap::store(&request,IPhone16Swap::Surfaces+8,&f.surface);break;
                case 2:IPhone16Swap::store(&request,25,16U);break;
                case 3:IPhone16Swap::store(&request,81,1U);break;
                case 4:IPhone16Swap::store(&request,532,0U);break;
                case 5:IPhone16Swap::store(&request,564,0x3f800000U);break;
                case 6:IPhone16Swap::store(&request,580,1U);break;
                case 7:IPhone16Swap::store(&request,808,1U);break;
                case 8:IPhone16Swap::store(&request,816,1U);break;
                case 9:++f.surface.id;break;
                case 10:f.surface.valid=false;break;
            }
        };
        assert(f.submit()==kIOReturnBadArgument && !f.status().pending && !backingCalls && !presentOffers);f.unchanged();
    });
    run("original-builder-error-releases-reservation",[]{
        Fixture f;f.create();originalStatus=kIOReturnError;assert(f.submit()==kIOReturnError && !f.status().pending);
    });
    run("original-unqueued-success-releases-validated-reference",[]{
        Fixture f;f.create();enqueue=false;assert(!f.submit() && f.status().validated==1 && !f.status().pending && !presentOffers);
    });
    run("backing-failure-does-not-consume-original-request",[]{
        Fixture f;f.create();backingStatus=kIOReturnUnsupported;assert(!f.submit() && !offered.context && !completionCalls && f.status().pending==1);
        backingStatus=0;assert(!f.kick());completeOffer();assert(f.status().retired==1);
    });
    run("allocation-failure-before-offer-can-retry",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit());allocationFailure=0;
        f.loop.withGate([&]{IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);});
        assert(f.kick()==kIOReturnNoMemory && !offered.context && !f.status().active && f.status().pending==1);
        allocationFailure=-1;assert(!f.kick());completeOffer();
    });
    run("reentrant-stop-during-backing-does-not-leak-output",[]{
        Fixture f;f.create();backingHook=[&]{assert(!f.stop());};assert(!f.submit() && !f.front && !offered.context && !completionCalls);f.unchanged();
    });
    run("stop-drains-active-callback-before-consuming-owner",[]{
        Fixture f;f.create();assert(!f.submit());assert(f.stop()==kIOReturnBusy && f.front && f.status().draining);
        assert(f.submit(2)==kIOReturnNotReady);completeOffer();assert(!completionCalls && !f.status().active && !f.status().pending);
        assert(!f.stop());f.unchanged();
    });
    run("completion-can-request-stop-before-observer",[]{
        Fixture f;f.create();completionHook=[&]{assert(f.stop()==kIOReturnBusy);};assert(!f.submit());completeOffer();
        assert(completionCalls==1 && f.status().draining && !f.status().pending && !f.status().active);assert(!f.stop());
    });
    for(unsigned defect=0;defect<5;++defect)run("inflight-reservation-mutation-"+std::to_string(defect),[&]{
        Fixture f;f.create();assert(!f.submit());
        switch(defect) {
            case 0:IPhone16Swap::store(&f.requests[0],25,16U);break;
            case 1:IPhone16Swap::store<void *>(&f.requests[0],IPhone16Swap::EffectiveSurfaces,nullptr);break;
            case 2:IPhone16Swap::store(&f.requests[0],788,2U);break;
            case 3:++f.surface.id;break;
            case 4:IPhone16Swap::store<uint8_t>(&f.requests[0],IPhone16Swap::CancelledRequest,1);break;
        }
        completeOffer(kIOReturnError);assert(!completionCalls && !pixelCopies && !f.status().active && f.status().pending==1);f.unchanged();
    });
    run("validation-and-kick-require-original-gate",[]{
        Fixture f;f.create();assert(!dodge_display_frontend_validate(f.front,&f.requests[0]));
        assert(dodge_display_frontend_kick(f.front)==kIOReturnNotPermitted && dodge_display_frontend_stop(f.front)==kIOReturnNotPermitted);
    });
    run("cross-thread-completion-uses-original-workloop",[]{
        Fixture f;f.create();assert(!f.submit());std::thread worker([]{completeOffer();});worker.join();assert(f.status().retired==1);
    });
    std::printf("{\"result\":\"PASS\",\"cases\":[");
    for(unsigned index=0;index<cases.size();++index)std::printf("%s\"%s\"",index?",":"",cases[index].c_str());
    std::puts("],\"noncanonical_byte_mutations\":1124,\"software_iokit_and_original_callee_peers\":true}");
}
#endif
