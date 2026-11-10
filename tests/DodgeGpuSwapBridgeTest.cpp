// SPDX-License-Identifier: MIT
// Execute the actual bridge and pixel-copy source with explicit software
// presenter, work-loop and original-completion peers. No private callee runs.
#include "DodgeGpuSwapBridge.h"
#include "OriginalLegacySwapCompletionABI.h"
#include "OriginalLegacyProducerABI.h"
#include <IOKit/IOCommandGate.h>
#include <pexpert/pexpert.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static int allocationFailure=-1;
static std::unordered_map<void *,size_t> allocations;
void *IOMallocZero(size_t bytes) {
    if(allocationFailure==0)return nullptr;
    if(allocationFailure>0)--allocationFailure;
    void *result=std::calloc(1,bytes);assert(result);allocations[result]=bytes;return result;
}
void IOFree(void *pointer,size_t bytes) {
    auto found=allocations.find(pointer);assert(found!=allocations.end() && found->second==bytes);
    allocations.erase(found);std::free(pointer);
}
static PE_Video video;
static bool consoleError=false,handoffReady=true,presenterAccept=true,synchronous=false;
static unsigned handoffs=0,failures=0,copies=0,frames=0,synchronizes=0,originalCalls=0,presenterOffers=0;
static uint64_t copiedBytes=0,clockTicks=0;
static uint32_t overlayFirst=0,overlayRows=0;
static int synchronousStatus=0;
static std::function<void()> originalHook;
static std::vector<std::string> cases;
extern "C" void native_legacy_gpu_complete(void *,int);
extern "C" int PE_current_console(PE_Video *out) {*out=video;return consoleError;}
extern "C" int boot_progress_display_handoff(void) {++handoffs;return handoffReady;}
extern "C" void boot_progress_display_failed(void) {++failures;}
extern "C" void boot_progress_display_copy(uint64_t ticks,uint64_t bytes) {
    assert(ticks && synchronizes);++copies;copiedBytes=bytes;
}
extern "C" void boot_progress_peripheral_frame(void) {++frames;}
extern "C" void native_legacy_overlay_rows(uint32_t *first,uint32_t *rows) {*first=overlayFirst;*rows=overlayRows;}
extern "C" void OSSynchronizeIO(void) {++synchronizes;}
extern "C" uint64_t mach_absolute_time(void) {return ++clockTicks;}

struct Display : IOService {
    unsigned char opaque[IPhone16Swap::DisplayBytes-sizeof(IOService)]{};
    Display():IOService(DodgeSwapKind::Display) {}
};
struct IOMFBSwapIORequest : OSObject {
    unsigned char opaque[IPhone16Swap::RequestBytes-sizeof(OSObject)]{};
    IOMFBSwapIORequest():OSObject(DodgeSwapKind::Request) {}
};
static_assert(sizeof(Display)==5728 && sizeof(IOMFBSwapIORequest)==2424,"Exact storage extents only, not original class implementations");
struct Offered {void *context=nullptr;IOMemoryDescriptor *memory=nullptr;};
static Offered offered;
static void completeOffer(int status) {
    assert(offered.context && offered.memory);
    const auto done=offered;offered={};
    // Match the actual presenter: relinquish its backing ref before callback.
    done.memory->release();native_legacy_gpu_complete(done.context,status);
}
extern "C" bool native_gop_gpu_offer(IOService *presenter,void *context,IOMemoryDescriptor *memory,
    uint64_t stride,uint32_t width,uint32_t height) {
    ++presenterOffers;
    assert(presenter && context && memory && stride>=width*4 && width==video.v_width && height==video.v_height);
    if(!presenterAccept)return false;
    assert(!offered.context);memory->retain();offered={context,memory};
    if(synchronous)completeOffer(synchronousStatus);
    return true;
}
extern "C" void native_iphone_complete_current(void *object) {
    auto *display=static_cast<Display *>(object);
    assert(display->loop->inGate());
    auto *request=IPhone16Swap::load<IOMFBSwapIORequest *>(display,IPhone16Swap::Current);
    assert(request && request->references>=3);++originalCalls;
    // A callee peer releases only the software queue ref and clears Current.
    // This does not emulate the private IOSurface/fence/free/wakeup lifecycle.
    request->release();IPhone16Swap::store<void *>(display,IPhone16Swap::Current,nullptr);
    if(originalHook)originalHook();
}

struct Fixture {
    IOWorkLoop loop;
    IOCommandGate gate;
    Display display;
    IOService presenter{DodgeSwapKind::Presenter};
    IOMemoryMap scanout,sourceMap;
    IOMemoryDescriptor memory;
    IOMFBSwapIORequest request,next;
    DodgeSurfaceBacking source;
    DodgeGpuSwapBridge *bridge=nullptr;
    std::vector<uint8_t> destination,input,originalInput;
    unsigned observed=0;
    IOReturn observedStatus=99;
    bool owner=true,queued=true,nextQueued=false;
    std::function<void()> observerHook;
    explicit Fixture(uint32_t width=17,uint32_t destinationStride=80,uint32_t sourceStride=84) {
        assert(allocations.empty() && !offered.context);
        video={};video.v_width=width;video.v_rowBytes=destinationStride;
        consoleError=false;handoffReady=presenterAccept=true;synchronous=false;synchronousStatus=0;
        allocationFailure=-1;handoffs=failures=copies=frames=synchronizes=originalCalls=presenterOffers=0;
        overlayFirst=overlayRows=0;copiedBytes=0;originalHook={};
        destination.assign(64+destinationStride*video.v_height+64,0xcd);
        input.resize(64+sourceStride*video.v_height+64);
        for(size_t i=0;i<input.size();++i)input[i]=uint8_t(i*37+19);
        originalInput=input;
        scanout.physical=video.v_baseAddr;scanout.bytes=destinationStride*video.v_height;
        scanout.address=reinterpret_cast<uintptr_t>(destination.data()+64);
        sourceMap.address=reinterpret_cast<uintptr_t>(input.data()+64);sourceMap.bytes=sourceStride*video.v_height;
        memory.bytes=sourceMap.bytes;memory.mapping=&sourceMap;
        source={&memory,width,uint32_t(video.v_height),sourceStride};
        display.loop=&loop;presenter.loop=&loop;gate.loop=&loop;
        IPhone16Swap::store(&display,5040,&gate);
        IPhone16Swap::store(&display,IPhone16Swap::Head,&request);
        IPhone16Swap::store(&display,IPhone16Swap::Tail,reinterpret_cast<uint8_t *>(&request)+IPhone16Swap::Next);
        IPhone16Swap::store(&request,IPhone16Swap::PreviousLink,reinterpret_cast<uint8_t *>(&display)+IPhone16Swap::Head);
        for(auto *item:{&request,&next}) {
            IPhone16Swap::store(item,IPhone16Swap::RequestedLayers,1U);
            IPhone16Swap::store(item,IPhone16Swap::ReadyLayers,1U);
            IPhone16Swap::store<uint8_t>(item,IPhone16Swap::ProducerRegistration,1);
            IPhone16Swap::store(item,IPhone16Swap::Surfaces,&memory);
        }
        request.retain();
    }
    static void observe(IOService *display,IOMFBSwapIORequest *request,IOReturn status,void *cookie) {
        auto *self=static_cast<Fixture *>(cookie);
        assert(display==&self->display && self->loop.inGate() && request->references>=2 && self->memory.references>=2);
        ++self->observed;self->observedStatus=status;
        if(status==kIOReturnSuccess) {if(request==&self->request)self->queued=false;else self->nextQueued=false;}
        if(self->observerHook)self->observerHook();
    }
    void create() {
        bridge=loop.withGate([&] {return dodge_gpu_swap_bridge_create(&display,&presenter,&scanout,observe,this,nullptr,DodgeDisplayTransfer::Presenter);});
        assert(bridge);
    }
    IOReturn offer(IOMFBSwapIORequest *object=nullptr,bool complete=true) {
        return loop.withGate([&] {return dodge_gpu_swap_bridge_offer(bridge,object?object:&request,source,complete);});
    }
    void stop() {assert(owner && bridge);assert(!loop.withGate([&] {return dodge_gpu_swap_bridge_stop(bridge);}));owner=false;}
    void queueNext() {
        next.retain();nextQueued=true;
        IPhone16Swap::store(&request,IPhone16Swap::Next,&next);
        IPhone16Swap::store(&next,IPhone16Swap::PreviousLink,reinterpret_cast<uint8_t *>(&request)+IPhone16Swap::Next);
        IPhone16Swap::store(&display,IPhone16Swap::Tail,reinterpret_cast<uint8_t *>(&next)+IPhone16Swap::Next);
    }
    void unchangedPixels() const {assert(std::all_of(destination.begin(),destination.end(),[](uint8_t b){return b==0xcd;}));}
    void copiedPixels() const {
        for(size_t i=0;i<destination.size();++i) {
            uint8_t expected=0xcd;
            if(i>=64 && i<64+scanout.bytes) {
                const auto row=(i-64)/video.v_rowBytes,column=(i-64)%video.v_rowBytes;
                if(column<video.v_width*4 && !(row>=overlayFirst && row-overlayFirst<overlayRows))
                    expected=input[64+row*source.stride+column];
            }
            assert(destination[i]==expected);
        }
        assert(input==originalInput);
    }
    void refs(unsigned requestRefs=2,unsigned memoryRefs=1) const {
        assert(request.references==requestRefs && memory.references==memoryRefs && sourceMap.references==1 && !memory.prepared);
    }
    ~Fixture() {
        if(bridge && owner)stop();
        assert(!offered.context && allocations.empty());
        if(queued && request.references>1)request.release();
        if(nextQueued && next.references>1)next.release();
        assert(display.references==1 && presenter.references==1 && gate.references==1 && loop.references==1 && scanout.references==1);
        assert(memory.references==1 && sourceMap.references==1 && !memory.prepared && request.references==1 && next.references==1);
        originalHook={};
    }
};
static void run(const char *name,const std::function<void()> &test) {test();assert(allocations.empty() && !offered.context);cases.emplace_back(name);}

int main() {
    run("default-cpu-copy-needs-no-presenter-and-performs-real-stores",[] {
        Fixture f;f.bridge=f.loop.withGate([&]{return dodge_gpu_swap_bridge_create(&f.display,nullptr,&f.scanout,Fixture::observe,&f);});
        assert(f.bridge);assert(!f.offer() && !presenterOffers && !offered.context && f.observed==1 && originalCalls==1 && copies==1);
        f.refs(1);f.copiedPixels();
    });
    run("explicit-cpu-copy-never-offers-to-live-presenter",[] {
        Fixture f;f.bridge=f.loop.withGate([&]{return dodge_gpu_swap_bridge_create(&f.display,&f.presenter,&f.scanout,Fixture::observe,&f);});
        assert(f.bridge);overlayFirst=2;overlayRows=1;
        assert(!f.offer() && !presenterOffers && !offered.context && copies==1 && originalCalls==1);f.refs(1);f.copiedPixels();
    });
    run("cpu-copy-still-refuses-unfinished-producer",[] {
        Fixture f;f.bridge=f.loop.withGate([&]{return dodge_gpu_swap_bridge_create(&f.display,nullptr,&f.scanout,Fixture::observe,&f);});
        assert(f.bridge);IPhone16Swap::store(&f.request,IPhone16Swap::ReadyLayers,0U);
        assert(f.offer()==kIOReturnNotReady && !presenterOffers && !copies && !originalCalls && !f.observed);f.refs();f.unchangedPixels();
    });
    run("unknown-scanout-transfer-policy-refused",[] {
        Fixture f;assert(!f.loop.withGate([&]{return dodge_gpu_swap_bridge_create(&f.display,&f.presenter,&f.scanout,Fixture::observe,&f,
            nullptr,static_cast<DodgeDisplayTransfer>(-1));}));f.refs();f.unchangedPixels();
    });
    const char *producerFailures[]={"original-producer-pending","original-producer-unregistered","original-request-cancelled",
        "unknown-original-producer-bits","extra-original-ready-bit","surface-without-request-bit"};
    for(unsigned defect=0;defect<6;++defect)run(producerFailures[defect],[&] {
        Fixture f;f.create();
        switch(defect) {
            case 0:IPhone16Swap::store(&f.request,IPhone16Swap::ReadyLayers,0U);break;
            case 1:IPhone16Swap::store<uint8_t>(&f.request,IPhone16Swap::ProducerRegistration,0);break;
            case 2:IPhone16Swap::store<uint8_t>(&f.request,IPhone16Swap::CancelledRequest,1);break;
            case 3:IPhone16Swap::store(&f.request,IPhone16Swap::RequestedLayers,0x11U);IPhone16Swap::store(&f.request,IPhone16Swap::ReadyLayers,0x11U);break;
            case 4:IPhone16Swap::store(&f.request,IPhone16Swap::ReadyLayers,3U);break;
            case 5:IPhone16Swap::store(&f.request,IPhone16Swap::RequestedLayers,0U);IPhone16Swap::store(&f.request,IPhone16Swap::ReadyLayers,0U);break;
        }
        assert(f.offer()==kIOReturnNotReady && !offered.context && !f.observed && !originalCalls && !f.memory.prepares && !handoffs);
        f.refs();f.unchangedPixels();
    });
    for(int status:{0,int(kIOReturnError)})run(status?"failed-gpu-cancelled-request-does-not-copy":"completed-gpu-cancelled-request-does-not-retire",[&] {
        Fixture f;f.create();assert(!f.offer());
        IPhone16Swap::store<uint8_t>(&f.request,IPhone16Swap::CancelledRequest,1);completeOffer(status);
        assert(f.observed==1 && f.observedStatus==kIOReturnAborted && !originalCalls && !f.memory.prepares && !copies);
        f.refs();f.unchangedPixels();
    });
    const char *createFailures[]={"null-display","null-presenter","null-map","null-observer","wrong-class","no-loop","outside-gate",
        "no-original-gate","wrong-gate-class","gate-other-loop","disabled-gate","console-error","zero-physical","zero-width","zero-height",
        "wide-mode","tall-mode","wrong-depth","rotated","short-row","unaligned-row","span-overflow","physical-overflow",
        "wrong-physical","no-virtual","unaligned-virtual","virtual-overflow","short-map","long-map","allocation-failure"};
    for(unsigned defect=0;defect<sizeof(createFailures)/sizeof(*createFailures);++defect)run(createFailures[defect],[&] {
        Fixture f;IOWorkLoop other;auto *display=&f.display;auto *presenter=&f.presenter;auto *map=&f.scanout;
        DodgeGpuSwapObserver observer=Fixture::observe;
        switch(defect) {
            case 0:display=nullptr;break;case 1:presenter=nullptr;break;case 2:map=nullptr;break;case 3:observer=nullptr;break;
            case 4:f.display.kind=DodgeSwapKind::Other;break;case 5:f.display.loop=nullptr;break;case 6:break;
            case 7:IPhone16Swap::store<void *>(&f.display,5040,nullptr);break;case 8:f.gate.kind=DodgeSwapKind::Other;break;
            case 9:f.gate.loop=&other;break;case 10:f.gate.enabled=false;break;case 11:consoleError=true;break;
            case 12:video.v_baseAddr=0;break;case 13:video.v_width=0;break;case 14:video.v_height=0;break;
            case 15:video.v_width=16385;break;case 16:video.v_height=16385;break;case 17:video.v_depth=24;break;
            case 18:video.v_rotate=1;break;case 19:video.v_rowBytes=64;break;case 20:video.v_rowBytes=79;break;
            case 21:video.v_rowBytes=UINT64_MAX-3;break;case 22:video.v_baseAddr=UINT64_MAX-127;break;
            case 23:++f.scanout.physical;break;case 24:f.scanout.address=0;break;case 25:++f.scanout.address;break;
            case 26:f.scanout.address=UINTPTR_MAX-3;break;case 27:--f.scanout.bytes;break;case 28:++f.scanout.bytes;break;
            case 29:allocationFailure=0;break;default:assert(false);
        }
        auto action=[&] {return dodge_gpu_swap_bridge_create(display,presenter,map,observer,&f,nullptr,DodgeDisplayTransfer::Presenter);};
        assert(!(defect==6?action():f.loop.withGate(action)));
        f.refs();assert(!handoffs && !failures);f.unchangedPixels();
    });
    const char *offerFailures[]={"offer-outside-gate","offer-disabled-gate","display-workloop-changed","original-gate-changed","console-mode-changed",
        "null-request","no-backing","source-width","source-height","source-stride","source-length","source-direction","queue-head-changed",
        "current-busy","producer-not-complete","console-handoff-refused","frame-allocation-failed"};
    for(unsigned defect=0;defect<sizeof(offerFailures)/sizeof(*offerFailures);++defect)run(offerFailures[defect],[&] {
        Fixture f;f.create();IOReturn expected=kIOReturnBadArgument;
        switch(defect) {
            case 0:expected=kIOReturnNotPermitted;break;case 1:f.gate.enabled=false;expected=kIOReturnBusy;break;
            case 2:f.display.loop=nullptr;expected=kIOReturnBusy;break;
            case 3:IPhone16Swap::store<void *>(&f.display,5040,nullptr);expected=kIOReturnBusy;break;
            case 4:++video.v_rowBytes;expected=kIOReturnBusy;break;case 5:break;case 6:f.source.memory=nullptr;break;
            case 7:--f.source.width;break;case 8:--f.source.height;break;case 9:f.source.stride=64;break;
            case 10:--f.memory.bytes;break;case 11:f.memory.direction=kIODirectionIn;break;
            case 12:IPhone16Swap::store<void *>(&f.display,IPhone16Swap::Head,nullptr);break;
            case 13:IPhone16Swap::store(&f.display,IPhone16Swap::Current,&f.next);break;
            case 14:expected=kIOReturnNotReady;break;case 15:handoffReady=false;expected=kIOReturnNotReady;break;
            case 16:allocationFailure=0;expected=kIOReturnNoMemory;break;
            default:assert(false);
        }
        IOReturn result;
        if(defect==0)result=dodge_gpu_swap_bridge_offer(f.bridge,&f.request,f.source,true);
        else if(defect==5)result=f.loop.withGate([&]{return dodge_gpu_swap_bridge_offer(f.bridge,nullptr,f.source,true);});
        else result=f.offer(nullptr,defect!=14);
        assert(result==expected && !f.observed && !originalCalls && !f.memory.prepares);
        f.refs();f.unchangedPixels();
        assert(failures==unsigned(defect==16));
    });
    run("presenter-rejection-takes-immediate-real-pixel-fallback",[] {
        Fixture f;f.create();presenterAccept=false;overlayFirst=2;overlayRows=1;
        assert(!f.offer());assert(!offered.context && f.observed==1 && !f.observedStatus && originalCalls==1 && !failures);
        assert(copies==1 && f.memory.completes==1);f.refs(1);f.copiedPixels();
    });
    run("presenter-rejection-fallback-can-stop-reentrantly",[] {
        Fixture f;f.create();presenterAccept=false;f.observerHook=[&]{f.stop();};
        assert(!f.offer());assert(f.observed==1 && originalCalls==1 && f.display.references==1);f.refs(1);f.copiedPixels();
    });
    run("presenter-rejection-failed-prepare-does-not-retire",[] {
        Fixture f;f.create();presenterAccept=false;f.memory.prepareResult=kIOReturnError;
        assert(f.offer()==kIOReturnError);assert(f.observed==1 && !originalCalls && failures==1);f.refs();f.unchangedPixels();
    });
    run("asynchronous-completion-and-extra-references",[] {
        Fixture f;f.create();assert(f.offer()==kIOReturnSuccess);
        assert(f.request.references==3 && f.memory.references==3 && !f.observed);
        assert(f.offer()==kIOReturnBusy);
        std::thread worker([]{completeOffer(0);});worker.join();
        assert(f.observed==1 && !f.observedStatus && originalCalls==1 && frames==1 && f.loop.actions==1);
        assert(!f.memory.prepares && !copies && !failures);f.refs(1);f.unchangedPixels();
    });
    for(unsigned layout=0;layout<3;++layout)run((std::string("actual-scalar-fallback-layout-")+std::to_string(layout)).c_str(),[&] {
        Fixture f(layout==2?1:17,layout==0?80:layout==1?76:4,layout==2?7:87);
        overlayFirst=1;overlayRows=2;f.create();assert(!f.offer());completeOffer(kIOReturnError);
        assert(f.observed==1 && !f.observedStatus && originalCalls==1 && copies==1 && synchronizes==1 && frames==1);
        assert(copiedBytes==video.v_width*(video.v_height-overlayRows)*4);
        assert(f.memory.prepares==1 && f.memory.maps==1 && f.memory.completes==1);f.refs(1);f.copiedPixels();
    });
    const char *fallbackFailures[]={"source-prepare-failure","source-map-failure","source-null-address","source-map-short","source-address-overflow",
        "overlay-first-outside","overlay-rows-outside","source-complete-failure"};
    for(unsigned defect=0;defect<sizeof(fallbackFailures)/sizeof(*fallbackFailures);++defect)run(fallbackFailures[defect],[&] {
        Fixture f;f.create();assert(!f.offer());
        switch(defect) {
            case 0:f.memory.prepareResult=kIOReturnError;break;case 1:f.memory.mapping=nullptr;break;
            case 2:f.sourceMap.address=0;break;case 3:--f.sourceMap.bytes;break;case 4:f.sourceMap.address=UINTPTR_MAX-1;break;
            case 5:overlayFirst=6;break;case 6:overlayFirst=4;overlayRows=2;break;
            case 7:f.memory.completeResult=kIOReturnError;break;default:assert(false);
        }
        completeOffer(kIOReturnError);
        assert(f.observed==1 && f.observedStatus!=kIOReturnSuccess && !originalCalls && !frames && failures==1);
        assert(f.memory.prepares==1 && f.memory.completes==unsigned(defect!=0));f.refs();
        if(defect==7) {assert(copies==1);f.copiedPixels();}else {assert(!copies);f.unchangedPixels();}
    });
    const char *cancelCases[]={"queue-cancelled-before-success","queue-cancelled-before-failure","disabled-gate-completion-does-not-wait",
        "console-changed-before-completion","gate-replaced-before-completion","workloop-changed-before-completion"};
    for(unsigned defect=0;defect<sizeof(cancelCases)/sizeof(*cancelCases);++defect)run(cancelCases[defect],[&] {
        Fixture f;f.create();assert(!f.offer());
        if(defect<2)IPhone16Swap::store<void *>(&f.display,IPhone16Swap::Head,nullptr);
        else if(defect==2)f.gate.enabled=false;
        else if(defect==3)++video.v_width;
        else if(defect==4)IPhone16Swap::store<void *>(&f.display,5040,nullptr);
        else f.display.loop=nullptr;
        completeOffer(defect==0?0:kIOReturnError);
        assert(f.observed==1 && f.observedStatus==kIOReturnAborted && !originalCalls && !f.memory.prepares && failures==1);
        f.refs();f.unchangedPixels();
    });
    run("stop-retains-inflight-until-asynchronous-callback",[] {
        Fixture f;f.create();assert(!f.offer());f.stop();
        assert(f.display.references==2 && f.request.references==3);
        std::thread worker([]{completeOffer(kIOReturnAborted);});worker.join();
        assert(!f.observed && !originalCalls && !f.memory.prepares && f.display.references==1);f.refs();f.unchangedPixels();
    });
    run("stop-outside-gate-does-not-consume-reference",[] {
        Fixture f;f.create();assert(dodge_gpu_swap_bridge_stop(f.bridge)==kIOReturnNotPermitted);
        assert(f.display.references==2);assert(!f.offer());completeOffer(0);assert(f.observed==1);f.refs(1);
    });
    run("concurrent-stop-and-completion-serialize-on-workloop",[] {
        for(unsigned iteration=0;iteration<32;++iteration) {
            Fixture f;f.create();assert(!f.offer());
            std::thread worker([]{completeOffer(0);});f.stop();worker.join();
            assert(f.observed==originalCalls && f.observed<=1 && f.display.references==1);
            f.refs(originalCalls?1:2);f.unchangedPixels();
        }
    });
    run("observer-can-consume-owner-reference",[] {
        Fixture f;f.create();f.observerHook=[&]{f.stop();};assert(!f.offer());completeOffer(0);
        assert(f.observed==1 && originalCalls==1 && f.display.references==1);f.refs(1);
    });
    run("original-completion-reentry-still-sees-active-frame",[] {
        Fixture f;f.queueNext();f.create();originalHook=[&]{assert(f.offer(&f.next)==kIOReturnBusy);};
        assert(!f.offer());completeOffer(0);assert(f.observed==1 && originalCalls==1);f.refs(1);
    });
    run("observer-can-submit-successor-without-losing-its-active-frame",[] {
        Fixture f;f.queueNext();f.create();f.observerHook=[&]{if(f.observed==1)assert(!f.offer(&f.next));};
        assert(!f.offer());completeOffer(0);assert(offered.context && f.next.references==3);
        completeOffer(0);assert(f.observed==2 && originalCalls==2 && frames==2 && !failures);f.refs(1);
    });
    run("failed-successor-preserves-console-ownership-after-first-frame",[] {
        Fixture f;f.queueNext();f.create();assert(!f.offer());completeOffer(0);
        f.memory.prepareResult=kIOReturnError;assert(!f.offer(&f.next));completeOffer(kIOReturnError);
        assert(f.observed==2 && f.observedStatus==kIOReturnError && originalCalls==1 && !failures && frames==1);
        assert(f.next.references==2);f.refs(1);f.unchangedPixels();
    });
    run("synchronous-completion-with-observer-stop",[] {
        Fixture f;f.create();synchronous=true;f.observerHook=[&]{f.stop();};
        assert(!f.offer());assert(f.observed==1 && originalCalls==1 && f.display.references==1);f.refs(1);
    });
    run("fallback-prepare-can-cancel-without-pixel-write",[] {
        Fixture f;f.create();assert(!f.offer());
        static Fixture *active;active=&f;
        f.memory.prepareHook=[]{IPhone16Swap::store<void *>(&active->display,IPhone16Swap::Head,nullptr);};
        completeOffer(kIOReturnError);assert(f.observedStatus==kIOReturnAborted && !originalCalls && f.memory.completes==1);
        f.refs();f.unchangedPixels();
    });
    run("fallback-complete-can-cancel-before-original-retirement",[] {
        Fixture f;f.create();assert(!f.offer());
        static Fixture *active;active=&f;
        f.memory.completeHook=[]{IPhone16Swap::store<void *>(&active->display,IPhone16Swap::Head,nullptr);};
        completeOffer(kIOReturnError);assert(f.observedStatus==kIOReturnNotReady && !originalCalls && f.memory.completes==1);
        f.refs();f.copiedPixels();
    });
    run("fallback-prepare-can-stop-without-observer-or-copy",[] {
        Fixture f;f.create();assert(!f.offer());
        static Fixture *active;active=&f;f.memory.prepareHook=[]{active->stop();};
        completeOffer(kIOReturnError);assert(!f.observed && !originalCalls && f.memory.completes==1 && f.display.references==1);
        f.refs();f.unchangedPixels();
    });
    run("original-completion-can-stop-before-observer",[] {
        Fixture f;f.create();originalHook=[&]{f.queued=false;f.stop();};assert(!f.offer());completeOffer(0);
        assert(!f.observed && originalCalls==1 && f.display.references==1);f.refs(1);
    });
    run("null-completion-context",[]{native_legacy_gpu_complete(nullptr,kIOReturnError);});
    std::printf("{\"result\":\"PASS\",\"cases\":[");
    for(size_t index=0;index<cases.size();++index)std::printf("%s\"%s\"",index?",":"",cases[index].c_str());
    std::puts("],\"original_completion_executed\":false,\"software_iokit_peers\":true}");
}
