// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeDisplayService.h"
#include "OriginalLegacyLifecycleABI.h"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>

struct DodgeDisplayService {
    static void *operator new(size_t,void *storage) noexcept {return storage;}
    unsigned references,operations;
    IOService *display,*provider;
    IOWorkLoop *loop;
    IOCommandGate *gate;
    IOMemoryMap *scanout;
    IOTimerEventSource *retry;
    DodgeDisplayFrontend *front;
    DodgeDisplayStopped completion;
    uint32_t previousWidth,previousHeight,width,height;
    bool attempted,ready,stopping,stopped,retryAttached,retryArmed,modeInstalled,ownerReleased,constructing,inStop;
    IOReturn last;
};

static void retainService(DodgeDisplayService *service) {++service->references;}
static void releaseService(DodgeDisplayService *service) {
    if(--service->references)return;
    service->loop->release();service->~DodgeDisplayService();IOFree(service,sizeof(*service));
}
static bool originalGate(const DodgeDisplayService *service) {
    return service->display && service->display->getWorkLoop()==service->loop &&
        IPhone16Swap::load<IOCommandGate *>(service->display,5040)==service->gate &&
        service->gate->getWorkLoop()==service->loop && service->gate->isEnabled();
}
static bool scanoutMode(const PE_Video &video,IOMemoryMap *scanout) {
    if(!video.v_baseAddr || !video.v_width || !video.v_height || video.v_width>8192 || video.v_height>8192 ||
       video.v_depth!=32 || video.v_rotate || video.v_rowBytes<video.v_width*4 || video.v_rowBytes>32768 ||
       video.v_rowBytes>UINT64_MAX/video.v_height)return false;
    const uint64_t length=video.v_rowBytes*video.v_height;
    return video.v_baseAddr<=UINT64_MAX-length && scanout && scanout->getLength()==length &&
        scanout->getPhysicalAddress()==video.v_baseAddr && scanout->getVirtualAddress() &&
        scanout->getVirtualAddress()<=UINTPTR_MAX-length;
}
static bool readyOnGate(DodgeDisplayService *service) {
    if(!service->ready || service->stopping || !originalGate(service))return false;
    PE_Video video={};
    return !PE_current_console(&video) && scanoutMode(video,service->scanout) &&
        video.v_width==service->width && video.v_height==service->height &&
        IPhone16Swap::load<uint32_t>(service->display,5208)==service->width &&
        IPhone16Swap::load<uint32_t>(service->display,5212)==service->height && !service->stopping;
}
static void restoreUnpublishedMode(DodgeDisplayService *service) {
    // Only rollback startup failure, before any request/client could own state.
    if(!service->ready && service->modeInstalled && IPhone16Lifecycle::emptyStartupQueues(service->display) &&
       IPhone16Swap::load<uint32_t>(service->display,5208)==service->width &&
       IPhone16Swap::load<uint32_t>(service->display,5212)==service->height) {
        IPhone16Swap::store(service->display,5208,service->previousWidth);
        IPhone16Swap::store(service->display,5212,service->previousHeight);
        service->modeInstalled=false;
    }
}
static IOReturn stopOnGate(DodgeDisplayService *);
static void retryAction(OSObject *owner,IOTimerEventSource *sender) {
    auto *service=static_cast<DodgeDisplayService *>(sender->getRefcon());
    if(!service || service->display!=owner || service->retry!=sender || !service->loop->inGate())return;
    retainService(service);sender->retain();service->retryArmed=false;
    stopOnGate(service);
    sender->release();releaseService(service);
}
static IOReturn retryStop(DodgeDisplayService *service,IOReturn reason) {
    service->last=reason;
    if(service->retry && service->retryAttached && !service->retryArmed) {
        uint64_t interval=0;nanoseconds_to_absolutetime(1000000,&interval);
        const uint64_t now=mach_absolute_time();
        if(interval && now<=UINT64_MAX-interval) {
            const IOReturn wake=service->retry->wakeAtTime(now+interval);
            service->retryArmed=wake==kIOReturnSuccess;
            if(wake!=kIOReturnSuccess)service->last=wake;
        }
    }
    return reason;
}
static IOReturn stopOnGate(DodgeDisplayService *service) {
    if(service->stopped)return kIOReturnSuccess;
    service->stopping=true;
    if(service->constructing || service->inStop || service->operations)return retryStop(service,kIOReturnBusy);
    struct StopScope {
        DodgeDisplayService *value;
        explicit StopScope(DodgeDisplayService *s):value(s) {s->inStop=true;}
        ~StopScope() {value->inStop=false;}
    } scope(service);
    if(service->retry) {service->retry->cancelTimeout();service->retryArmed=false;}
    if(service->front) {
        const IOReturn result=dodge_display_frontend_stop(service->front);
        if(result!=kIOReturnSuccess)return retryStop(service,result);
        service->front=nullptr;
    }
    if(service->retryAttached) {
        const IOReturn result=service->loop->removeEventSource(service->retry);
        if(result!=kIOReturnSuccess)return retryStop(service,result);
        service->retryAttached=false;
    }
    if(service->retry) {service->retry->setRefcon(nullptr);service->retry->release();service->retry=nullptr;}
    restoreUnpublishedMode(service);
    service->ready=false;service->stopped=true;service->last=kIOReturnSuccess;
    // Detach state before any virtual call: releases or parent stop can reenter.
    auto *display=service->display;auto *provider=service->provider;
    auto *scanout=service->scanout;auto *gate=service->gate;
    service->display=nullptr;service->provider=nullptr;service->scanout=nullptr;service->gate=nullptr;
    if(service->completion)service->completion(display,provider);
    if(scanout)scanout->release();
    gate->release();provider->release();display->release();
    return kIOReturnSuccess;
}
struct ServiceCall {
    DodgeDisplayService *service;
    enum Operation {Start,Ready,Submit,Validate,Kick,Refresh,Stop,Status,Release,Admit} operation;
    DodgeDisplayProducer producer;
    const void *packet;
    void *submitter;
    IOMFBSwapIORequest *request;
    DodgeDisplayServiceStatus *status;
    DodgeDisplayOperation admitted;
    void *context;
    bool enabled,result;
};
static IOReturn startOnGate(DodgeDisplayService *service,DodgeDisplayProducer producer) {
    if(service->attempted || service->stopping || service->stopped)return kIOReturnNotPermitted;
    service->attempted=true;
    struct StartScope {
        DodgeDisplayService *value;
        explicit StartScope(DodgeDisplayService *s):value(s) {s->constructing=true;}
        ~StartScope() {value->constructing=false;}
    } scope(service);
    if((producer!=DodgeDisplayProducer::CpuOnly && producer!=DodgeDisplayProducer::AdrenoTimeline) ||
       !originalGate(service) || !IPhone16Lifecycle::emptyStartupQueues(service->display))return kIOReturnNotReady;
    PE_Video video={};
    if(PE_current_console(&video))return kIOReturnNotReady;
    service->scanout=service->provider->mapDeviceMemoryWithIndex(0,kIOMapInhibitCache);
    if(service->stopping)return kIOReturnAborted;
    if(!scanoutMode(video,service->scanout))return kIOReturnNotReady;
    service->previousWidth=IPhone16Swap::load<uint32_t>(service->display,5208);
    service->previousHeight=IPhone16Swap::load<uint32_t>(service->display,5212);
    if((service->previousWidth || service->previousHeight) &&
       (service->previousWidth!=video.v_width || service->previousHeight!=video.v_height))return kIOReturnUnsupported;
    service->width=uint32_t(video.v_width);service->height=uint32_t(video.v_height);
    service->retry=IOTimerEventSource::timerEventSource(service->display,retryAction);
    if(!service->retry)return kIOReturnNoMemory;
    service->retry->setRefcon(service);
    const IOReturn added=service->loop->addEventSource(service->retry);
    if(added!=kIOReturnSuccess)return added;
    service->retryAttached=true;
    if(service->stopping)return kIOReturnAborted;
    if(!originalGate(service) || !IPhone16Lifecycle::emptyStartupQueues(service->display) ||
       IPhone16Swap::load<uint32_t>(service->display,5208)!=service->previousWidth ||
       IPhone16Swap::load<uint32_t>(service->display,5212)!=service->previousHeight)return kIOReturnNotReady;
    IPhone16Swap::store(service->display,5208,service->width);
    IPhone16Swap::store(service->display,5212,service->height);service->modeInstalled=true;
    service->front=dodge_display_frontend_create(service->display,nullptr,service->scanout,producer,DodgeDisplayTransfer::CpuCopy);
    if(service->stopping)return kIOReturnAborted;
    if(!service->front)return kIOReturnNotReady;
    service->ready=true;
    if(!readyOnGate(service)) {service->ready=false;return kIOReturnNotReady;}
    return kIOReturnSuccess;
}
static IOReturn serviceAction(OSObject *,void *argument,void *,void *,void *) {
    auto *call=static_cast<ServiceCall *>(argument);auto *service=call->service;
    retainService(service);IOReturn result=kIOReturnNotReady;
    const bool operation=call->operation!=ServiceCall::Start && call->operation!=ServiceCall::Stop && call->operation!=ServiceCall::Release;
    if(operation)++service->operations;
    switch(call->operation) {
    case ServiceCall::Start:
        if(service->attempted || service->stopping || service->stopped) {result=kIOReturnNotPermitted;break;}
        result=startOnGate(service,call->producer);
        if(result!=kIOReturnSuccess) {
            if(stopOnGate(service)==kIOReturnSuccess)service->last=result;
        } else service->last=result;
        break;
    case ServiceCall::Ready:call->result=readyOnGate(service);result=kIOReturnSuccess;break;
    case ServiceCall::Submit:
        if(readyOnGate(service))result=dodge_display_frontend_submit(service->front,call->packet,1132,call->submitter);
        break;
    case ServiceCall::Validate:
        call->result=readyOnGate(service) && dodge_display_frontend_validate(service->front,call->request);
        result=kIOReturnSuccess;break;
    case ServiceCall::Kick:
        if(readyOnGate(service))result=dodge_display_frontend_kick(service->front);
        break;
    case ServiceCall::Refresh:
        if(readyOnGate(service))result=dodge_display_frontend_set_refresh(service->front,call->enabled);
        break;
    case ServiceCall::Admit:
        if(readyOnGate(service))result=call->admitted(service->display,call->context);
        break;
    case ServiceCall::Stop:result=stopOnGate(service);break;
    case ServiceCall::Status:
        *call->status={readyOnGate(service),service->stopping,service->stopped,service->retryArmed,service->last};
        result=kIOReturnSuccess;break;
    case ServiceCall::Release:
        result=stopOnGate(service);
        if(result==kIOReturnSuccess && !service->ownerReleased) {service->ownerReleased=true;releaseService(service);}
        break;
    }
    if(operation)--service->operations;
    releaseService(service);return result;
}
static IOReturn perform(ServiceCall &call) {
    if(!call.service)return kIOReturnBadArgument;
    auto *loop=call.service->loop;loop->retain();
    const IOReturn result=loop->runAction(serviceAction,nullptr,&call);
    loop->release();return result;
}
DodgeDisplayService *dodge_display_service_create(IOService *display,IOService *provider,DodgeDisplayStopped completion) {
    if(!display || !provider || !completion || !display->metaCast("IOMobileFramebufferLegacy"))return nullptr;
    auto *loop=display->getWorkLoop();auto *gate=IPhone16Swap::load<IOCommandGate *>(display,5040);
    if(!loop || !gate || !gate->metaCast("IOCommandGate") || gate->getWorkLoop()!=loop || !gate->isEnabled())return nullptr;
    void *storage=IOMallocZero(sizeof(DodgeDisplayService));if(!storage)return nullptr;
    auto *service=new(storage) DodgeDisplayService();service->references=1;
    service->display=display;service->provider=provider;service->loop=loop;service->gate=gate;service->completion=completion;
    display->retain();provider->retain();loop->retain();gate->retain();return service;
}
IOReturn dodge_display_service_start(DodgeDisplayService *service,DodgeDisplayProducer producer) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Start;call.producer=producer;return perform(call);
}
bool dodge_display_service_ready(DodgeDisplayService *service) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Ready;return perform(call)==kIOReturnSuccess && call.result;
}
IOReturn dodge_display_service_submit(DodgeDisplayService *service,const void *packet,void *submitter) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Submit;call.packet=packet;call.submitter=submitter;return perform(call);
}
bool dodge_display_service_validate(DodgeDisplayService *service,IOMFBSwapIORequest *request) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Validate;call.request=request;
    return perform(call)==kIOReturnSuccess && call.result;
}
void dodge_display_service_kick(DodgeDisplayService *service) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Kick;perform(call);
}
IOReturn dodge_display_service_refresh(DodgeDisplayService *service,bool enabled) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Refresh;call.enabled=enabled;return perform(call);
}
IOReturn dodge_display_service_stop(DodgeDisplayService *service) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Stop;return perform(call);
}
IOReturn dodge_display_service_release(DodgeDisplayService *service) {
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Release;return perform(call);
}
bool dodge_display_service_status(DodgeDisplayService *service,DodgeDisplayServiceStatus *status) {
    if(!status)return false;
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Status;call.status=status;return perform(call)==kIOReturnSuccess;
}
IOWorkLoop *dodge_display_service_workloop(DodgeDisplayService *service) {return service?service->loop:nullptr;}
IOReturn dodge_display_service_admit(DodgeDisplayService *service,DodgeDisplayOperation operation,void *context) {
    if(!operation)return kIOReturnBadArgument;
    ServiceCall call={};call.service=service;call.operation=ServiceCall::Admit;call.admitted=operation;call.context=context;
    return perform(call);
}
