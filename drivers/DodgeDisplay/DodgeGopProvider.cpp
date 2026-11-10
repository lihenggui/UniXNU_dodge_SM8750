// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGopProvider.h"
#include "DodgeGraphicsBoot.h"
#include "OriginalGopProviderABI.h"
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceMemory.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

namespace {
struct Mode {
    uint64_t base,length;
    uint32_t width,height,rowBytes;
};
unsigned phase=unsigned(DodgeGopProviderPhase::Cold);
IOReturn last=kIOReturnNotReady;
IOService *published=nullptr,*publishedPlatform=nullptr;
const OSMetaClass *pinnedMeta=nullptr;
Mode publishedMode={};

bool consoleMode(Mode *mode) {
    PE_Video video={};
    if(PE_current_console(&video) || !video.v_baseAddr || !video.v_width || !video.v_height ||
       video.v_width>8192 || video.v_height>8192 || video.v_depth!=32 || video.v_rotate ||
       video.v_rowBytes<video.v_width*4 || video.v_rowBytes>32768 ||
       video.v_rowBytes>UINT64_MAX/video.v_height)return false;
    const uint64_t length=video.v_rowBytes*video.v_height;
    if(video.v_baseAddr>UINT64_MAX-length)return false;
    *mode={video.v_baseAddr,length,uint32_t(video.v_width),uint32_t(video.v_height),uint32_t(video.v_rowBytes)};
    return true;
}
bool sameMode(const Mode &a,const Mode &b) {
    return a.base==b.base && a.length==b.length && a.width==b.width && a.height==b.height && a.rowBytes==b.rowBytes;
}
IOReturn finish(DodgeGopProviderPhase next,IOReturn result) {
    __atomic_store_n(&last,result,__ATOMIC_RELAXED);
    __atomic_store_n(&phase,unsigned(next),__ATOMIC_RELEASE);return result;
}
IOReturn copyPublished(IOService *platform,IOService **out) {
    Mode current={};
    if(platform!=publishedPlatform || platform->isInactive() || !published || !pinnedMeta || published->isInactive() ||
       !consoleMode(&current) || !sameMode(current,publishedMode))return kIOReturnNotReady;
    auto *memory=published->getDeviceMemoryWithIndex(0);
    if(published->getDeviceMemoryCount()!=1 || !memory || memory->getPhysicalAddress()!=publishedMode.base ||
       memory->getLength()!=publishedMode.length)return kIOReturnNotReady;
    published->retain();*out=published;return kIOReturnSuccess;
}
}

extern "C" IOReturn dodge_gop_provider_publish(IOService *platform,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;if(!platform)return kIOReturnBadArgument;
    unsigned expected=unsigned(DodgeGopProviderPhase::Cold);
    if(!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeGopProviderPhase::Creating),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==unsigned(DodgeGopProviderPhase::Published)?copyPublished(platform,out):kIOReturnBusy;
    // No invented Apple DT node or bus pointer is supplied to the original
    // bus-specific initializer. This nub describes the real firmware scanout.
    if(platform!=IOService::getPlatform() || !platform->metaCast("IODTPlatformExpert") || platform->isInactive())
        return finish(DodgeGopProviderPhase::Cold,kIOReturnUnsupported);
    DodgeGraphicsStatus graphics={};dodge_graphics_status(&graphics);
    if(graphics.phase!=DodgeGraphicsPhase::Ready)return finish(DodgeGopProviderPhase::Cold,kIOReturnNotReady);
    Mode mode={},current={};
    if(!consoleMode(&mode))return finish(DodgeGopProviderPhase::Cold,kIOReturnUnsupported);
    platform->retain();
    const OSMetaClass *meta=nullptr;
    IOService *provider=nullptr;
    IODeviceMemory *memory=nullptr;
    OSArray *array=nullptr;
    bool attached=false;
    IOReturn result=kIOReturnNoMemory;
    const OSSymbol *name=OSSymbol::withCStringNoCopy(DodgeGopProviderClass);
    if(!name)goto failed;
    meta=OSMetaClass::copyMetaClassWithName(name);name->release();
    if(!meta || static_cast<const void *>(meta)!=dodge_original_gop_provider_meta ||
       meta->getClassSize()!=DodgeGopProviderBytes || meta->getSuperClass()!=IOService::metaClass) {
        result=kIOReturnUnsupported;goto failed;
    }
    {
        auto *object=meta->alloc();
        if(!object)goto failed;
        provider=OSDynamicCast(IOService,object);
        if(!provider || provider->getMetaClass()!=meta) {
            object->release();provider=nullptr;result=kIOReturnUnsupported;goto failed;
        }
    }
    // Slot 21 is the actual inherited IOService::init(OSDictionary *).
    // The real typed allocator has zeroed the unused Apple-specific fields.
    if(!provider->init()) {result=kIOReturnNotReady;goto failed;}
    provider->setName("dodge-gop");
    {const char *value=provider->getName();if(!value || strcmp(value,"dodge-gop"))goto failed;}
    memory=IODeviceMemory::withRange(mode.base,mode.length);
    if(!memory)goto failed;
    if(memory->getPhysicalAddress()!=mode.base || memory->getLength()!=mode.length) {
        result=kIOReturnUnsupported;goto failed;
    }
    array=OSArray::withCapacity(1);
    if(!array || !array->setObject(memory))goto failed;
    // setDeviceMemory has no return value. Read back the installed property
    // before attaching or publishing; allocation failure must not be hidden.
    provider->setDeviceMemory(array);
    if(provider->getDeviceMemoryCount()!=1 || provider->getDeviceMemoryWithIndex(0)!=memory)goto failed;
    // Original getResources must use its existing-memory fast path, never
    // search for an AppleARMIO ancestor on this Qualcomm platform.
    result=provider->getResources();if(result!=kIOReturnSuccess)goto failed;
    if(!provider->attach(platform)) {result=kIOReturnNotReady;goto failed;}
    attached=true;
    if(platform->isInactive() || !consoleMode(&current) || !sameMode(mode,current)) {
        result=kIOReturnNotReady;goto failed;
    }
    array->release();array=nullptr;memory->release();memory=nullptr;
    published=provider;publishedPlatform=platform;publishedMode=mode;pinnedMeta=meta;
    // Keep the allocator's reference and the metadata pin for the whole boot,
    // including a later failed display start or a delayed original worker.
    // registerService can reenter; Creating remains visible until it returns.
    provider->registerService();
    result=copyPublished(platform,out);
    platform->release();
    return finish(DodgeGopProviderPhase::Published,result);
failed:
    if(attached)provider->detach(platform);
    if(array)array->release();
    if(memory)memory->release();
    if(provider)provider->release();
    if(meta)meta->releaseMetaClass();
    platform->release();
    return finish(DodgeGopProviderPhase::Cold,result);
}

extern "C" void dodge_gop_provider_status(DodgeGopProviderStatus *out) {
    if(!out)return;
    *out={};out->phase=DodgeGopProviderPhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->last=__atomic_load_n(&last,__ATOMIC_RELAXED);
    if(out->phase==DodgeGopProviderPhase::Published) {
        out->physicalAddress=publishedMode.base;out->length=publishedMode.length;
        out->width=publishedMode.width;out->height=publishedMode.height;out->rowBytes=publishedMode.rowBytes;
    }
}

extern "C" IOReturn dodge_graphics_boot_gop(IOService *platform,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;if(!platform)return kIOReturnBadArgument;
    IOReturn result=dodge_graphics_prepare();if(result!=kIOReturnSuccess)return result;
    IOService *provider=nullptr;
    result=dodge_gop_provider_publish(platform,&provider);if(result!=kIOReturnSuccess)return result;
    result=dodge_graphics_boot(provider,out);provider->release();return result;
}
