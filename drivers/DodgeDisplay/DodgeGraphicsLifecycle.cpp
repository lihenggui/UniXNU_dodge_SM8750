// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeGraphicsLifecycle.h"
#include "DodgeIPhoneFramebuffer.h"
#include "OriginalGraphicsModulesABI.h"
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>

extern "C" kmod_info_t g_kernel_kmod_info;
static unsigned phase=unsigned(DodgeGraphicsPhase::Cold),attachment=0;
static IOReturn last=kIOReturnNotReady;
// Once our kernel-owned metaclass has been constructed, these original parent
// libraries must stay resident even when no framebuffer instance exists.
static const OSMetaClass *pinned[DodgeOriginalGraphicsModuleCount]={};

static IOReturn finish(DodgeGraphicsPhase next,IOReturn error) {
    __atomic_store_n(&last,error,__ATOMIC_RELAXED);
    __atomic_store_n(&phase,unsigned(next),__ATOMIC_RELEASE);return error;
}
static void releasePins() {
    for(unsigned i=0;i<DodgeOriginalGraphicsModuleCount;++i) {
        auto *meta=pinned[i];pinned[i]=nullptr;if(meta)meta->releaseMetaClass();
    }
}
extern "C" IOReturn dodge_graphics_prepare() {
    unsigned expected=unsigned(DodgeGraphicsPhase::Cold);
    if(!__atomic_compare_exchange_n(&phase,&expected,unsigned(DodgeGraphicsPhase::Loading),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        if(expected==unsigned(DodgeGraphicsPhase::Ready))return kIOReturnSuccess;
        return expected==unsigned(DodgeGraphicsPhase::Failed)?__atomic_load_n(&last,__ATOMIC_RELAXED):kIOReturnBusy;
    }
    for(unsigned i=0;i<DodgeOriginalGraphicsModuleCount;++i) {
        const auto &module=DodgeOriginalGraphicsModules[i];
        // The original IOSurface software-root personality matches IOResources
        // / IOBSD. Other families stay excluded from automatic matching. Real
        // OSKext starts dependency constructors before actual module start.
        const IOReturn result=OSKext::loadKextWithIdentifier(module.bundle,false,true,kOSKextExcludeNone,
            module.requestMatching?kOSKextExcludeNone:kOSKextExcludeAll,nullptr);
        if(result!=kIOReturnSuccess) {releasePins();return finish(DodgeGraphicsPhase::Cold,result);}
        const OSSymbol *name=OSSymbol::withCStringNoCopy(module.className);
        if(!name) {releasePins();return finish(DodgeGraphicsPhase::Cold,kIOReturnNoMemory);}
        auto *meta=OSMetaClass::copyMetaClassWithName(name);name->release();pinned[i]=meta;
        if(!meta || static_cast<const void *>(meta)!=module.expected || meta->getClassSize()!=module.instanceBytes) {
            releasePins();return finish(DodgeGraphicsPhase::Cold,kIOReturnUnsupported);
        }
    }
    // OSRuntimeInitializeCPP has already completed for all original modules.
    // Use the existing Kernel OSKext owner for the deferred source constructor.
    // preModLoad's allocation-failure path cannot safely be retried on this
    // pinned XNU source; latch all failures after entering this phase.
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if(!handle) {releasePins();return finish(DodgeGraphicsPhase::Failed,kIOReturnNoMemory);}
    const bool constructed=dodge_iphone_framebuffer_initialize();
    const IOReturn posted=OSMetaClass::postModLoad(handle);
    if(!constructed)releasePins();
    if(posted!=kIOReturnSuccess)return finish(DodgeGraphicsPhase::Failed,posted);
    if(!constructed || !dodge_iphone_framebuffer_registered())return finish(DodgeGraphicsPhase::Failed,kIOReturnNotReady);
    return finish(DodgeGraphicsPhase::Ready,kIOReturnSuccess);
}
extern "C" IOReturn dodge_graphics_acquire_root(IOService *provider,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;if(!provider)return kIOReturnBadArgument;
    if(__atomic_load_n(&phase,__ATOMIC_ACQUIRE)!=unsigned(DodgeGraphicsPhase::Ready))return kIOReturnNotReady;
    if(!provider->metaCast(DodgeOriginalGraphicsProviderClass))return kIOReturnUnsupported;
    // Original Legacy::start calls waitForService("IOCoreSurfaceRoot",NULL).
    // Request normal matching above, but never enter that wait while the root
    // is predictably absent. Keep the actual matched service retained through
    // start. Runtime termination/matching races remain to be qualified.
    auto *matching=IOService::nameMatching(DodgeOriginalGraphicsSurfaceRoot);
    if(!matching)return kIOReturnNoMemory;
    auto *surfaceRoot=IOService::copyMatchingService(matching);matching->release();
    if(!surfaceRoot)return kIOReturnNotReady;
    if(surfaceRoot->isInactive() || !surfaceRoot->metaCast(DodgeOriginalGraphicsSurfaceRootClass)) {
        surfaceRoot->release();return kIOReturnNotReady;
    }
    *out=surfaceRoot;return kIOReturnSuccess;
}
extern "C" IOReturn dodge_graphics_attach(IOService *provider,IOService **out) {
    if(!out)return kIOReturnBadArgument;
    *out=nullptr;IOService *surfaceRoot=nullptr;
    const IOReturn prerequisites=dodge_graphics_acquire_root(provider,&surfaceRoot);
    if(prerequisites!=kIOReturnSuccess)return prerequisites;
    struct RootReference {IOService *value;~RootReference() {value->release();}} heldRoot{surfaceRoot};
    unsigned expected=0;
    if(!__atomic_compare_exchange_n(&attachment,&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==1?kIOReturnBusy:kIOReturnNotPermitted;
    auto *display=dodge_iphone_framebuffer_allocate();
    if(!display) {__atomic_store_n(&attachment,0,__ATOMIC_RELEASE);return kIOReturnNoMemory;}
    if(!display->init()) {display->release();__atomic_store_n(&attachment,0,__ATOMIC_RELEASE);return kIOReturnNotReady;}
    if(!display->attach(provider)) {display->release();__atomic_store_n(&attachment,0,__ATOMIC_RELEASE);return kIOReturnNotReady;}
    if(!display->start(provider)) {
        // The concrete detach override preserves the registry attachment until
        // its retained controller has drained and called original parent stop.
        display->stop(provider);display->detach(provider);display->release();
        __atomic_store_n(&attachment,3,__ATOMIC_RELEASE);return kIOReturnNotReady;
    }
    *out=display;__atomic_store_n(&attachment,2,__ATOMIC_RELEASE);return kIOReturnSuccess;
}
extern "C" void dodge_graphics_status(DodgeGraphicsStatus *out) {
    if(!out)return;
    out->phase=DodgeGraphicsPhase(__atomic_load_n(&phase,__ATOMIC_ACQUIRE));
    out->last=__atomic_load_n(&last,__ATOMIC_RELAXED);
    out->attachment=__atomic_load_n(&attachment,__ATOMIC_ACQUIRE);
}
