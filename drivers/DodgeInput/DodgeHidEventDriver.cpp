// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "OriginalHidEventABI.h"
#include "DodgeHidEventDriver.h"
#include "DodgeHidEdgePolicy.h"
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
extern "C" {
extern kmod_info_t g_kernel_kmod_info;
extern const unsigned char dodge_original_hid_event_vtable[];
void dodge_hid_edge_cpp_initializer() asm("__GLOBAL__sub_I_DodgeHidEventDriver.cpp");
}
namespace {
unsigned preparation=0,initialization=0;
IOReturn preparationResult=kIOReturnNotReady;
const OSMetaClass *parentPin=nullptr;
OSObject *instancePin=nullptr;
bool knownEvent(IOHIDEvent *event) {
    return event && *reinterpret_cast<const void *const *>(event)==dodge_original_hid_event_vtable;
}
}

// One device, one initialization attempt per boot. As with DodgeInput, a
// partial original init can leave an expansion pointer null while original
// free dereferences it. Keep the attempted instance and provider pinned.
class DodgeHidEventDriver final : public IOHIDEventDriver {
    OSDeclareDefaultStructors(DodgeHidEventDriver)
    DodgeHidEdgePolicy edges={};
    IOWorkLoop *loop=nullptr;
    IOService *providerPin=nullptr;
    bool initAttempted=false,startAttempted=false,ready=false;
    void annotate(IOHIDEvent *event) {
        if (!knownEvent(event) || event->getType()!=11) return;
        IOHIDEvent *events[10]={};DodgeHidEdgeContact contacts[10]={};unsigned count=0;
        auto *children=event->getChildren();
        if (children) {
            auto *array=OSDynamicCast(OSArray,children);
            if (!array) return;
            const unsigned childrenCount=array->getCount();if (childrenCount>10) return;
            for (unsigned i=0;i<childrenCount;++i) {
                auto *child=static_cast<IOHIDEvent *>(array->getObject(i));
                if (knownEvent(child) && child->getType()==11) events[count++]=child;
            }
            if (array->getCount()!=childrenCount) return;
        } else {
            // An empty hand collection is not a new finger with identity 0.
            if (event->getIntegerValue(0xb0004,0)!=2) return;
            events[count++]=event;
        }
        for (unsigned i=0;i<count;++i) {
            auto *child=events[i];auto &contact=contacts[i];
            contact.identity=(uint32_t)child->getIntegerValue(0xb0005,0);
            contact.mask=(uint32_t)child->getIntegerValue(0xb0007,0);
            contact.down=child->getIntegerValue(0xb0009,0)!=0;
            contact.x=child->getFixedValue(0xb0000,0);contact.y=child->getFixedValue(0xb0001,0);
            if (!dodge_hid_edge_valid(contact)) return;
            for (unsigned j=0;j<i;++j) if (contacts[j].identity==contact.identity) return;
        }
        // Validate the entire bounded collection before changing state/events.
        bool fromEdge=false;
        for (unsigned i=0;i<count;++i) {
            uint32_t mask=0;bool edge=dodge_hid_edge_mark(&edges,contacts[i],&mask);fromEdge|=edge;
            if (edge) events[i]->setIntegerValue(0xb0007,(int32_t)mask,0);
        }
        if (fromEdge && children) {
            uint32_t mask=(uint32_t)event->getIntegerValue(0xb0007,0);
            event->setIntegerValue(0xb0007,(int32_t)(mask|0x800u),0);
        }
    }
    struct DispatchCall {IOWorkLoop *loop;IOHIDEvent *event;IOOptionBits options;};
    static IOReturn dispatchAction(OSObject *owner,void *argument,void *,void *,void *) {
        auto *self=static_cast<DodgeHidEventDriver *>(owner);auto *call=static_cast<DispatchCall *>(argument);
        if (!call || call->loop!=self->loop || !call->loop->inGate() ||
            !__atomic_load_n(&self->ready,__ATOMIC_ACQUIRE) || self->isInactive()) return kIOReturnNotReady;
        self->annotate(call->event);
        self->IOHIDEventDriver::dispatchEvent(call->event,call->options);return kIOReturnSuccess;
    }
public:
    bool init(OSDictionary *properties=nullptr) override {
        unsigned expected=0;
        if (!__atomic_compare_exchange_n(&initialization,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return false;
        retain();__atomic_store_n(&instancePin,static_cast<OSObject *>(this),__ATOMIC_RELEASE);initAttempted=true;
        return IOHIDEventDriver::init(properties);
    }
    bool start(IOService *provider) override {
        if (!initAttempted || startAttempted || !provider || !provider->metaCast("IOHIDInterface")) return false;
        startAttempted=true;provider->retain();providerPin=provider;
        loop=getWorkLoop();if (!loop) return false;
        loop->retain();
        PE_Video video={};
        if (PE_current_console(&video) || video.v_rotate || video.v_width>UINT32_MAX || video.v_height>UINT32_MAX ||
            !dodge_hid_edge_configure(&edges,(uint32_t)video.v_width,(uint32_t)video.v_height,48)) return false;
        __atomic_store_n(&ready,true,__ATOMIC_RELEASE);
        bool ok=IOHIDEventDriver::start(provider);
        if (!ok) __atomic_store_n(&ready,false,__ATOMIC_RELEASE);
        return ok;
    }
    void dispatchEvent(IOHIDEvent *event,IOOptionBits options) override {
        if (!event || !loop || !__atomic_load_n(&ready,__ATOMIC_ACQUIRE) || isInactive()) return;
        retain();event->retain();auto *workLoop=loop;workLoop->retain();
        DispatchCall call={workLoop,event,options};workLoop->runAction(dispatchAction,this,&call);
        workLoop->release();event->release();release();
    }
    void stop(IOService *provider) override {
        __atomic_store_n(&ready,false,__ATOMIC_RELEASE);
        IOHIDEventDriver::stop(provider);
    }
    void free() override {
        if (initAttempted) return;
        // Rejected duplicate allocations never entered original init. Their
        // constructors/destructors have no original expansion-resource work.
        OSObject::free();
    }
};
OSDefineMetaClassAndStructors(DodgeHidEventDriver,IOHIDEventDriver)
extern "C" unsigned dodge_hid_edge_driver_bytes() {return sizeof(DodgeHidEventDriver);}
extern "C" const OSMetaClass *dodge_hid_edge_driver_meta() {return &DodgeHidEventDriver::gMetaClass;}
extern "C" bool dodge_hid_edge_instance_pinned() {return __atomic_load_n(&instancePin,__ATOMIC_ACQUIRE)!=nullptr;}
extern "C" IOReturn dodge_hid_edge_prepare() {
    unsigned expected=0;
    if (!__atomic_compare_exchange_n(&preparation,&expected,1u,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==2?kIOReturnSuccess:expected==3?__atomic_load_n(&preparationResult,__ATOMIC_RELAXED):kIOReturnBusy;
    auto finish=[](IOReturn result,unsigned phase) {
        __atomic_store_n(&preparationResult,result,__ATOMIC_RELAXED);__atomic_store_n(&preparation,phase,__ATOMIC_RELEASE);return result;
    };
    IOReturn rc=OSKext::loadKextWithIdentifier("com.apple.iokit.IOHIDFamily",false,true,kOSKextExcludeNone,kOSKextExcludeNone,nullptr);
    if (rc) return finish(rc,0);
    const OSSymbol *name=OSSymbol::withCStringNoCopy("IOHIDEventDriver");if (!name) return finish(kIOReturnNoMemory,0);
    parentPin=OSMetaClass::copyMetaClassWithName(name);name->release();
    if (!parentPin || parentPin!=&IOHIDEventDriver::gMetaClass || parentPin->getClassSize()!=264) {
        if (parentPin) parentPin->releaseMetaClass();parentPin=nullptr;return finish(kIOReturnUnsupported,0);
    }
    void *handle=OSMetaClass::preModLoad(g_kernel_kmod_info.name);if (!handle) return finish(kIOReturnNoMemory,3);
    dodge_hid_edge_cpp_initializer();rc=OSMetaClass::postModLoad(handle);if (rc) return finish(rc,3);
    name=OSSymbol::withCStringNoCopy("DodgeHidEventDriver");if (!name) return finish(kIOReturnNoMemory,3);
    const OSMetaClass *meta=OSMetaClass::copyMetaClassWithName(name);name->release();
    bool ok=meta && meta==dodge_hid_edge_driver_meta() && meta->getClassSize()==dodge_hid_edge_driver_bytes();
    if (meta) meta->releaseMetaClass();
    return finish(ok?kIOReturnSuccess:kIOReturnNotReady,ok?2u:3u);
}
