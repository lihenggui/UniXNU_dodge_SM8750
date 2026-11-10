// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceBacking.h"
#include "OriginalIOSurfaceBackingABI.h"
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLocks.h>
#include <NativeAdrenoMemory.h>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

extern "C" bool dodge_iphone_surface_init(OSObject *,OSObject *,task *,OSObject *,OSObject *);
extern "C" void dodge_iphone_surface_replace(OSObject *,IOMemoryDescriptor *);
extern "C" void dodge_iphone_surface_clear(OSObject *);
extern "C" void dodge_iphone_surface_free(OSObject *);
std::atomic<unsigned> descriptorDeletes{0};
static thread_local unsigned lockDepth;
static bool lockFailure=false,allocationFailure=false,initResult=true,lookupAllowed=true,hostLockCreated=false;
static std::atomic<unsigned> allocations{0};
static unsigned cases=0,originalCalls=0;
struct Surface:OSObject {
    std::atomic<IOMemoryDescriptor *> backing{nullptr};
    uint32_t allocation=12288;
    Surface():OSObject("IOSurface") {}
    ~Surface() override {assert(!backing && refs==1);}
};
static Surface *selected;
static IOMemoryDescriptor *initial;
static void (*duringOriginal)(Surface *);
static void (*duringGetter)(Surface *);
IOLock *IOLockAlloc() {if(lockFailure)return nullptr;hostLockCreated=true;return new IOLock;}
void IOLockFree(IOLock *lock) {delete lock;}
void IOLockLock(IOLock *lock) {lock->mutex.lock();assert(!lockDepth++);}
void IOLockUnlock(IOLock *lock) {assert(lockDepth--==1);lock->mutex.unlock();}
void *IOMalloc(size_t bytes) {if(allocationFailure)return nullptr;void *p=std::malloc(bytes);if(p)++allocations;return p;}
void IOFree(void *p,size_t) {assert(p && allocations);--allocations;std::free(p);}
static void setBacking(Surface *s,IOMemoryDescriptor *p) {
    assert(!lockDepth);if(p)p->retain();auto *old=s->backing.exchange(p);if(old)old->release();
}
extern "C" bool dodge_original_surface_init(OSObject *s,OSObject *,task *,OSObject *,OSObject *) {
    assert(!lockDepth);++originalCalls;if(initResult)setBacking(static_cast<Surface *>(s),initial);return initResult;
}
extern "C" void dodge_original_surface_replace(OSObject *s,IOMemoryDescriptor *p) {
    assert(!lockDepth);++originalCalls;setBacking(static_cast<Surface *>(s),p);
    if(duringOriginal)duringOriginal(static_cast<Surface *>(s));
}
extern "C" void dodge_original_surface_clear(OSObject *s) {
    assert(!lockDepth);++originalCalls;setBacking(static_cast<Surface *>(s),nullptr);
    if(duringOriginal)duringOriginal(static_cast<Surface *>(s));
}
extern "C" void dodge_original_surface_free(OSObject *s) {
    assert(!lockDepth);++originalCalls;DodgeSurfaceIdentity id{s,7};IOMemoryDescriptor *p=nullptr;
    if(hostLockCreated)assert(dodge_copy_surface_backing(&id,&p)==kIOReturnNotReady && !p);
    setBacking(static_cast<Surface *>(s),nullptr);
}
extern "C" IOMemoryDescriptor *native_iphone_surface_memory(const OSObject *s) {
    auto *surface=const_cast<Surface *>(static_cast<const Surface *>(s));
    if(duringGetter) {auto fn=duringGetter;duringGetter=nullptr;fn(surface);}
    return surface->backing.load();
}
extern "C" uint32_t native_iphone_surface_allocation(const OSObject *s) {return static_cast<const Surface *>(s)->allocation;}
extern "C" IOReturn dodge_copy_current_surface(uint32_t id,DodgeSurfaceIdentity *out) {
    if(!lookupAllowed || id!=7 || !selected)return kIOReturnNotPermitted;
    selected->retain();*out={selected,id};return 0;
}
extern "C" void dodge_release_surface_identity(DodgeSurfaceIdentity *id) {
    if(id && id->surface)id->surface->release();if(id)*id={};
}
struct Fixture {
    Surface surface;IOMemoryDescriptor *a=new IOMemoryDescriptor,*b=new IOMemoryDescriptor;
    DodgeSurfaceIdentity identity{&surface,7};
    Fixture() {initial=a;selected=&surface;}
    void start() {assert(dodge_iphone_surface_init(&surface,nullptr,nullptr,nullptr,nullptr));}
    IOReturn copy(IOMemoryDescriptor **out) {return dodge_copy_surface_backing(&identity,out);}
    ~Fixture() {
        duringGetter=duringOriginal=nullptr;allocationFailure=lockFailure=false;initResult=lookupAllowed=true;
        dodge_iphone_surface_free(&surface);a->release();b->release();selected=nullptr;
        assert(!allocations && !lockDepth);
    }
};
static void staleCopy(Surface *s) {
    DodgeSurfaceIdentity id{s,7};IOMemoryDescriptor *p=nullptr;
    assert(dodge_copy_surface_backing(&id,&p)==kIOReturnNotReady && !p);
}
int main() {
    {Fixture f;lockFailure=true;IOMemoryDescriptor *p=nullptr;assert(f.copy(&p)==kIOReturnNoMemory);++cases;}
    // The lock still does not exist. Failed observation must preserve original
    // successful init, then refuse all attempts to acquire an untracked value.
    {Fixture f;lockFailure=true;f.start();lockFailure=false;IOMemoryDescriptor *p=nullptr;
     assert(f.a->refs==2 && f.copy(&p)==kIOReturnNotReady && !p);++cases;}
    {Fixture f;f.start();IOMemoryDescriptor *p=nullptr;assert(!f.copy(&p) && p==f.a && f.a->refs==4);
     p->release();assert(f.a->refs==3);++cases;}
    {Fixture f;initResult=false;assert(!dodge_iphone_surface_init(&f.surface,nullptr,nullptr,nullptr,nullptr));
     IOMemoryDescriptor *p=nullptr;assert(f.copy(&p)==kIOReturnNotReady && f.a->refs==1);++cases;}
    {Fixture f;initial=nullptr;f.start();IOMemoryDescriptor *p=nullptr;assert(f.copy(&p)==kIOReturnNotReady);
     dodge_iphone_surface_replace(&f.surface,f.b);assert(!f.copy(&p) && p==f.b);p->release();++cases;}
    {Fixture f;allocationFailure=true;f.start();allocationFailure=false;IOMemoryDescriptor *p=nullptr;
     assert(f.copy(&p)==kIOReturnNotReady && f.a->refs==2);++cases;}
    {Fixture f;f.start();allocationFailure=true;dodge_iphone_surface_replace(&f.surface,f.b);allocationFailure=false;
     IOMemoryDescriptor *p=nullptr;assert(!f.copy(&p) && p==f.b && f.a->refs==1);p->release();++cases;}
    {Fixture f;f.start();IOMemoryDescriptor *old=nullptr;assert(!f.copy(&old));
     dodge_iphone_surface_replace(&f.surface,f.b);assert(old==f.a && old->refs==2);
     IOMemoryDescriptor *p=nullptr;assert(!f.copy(&p) && p==f.b);old->release();p->release();++cases;}
    {Fixture f;f.start();duringOriginal=staleCopy;dodge_iphone_surface_replace(&f.surface,f.b);duringOriginal=nullptr;
     IOMemoryDescriptor *p=nullptr;assert(!f.copy(&p) && p==f.b);p->release();++cases;}
    {Fixture f;f.start();duringOriginal=staleCopy;dodge_iphone_surface_clear(&f.surface);duringOriginal=nullptr;
     IOMemoryDescriptor *p=nullptr;assert(f.copy(&p)==kIOReturnNotReady && f.a->refs==1);++cases;}
    {Fixture f;f.start();dodge_iphone_surface_replace(&f.surface,nullptr);IOMemoryDescriptor *p=nullptr;
     assert(f.copy(&p)==kIOReturnNotReady && f.a->refs==1);++cases;}
    {Fixture f;f.start();duringGetter=[](Surface *s) {dodge_iphone_surface_replace(s,nullptr);};
     IOMemoryDescriptor *p=nullptr;assert(f.copy(&p)==kIOReturnNotReady && !p && f.a->refs==1);++cases;}
    {Fixture f;f.start();setBacking(&f.surface,f.b);IOMemoryDescriptor *p=nullptr;
     assert(f.copy(&p)==kIOReturnNotReady && !p && f.a->refs==2);++cases;}
    {Fixture f;f.start();dodge_iphone_surface_free(&f.surface);IOMemoryDescriptor *p=nullptr;
     assert(f.copy(&p)==kIOReturnNotReady && f.a->refs==1);
     initial=f.b;f.start();assert(!f.copy(&p) && p==f.b);p->release();++cases;}
    {Fixture f;f.start();IOMemoryDescriptor *p=f.b;
     assert(f.copy(&p)==kIOReturnBadArgument && p==f.b && f.b->refs==1);
     assert(dodge_copy_surface_backing(nullptr,&p)==kIOReturnBadArgument);
     p=nullptr;DodgeSurfaceIdentity empty{};assert(dodge_copy_surface_backing(&empty,&p)==kIOReturnBadArgument);
     assert(dodge_copy_surface_backing(&f.identity,nullptr)==kIOReturnBadArgument);++cases;}
    // The provider's last reference disappears during clear. Only the actual
    // copy may keep this heap descriptor alive after the observer is removed.
    {Fixture f;f.start();IOMemoryDescriptor *p=nullptr;assert(!f.copy(&p));
     const unsigned before=descriptorDeletes;f.a->release();f.a=new IOMemoryDescriptor;
     dodge_iphone_surface_clear(&f.surface);assert(descriptorDeletes==before && p->refs==1);
     p->release();assert(descriptorDeletes==before+1);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};
     assert(!dodge_surface_pages_acquire(7,&memory,&pages) && pages.backing==f.a && f.surface.refs==2 && memory.references==1);
     dodge_iphone_surface_clear(&f.surface);assert(dodge_surface_pages_current(&pages)==kIOReturnNotReady && f.a->refs==2);
     assert(!dodge_surface_pages_release(&pages) && f.a->refs==1 && f.surface.refs==1);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};memory.pages[0].physical+=4096;
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnNotPermitted);
     assert(!pages.backing && !memory.references && f.a->refs==3 && f.surface.refs==1);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};f.a->prepareFails=true;
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnIOError && !pages.backing && !memory.references);
     assert(f.a->refs==3 && f.surface.refs==1);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};lookupAllowed=false;
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnNotPermitted && f.a->refs==3 && f.surface.refs==1);++cases;}
    {Fixture f;NativeAdrenoMemory memory;DodgeSurfacePages pages{};
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnNotReady && f.surface.refs==1);
     assert(dodge_surface_pages_acquire(0,&memory,&pages)==kIOReturnBadArgument);
     assert(dodge_surface_pages_acquire(7,nullptr,&pages)==kIOReturnBadArgument);
     pages.bytes=1;assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnBadArgument);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};memory.references=1;
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnBusy && !pages.backing && f.surface.refs==1 && f.a->refs==3);++cases;}
    {Fixture f;f.start();NativeAdrenoMemory memory;DodgeSurfacePages pages{};
     memory.pages[0].physical+=4096;f.a->completeFails=true;
     assert(dodge_surface_pages_acquire(7,&memory,&pages)==kIOReturnIOError && pages.quarantined && memory.isQuarantined);
     assert(f.a->refs==4 && f.surface.refs==2 && memory.references==1);
     // Fixture-only external recovery, after checking ownership remains held.
     f.a->completeFails=false;pages.quarantined=false;memory.isQuarantined=false;
     assert(!dodge_surface_pages_release(&pages) && f.a->refs==3 && f.surface.refs==1);++cases;}
    {Fixture f;f.start();std::atomic<bool> go{false};
     std::thread writer([&] {while(!go.load()){}for(unsigned i=0;i<2000;++i)dodge_iphone_surface_replace(&f.surface,(i&1)?f.a:f.b);});
     std::thread reader([&] {go=true;for(unsigned i=0;i<4000;++i) {IOMemoryDescriptor *p=nullptr;auto status=f.copy(&p);
         assert(status==0 || status==kIOReturnNotReady);if(!status) {assert(p==f.a || p==f.b);p->release();}else assert(!p);}});
     writer.join();reader.join();assert(f.a->refs==3 && f.b->refs==1);++cases;}
    {IOMemoryDescriptor *md=new IOMemoryDescriptor;std::vector<std::unique_ptr<Surface>> many;
     for(unsigned i=0;i<4097;++i) {many.emplace_back(new Surface);initial=md;assert(dodge_iphone_surface_init(many.back().get(),nullptr,nullptr,nullptr,nullptr));}
     IOMemoryDescriptor *p=nullptr;DodgeSurfaceIdentity id{many.back().get(),7};
     assert(dodge_copy_surface_backing(&id,&p)==kIOReturnNotReady && !p && allocations==4096);
     dodge_iphone_surface_free(many.front().get());
     dodge_iphone_surface_replace(many.back().get(),md);assert(!dodge_copy_surface_backing(&id,&p));p->release();
     for(auto &s:many)dodge_iphone_surface_free(s.get());assert(!allocations && md->refs==1);md->release();++cases;}
    assert(cases==25 && !allocations && !lockDepth && originalCalls>8000);
    std::printf("PASS: %u actual surface observer/acquisition cases, concurrent replacement/copy, bounded registry\n",cases);
}
