// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceBacking.h"
#include "OriginalIOSurfaceBackingABI.h"
#include "OriginalIOSurfaceMemoryABI.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOMemoryDescriptor.h>

namespace {
struct Entry { OSObject *surface; IOMemoryDescriptor *backing; Entry *next; };
static IOLock *registryLock;
static Entry *entries[64];
static unsigned entryCount;
static constexpr unsigned maxEntries=4096;

static IOLock *getLock()
{
    IOLock *lock=__atomic_load_n(&registryLock,__ATOMIC_ACQUIRE);
    if(lock)return lock;
    IOLock *fresh=IOLockAlloc();if(!fresh)return nullptr;
    IOLock *expected=nullptr;
    if(!__atomic_compare_exchange_n(&registryLock,&expected,fresh,false,__ATOMIC_RELEASE,__ATOMIC_ACQUIRE)) {
        IOLockFree(fresh);return expected;
    }
    return fresh;
}
static unsigned bucket(const OSObject *surface)
{
    return (reinterpret_cast<uintptr_t>(surface)>>4)&63;
}
// owned is an actual reference captured while init still owns the unpublished
// descriptor, or from the original replacement caller's valid input. Transfer
// it into the registry. Releases and all original calls run outside this lock.
// OOM/capacity exhaustion leaves the surface untracked; it never permits a
// fallback retain of the borrowed getter.
static void observe(OSObject *surface,IOMemoryDescriptor *owned)
{
    IOLock *lock=getLock();
    if(!lock) {if(owned)owned->release();return;}
    auto *fresh=static_cast<Entry *>(IOMalloc(sizeof(Entry)));
    IOMemoryDescriptor *old=nullptr;bool stored=false;
    IOLockLock(lock);
    Entry *entry=entries[bucket(surface)];
    while(entry && entry->surface!=surface)entry=entry->next;
    if(entry) {old=entry->backing;entry->backing=owned;stored=true;}
    else if(fresh && entryCount<maxEntries) {
        *fresh={surface,owned,entries[bucket(surface)]};entries[bucket(surface)]=fresh;
        fresh=nullptr;++entryCount;stored=true;
    }
    IOLockUnlock(lock);
    if(fresh)IOFree(fresh,sizeof(Entry));
    if(old)old->release();
    if(!stored && owned)owned->release();
}
static void forget(OSObject *surface)
{
    IOLock *lock=__atomic_load_n(&registryLock,__ATOMIC_ACQUIRE);if(!lock)return;
    Entry *removed=nullptr;
    IOLockLock(lock);
    Entry **link=&entries[bucket(surface)];
    while(*link && (*link)->surface!=surface)link=&(*link)->next;
    if(*link) {removed=*link;*link=removed->next;--entryCount;}
    IOLockUnlock(lock);
    if(removed) {
        IOMemoryDescriptor *backing=removed->backing;IOFree(removed,sizeof(Entry));
        if(backing)backing->release();
    }
}
static bool empty(const DodgeSurfacePages &p)
{
    return !p.identity.surface && !p.identity.id && !p.backing && !p.memory &&
        !p.bytes && !p.prepared && !p.quarantined;
}
}

// These four entries are called only by the reviewed original entry hooks.
// Initial construction has not published the surface in the root table. The
// original factory publishes only after init returns. A retained surface from
// the current-task lookup excludes final free while acquisition is in progress.
extern "C" bool dodge_iphone_surface_init(OSObject *surface,OSObject *root,task *owner,
    OSObject *properties,OSObject *parent)
{
    const bool ok=dodge_original_surface_init(surface,root,owner,properties,parent);
    if(ok) {
        IOMemoryDescriptor *backing=native_iphone_surface_memory(surface);
        if(backing)backing->retain();
        observe(surface,backing);
    }
    return ok;
}
extern "C" void dodge_iphone_surface_replace(OSObject *surface,IOMemoryDescriptor *backing)
{
    if(backing)backing->retain();
    dodge_original_surface_replace(surface,backing);
    observe(surface,backing);
}
extern "C" void dodge_iphone_surface_clear(OSObject *surface)
{
    dodge_original_surface_clear(surface);forget(surface);
}
extern "C" void dodge_iphone_surface_free(OSObject *surface)
{
    // Drop the observer before the original destructor releases its descriptor.
    // The registry does not retain surfaces and cannot keep them alive forever.
    forget(surface);dodge_original_surface_free(surface);
}
extern "C" IOReturn dodge_copy_surface_backing(const DodgeSurfaceIdentity *identity,IOMemoryDescriptor **out)
{
    if(!identity || !identity->surface || !identity->id || !out || *out)return kIOReturnBadArgument;
    IOLock *lock=getLock();if(!lock)return kIOReturnNoMemory;
    IOMemoryDescriptor *backing=nullptr;
    IOLockLock(lock);
    Entry *entry=entries[bucket(identity->surface)];
    while(entry && entry->surface!=identity->surface)entry=entry->next;
    if(entry && entry->backing) {backing=entry->backing;backing->retain();}
    IOLockUnlock(lock);
    if(!backing)return kIOReturnNotReady;
    // Pointer comparison only. The retained descriptor already comes from the
    // registry; concurrent clears/replacements cannot invalidate that reference.
    if(native_iphone_surface_memory(identity->surface)!=backing) {
        backing->release();return kIOReturnNotReady;
    }
    *out=backing;return kIOReturnSuccess;
}
extern "C" IOReturn dodge_surface_pages_acquire(uint32_t id,NativeAdrenoMemory *memory,DodgeSurfacePages *out)
{
    if(!id || !memory || !out || !empty(*out))return kIOReturnBadArgument;
    DodgeSurfaceIdentity identity{};
    IOReturn status=dodge_copy_current_surface(id,&identity);if(status)return status;
    IOMemoryDescriptor *backing=nullptr;
    status=dodge_copy_surface_backing(&identity,&backing);
    if(!status)status=dodge_surface_pages_bind(&identity,backing,memory,out);
    if(backing)backing->release();
    dodge_release_surface_identity(&identity);
    return status;
}
