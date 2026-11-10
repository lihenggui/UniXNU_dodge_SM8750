// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfacePages.h"
#include "NativeAdrenoMemory.h"
#include "OriginalIOSurfaceMemoryABI.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#define CHECK(e) do {if(!(e)) {std::fprintf(stderr,"CHECK failed at %d: %s\n",__LINE__,#e);std::abort();}}while(0)
struct Surface:OSObject {
    uint32_t allocation=12288;
    IOMemoryDescriptor *descriptor=nullptr;
    Surface():OSObject("IOSurface") {}
};
extern "C" IOMemoryDescriptor *native_iphone_surface_memory(const OSObject *s) {return static_cast<const Surface *>(s)->descriptor;}
extern "C" uint32_t native_iphone_surface_allocation(const OSObject *s) {return static_cast<const Surface *>(s)->allocation;}
// This previously checked source release is a host peer here. The new native
// checks execute its actual source and original surface virtual release.
extern "C" void dodge_release_surface_identity(DodgeSurfaceIdentity *identity)
{OSObject *s=identity->surface;*identity={};if(s)s->release();}
struct Fixture {
    Surface surface;IOMemoryDescriptor backing,other;NativeAdrenoMemory memory;
    DodgeSurfaceIdentity identity{};DodgeSurfacePages association{};
    Fixture() {surface.descriptor=&backing;surface.retain();identity={&surface,7};}
    IOReturn bind() {return dodge_surface_pages_bind(&identity,&backing,&memory,&association);}
    void balanced() {CHECK(!association.memory && !association.backing && !identity.surface && surface.refs==1 && backing.refs==1 && !memory.references && !backing.prepared);}
    ~Fixture() {
        if(association.quarantined || memory.isQuarantined) {
            CHECK(association.memory==&memory && association.identity.surface==&surface && memory.references==1 && backing.refs==2 && surface.refs==2);
            return; // Explicit quarantined fixture owners survive until test teardown.
        }
        if(association.memory)CHECK(!dodge_surface_pages_release(&association));
        if(identity.surface)dodge_release_surface_identity(&identity);
        balanced();
    }
};
static unsigned cases;
static void passed(const char *name) {++cases;std::printf("PASS: %s\n",name);}
static Fixture *active;
static void replaceDuringPrepare() {active->surface.descriptor=&active->other;}
static void replaceDuringWalk() {if(active->backing.segments==3)active->surface.descriptor=reinterpret_cast<IOMemoryDescriptor *>(uintptr_t(0xdeadbeef));}
static void resizeDuringWalk() {if(active->backing.segments==3)active->surface.allocation=16384;}
int main()
{
    {Fixture f;CHECK(!f.bind() && !f.identity.surface && f.association.identity.surface==&f.surface && f.memory.references==1 && f.backing.refs==2);
     CHECK(!dodge_surface_pages_current(&f.association));CHECK(!dodge_surface_pages_release(&f.association));f.balanced();
     CHECK(!dodge_surface_pages_release(&f.association));passed("contiguous-full-page-match-retains-both-owners-through-balanced-release");}
    {Fixture f;f.memory.count=3;for(unsigned i=0;i<3;++i) {f.memory.pages[i]={i*4096,0x40000000+i*8192,4096};f.backing.physical[i]=f.memory.pages[i].physical;}
     CHECK(!f.bind() && f.backing.segments==3);passed("fragmented-backing-compared-at-every-logical-page");}
    for(unsigned page:{0u,1u,2u}) {Fixture f;f.backing.physical[page]+=0x100000;
        CHECK(f.bind()==kIOReturnNotPermitted && f.backing.completes==1);f.balanced();passed("mismatched-physical-page-refuses-and-rolls-back-all-ownership");}
    {Fixture f;f.backing.run=4095;CHECK(f.bind()==kIOReturnNotPermitted);f.balanced();passed("short-physical-segment-refused");}
    for(unsigned corruption=0;corruption<6;++corruption) {
        Fixture f;
        switch(corruption) {
        case 0:f.memory.pages[0].physical=0;break;
        case 1:f.memory.pages[0].offset=4096;break;
        case 2:f.memory.pages[0].bytes=8192;break;
        case 3:f.memory.pages[0].physical=UINT64_MAX-4095;break;
        case 4:f.memory.pages[0].bytes=16384;break;
        case 5:f.memory.count=0;break;
        }
        CHECK(f.bind()==kIOReturnBadArgument);f.balanced();passed("malformed-span-bounds-offset-count-or-overflow-refused");
    }
    {Fixture f;f.surface.allocation=8193;CHECK(!f.bind());passed("allocation-rounds-up-with-64-bit-arithmetic");}
    for(unsigned kind=0;kind<7;++kind) {
        Fixture f;IOReturn expected=kIOReturnBadArgument;
        switch(kind) {
        case 0:f.surface.allocation=0;break;
        case 1:f.surface.allocation=12289;break;
        case 2:f.backing.bytes=8192;break;
        case 3:f.surface.descriptor=&f.other;expected=kIOReturnNotPermitted;break;
        case 4:f.backing.type="Other";break;
        case 5:f.surface.type="Other";break;
        case 6:f.memory.isImported=false;expected=kIOReturnNotReady;break;
        }
        CHECK(f.bind()==expected && f.identity.surface==&f.surface && !f.backing.prepares && !f.memory.references);
        passed("invalid-input-is-refused-before-consuming-identity-or-preparing-pages");
    }
    {Fixture f;f.memory.references=1;CHECK(f.bind()==kIOReturnBusy && f.identity.surface==&f.surface);f.memory.references=0;passed("already-mapped-or-held-memory-cannot-be-reassociated");}
    {Fixture f;f.memory.isPrepared=false;CHECK(f.bind()==kIOReturnNotReady && f.identity.surface==&f.surface);passed("unprepared-import-cannot-be-held");}
    {Fixture f;f.backing.direction=kIODirectionOut;CHECK(f.bind()==kIOReturnNotPermitted && !f.backing.prepares);passed("writable-import-requires-writable-surface-descriptor");}
    {Fixture f;f.backing.direction=kIODirectionOut;f.memory.readOnlyFlag=true;CHECK(!f.bind());passed("read-only-import-accepts-read-only-descriptor");}
    {Fixture f;f.backing.direction=kIODirectionIn;CHECK(f.bind()==kIOReturnNotPermitted);passed("device-read-permission-is-required");}
    {Fixture f;f.backing.prepareFails=true;CHECK(f.bind()==kIOReturnIOError && !f.backing.completes);f.balanced();passed("prepare-failure-releases-retained-identity-and-memory-hold");}
    {Fixture f;f.backing.physical[1]+=4096;f.backing.completeFails=true;CHECK(f.bind()==kIOReturnIOError && f.association.quarantined && f.backing.prepared);
     const unsigned calls=f.backing.completes;CHECK(dodge_surface_pages_release(&f.association)==kIOReturnNotReady && f.backing.completes==calls);
     passed("failed-rollback-complete-quarantines-and-retains-both-owners");}
    {Fixture f;CHECK(!f.bind());f.backing.completeFails=true;CHECK(dodge_surface_pages_release(&f.association)==kIOReturnIOError && f.association.quarantined && f.backing.prepared);
     passed("release-complete-failure-keeps-prepared-pages-and-quarantines-import");}
    {Fixture f;CHECK(!f.bind());CHECK(!f.memory.holdForDevice());const unsigned calls=f.backing.completes;
     CHECK(dodge_surface_pages_release(&f.association)==kIOReturnBusy && f.backing.completes==calls && f.backing.prepared);
     CHECK(!f.memory.retireAfterQuiescence());CHECK(!dodge_surface_pages_release(&f.association));f.balanced();passed("VM-or-job-reference-defers-association-release");}
    {Fixture f;CHECK(!f.bind());f.memory.quarantine();CHECK(dodge_surface_pages_current(&f.association)==kIOReturnNotReady && dodge_surface_pages_release(&f.association)==kIOReturnNotReady);
     passed("external-memory-quarantine-keeps-original-backing-owner");}
    for(auto hook:{replaceDuringPrepare,replaceDuringWalk,resizeDuringWalk}) {
        Fixture f;active=&f;if(hook==replaceDuringPrepare)f.backing.onPrepare=hook;else f.backing.onSegment=hook;
        CHECK(f.bind()==kIOReturnNotReady);f.balanced();passed("observed-replacement-or-resize-during-capture-refuses-and-cleans-up");
    }
    {Fixture f;CHECK(!f.bind());f.surface.descriptor=reinterpret_cast<IOMemoryDescriptor *>(uintptr_t(0xdeadbeef));
     CHECK(dodge_surface_pages_current(&f.association)==kIOReturnNotReady);CHECK(!dodge_surface_pages_release(&f.association));f.balanced();
     passed("later-borrowed-descriptor-replacement-is-compared-without-dereference");}
    {Fixture f;CHECK(!f.bind());const unsigned calls=f.backing.prepares;CHECK(f.bind()==kIOReturnBadArgument && f.backing.prepares==calls);
     CHECK(dodge_surface_pages_bind(nullptr,&f.backing,&f.memory,&f.association)==kIOReturnBadArgument);
     CHECK(dodge_surface_pages_current(nullptr)==kIOReturnBadArgument && dodge_surface_pages_release(nullptr)==kIOReturnBadArgument);
     passed("occupied-record-and-null-inputs-refused-without-overwrite");}
    std::printf("PASS: %u actual surface page-association cases; IOKit, identity release and memory-reference primitives are host peers\n",cases);
}
