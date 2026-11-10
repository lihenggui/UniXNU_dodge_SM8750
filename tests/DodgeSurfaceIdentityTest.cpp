// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceIdentity.h"
#include "OriginalIOSurfaceIdentityABI.h"
#include <IOKit/IOService.h>
#include <kern/task.h>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#define CHECK(e) do {if(!(e)) {std::fprintf(stderr,"CHECK failed at %d: %s\n",__LINE__,#e);std::abort();}}while(0)

static task user{42},kernel{1};
task_t kernel_task=&kernel;
static task_t caller=&user;
task_t current_task() {return caller;}
static IOService root("IOSurfaceRoot");
static OSObject surface("IOSurface");
static OSDictionary matching;
static bool matchingFails=false,rootAbsent=false,lookupRefused=false,terminateInLookup=false;
static unsigned lookups=0,matches=0,cases=0;
OSDictionary *IOService::nameMatching(const char *name)
{CHECK(!std::strcmp(name,"IOCoreSurfaceRoot"));++matches;if(matchingFails)return nullptr;matching.retain();return &matching;}
IOService *IOService::copyMatchingService(OSDictionary *dictionary)
{CHECK(dictionary==&matching && matching.refs==2);if(rootAbsent)return nullptr;root.retain();return &root;}
extern "C" OSObject *native_iphone_surface_copy_for_task(IOService *r,uint32_t id,task_t t)
{
    CHECK(r==&root && root.refs==2 && id==0x80000057 && t==&user);++lookups;
    if(lookupRefused)return nullptr;
    surface.retain();if(terminateInLookup)root.inactive=true;return &surface;
}
static void reset()
{
    CHECK(root.refs==1 && surface.refs==1 && matching.refs==1);
    root.type="IOSurfaceRoot";surface.type="IOSurface";root.inactive=false;
    matchingFails=rootAbsent=lookupRefused=terminateInLookup=false;caller=&user;lookups=matches=0;
}
static void passed(const char *name)
{CHECK(root.refs==1 && surface.refs==1 && matching.refs==1);++cases;std::printf("PASS: %s\n",name);}
int main()
{
    const uint32_t id=0x80000057;
    {reset();DodgeSurfaceIdentity out;CHECK(!dodge_copy_current_surface(id,&out));
     CHECK(out.surface==&surface && out.id==id && surface.refs==2 && lookups==1);
     dodge_release_surface_identity(&out);CHECK(!out.surface && !out.id);dodge_release_surface_identity(&out);
     passed("owned-result-high-bit-ID-balanced-virtual-release-and-empty-second-release");}
    {reset();DodgeSurfaceIdentity out;CHECK(dodge_copy_current_surface(0,&out)==kIOReturnBadArgument && !matches);
     CHECK(dodge_copy_current_surface(id,nullptr)==kIOReturnBadArgument && !matches);passed("zero-ID-and-null-output-refused-before-matching");}
    {reset();DodgeSurfaceIdentity out;CHECK(!dodge_copy_current_surface(id,&out));
     const unsigned calls=matches;CHECK(dodge_copy_current_surface(id,&out)==kIOReturnBadArgument && matches==calls && surface.refs==2);
     dodge_release_surface_identity(&out);passed("occupied-output-cannot-overwrite-owned-reference");}
    {reset();DodgeSurfaceIdentity out;out.id=7;CHECK(dodge_copy_current_surface(id,&out)==kIOReturnBadArgument && !matches);
     passed("nonempty-ID-field-refused-without-provider-access");}
    for(bool isKernel:{false,true}) {
        reset();DodgeSurfaceIdentity out;caller=isKernel?kernel_task:nullptr;
        CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotPermitted && !matches && !lookups);
        passed(isKernel?"kernel-worker-cannot-impersonate-user":"missing-current-task-refused");
    }
    {reset();DodgeSurfaceIdentity out;matchingFails=true;
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNoMemory && !out.surface && !lookups);passed("matching-allocation-failure");}
    {reset();DodgeSurfaceIdentity out;rootAbsent=true;
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotReady && !out.surface && !lookups);passed("missing-root-is-nonblocking");}
    {reset();DodgeSurfaceIdentity out;root.inactive=true;
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotReady && !lookups);passed("inactive-root-refused-before-lookup");}
    {reset();DodgeSurfaceIdentity out;root.type="OtherService";
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotReady && !lookups);passed("wrong-root-class-refused-before-lookup");}
    {reset();DodgeSurfaceIdentity out;lookupRefused=true;
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotPermitted && !out.surface && !out.id && lookups==1);
     passed("original-authorization-refusal-has-empty-result");}
    {reset();DodgeSurfaceIdentity out;surface.type="OtherObject";
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotReady && !out.surface && !out.id);
     passed("unexpected-result-class-discharges-original-owned-reference");}
    {reset();DodgeSurfaceIdentity out;terminateInLookup=true;
     CHECK(dodge_copy_current_surface(id,&out)==kIOReturnNotReady && !out.surface && !out.id);
     passed("root-termination-observed-after-lookup-releases-result");}
    dodge_release_surface_identity(nullptr);CHECK(cases==13);
    std::printf("PASS: %u actual identity source cases; provider lookup and IOKit primitives are peers\n",cases);
}
