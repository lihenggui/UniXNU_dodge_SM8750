// SPDX-License-Identifier: BSD-2-Clause-Patent
// Runs the actual staged board metal() body with explicit loader/IOKit peers.
#include <cassert>
#include <cstdlib>
#include <cstring>

static unsigned scenario,allocations,releases,propertyCalls,attachCalls,registrations,initializers,postCalls;
struct OSSymbol {
    static const OSSymbol *withCString(const char *name) {
        assert(!std::strcmp(name,"IOAcceleratorES"));
        return scenario==2?nullptr:new OSSymbol;
    }
    void release() const {delete this;}
};
#define OSSafeReleaseNULL(value) do {if(value) {(value)->release();(value)=nullptr;}} while(0)
struct OSMetaClass {
    static const OSMetaClass *getMetaClassWithName(const OSSymbol *name) {
        assert(name);static OSMetaClass parent;return scenario==3?nullptr:&parent;
    }
    unsigned getClassSize() const {return scenario==4?144:136;}
    static void *preModLoad(const char *name) {
        assert(!std::strcmp(name,"__kernel__"));return scenario==5?nullptr:reinterpret_cast<void *>(0x100);
    }
    static int postModLoad(void *handle) {
        assert(handle==reinterpret_cast<void *>(0x100) && initializers==1);++postCalls;return scenario==6?-1:0;
    }
};
static struct {const char *name;} g_kernel_kmod_info={"__kernel__"};
static int OSKextLoadKextWithIdentifier(const char *name) {
    assert(!std::strcmp(name,"com.apple.iokit.IOGPUFamily"));return scenario==1?-42:0;
}
static void native_adreno_accelerator_static_init() {++initializers;}
static unsigned native_adreno_accelerator_instance_size() {assert(postCalls==1);return scenario==7?144:136;}
struct IOService {
    bool initialized=false,attached=false,external=false;
    unsigned properties=0;
    explicit IOService(bool outside=false):external(outside) {if(!outside)++allocations;}
    bool init() {assert(!initialized);initialized=scenario!=9;return initialized;}
    bool setProperty(const char *key,const char *value) {
        assert(initialized && !attached && properties<3);
        const char *names[]={"MetalPluginName","MetalPluginClassName","NativeSandboxGrantProcess"};
        const char *values[]={"NativeAdrenoMetal","NativeAdrenoMetalDevice","backboardd,iconservicesagent,WidgetRenderer_Default,PosterBoard"};
        assert(!std::strcmp(key,names[properties]) && !std::strcmp(value,values[properties]));
        ++propertyCalls;
        if(scenario==10+properties)return false;
        ++properties;return true;
    }
    static IOService *getPlatform() {static IOService platform(true);return scenario==14?nullptr:&platform;}
    bool attach(IOService *provider) {
        assert(initialized && properties==3 && !attached);++attachCalls;
        if(scenario==13 || !provider)return false;
        attached=true;return true;
    }
    void registerService() {assert(initialized && attached && properties==3);++registrations;}
    void release() {assert(!external && !attached);++releases;delete this;}
};
static IOService *lastService;
static IOService *native_adreno_accelerator_allocate() {
    assert(postCalls==1 && initializers==1);
    lastService=scenario==8?nullptr:new IOService;return lastService;
}

#include "PaganiGpuMetal.inc"

int main(int argc,char **argv) {
    assert(argc==2);scenario=unsigned(std::strtoul(argv[1],nullptr,10));assert(scenario<15);
    const int result=metal();assert(result==(scenario==0?0:scenario==1?-42:-1));
    assert(allocations==unsigned(scenario==0 || scenario>=9));
    assert(registrations==unsigned(scenario==0));
    assert(releases==unsigned(scenario>=9));
    if(scenario==0) {assert(lastService);lastService->attached=false;lastService->release();}
    if(scenario>=10 && scenario<=12)assert(propertyCalls==scenario-9 && !attachCalls);
    if(scenario==13 || scenario==14)assert(propertyCalls==3 && attachCalls==1);
    return 0;
}
