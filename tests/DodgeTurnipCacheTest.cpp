// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <vector>
#include <pthread.h>
#include "NativeAdrenoABI.h"

using VkResult = int;
using VkMemoryPropertyFlags = unsigned;
constexpr VkResult VK_SUCCESS=0, VK_ERROR_DEVICE_LOST=-4, VK_ERROR_OUT_OF_DEVICE_MEMORY=-2;
constexpr int KERN_SUCCESS=0;
using kern_return_t=int;
struct vk_device {};
struct vk_object_base { vk_device *device; };
struct vk_pipeline_cache_object { uint32_t key; std::atomic<unsigned> references{1}; };
struct tu_shader { vk_pipeline_cache_object base; explicit tu_shader(uint32_t key):base{key,1} {} };
struct vk_pipeline_cache { vk_object_base base; std::mutex lock; std::map<uint32_t,vk_pipeline_cache_object *> entries; };
static int tu_shader_ops;
static std::atomic<unsigned> destroyed;
static vk_pipeline_cache_object *vk_pipeline_cache_object_ref(vk_pipeline_cache_object *object) {
    ++object->references;return object;
}
static void vk_pipeline_cache_object_unref(vk_device *,vk_pipeline_cache_object *object) {
    if (--object->references==0) { ++destroyed;delete reinterpret_cast<tu_shader *>(object); }
}
static vk_pipeline_cache_object *vk_pipeline_cache_lookup_object(vk_pipeline_cache *cache,const void *key,size_t bytes,
    const int *,bool *hit) {
    assert(bytes==sizeof(uint32_t));uint32_t value;std::memcpy(&value,key,bytes);
    std::lock_guard<std::mutex> guard(cache->lock);auto found=cache->entries.find(value);
    if(hit)*hit=found!=cache->entries.end();
    return found==cache->entries.end()?nullptr:vk_pipeline_cache_object_ref(found->second);
}
static vk_pipeline_cache_object *vk_pipeline_cache_add_object(vk_pipeline_cache *cache,vk_pipeline_cache_object *object) {
    std::lock_guard<std::mutex> guard(cache->lock);auto [at,inserted]=cache->entries.emplace(object->key,object);
    auto *result=vk_pipeline_cache_object_ref(at->second);
    if(!inserted)vk_pipeline_cache_object_unref(cache->base.device,object);
    return inserted?object:result;
}
static void clear(vk_pipeline_cache &cache) {
    for(auto [key,object]:cache.entries) { (void)key;vk_pipeline_cache_object_unref(cache.base.device,object); }
    cache.entries.clear();
}
#define container_of(pointer,type,field) reinterpret_cast<type *>(reinterpret_cast<char *>(pointer)-offsetof(type,field))
enum tu_bo_alloc_flags { TU_BO_ALLOC_NO_FLAGS=0, TU_BO_ALLOC_REPLAYABLE=1, TU_BO_ALLOC_GPU_READ_ONLY=2,
    TU_BO_ALLOC_INTERNAL_RESOURCE=4, TU_BO_ALLOC_IMPLICIT_SYNC=8 };
struct tu_sparse_vma { struct { uint64_t iova;bool backs_lazy_bo; } msm; };
struct tu_bo {
    uint32_t gem_handle;uint64_t size,iova;const char *name;unsigned refcnt;bool implicit_sync;vk_object_base *base;uint64_t unique_id;
    uint64_t darwin_handle,darwin_alloc_size;bool darwin_read_only;void *map;uint32_t darwin_token;bool never_unmap,lazy;
};
struct darwin_cached_bo { uint64_t handle=41,iova=0x800000,size=8192;void *mapping=nullptr;uint32_t token=23; };
struct darwin_retire_state {
    pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;unsigned count=0;VkResult failure=VK_SUCCESS;
    bool cached=false,produce=false,reapFailure=false;darwin_cached_bo hit{};
    unsigned gets=0,reaps=0,trims=0,flushes=0;
};
struct tu_device { vk_device vk;vk_pipeline_cache *mem_cache=nullptr;void *darwin_retire=nullptr;tu_bo bo{}; };
static unsigned allocs,maps,iovaAllocs,iovaFrees,mapFailures;
static bool allocFailOnce,mapFail;static VkResult fenceResult;
#define MESA_TRACE_FUNC() ((void)0)
#define TU_RMV(...) ((void)0)
static bool debug_get_bool_option(const char *,bool value) { return value; }
static uint64_t darwin_size_class(uint64_t size) { return (size+8191)&~UINT64_C(8191); }
static bool darwin_cache_get(darwin_retire_state *retire,uint64_t size,bool,bool,darwin_cached_bo *out) {
    ++retire->gets;if(!retire->cached || retire->hit.size<size)return false;
    *out=retire->hit;retire->cached=false;return true;
}
static VkResult darwin_reap_locked(tu_device *,darwin_retire_state *retire) {
    assert(pthread_mutex_trylock(&retire->lock)!=0);++retire->reaps;
    if(retire->reapFailure)return retire->failure=VK_ERROR_DEVICE_LOST;
    if(retire->failure)return retire->failure;
    if(retire->produce)retire->cached=true;
    retire->count=0;return VK_SUCCESS;
}
static void darwin_cache_trim(tu_device *,darwin_retire_state *retire) { ++retire->trims; }
static bool darwin_cache_flush(tu_device *,darwin_retire_state *retire) {
    ++retire->flushes;bool any=retire->cached;retire->cached=false;return any;
}
static VkResult darwin_allocate_iova(tu_device *,uint64_t,uint64_t,tu_bo_alloc_flags,uint64_t *out) {
    ++iovaAllocs;*out=0x900000;return VK_SUCCESS;
}
static void darwin_free_iova(tu_device *,uint64_t,uint64_t) { ++iovaFrees; }
static kern_return_t dw_call(unsigned method,const void *,size_t,void *output,size_t) {
    if(method==NativeAdrenoMethodBoAlloc) {
        ++allocs;if(allocFailOnce){allocFailOnce=false;return -1;}
        static_cast<NativeAdrenoAbiBoAllocReply *>(output)->handle=81;return KERN_SUCCESS;
    }
    assert(method==NativeAdrenoMethodBoMap);++maps;return mapFail?-1:KERN_SUCCESS;
}
static VkResult vk_errorf(tu_device *,VkResult result,const char *,int) { return result; }
static VkResult darwin_map_failure(tu_device *,uint64_t,uint64_t,uint64_t,kern_return_t,bool) {
    ++mapFailures;return VK_ERROR_DEVICE_LOST;
}
static tu_bo *tu_device_lookup_bo(tu_device *device,uint32_t) { return &device->bo; }
static const char *tu_debug_bos_add(tu_device *,uint64_t,const char *name) { return name; }
static void tu_dump_bo_init(tu_device *,tu_bo *) {}
static VkResult dw_wait_fence_raw(tu_device *,uint32_t,uint64_t) { return fenceResult; }
static VkResult darwin_collect_retired(tu_device *,bool=false);
#include "TurnipCache.inc"

struct Fixture {
    darwin_retire_state retire;tu_device device{};tu_bo *output=nullptr;
    Fixture() { device.darwin_retire=&retire;allocs=maps=iovaAllocs=iovaFrees=mapFailures=0;allocFailOnce=mapFail=false;fenceResult=VK_SUCCESS; }
    ~Fixture() { pthread_mutex_destroy(&retire.lock); }
    VkResult allocate(tu_bo_alloc_flags flags=TU_BO_ALLOC_NO_FLAGS,tu_sparse_vma *lazy=nullptr,uint64_t bytes=4096) {
        return darwin_bo_init(&device,nullptr,&output,bytes,0,0,flags,lazy,"test");
    }
};
int main() {
    unsigned cases=0;
    {
        Fixture f;f.retire.cached=true;f.retire.count=7;
        assert(f.allocate()==VK_SUCCESS && f.output->darwin_handle==41 && f.retire.count==7);
        assert(f.retire.gets==1 && f.retire.reaps==0 && allocs==0 && maps==0);++cases;
    }
    {
        Fixture f;f.retire.count=1;f.retire.produce=true;
        assert(f.allocate()==VK_SUCCESS && f.retire.gets==2 && f.retire.reaps==1 && f.retire.trims==1 && allocs==0);++cases;
    }
    {
        Fixture f;assert(f.allocate()==VK_SUCCESS && f.retire.gets==1 && f.retire.reaps==0 && allocs==1 && maps==1);++cases;
    }
    {
        Fixture f;f.retire.cached=true;f.retire.failure=VK_ERROR_DEVICE_LOST;
        assert(f.allocate()==VK_ERROR_DEVICE_LOST && !f.output && f.retire.cached && !f.retire.gets && !allocs);++cases;
    }
    {
        Fixture f;f.retire.count=1;f.retire.reapFailure=true;
        assert(f.allocate()==VK_ERROR_DEVICE_LOST && !f.output && f.retire.gets==1 && !allocs);++cases;
    }
    {
        Fixture f;f.retire.cached=true;
        assert(f.allocate(TU_BO_ALLOC_REPLAYABLE)==VK_SUCCESS && f.retire.reaps==1 && !f.retire.gets && allocs==1);
        assert(f.output->darwin_alloc_size==0);++cases;
    }
    {
        Fixture f;tu_sparse_vma vma{{0x770000,false}};f.retire.cached=true;
        assert(f.allocate(TU_BO_ALLOC_NO_FLAGS,&vma)==VK_SUCCESS && !iovaAllocs && vma.msm.backs_lazy_bo && f.output->lazy);
        assert(f.retire.reaps==1 && !f.retire.gets);++cases;
    }
    {
        Fixture f;f.retire.cached=true;f.retire.hit.size=2048;allocFailOnce=true;
        assert(f.allocate()==VK_SUCCESS && allocs==2 && iovaAllocs==2 && iovaFrees==1 && f.retire.flushes==1);++cases;
    }
    {
        Fixture f;mapFail=true;assert(f.allocate()==VK_ERROR_DEVICE_LOST && !f.output && mapFailures==1);++cases;
    }
    {
        Fixture f;std::array<uint8_t,8192> bytes;bytes.fill(0x7f);f.retire.cached=true;f.retire.hit.mapping=bytes.data();
        assert(f.allocate(TU_BO_ALLOC_INTERNAL_RESOURCE)==VK_SUCCESS && f.output->never_unmap && f.output->darwin_token==23);
        for(size_t i=0;i<bytes.size();++i)assert(bytes[i]==(i<4096?0:0x7f));++cases;
    }
    {
        Fixture f;pthread_mutex_lock(&f.retire.lock);
        assert(darwin_collect_retired(&f.device,true)==VK_SUCCESS && f.retire.reaps==0);
        pthread_mutex_unlock(&f.retire.lock);
        assert(darwin_collect_retired(&f.device)==VK_SUCCESS && f.retire.reaps==1);++cases;
    }
    {
        Fixture f;pthread_mutex_lock(&f.retire.lock);
        assert(dw_wait_fence_locked_free(&f.device,1,0)==VK_SUCCESS && !f.retire.reaps);
        pthread_mutex_unlock(&f.retire.lock);++cases;
    }
    {
        Fixture f;fenceResult=VK_ERROR_DEVICE_LOST;
        assert(dw_wait_fence_locked_free(&f.device,1,0)==VK_ERROR_DEVICE_LOST && !f.retire.reaps);++cases;
    }
    {
        tu_device device{};vk_pipeline_cache memory{{&device.vk},{},{}},a{{&device.vk},{},{}},b{{&device.vk},{},{}};
        device.mem_cache=&memory;uint32_t key=91;bool hit=true;auto *shader=new tu_shader(key);
        assert(tu_pipeline_cache_insert(&a,shader)==shader && shader->base.references==3);++cases;
        auto *shared=tu_pipeline_cache_lookup(&b,&key,sizeof(key),&hit);
        assert(shared==shader && !hit && b.entries.size()==1);vk_pipeline_cache_object_unref(&device.vk,&shared->base);++cases;
        shared=tu_pipeline_cache_lookup(&b,&key,sizeof(key),&hit);
        assert(shared==shader && hit);vk_pipeline_cache_object_unref(&device.vk,&shared->base);++cases;
        clear(a);vk_pipeline_cache_object_unref(&device.vk,&shader->base);
        shared=tu_pipeline_cache_lookup(&memory,&key,sizeof(key),nullptr);assert(shared);
        vk_pipeline_cache_object_unref(&device.vk,&shared->base);clear(b);clear(memory);assert(destroyed==1);++cases;
    }
    {
        tu_device a{},b{};vk_pipeline_cache ma{{&a.vk},{},{}},mb{{&b.vk},{},{}},client{{&b.vk},{},{}};
        a.mem_cache=&ma;b.mem_cache=&mb;auto *shader=new tu_shader(7);tu_pipeline_cache_insert(&ma,shader);
        uint32_t key=7;bool hit=true;assert(!tu_pipeline_cache_lookup(&client,&key,sizeof(key),&hit) && !hit);
        vk_pipeline_cache_object_unref(&a.vk,&shader->base);clear(ma);++cases;
    }
    {
        tu_device device{};vk_pipeline_cache memory{{&device.vk},{},{}};device.mem_cache=&memory;
        std::vector<std::thread> threads;
        for(unsigned index=0;index<8;++index)threads.emplace_back([&]{
            vk_pipeline_cache local{{&device.vk},{},{}};uint32_t key=3;
            auto *shader=tu_pipeline_cache_insert(&local,new tu_shader(key));vk_pipeline_cache_object_unref(&device.vk,&shader->base);
            for(unsigned n=0;n<100;++n) {
                auto *found=tu_pipeline_cache_lookup(&local,&key,sizeof(key),nullptr);assert(found);
                vk_pipeline_cache_object_unref(&device.vk,&found->base);
            }
            clear(local);
        });
        for(auto &thread:threads)thread.join();assert(memory.entries.size()==1);clear(memory);++cases;
    }
    assert(cases==19 && destroyed==10);
    std::printf("{\"cases\":%u,\"retirement\":13,\"shader_cache\":6,\"concurrent_lookups\":800}\n",cases);
}
