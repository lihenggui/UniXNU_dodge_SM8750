// SPDX-License-Identifier: MIT
// The generated include contains the actual staged Turnip status functions.
#include "NativeAdrenoABI.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
using VkResult=int;
using kern_return_t=int32_t;
constexpr int VK_SUCCESS=0,VK_ERROR_DEVICE_LOST=-4,KERN_SUCCESS=0;
constexpr int32_t kIOReturnUnsupported=int32_t(0xe00002c7u),kIOReturnBusy=int32_t(0xe00002d5u);
constexpr int32_t kIOReturnNotResponding=int32_t(0xe00002edu);
struct vk_device {bool lost=false;};
struct tu_device {vk_device vk;uint64_t fault_count=0;};
static int32_t answer;
static NativeAdrenoAbiStatus counters;
static unsigned calls;
static int32_t dw_call(uint32_t method,const void *in,size_t in_bytes,void *out,size_t out_bytes)
{
    assert(method==NativeAdrenoMethodGetStatus && !in && !in_bytes && out && out_bytes==sizeof(counters));
    ++calls;if(!answer)std::memcpy(out,&counters,sizeof counters);return answer;
}
static VkResult vk_device_set_lost(vk_device *device,const char *,...)
{device->lost=true;return VK_ERROR_DEVICE_LOST;}
#define p_atomic_read(p) __atomic_load_n(p,__ATOMIC_RELAXED)
#define p_atomic_add(p,v) __atomic_fetch_add(p,v,__ATOMIC_RELAXED)
#include "TurnipRecovery.inc"
int main()
{
    tu_device device{};
    assert(!darwin_device_check_status(&device) && !device.vk.lost && !tu_darwin_restarts());
    counters.faults=1;assert(!darwin_device_check_status(&device) && !device.vk.lost && device.fault_count==1);
    assert(tu_darwin_restarts()==1 && !darwin_device_check_status(&device) && tu_darwin_restarts()==1);
    counters.faults=5;assert(!darwin_device_check_status(&device) && tu_darwin_restarts()==5);
    answer=kIOReturnBusy;counters.faults=6;
    assert(!darwin_device_check_status(&device) && !device.vk.lost && device.fault_count==5);
    answer=KERN_SUCCESS;assert(!darwin_device_check_status(&device) && device.fault_count==6 && tu_darwin_restarts()==6);
    answer=kIOReturnUnsupported;assert(!darwin_device_check_status(&device) && !device.vk.lost && device.fault_count==6);
    answer=KERN_SUCCESS;device.fault_count=UINT64_MAX-2;counters.faults=1;
    assert(!darwin_device_check_status(&device) && device.fault_count==1 && tu_darwin_restarts()==10);
    __atomic_store_n(&darwin_restarts,UINT32_MAX-1,__ATOMIC_RELAXED);counters.faults=3;
    assert(!darwin_device_check_status(&device) && !tu_darwin_restarts());
    answer=kIOReturnNotResponding;
    assert(darwin_device_check_status(&device)==VK_ERROR_DEVICE_LOST && device.vk.lost);
    tu_device failed{};answer=-1;
    assert(darwin_device_check_status(&failed)==VK_ERROR_DEVICE_LOST && failed.vk.lost);
    assert(calls==11);
    std::puts("PASS: 11 actual Turnip status calls, counter wrap and terminal transport errors");
}
