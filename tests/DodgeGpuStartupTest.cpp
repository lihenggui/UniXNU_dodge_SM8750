// SPDX-License-Identifier: BSD-2-Clause-Patent
// Executes the actual staged entry body; hardware startup/loggers are peers.
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>
static constexpr int kIOReturnBusy=-6;
static constexpr uint32_t NativeAdrenoChipA830=0x44050001;
static struct {bool attempted=false;} g;
static const char *current_stage="GPU start";
static int startup_result=-2;
static std::atomic<unsigned> starts{},logs{},displayCalls{},traceCalls{},arrived{},returned{};
static std::atomic<bool> go{},entered{},unblock{};
static bool concurrent;
static int wanted;
static void displayPeer(const char *,uint64_t) {++displayCalls;}
static void tracePeer() {++traceCalls;}
static void (*boot_progress_display_status)(const char *,uint64_t);
static void (*pagani_gpu_trace_start)();
template<class F> static void dodge_optional_call(F function) {assert(function);function();}
static void IOLog(const char *,...) {++logs;}
static void stage(const char *name,uint64_t chip) {assert(!std::strcmp(name,"GPU Metal registered") && chip==NativeAdrenoChipA830);}
static int start() {
    ++starts;entered.store(true,std::memory_order_release);
    if(concurrent)while(!unblock.load(std::memory_order_acquire))std::this_thread::yield();
    return wanted;
}
#include "PaganiGpuStartup.inc"

int main(int argc,char **argv) {
    assert(argc==2);const char *mode=argv[1];
    concurrent=!std::strncmp(mode,"concurrent-",11);
    wanted=std::strstr(mode,"failure")?-41:0;
    if(!std::strncmp(mode,"callbacks-",10)) {boot_progress_display_status=displayPeer;pagani_gpu_trace_start=tracePeer;}
    if(concurrent) {
        constexpr unsigned count=16;std::vector<int> results(count);std::vector<std::thread> threads;
        for(unsigned i=0;i<count;++i)threads.emplace_back([&,i] {
            ++arrived;while(!go.load(std::memory_order_acquire))std::this_thread::yield();
            results[i]=dodge_gpu_start();++returned;
        });
        while(arrived!=count)std::this_thread::yield();
        go.store(true,std::memory_order_release);
        while(!entered.load(std::memory_order_acquire) || returned!=count-1)std::this_thread::yield();
        assert(starts==1);unblock.store(true,std::memory_order_release);
        for(auto &thread:threads)thread.join();
        unsigned winners=0;
        for(int value:results) {assert(value==wanted || value==kIOReturnBusy);winners+=value==wanted;}
        assert(winners==1);
    } else assert(dodge_gpu_start()==wanted);
    assert(dodge_gpu_start()==kIOReturnBusy && starts==1 && g.attempted);
    assert(__atomic_load_n(&startup_result,__ATOMIC_ACQUIRE)==wanted);
    assert(logs==unsigned(wanted!=0));
    assert(displayCalls==unsigned(wanted && boot_progress_display_status));
    assert(traceCalls==unsigned(!wanted && pagani_gpu_trace_start));
}
