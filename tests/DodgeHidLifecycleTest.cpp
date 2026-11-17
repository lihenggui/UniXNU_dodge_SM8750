// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>
#include "HidDriverSource.inc"

extern "C" {
kmod_info_t g_kernel_kmod_info={"__kernel__"};
const unsigned char dodge_original_hid_event_vtable[16]={};
void hid_test_initializer() asm("__GLOBAL__sub_I_DodgeHidEventDriver.cpp");
void hid_test_initializer(){}
}
using namespace std::chrono_literals;

__attribute__((noinline)) static bool requestTermination(DodgeHidEventDriver *driver,IOService *provider,unsigned options){
    const bool opened=provider->isOpen(driver);bool deferred=false;
    assert(driver->didTerminate(provider,options,&deferred));
    assert(!opened || !deferred);return opened || deferred;
}

int main(int argc,char **argv){
    assert(argc==2);const std::string name=argv[1];auto &h=hid_peer::state;
    IOWorkLoop loop;IOService provider,foreign;IOHIDEvent event;
    h.loop=&loop;
    auto driver=std::make_unique<DodgeHidEventDriver>();
    auto dispatch=[&]{driver->dispatchEvent(&event,0x80000001);};
    auto stop=[&]{driver->stop(&provider);};
    auto start=[&]{const bool ok=driver->start(&provider);loop.drain();return ok;};
    if(name=="init-failure")h.initOk=false;
    if(name=="free-untouched"){
        driver->free();assert(h.nativeFrees==1 && !h.inits);
    }else{
        assert(driver->init()==h.initOk && h.inits==1 && driver->retainCount()==2);
        if(name=="init-failure"){
            assert(!start() && !h.starts);stop();driver->free();assert(!h.stops && !h.nativeFrees);
        }else if(name=="init-repeat"){
            assert(!driver->init() && h.inits==1);
            auto duplicate=std::make_unique<DodgeHidEventDriver>();assert(!duplicate->init());duplicate->free();
            assert(duplicate->retainCount()==1 && h.nativeFrees==1);
        }else if(name=="stop-before-start"){
            stop();assert(!start() && !h.starts && !h.stops && provider.retainCount()==1);
        }else if(name=="null-start"){
            assert(!driver->start(nullptr) && !h.starts);
        }else if(name=="wrong-provider"){
            h.validProvider=false;assert(!start() && !h.starts && provider.retainCount()==1);
        }else if(name=="no-loop"){
            h.loop=nullptr;assert(!start() && !h.starts);stop();assert(!h.stops);
        }else if(name=="start-busy-interface"){
            provider.openedClient=&foreign;
            assert(!start() && !h.starts && "busy interface was started");
            stop();assert(requestTermination(driver.get(),&provider,0xa5000012));loop.drain();
            assert(provider.isOpen(&foreign) && !h.interfaceCloses && !h.originalDidCalls && !h.stops && h.nativeDidCalls==1);
        }else if(name=="cleanup-allocation-failure" || name=="cleanup-attach-failure"){
            h.cleanupOk=name!="cleanup-allocation-failure";h.addOk=name!="cleanup-attach-failure";
            assert(!start() && !h.starts);stop();dispatch();assert(!h.stops && !h.forwards && !h.cleanupSignals);
            for(auto &allocation:hid_peer::allocations)assert(allocation->retainCount()==0);
        }else if(name=="producer-concurrent-stop"){
            assert(start());std::mutex mutex;std::condition_variable condition;bool entered=false,waiting=false,resume=false;
            h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){
                std::unique_lock<std::mutex> lock(mutex);entered=true;condition.notify_all();
                assert(condition.wait_for(lock,2s,[&]{return resume;}));
            };
            std::function<void()> callback=[&]{++h.activeProducer;dispatch();assert(!h.stops && !h.interfaceCloses);--h.activeProducer;};
            std::thread producer([&]{loop.runAction([](OSObject *,void *argument,void *,void *,void *){
                (*static_cast<std::function<void()> *>(argument))();return kIOReturnSuccess;
            },driver.get(),&callback);});
            {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return entered;}));}
            h.beforeGate=[&]{std::lock_guard<std::mutex> lock(mutex);waiting=true;condition.notify_all();};
            std::thread stopper(stop);
            {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return waiting;}));resume=true;condition.notify_all();}
            producer.join();stopper.join();h.beforeGate={};h.onDispatch={};loop.drain();
            assert(h.stops==1 && h.interfaceCloses==1 && h.cleanupSignals==1 && h.cleanupCallbacks==1);
        }else if(name=="interface-close-reentry" || name=="interface-foreign-client"){
            assert(start());
            if(name=="interface-close-reentry")h.onClose=[&]{stop();dispatch();};
            else{
                std::function<void()> close=[&]{provider.close(driver.get());provider.openedClient=&foreign;};
                loop.runAction([](OSObject *,void *argument,void *,void *,void *){
                    (*static_cast<std::function<void()> *>(argument))();return kIOReturnSuccess;
                },driver.get(),&close);
            }
            stop();loop.drain();assert(h.stops==1 && h.interfaceCloses==1);
            if(name=="interface-foreign-client"){
                assert(provider.isOpen(&foreign));assert(requestTermination(driver.get(),&provider,0xa5000011));
                loop.drain();assert(provider.isOpen(&foreign) && h.interfaceCloses==1 && !h.originalDidCalls && h.nativeDidCalls==1);
            }
        }else if(name.rfind("will-",0)==0){
            constexpr unsigned options=0xa5000001;
            if(name=="will-before-start"){
                assert(driver->willTerminate(&provider,options));assert(!start() && h.nativeWillCalls==1 && !h.starts && !h.stops);
            }else{
                h.willOk=name!="will-parent-failure";
                if(name=="will-start")h.onStart=[&](IOService *){assert(driver->willTerminate(&provider,options));};
                assert(start()==(name!="will-start"));
                if(name=="will-dispatch"){
                    h.onWill=dispatch;h.onDispatch=[&,requested=false](IOService *,IOHIDEvent *,unsigned)mutable{
                        if(!requested){requested=true;assert(driver->willTerminate(&provider,options));}
                        assert(h.forwards==1 && "termination admitted event dispatch");
                    };dispatch();
                }else if(name!="will-start"){
                    const bool result=driver->willTerminate(name=="will-foreign"?&foreign:&provider,options);
                    assert(result==(name!="will-foreign" && name!="will-parent-failure"));
                }
                if(name=="will-foreign"){dispatch();assert(h.forwards==1 && !h.nativeWillCalls);}
                else{dispatch();assert(h.forwards==(name=="will-dispatch"?1u:0u) && h.nativeWillCalls==1);}
                stop();loop.drain();assert(h.stops==1 && h.interfaceCloses==1);
            }
        }else if(name.rfind("did-",0)==0){
            constexpr unsigned options=0xa5000002;
            if(name=="did-no-loop"){
                assert(!requestTermination(driver.get(),&provider,options));assert(!start() && h.nativeDidCalls==1 && !h.starts);
            }else{
                if(name=="did-cleanup-failure")h.cleanupOk=false;
                if(name=="did-start")h.onStart=[&](IOService *){assert(requestTermination(driver.get(),&provider,options));};
                assert(start()==(name!="did-start" && name!="did-cleanup-failure"));
                if(name=="did-foreign" || name=="did-null-output"){
                    bool deferred=false;
                    assert(!driver->didTerminate(name=="did-foreign"?&foreign:&provider,options,name=="did-null-output"?nullptr:&deferred));
                    assert(!deferred && !h.nativeDidCalls);dispatch();assert(h.forwards==1);stop();
                }else if(name=="did-start"){
                    assert(h.nativeDidCalls==1 && h.originalDidCalls==1 && h.stops==1);
                }else{
                    if(name=="did-after-stop")stop();
                    if(name=="did-reentrant-notify")h.onDid=[&]{assert(requestTermination(driver.get(),&provider,0xffffffff));};
                    if(name=="did-during-stop" || name=="did-during-close"){
                        auto request=[&]{assert(requestTermination(driver.get(),&provider,options));};
                        if(name=="did-during-stop")h.onStop=[request](IOService *){request();};else h.onClose=request;
                        stop();
                    }else if(name=="did-producer"){
                        h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){assert(requestTermination(driver.get(),&provider,options));};
                        std::function<void()> callback=[&]{++h.activeProducer;dispatch();assert(!h.nativeDidCalls && !h.stops);--h.activeProducer;};
                        loop.runAction([](OSObject *,void *argument,void *,void *,void *){
                            (*static_cast<std::function<void()> *>(argument))();return kIOReturnSuccess;
                        },driver.get(),&callback);
                    }else{
                        const bool expected=name!="did-cleanup-failure";
                        assert(requestTermination(driver.get(),&provider,options)==expected);
                        if(name=="did-repeat")assert(requestTermination(driver.get(),&provider,0xa5000003));
                    }
                    loop.drain();assert(h.nativeDidCalls==1 && h.didOptions[0]==options && !h.didDeferred[0]);
                    if(name!="did-cleanup-failure")assert(h.stops==1 && h.interfaceCloses==1);
                    if(name=="did-after-stop" || name=="did-during-stop" || name=="did-during-close" || name=="did-cleanup-failure")assert(!h.originalDidCalls);
                    if(name=="did-repeat"){
                        assert(requestTermination(driver.get(),&provider,0xa5000004));loop.drain();
                        assert(h.nativeDidCalls==2 && h.originalDidCalls==1 && h.interfaceCloses==1 && h.stops==1);
                    }
                }
                const unsigned before=h.forwards;dispatch();loop.drain();assert(h.forwards==before);
            }
        }else if(name.rfind("producer-",0)==0){
            const bool duringStart=name=="producer-start-stop" || name=="producer-start-failure";
            if(name=="producer-start-stop")h.onStart=[&](IOService *){stop();};
            if(name=="producer-start-failure")h.startOk=false;
            if(!duringStart)assert(start());
            if(name=="producer-reentrant-stop" || name=="producer-external-stop")
                h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){stop();};
            if(name=="producer-nested-dispatch")
                h.onDispatch=[&,nested=0u](IOService *,IOHIDEvent *,unsigned)mutable{if(!nested++)dispatch();else stop();};
            std::function<void()> callback=[&]{
                ++h.activeProducer;
                if(duringStart)assert(!driver->start(&provider));else dispatch();
                if(name=="producer-stop-tail")stop();
                assert(!h.stops);stop();assert(!h.stops);dispatch();
                --h.activeProducer;
            };
            loop.runAction([](OSObject *,void *argument,void *,void *,void *){
                (*static_cast<std::function<void()> *>(argument))();return kIOReturnSuccess;
            },driver.get(),&callback);
            assert(!h.stops && h.cleanupSignals==1);
            if(name=="producer-external-stop"){stop();assert(h.stops==1);}
            loop.drain();assert(h.stops==1 && h.cleanupCallbacks==1);
            stop();dispatch();loop.drain();assert(h.stops==1 && h.cleanupSignals==1);
        }else if(name=="concurrent-starts"){
            std::atomic<unsigned> successes{0};std::vector<std::thread> starters;
            for(unsigned i=0;i<4;++i)starters.emplace_back([&]{if(start())++successes;});
            for(auto &thread:starters)thread.join();
            assert(successes==1 && h.starts==1);stop();dispatch();assert(h.stops==1 && !h.forwards);
            assert(loop.retainCount()==2 && provider.retainCount()==2);
        }else if(name=="concurrent-start-stop"){
            std::mutex mutex;std::condition_variable condition;bool entered=false,queued=false,release=false;
            h.onStart=[&](IOService *){
                std::unique_lock<std::mutex> lock(mutex);entered=true;condition.notify_all();
                assert(condition.wait_for(lock,2s,[&]{return release;}));assert(!h.stops);
            };
            std::atomic<bool> succeeded{true};std::thread starter([&]{succeeded=start();});
            {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return entered;}));}
            h.beforeGate=[&]{std::lock_guard<std::mutex> lock(mutex);queued=true;condition.notify_all();};
            std::thread stopper(stop);
            {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return queued;}));release=true;condition.notify_all();}
            starter.join();stopper.join();h.beforeGate={};h.onStart={};
            assert(!succeeded && h.starts==1 && h.stops==1);dispatch();assert(!h.forwards);
            assert(loop.retainCount()==2 && provider.retainCount()==2);
        }else{
            if(name=="bad-geometry")h.video.v_width=96;
            if(name=="rotated")h.video.v_rotate=1;
            if(name=="video-error")h.videoOk=false;
            if(name=="start-parent-failure")h.startOk=false;
            if(name=="stop-during-video")h.onVideo=[&](IOService *){stop();};
            if(name=="start-reentrant-stop" || name=="start-reentrant-stop-twice" || name=="start-failure-reentrant-stop"){
                if(name=="start-failure-reentrant-stop")h.startOk=false;
                h.onStart=[&](IOService *){stop();if(name=="start-reentrant-stop-twice")stop();dispatch();};
            }
            if(name=="start-event-stop"){
                h.onStart=[&](IOService *){dispatch();};h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){stop();};
            }
            if(name=="stop-parent-reentry")h.onStop=[&](IOService *){stop();dispatch();};
            if(name=="original-control")h.requireStartGate=false;
            const bool wanted=name!="bad-geometry" && name!="rotated" && name!="video-error" && name!="stop-during-video" &&
                name!="start-parent-failure" && name!="start-reentrant-stop" && name!="start-reentrant-stop-twice" &&
                name!="start-failure-reentrant-stop" && name!="start-event-stop";
            assert(start()==wanted);
            const unsigned before=h.starts;assert(!start() && h.starts==before);
            if(!wanted){
                const bool entered=name=="start-parent-failure" || name=="start-reentrant-stop" || name=="start-reentrant-stop-twice" ||
                    name=="start-failure-reentrant-stop" || name=="start-event-stop";
                assert(h.stops==unsigned(entered));stop();dispatch();assert(h.stops==unsigned(entered));
            }else if(name=="concurrent-dispatch-stop" || name=="concurrent-stops"){
                std::mutex mutex;std::condition_variable condition;bool entered=false,release=false,stopping=false;
                h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){
                    std::unique_lock<std::mutex> lock(mutex);entered=true;condition.notify_all();
                    assert(condition.wait_for(lock,2s,[&]{return release;}));assert(!h.stops);
                };
                std::thread producer(dispatch);
                {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return entered;}));}
                h.beforeGate=[&]{std::lock_guard<std::mutex> lock(mutex);stopping=true;condition.notify_all();};
                std::vector<std::thread> stoppers;
                for(unsigned i=0;i<(name=="concurrent-stops" ? 4u:1u);++i)stoppers.emplace_back([&]{
                    stop();
                });
                {std::unique_lock<std::mutex> lock(mutex);assert(condition.wait_for(lock,2s,[&]{return stopping;}));}
                dispatch();assert(h.forwards==1); // Admission closes while stop is waiting for the active callback.
                {std::lock_guard<std::mutex> lock(mutex);release=true;condition.notify_all();}
                producer.join();for(auto &thread:stoppers)thread.join();assert(h.forwards==1 && h.stops==1);
                h.beforeGate={};h.onDispatch={};
            }else{
                if(name=="dispatch-reentrant-stop" || name=="dispatch-reentrant-stop-twice" || name=="original-control"){
                    h.onDispatch=[&](IOService *,IOHIDEvent *,unsigned){stop();if(name=="dispatch-reentrant-stop-twice")stop();dispatch();};
                }
                if(name=="nested-dispatch-stop"){
                    h.onDispatch=[&,nested=0u](IOService *,IOHIDEvent *,unsigned)mutable{if(!nested++){dispatch();}else stop();};
                }
                if(name=="foreign-stop"){driver->stop(&foreign);assert(!h.stops);}
                if(name=="null-stop"){driver->stop(nullptr);assert(!h.stops);}
                if(name=="inactive"){driver->inactive=true;dispatch();assert(!h.forwards);driver->inactive=false;}
                if(name=="null-event"){driver->dispatchEvent(nullptr,0);assert(!h.forwards);}
                dispatch();assert(h.forwards==(name=="nested-dispatch-stop" ? 2u:1u));
                stop();stop();assert(h.stops==1);
            }
            const unsigned forwards=h.forwards;dispatch();assert(h.forwards==forwards);
            assert(!h.activeStart && !h.activeDispatch);
            assert(loop.retainCount()==2 && provider.retainCount()==2);
        }
        // Existing partial-init quarantine is deliberately preserved.
        driver->free();assert(h.nativeFrees==(name=="init-repeat" ? 1u:0u));
    }
    assert(event.retainCount()==1 && foreign.retainCount()==1);
    std::printf("PASS: %s\n",name.c_str());
}
