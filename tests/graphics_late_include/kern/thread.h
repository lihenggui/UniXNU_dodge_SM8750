#pragma once
using wait_result_t=int;
using kern_return_t=int;
using thread_t=void *;
using thread_continue_t=void (*)(void *,wait_result_t);
constexpr thread_t THREAD_NULL=nullptr;
constexpr kern_return_t KERN_SUCCESS=0;
kern_return_t kernel_thread_start(thread_continue_t,void *,thread_t *);
void thread_deallocate(thread_t);
thread_t current_thread();
kern_return_t thread_terminate(thread_t);
