// SPDX-License-Identifier: MIT
#pragma once
#include <mutex>
using IOLock=std::mutex;
inline IOLock *IOLockAlloc() {return new std::mutex;}
inline void IOLockFree(IOLock *p) {delete p;}
inline void IOLockLock(IOLock *p) {p->lock();}
inline bool IOLockTryLock(IOLock *p) {return p->try_lock();}
inline void IOLockUnlock(IOLock *p) {p->unlock();}
