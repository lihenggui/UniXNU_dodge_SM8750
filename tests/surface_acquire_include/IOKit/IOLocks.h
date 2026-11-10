// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <mutex>
struct IOLock { std::mutex mutex; };
IOLock *IOLockAlloc();
void IOLockFree(IOLock *);
void IOLockLock(IOLock *);
void IOLockUnlock(IOLock *);
