// SPDX-License-Identifier: MIT
#pragma once
#include "DodgeSurfacePages.h"
#include "OriginalIOSurfaceSyncABI.h"
#include <libkern/c++/OSObject.h>
#include <vector>
#include <atomic>

struct DodgeTestTicket : OSObject {
    OSObject *surface;
    IPhone16SurfaceSyncCallback callback;
    void *target,*context;
    bool granted=false,signalled=false,released=false;
    int32_t result=0;
    void release() override;
};
extern std::vector<DodgeTestTicket *> dodge_test_tickets;
extern bool dodge_test_grant_immediately,dodge_test_pages_current,dodge_test_register_failure;
extern int32_t dodge_test_signal_error;
extern unsigned dodge_test_signal_calls;
extern std::atomic_uint dodge_test_schedules,dodge_test_epoch;
extern void (*dodge_test_signal_check)(void *);
extern void *dodge_test_signal_context;
void dodge_test_grant_pending(int32_t status=0);
void dodge_test_clear_tickets();
