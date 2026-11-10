// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
extern "C" uint64_t mach_absolute_time(void);
extern "C" void nanoseconds_to_absolutetime(uint64_t,uint64_t *);
