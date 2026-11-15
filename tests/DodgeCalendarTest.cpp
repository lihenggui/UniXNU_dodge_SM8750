// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeCalendar.h"
#include <assert.h>
#include <stdio.h>
#include <string>

extern "C" const char version[] = "Darwin Kernel Version 22.6.0: Fri Nov 13 23:58:59 PST 2026; root:xnu-8796.141.3/DEVELOPMENT_ARM64";
class ArmDTPlatform {
public:
    long getGMTTimeOfDay();
    void setGMTTimeOfDay(long);
};
#include "DodgePlatformClock.inc"
static uint64_t clockValue, setValue;
static int clockResult;
static unsigned setCalls;
static int readClock(uint64_t *out) { *out = clockValue;return clockResult; }
static void setClock(uint64_t seconds) { setValue = seconds;++setCalls; }

int main() {
    const std::string good = "Darwin Kernel Version 22.6.0: Fri Nov 13 23:58:59 PST 2026; root:xnu-8796.141.3/DEVELOPMENT_ARM64";
    assert(dodge_calendar_version_seconds(good.c_str()) == UINT64_C(1794614339));
    assert(dodge_calendar_floor(good.c_str()) == UINT64_C(1794527939));
    assert(dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Thu Feb 29 00:00:00 UTC 2024; root:xnu") == UINT64_C(1709164800));
    assert(!dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Wed Feb 29 00:00:00 UTC 2023; root:xnu"));
    assert(dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Wed Jan  1 00:00:00 UTC 2025; root:xnu") == UINT64_C(1735689600));
    assert(!dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Thu Apr 31 00:00:00 UTC 2025; root:xnu"));
    assert(!dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Thu Jan 01 24:00:00 UTC 2025; root:xnu"));
    assert(!dodge_calendar_version_seconds("Darwin Kernel Version 22.6.0: Thu Jan 01 00:60:00 UTC 2025; root:xnu"));
    assert(!dodge_calendar_version_seconds(nullptr));
    unsigned cases = 9;
    const size_t terminator = good.find(';');
    for (size_t n = 0; n <= terminator; ++n) {
        const auto shortText = good.substr(0, n);
        assert(!dodge_calendar_version_seconds(shortText.c_str()));++cases;
    }
    for (size_t n = 0; n < 514; ++n) {
        const std::string text(n, 'x');
        assert(!dodge_calendar_version_seconds(text.c_str()));++cases;
    }
    assert(!dodge_calendar_read_usable(0, 0));
    assert(!dodge_calendar_read_usable(99, 100));
    assert(dodge_calendar_read_usable(100, 100));
    assert(dodge_calendar_read_usable(UINT64_C(253402300799), 100));
    assert(!dodge_calendar_read_usable(UINT64_C(253402300800), 100));
    assert(!dodge_calendar_read_usable(UINT64_MAX, 100));cases += 6;
    ArmDTPlatform platform;
    const uint64_t floor = dodge_calendar_floor(version);
    assert(uint64_t(platform.getGMTTimeOfDay()) == floor);++cases;
    armdt_platform_clock_register(readClock, setClock);
    clockValue = floor + 3600;
    assert(uint64_t(platform.getGMTTimeOfDay()) == clockValue);++cases;
    clockResult = 1;assert(uint64_t(platform.getGMTTimeOfDay()) == floor);++cases;
    clockResult = 0;clockValue = floor - 1;assert(uint64_t(platform.getGMTTimeOfDay()) == floor);++cases;
    clockValue = UINT64_MAX;assert(uint64_t(platform.getGMTTimeOfDay()) == floor);++cases;
    platform.setGMTTimeOfDay(-1);platform.setGMTTimeOfDay(0);assert(!setCalls);++cases;
    platform.setGMTTimeOfDay(long(floor + 86400));assert(setCalls == 1 && setValue == floor + 86400);++cases;
    platform.setGMTTimeOfDay(long(UINT64_C(253402300800)));assert(setCalls == 1);++cases;
    armdt_platform_clock_register(nullptr, nullptr);
    assert(uint64_t(platform.getGMTTimeOfDay()) == floor);++cases;
    platform.setGMTTimeOfDay(long(floor));assert(setCalls == 1);++cases;
    printf("PASS: %u calendar parsing, truncation and clock-range cases\n", cases);
}
