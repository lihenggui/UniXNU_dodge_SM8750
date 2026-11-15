// SPDX-License-Identifier: BSD-2-Clause-Patent
// Darwin 22 backport of UniXNU/ArmDTPlatform's board clock and build-date floor.
extern "C" {
extern const char version[];
volatile uint64_t armdt_platform_clock_floor = 0;
static int (*volatile gClockRead)(uint64_t *);
static void (*volatile gClockSet)(uint64_t);
void armdt_platform_clock_register(int (*read)(uint64_t *), void (*set)(uint64_t)) {
    __atomic_store_n(&gClockSet, set, __ATOMIC_RELEASE);
    __atomic_store_n(&gClockRead, read, __ATOMIC_RELEASE);
}
}

long ArmDTPlatform::getGMTTimeOfDay() {
    const uint64_t floor = dodge_calendar_floor(version);
    armdt_platform_clock_floor = floor;
    uint64_t seconds = 0;
    auto read = __atomic_load_n(&gClockRead, __ATOMIC_ACQUIRE);
    if (read && read(&seconds) == 0 && dodge_calendar_read_usable(seconds, floor)) return static_cast<long>(seconds);
    return static_cast<long>(floor);
}
void ArmDTPlatform::setGMTTimeOfDay(long seconds) {
    auto set = __atomic_load_n(&gClockSet, __ATOMIC_ACQUIRE);
    if (set && seconds > 0 && dodge_calendar_read_usable(static_cast<uint64_t>(seconds), 0)) set(static_cast<uint64_t>(seconds));
}
