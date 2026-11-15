// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>

// Bounded Darwin version-date parser for the upstream calendar-floor policy.
// A build date is a lower bound, not a replacement for an actual RTC.
inline uint64_t dodge_calendar_version_seconds(const char *text) {
    if (!text) return 0;
    size_t bytes = 0;
    while (bytes < 512 && text[bytes]) ++bytes;
    if (bytes == 512) return 0;
    const char prefix[] = "Darwin Kernel Version ";
    if (bytes < sizeof(prefix)) return 0;
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i) if (text[i] != prefix[i]) return 0;
    size_t at = sizeof(prefix) - 1;
    while (at < bytes && text[at] != ':') ++at;
    if (at + 6 >= bytes || text[++at] != ' ') return 0;
    ++at;
    for (unsigned i = 0; i < 3; ++i) if (text[at + i] < 'A' || text[at + i] > 'z') return 0;
    at += 3;
    if (text[at++] != ' ' || at + 4 > bytes) return 0;
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    unsigned month = 12;
    for (unsigned i = 0; i < 12; ++i)
        if (text[at] == months[3 * i] && text[at + 1] == months[3 * i + 1] && text[at + 2] == months[3 * i + 2]) month = i;
    if (month == 12 || text[at + 3] != ' ') return 0;
    at += 4;
    auto number = [&](unsigned minimumDigits, unsigned maximumDigits, unsigned limit) {
        unsigned value = 0, digits = 0;
        while (at < bytes && text[at] >= '0' && text[at] <= '9') {
            if (++digits > maximumDigits) return limit + 1;
            value = value * 10 + unsigned(text[at++] - '0');
        }
        return digits >= minimumDigits && value <= limit ? value : limit + 1;
    };
    if (at < bytes && text[at] == ' ') ++at;
    const unsigned day = number(1, 2, 31);
    if (at == bytes || text[at++] != ' ') return 0;
    const unsigned hour = number(2, 2, 23);
    if (at == bytes || text[at++] != ':') return 0;
    const unsigned minute = number(2, 2, 59);
    if (at == bytes || text[at++] != ':') return 0;
    const unsigned second = number(2, 2, 60);
    if (at == bytes || text[at++] != ' ') return 0;
    const size_t timezone = at;
    while (at < bytes && text[at] != ' ') ++at;
    if (at == bytes || at == timezone || at - timezone > 16) return 0;
    ++at;
    const unsigned year = number(4, 4, 9999);
    if (at == bytes || text[at] != ';' || year < 2020 || year > 9999 || !day || hour > 23 || minute > 59 || second > 60) return 0;
    static const uint8_t daysInMonth[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (day > unsigned(daysInMonth[month]) + unsigned(month == 1 && leap)) return 0;
    const unsigned y = month < 2 ? year - 1 : year, m = month < 2 ? month + 10 : month - 2;
    const uint64_t era = y / 400, yoe = y - era * 400;
    const uint64_t doy = (153 * m + 2) / 5 + day - 1, doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second;
}

inline uint64_t dodge_calendar_floor(const char *version) {
    const uint64_t built = dodge_calendar_version_seconds(version);
    return built > 86400 ? built - 86400 : 0;
}
inline bool dodge_calendar_read_usable(uint64_t seconds, uint64_t floor) {
    return seconds && seconds >= floor && seconds <= UINT64_C(253402300799);
}
