// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stddef.h>
#include <stdint.h>

// qcom,trng register protocol: DATA_OUT=0, STATUS=4, DATA_AVAIL=bit 0.
// Fixed 32-byte, all-or-nothing requests; no clock/configuration register writes.
struct DodgeTrngIo {
    void *context;
    bool (*read)(void *, unsigned, uint32_t *);
    void (*delay)(void *, unsigned);
};
struct DodgeTrngState { uint32_t previous; bool havePrevious, healthFailed; };
enum DodgeTrngResult { DodgeTrngOk, DodgeTrngArgument, DodgeTrngTimeout, DodgeTrngIoError, DodgeTrngHealth };

inline void dodge_trng_erase(void *data, size_t bytes) {
    auto *out = static_cast<volatile uint8_t *>(data);
    while (bytes--) *out++ = 0;
}
inline bool dodge_entropy_request_valid(unsigned selector, unsigned scalarIn, unsigned scalarOut, size_t inputBytes,
                                        size_t outputBytes, bool inputDescriptor, bool outputDescriptor) {
    return selector == 0 && !scalarIn && !scalarOut && !inputBytes && outputBytes == 32 && !inputDescriptor && !outputDescriptor;
}
inline DodgeTrngResult dodge_trng_read32(DodgeTrngState *state, const DodgeTrngIo *io, void *out, size_t bytes) {
    if (!state || !io || !io->read || !io->delay || !out || bytes != 32) return DodgeTrngArgument;
    if (state->healthFailed) return DodgeTrngHealth;
    uint8_t block[32] = {};
    DodgeTrngResult result = DodgeTrngOk;
    for (unsigned word = 0; word < 8; ++word) {
        bool ready = false;
        for (unsigned poll = 0; poll <= 50; ++poll) {
            uint32_t status = 0;
            if (!io->read(io->context, 4, &status)) { result = DodgeTrngIoError;break; }
            if (status & 1) { ready = true;break; }
            if (poll < 50) io->delay(io->context, 200);
        }
        if (result != DodgeTrngOk) break;
        if (!ready) { result = DodgeTrngTimeout;break; }
        uint32_t value = 0;
        if (!io->read(io->context, 0, &value)) { result = DodgeTrngIoError;break; }
        // Refuse empty/stuck output, including repetitions across requests.
        // These conservative checks do not establish a statistical entropy rate.
        if (!value || value == UINT32_MAX || (state->havePrevious && state->previous == value)) {
            state->healthFailed = true;result = DodgeTrngHealth;break;
        }
        state->previous = value;state->havePrevious = true;
        for (unsigned byte = 0; byte < 4; ++byte) block[4 * word + byte] = uint8_t(value >> (8 * byte));
    }
    if (result == DodgeTrngOk) {
        auto *destination = static_cast<uint8_t *>(out);
        for (unsigned i = 0; i < sizeof(block); ++i) destination[i] = block[i];
    }
    dodge_trng_erase(block, sizeof(block));
    return result;
}
