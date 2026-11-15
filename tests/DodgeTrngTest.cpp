// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeTrngRead.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct Device {
    unsigned words = 0, polls = 0, delays = 0, failAt = ~0U, unavailableAt = ~0U, badAt = ~0U;
    bool zero = false, repeated = false, failStatus = false;
    static bool read(void *opaque, unsigned offset, uint32_t *value) {
        auto &self = *static_cast<Device *>(opaque);
        if (offset == 4) { ++self.polls;*value = self.words == self.unavailableAt ? 0 : 1;return !self.failStatus; }
        assert(offset == 0);const unsigned index = self.words++;
        if (index == self.failAt) return false;
        *value = index == self.badAt ? (self.zero ? 0 : UINT32_MAX) : self.repeated ? 0x12345678 : 0x12345678 + index;
        return true;
    }
    static void delay(void *opaque, unsigned us) { assert(us == 200);++static_cast<Device *>(opaque)->delays; }
    DodgeTrngIo io() { return {this, read, delay}; }
};
int main() {
    unsigned cases = 0;
    for (unsigned failure = 0; failure < 4; ++failure) for (unsigned at = 0; at < 8; ++at) {
        Device device;DodgeTrngState state{};uint8_t out[34];memset(out, 0xa5, sizeof(out));auto io = device.io();
        if (failure == 0) device.failAt = at;
        if (failure == 1) device.unavailableAt = at;
        if (failure >= 2) { device.badAt = at;device.zero = failure == 2; }
        const auto result = dodge_trng_read32(&state, &io, out + 1, 32);
        assert(result != DodgeTrngOk);
        for (auto byte : out) assert(byte == 0xa5);
        assert(device.polls <= 58 && device.delays <= 50);++cases;
    }
    Device device;DodgeTrngState state{};uint8_t out[34];memset(out, 0xa5, sizeof(out));auto io = device.io();
    assert(dodge_trng_read32(&state, &io, out + 1, 32) == DodgeTrngOk);
    assert(out[0] == 0xa5 && out[33] == 0xa5 && out[1] == 0x78 && out[2] == 0x56 && out[32] == 0x12);++cases;
    assert(dodge_trng_read32(&state, &io, out + 1, 32) == DodgeTrngOk && device.words == 16);++cases;
    device.words = 15;assert(dodge_trng_read32(&state, &io, out + 1, 32) == DodgeTrngHealth);++cases;
    const auto reads = device.polls;assert(dodge_trng_read32(&state, &io, out + 1, 32) == DodgeTrngHealth && device.polls == reads);++cases;
    for (size_t bytes = 0; bytes < 65; ++bytes) if (bytes != 32) {
        assert(dodge_trng_read32(&state, &io, out + 1, bytes) == DodgeTrngArgument);++cases;
    }
    Device stuck;stuck.repeated = true;auto stuckIo = stuck.io();DodgeTrngState stuckState{};
    assert(dodge_trng_read32(&stuckState, &stuckIo, out + 1, 32) == DodgeTrngHealth && stuck.words == 2);++cases;
    Device error;error.failStatus = true;auto errorIo = error.io();DodgeTrngState errorState{};
    assert(dodge_trng_read32(&errorState, &errorIo, out + 1, 32) == DodgeTrngIoError && !error.words);++cases;
    assert(dodge_entropy_request_valid(0, 0, 0, 0, 32, false, false));++cases;
    for (unsigned selector = 1; selector < 256; ++selector) {
        assert(!dodge_entropy_request_valid(selector, 0, 0, 0, 32, false, false));++cases;
    }
    assert(!dodge_entropy_request_valid(0, 1, 0, 0, 32, false, false));
    assert(!dodge_entropy_request_valid(0, 0, 1, 0, 32, false, false));
    assert(!dodge_entropy_request_valid(0, 0, 0, 1, 32, false, false));
    assert(!dodge_entropy_request_valid(0, 0, 0, 0, 32, true, false));
    assert(!dodge_entropy_request_valid(0, 0, 0, 0, 32, false, true));cases += 5;
    dodge_trng_erase(out, sizeof(out));for (auto byte : out) assert(!byte);++cases;
    printf("PASS: %u TRNG transaction, partial/error/stuck-output and original request-shape cases\n", cases);
}
