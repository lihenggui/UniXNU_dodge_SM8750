// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeCryptoOnce.h"
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>

namespace {
constexpr int success = 0, failure = 5, invalid = 4;
struct Fixture {
    DodgeCryptoOnce state{DodgeCryptoCold, failure, 0};
    std::atomic<bool> valid{true}, crypto{false}, prng{false}, owner{true}, entered{false}, resume{false};
    std::atomic<unsigned> calls{0};
    bool setCrypto = true, setPrng = true, recursive = false, hold = false;
    int entryResult = success;
    void *module = reinterpret_cast<void *>(0x12340000), *data = reinterpret_cast<void *>(0x56780000);
    DodgeCryptoOperations operations{this, success, failure, invalid,
        [](void *value, void *module) { auto &f = *static_cast<Fixture *>(value); return int(f.valid && module == f.module); },
        [](void *value) { auto &f = *static_cast<Fixture *>(value); return int(!f.crypto && !f.prng); },
        [](void *value) { auto &f = *static_cast<Fixture *>(value); return int(f.crypto && f.prng && f.owner); },
        [](void *value, void *module, void *data) {
            auto &f = *static_cast<Fixture *>(value); assert(module == f.module && data == f.data);
            ++f.calls; f.entered = true;
            if (f.hold) while (!f.resume) std::this_thread::yield();
            if (f.recursive) return dodge_crypto_once_call(&f.state, &f.operations, module, data);
            if (f.setCrypto) f.crypto = true;
            if (f.setPrng) f.prng = true;
            return f.entryResult;
        }};
    int run() { return dodge_crypto_once_call(&state, &operations, module, data); }
};
}

int main(int argc, char **argv) {
    assert(argc == 2); const char *name = argv[1]; Fixture f;
    if (!std::strcmp(name, "null-module") || !std::strcmp(name, "wrong-module")) {
        void *bad = !std::strcmp(name, "null-module") ? nullptr : reinterpret_cast<void *>(0x12340001);
        assert(dodge_crypto_once_call(&f.state, &f.operations, bad, f.data) == invalid);
        assert(!f.calls && f.state.phase == DodgeCryptoCold && !f.state.attempts);
    } else if (!std::strcmp(name, "invalid-record-retry")) {
        f.valid = false; assert(f.run() == invalid && !f.calls && f.state.phase == DodgeCryptoCold);
        f.valid = true; assert(f.run() == success && f.calls == 1);
    } else if (!std::strcmp(name, "existing-crypto") || !std::strcmp(name, "existing-prng") || !std::strcmp(name, "existing-both")) {
        f.crypto = std::strcmp(name, "existing-prng") != 0; f.prng = std::strcmp(name, "existing-crypto") != 0;
        assert(f.run() == failure && f.state.phase == DodgeCryptoFailed && !f.calls && !f.state.attempts);
        f.crypto = f.prng = false; assert(f.run() == failure && !f.calls);
    } else if (!std::strcmp(name, "success") || !std::strcmp(name, "success-cached")) {
        assert(f.run() == success && f.state.phase == DodgeCryptoReady && f.state.attempts == 1 && f.calls == 1);
        if (!std::strcmp(name, "success-cached")) for (unsigned i = 0; i < 100; ++i) assert(f.run() == success);
        assert(f.calls == 1 && f.state.attempts == 1);
    } else if (!std::strcmp(name, "entry-failure") || !std::strcmp(name, "entry-partial-failure")) {
        f.entryResult = 77; f.setCrypto = !std::strcmp(name, "entry-partial-failure"); f.setPrng = false;
        assert(f.run() == 77 && f.state.phase == DodgeCryptoFailed && f.calls == 1);
        f.entryResult = success; assert(f.run() == 77 && f.calls == 1 && f.state.attempts == 1);
    } else if (!std::strcmp(name, "missing-crypto") || !std::strcmp(name, "missing-prng") || !std::strcmp(name, "wrong-owner")) {
        f.setCrypto = std::strcmp(name, "missing-crypto") != 0; f.setPrng = std::strcmp(name, "missing-prng") != 0;
        f.owner = std::strcmp(name, "wrong-owner") != 0;
        assert(f.run() == failure && f.state.phase == DodgeCryptoFailed && f.calls == 1);
        f.crypto = f.prng = f.owner = true; assert(f.run() == failure && f.calls == 1);
    } else if (!std::strcmp(name, "owner-lost-after-success")) {
        assert(f.run() == success); f.owner = false; assert(f.run() == failure && f.calls == 1);
    } else if (!std::strcmp(name, "record-changed-after-success")) {
        assert(f.run() == success); f.valid = false; assert(f.run() == invalid && f.calls == 1);
    } else if (!std::strcmp(name, "recursive")) {
        f.recursive = true; assert(f.run() == failure && f.calls == 1 && f.state.phase == DodgeCryptoFailed);
        assert(f.run() == failure && f.calls == 1);
    } else if (!std::strcmp(name, "concurrent-success") || !std::strcmp(name, "concurrent-failure")) {
        f.hold = true; if (!std::strcmp(name, "concurrent-failure")) f.entryResult = 77;
        int first = -1; std::thread worker([&] { first = f.run(); });
        while (!f.entered) std::this_thread::yield();
        assert(f.run() == failure && f.calls == 1 && f.state.phase == DodgeCryptoStarting);
        f.resume = true; worker.join();
        assert(first == f.entryResult && f.run() == f.entryResult && f.calls == 1 && f.state.attempts == 1);
    } else { assert(!"unknown crypto once case"); }
    std::printf("{\"case\":\"%s\",\"result\":\"PASS\",\"original_entry_calls\":%u,\"attempts\":%u}\n", name, f.calls.load(), f.state.attempts);
}
