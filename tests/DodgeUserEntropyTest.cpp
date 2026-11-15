// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <atomic>
#include <stdio.h>
#include <thread>
#include <vector>
#include "../drivers/DodgeSecurity/DodgeUserEntropy.c"

static std::atomic<unsigned> backendCalls;
static int backendResult;
int dodge_write_random_original(void *buffer, u_int bytes) {
    assert(buffer && bytes);
    backendCalls.fetch_add(1);
    return backendResult;
}
int main() {
    uint8_t input[32] = {1};
    sysctl_req request{};
    assert(!entropy_test_registration.handler(nullptr, nullptr, 0, &request));
    assert(request.bytes == 8 && !request.value); // Reading statistics never fabricates a reseed.
    assert(!write_random(nullptr, 0) && !backendCalls && !dodge_user_entropy_reseeds);
    assert(write_random(nullptr, sizeof(input)) == EINVAL && !backendCalls);
    backendResult = EIO;
    assert(write_random(input, sizeof(input)) == EIO && backendCalls == 1 && !dodge_user_entropy_reseeds && !dodge_user_entropy_bytes);
    backendResult = 0;
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 4; ++i) workers.emplace_back([&] {
        for (unsigned call = 0; call < 1000; ++call) assert(!write_random(input, sizeof(input)));
    });
    for (auto &worker : workers) worker.join();
    assert(backendCalls == 4001 && dodge_user_entropy_reseeds == 4000 && dodge_user_entropy_bytes == 4000 * sizeof(input));
    assert(!entropy_test_registration.handler(nullptr, nullptr, 0, &request) && request.value == 4000);
    request.result = EFAULT;assert(entropy_test_registration.handler(nullptr, nullptr, 0, &request) == EFAULT);
    assert(entropy_test_registration.flags == (CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED));
    assert(!strcmp(entropy_test_registration.format, "QU"));
    puts("PASS: 4000 concurrent reseeds, empty/null/backend failure controls and read-only sysctl");
}
