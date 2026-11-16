// SPDX-License-Identifier: BSD-2-Clause-Patent
// The generated include is the pinned reference MMIO fixture with the six-rail
// expectations adapted in the reviewed source patch, never a live controller.
#define main reference_bringup_main
#include "WifiBringupChecks.inc"
#undef main
#include "DodgeWifi.h"

int main() {
    CHECK(reference_bringup_main() == 0);
    CHECK(dodge_wifi_rail_count() == 6);
    for (const Rail &rail : kRails) CHECK(std::strcmp(rail.resource, "ldob8") != 0);
    for (unsigned stage = 1; stage <= 3; ++stage) {
        reset();M.relaxed = true;
        Bringup state{};
        CHECK(dodge_wifi_prepare(&state, &kHw, stage, 2) == 0);
        if (stage == 1) CHECK(M.writes.empty() && M.votes.empty());
        for (const Vote &vote : M.votes) CHECK(vote.resource != "ldob8");
        const size_t writes = M.writes.size();
        CHECK(dodge_wifi_prepare(&state, &kHw, stage, 2) == kErrArgument && M.writes.size() == writes);
    }
    for (unsigned stage : {0u, 4u, UINT32_MAX}) {
        reset();Bringup state{};
        CHECK(dodge_wifi_prepare(&state, &kHw, stage, 2) == kErrArgument && M.writes.empty() && M.votes.empty());
    }
    for (unsigned generation : {0u, 3u, UINT32_MAX}) {
        reset();Bringup state{};
        CHECK(dodge_wifi_prepare(&state, &kHw, 3, generation) == kErrArgument && M.writes.empty() && M.votes.empty());
    }
    reset();Bringup state{};Hw noPmic = kHw;noPmic.pmic = nullptr;
    CHECK(dodge_wifi_prepare(&state, &noPmic, 2, 2) == kErrArgument && M.writes.empty() && M.votes.empty());
    reset();M.relaxed = true;M.linkFails = true;
    CHECK(dodge_wifi_prepare(&state, &kHw, 3, 2) < 0);
    const size_t writes = M.writes.size();
    CHECK(dodge_wifi_prepare(&state, &kHw, 3, 2) == kErrArgument && M.writes.size() == writes);
    std::printf("PASS dodge Wi-Fi board/source callbacks: %u checks\n", checks);
}
