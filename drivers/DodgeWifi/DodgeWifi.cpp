// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeWifi.h"

using namespace pagani_wifi;
static_assert(sizeof kRails / sizeof kRails[0] == 6, "dodge has six WLAN supplies; no 13T antenna-share vote");
static_assert(kRails[5].ppid == 0x8ad && kRails[5].chosenMv == 1312, "shared UFS rail must retain its policy");
static_assert(kEndpointVendorDevice == 0x110e17cb && kSidEndpoint == 0x1401, "captured peach/PCIe0 selection");

extern "C" unsigned dodge_wifi_rail_count() { return sizeof kRails / sizeof kRails[0]; }
extern "C" int dodge_wifi_prepare(Bringup *state, const Hw *hardware, unsigned stage, unsigned generation) {
    if (!state || !hardware || state->hw || stage < 1 || stage > 3 || generation < 1 || generation > 2 ||
        !hardware->read || !hardware->pmic || !hardware->sleep_clock) return kErrArgument;
    // Gen3 requires additional CX/MX votes which this integration does not own.
    // Do not fall through to it just because the root complex advertises it.
    if (stage > 1 && (!hardware->write || !hardware->udelay || !hardware->msleep || !hardware->now_ms ||
        !hardware->vote_lock || !hardware->vrm || !hardware->bcm)) return kErrArgument;
    *state = {};
    state->hw = hardware;state->opt.stage = stage;state->opt.maxGen = generation;
    state->opt.s7iVote = 0;state->opt.pdc = 0;
    // No automatic endpoint probing, SMMU reprogramming, firmware loading or
    // fabricated network publication follows link training.
    return stage == 1 ? survey(*state) : stage == 2 ? powerOn(*state) : linkUp(*state);
}
