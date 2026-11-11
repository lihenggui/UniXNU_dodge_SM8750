/* SPDX-License-Identifier: MIT */
#include "DodgeNativeA830Board.h"
#include "NativeAdrenoFirmware.h"
#include "DodgeNativeA830Inputs.inc"

IOReturn DodgeNativeA830FillBoard(Adreno830Board *board, uint32_t expectedSoc,
                                const Adreno830Firmware (&firmware)[4])
{
    if (!board) return kIOReturnBadArgument;
    *board = {};
    if (!dodgeA830Soc(expectedSoc)) return kIOReturnUnsupported;
    for (unsigned i = 0; i < 4; ++i) {
        NativeAdrenoFirmwareRules rules = {firmware[i].length, {}};
        for (unsigned k = 0; k < 32; ++k) rules.sha256[k] = firmware[i].sha256[k];
        if (!firmware[i].bytes || !NativeAdrenoFirmware::matchesPin(i, rules)) return kIOReturnBadArgument;
    }
    dodgeA830Hardware(board);
    board->soc_id = expectedSoc;
    board->gmu_fw = firmware[0]; board->sqe_fw = firmware[1];
    board->aqe_fw = firmware[2]; board->zap_fw = firmware[3];
    DodgeNativeA830ParseKnobs(board, nullptr, nullptr);
    return kIOReturnSuccess;
}

namespace {
struct Arguments { DodgeNativeA830Argument get; void *cookie; };
bool argument(void *cookie, const char *name, uint32_t *value)
{
    auto *args = static_cast<Arguments *>(cookie);
    if (!args->get) return false;
    /* The upstream table has pagani-* names. This board exposes dodge-* names. */
    constexpr char prefix[] = "pagani";
    for (unsigned i = 0; i < sizeof prefix - 1; ++i) if (name[i] != prefix[i]) return false;
    char key[64] = {'d', 'o', 'd', 'g', 'e'};
    unsigned i = 5;
    for (name += sizeof prefix - 1; *name; ++name, ++i) {
        if (i >= sizeof key - 1) return false;
        key[i] = *name;
    }
    return args->get(args->cookie, key, value);
}
}

void DodgeNativeA830ParseKnobs(Adreno830Board *board, DodgeNativeA830Argument get, void *cookie)
{
    Arguments args = {get, cookie};
    Adreno830ParseKnobs(board, argument, &args);
}
