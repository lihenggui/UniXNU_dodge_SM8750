/* SPDX-License-Identifier: MIT */
#include "DodgeNativeA830Board.h"
#include "NativeAdrenoFirmware.h"
#include "Sm8750GpuFirmware.h"
#include <pexpert/pexpert.h>

namespace {
Adreno830Board board;
uint32_t attempted;
bool bootArgument(void *, const char *name, uint32_t *value)
{
    return PE_parse_boot_argn(name, value, sizeof *value);
}
}

extern "C" IOReturn dodge_native_a830_start(uint32_t expectedSoc)
{
    if (__atomic_exchange_n(&attempted, 1u, __ATOMIC_ACQ_REL)) return kIOReturnBusy;
    const uint8_t *bytes[] = {sm8750_gpu_gmu, sm8750_gpu_sqe, sm8750_gpu_aqe, sm8750_gpu_zap};
    const uint64_t sizes[] = {sm8750_gpu_gmu_size, sm8750_gpu_sqe_size, sm8750_gpu_aqe_size, sm8750_gpu_zap_size};
    Adreno830Firmware firmware[4] = {};
    for (unsigned i = 0; i < 4; ++i) {
        const auto *pin = NativeAdrenoFirmware::pin(i);
        firmware[i].bytes = bytes[i]; firmware[i].length = sizes[i];
        for (unsigned k = 0; k < 32; ++k) firmware[i].sha256[k] = pin->sha256[k];
    }
    IOReturn result = DodgeNativeA830FillBoard(&board, expectedSoc, firmware);
    if (result) return result;
    DodgeNativeA830ParseKnobs(&board, bootArgument, nullptr);
    /* Publication must finish before the caller starts its Metal consumers. */
    if (board.knobs.async) return kIOReturnUnsupported;
    return adreno830_start(&board);
}
