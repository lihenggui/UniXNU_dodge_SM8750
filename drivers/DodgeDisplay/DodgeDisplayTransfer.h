// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

// Producer rendering and the final scanout transfer are independent. The
// initial display path copies completed pixels on the CPU. Presenter handoff
// is experimental until failed/abandoned GPU work can be proven quiescent.
enum class DodgeDisplayTransfer { CpuCopy, Presenter };
