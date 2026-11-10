// SPDX-License-Identifier: MIT
// Software PE peer; production compilation uses actual Darwin22 headers.
#pragma once
#include <cstdint>
struct PE_Video {
    uint64_t v_baseAddr = 0xfc800000, v_rowBytes = 5760, v_width = 1440,
             v_height = 3168, v_depth = 32, v_rotate = 0;
};
extern "C" int PE_current_console(PE_Video *);
