// SPDX-License-Identifier: MIT
// Software PE peer, not the production Darwin22 structure layout.
#pragma once
#include <cstdint>
struct PE_Video {
    uint64_t v_baseAddr=0xfc800000,v_rowBytes=80,v_width=17,
             v_height=5,v_depth=32,v_rotate=0;
};
extern "C" int PE_current_console(PE_Video *);
