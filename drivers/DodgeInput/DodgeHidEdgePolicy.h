// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
#include <stdint.h>

struct DodgeHidEdgePolicy {
    bool fromEdge[256]={};
    uint32_t x=0,y=0;
};
struct DodgeHidEdgeContact {
    uint32_t identity=0,mask=0;
    int32_t x=0,y=0;
    bool down=false;
};
static inline bool dodge_hid_edge_configure(DodgeHidEdgePolicy *state,uint32_t width,uint32_t height,uint32_t pixels) {
    if (!state || !pixels || width<=2ULL*pixels || height<=2ULL*pixels) return false;
    uint64_t x=(uint64_t)pixels*65536/width,y=(uint64_t)pixels*65536/height;
    if (!x || !y || x>=32768 || y>=32768) return false;
    *state=DodgeHidEdgePolicy{};state->x=(uint32_t)x;state->y=(uint32_t)y;return true;
}
static inline bool dodge_hid_edge_valid(const DodgeHidEdgeContact &contact) {
    return contact.identity<256 && contact.x>=0 && contact.x<=65536 && contact.y>=0 && contact.y<=65536;
}
static inline bool dodge_hid_edge_mark(DodgeHidEdgePolicy *state,const DodgeHidEdgeContact &contact,uint32_t *mask) {
    if (!state || !mask || !state->x || !state->y || !dodge_hid_edge_valid(contact)) return false;
    if ((contact.mask&2) && contact.down) {
        state->fromEdge[contact.identity]=(uint32_t)contact.x<state->x || (uint32_t)contact.x>65536-state->x ||
            (uint32_t)contact.y<state->y || (uint32_t)contact.y>65536-state->y;
    }
    bool edge=state->fromEdge[contact.identity];
    if ((contact.mask&2) && !contact.down) state->fromEdge[contact.identity]=false;
    *mask=contact.mask|(edge?0x800u:0u);return edge;
}
