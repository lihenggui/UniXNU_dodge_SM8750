// SPDX-License-Identifier: MIT
#include "DodgeHidEdgePolicy.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <climits>
static unsigned cases=0;
static void same(const DodgeHidEdgePolicy &a,const DodgeHidEdgePolicy &b) {assert(!memcmp(&a,&b,sizeof a));}
int main() {
    const uint32_t dimensions[][2]={{1440,3168},{1080,2376},{2304,4096},{97,97},{1920,1080},{65536,65536}};
    for (const auto &d:dimensions) {
        DodgeHidEdgePolicy state={};assert(dodge_hid_edge_configure(&state,d[0],d[1],48));
        assert(state.x==48ULL*65536/d[0] && state.y==48ULL*65536/d[1]);
        for (bool value:state.fromEdge) assert(!value);
        ++cases;
    }
    const uint32_t bad[][3]={{0,3168,48},{1440,0,48},{96,3168,48},{1440,96,48},{1440,3168,0},
                            {UINT32_MAX,3168,48},{1440,UINT32_MAX,48},{UINT32_MAX,UINT32_MAX,UINT32_MAX}};
    for (const auto &d:bad) {
        DodgeHidEdgePolicy state={};assert(dodge_hid_edge_configure(&state,1440,3168,48));state.fromEdge[17]=true;
        auto before=state;assert(!dodge_hid_edge_configure(&state,d[0],d[1],d[2]));same(state,before);++cases;
    }
    assert(!dodge_hid_edge_configure(nullptr,1440,3168,48));++cases;
    for (unsigned identity=0;identity<256;++identity) {
        DodgeHidEdgePolicy state={};assert(dodge_hid_edge_configure(&state,1440,3168,48));uint32_t mask=0;
        DodgeHidEdgeContact contact={identity,0x80000002u,0,32768,true};
        assert(dodge_hid_edge_mark(&state,contact,&mask) && mask==0x80000802u && state.fromEdge[identity]);
        contact={identity,4,32768,32768,true};assert(dodge_hid_edge_mark(&state,contact,&mask) && mask==0x804);
        contact={identity,2,32768,32768,false};assert(dodge_hid_edge_mark(&state,contact,&mask) && mask==0x802 && !state.fromEdge[identity]);
        contact={identity,2,32768,32768,true};assert(!dodge_hid_edge_mark(&state,contact,&mask) && mask==2);
        for (bool value:state.fromEdge) assert(!value);
        ++cases;
    }
    DodgeHidEdgePolicy base={};assert(dodge_hid_edge_configure(&base,1440,3168,48));
    const int32_t positions[][3]={
        {0,32768,1},{65536,32768,1},{32768,0,1},{32768,65536,1},{0,0,1},{65536,65536,1},
        {(int32_t)base.x-1,32768,1},{(int32_t)base.x,32768,0},
        {65536-(int32_t)base.x,32768,0},{65537-(int32_t)base.x,32768,1},
        {32768,(int32_t)base.y-1,1},{32768,(int32_t)base.y,0},
        {32768,65536-(int32_t)base.y,0},{32768,65537-(int32_t)base.y,1},{32768,32768,0}};
    for (const auto &p:positions) {
        auto state=base;DodgeHidEdgeContact contact={9,2,p[0],p[1],true};uint32_t mask=0;
        assert(dodge_hid_edge_mark(&state,contact,&mask)==bool(p[2]) && mask==(2u|(p[2]?0x800u:0u)));++cases;
    }
    const DodgeHidEdgeContact invalid[]={{256,2,0,0,true},{UINT32_MAX,2,0,0,true},{0,2,-1,0,true},
        {0,2,0,-1,true},{0,2,65537,0,true},{0,2,0,65537,true},{0,2,INT32_MIN,0,true},{0,2,INT32_MAX,0,true}};
    for (const auto &contact:invalid) {
        auto state=base;uint32_t mask=0xabcdef01;auto before=state;
        assert(!dodge_hid_edge_mark(&state,contact,&mask) && mask==0xabcdef01);same(state,before);++cases;
    }
    {
        auto state=base;uint32_t mask=123;DodgeHidEdgeContact contact={0,4,0,0,true};
        assert(!dodge_hid_edge_mark(&state,contact,&mask) && mask==4 && !state.fromEdge[0]);++cases;
        contact.mask=2;assert(dodge_hid_edge_mark(&state,contact,&mask));
        contact.mask=0;contact.down=false;assert(dodge_hid_edge_mark(&state,contact,&mask) && mask==0x800 && state.fromEdge[0]);++cases;
        contact.mask=2;assert(dodge_hid_edge_mark(&state,contact,&mask) && !state.fromEdge[0]);
        assert(!dodge_hid_edge_mark(&state,contact,&mask) && mask==2);++cases;
        auto before=state;assert(!dodge_hid_edge_mark(&state,contact,nullptr));same(state,before);++cases;
        assert(!dodge_hid_edge_mark(nullptr,contact,&mask));++cases;
        DodgeHidEdgePolicy empty={};mask=123;assert(!dodge_hid_edge_mark(&empty,contact,&mask) && mask==123);++cases;
    }
    printf("{\"result\":\"PASS\",\"case_count\":%u,\"identities_exhausted\":256}\n",cases);
}
