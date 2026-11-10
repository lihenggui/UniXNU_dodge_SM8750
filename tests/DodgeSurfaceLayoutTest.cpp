// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeSurfaceLayout.h"
#include <cassert>
#include <cstdio>
#include <limits>

static constexpr uint32_t row=2560,lines=480,pixels=row*lines;

int main() {
    DodgeSurfaceGeometry good={640,480,row,128,pixels+128,0x42475241,0,4,1,1,0,0};
    DodgeSurfaceRange range={};
    assert(dodge_surface_range(good,640,480,4096,good.allocation,4096+good.allocation,&range));
    assert(range.offset==4224 && range.length==pixels);
    auto zero=good;zero.offset=0;zero.allocation=pixels;
    assert(dodge_surface_range(zero,640,480,0,pixels,pixels,&range));
    assert(range.offset==0 && range.length==pixels);
    DodgeSurfaceGeometry padded={768,512,4096,1024,4096*512+1024,0x42475241,0,4,1,1,0,0};
    assert(dodge_surface_range(padded,640,480,8192,padded.allocation,8192+padded.allocation,&range));
    assert(range.offset==9216 && range.length==4096*480);
    unsigned refusals=0;
    auto refuse=[&](DodgeSurfaceGeometry g,uint32_t w=640,uint32_t h=480,
                    uint64_t base=4096,uint64_t mapped=pixels+128,uint64_t descriptor=4096+pixels+128) {
        DodgeSurfaceRange output={0x1122334455667788,0x8877665544332211};
        assert(!dodge_surface_range(g,w,h,base,mapped,descriptor,&output));
        assert(output.offset==0x1122334455667788 && output.length==0x8877665544332211);
        ++refusals;
    };
    refuse(good,0);refuse(good,640,0);refuse(good,16385);refuse(good,640,16385);
    auto bad=good;bad.width=639;refuse(bad);
    bad=good;bad.height=479;refuse(bad);
    bad=good;bad.stride=2559;refuse(bad);
    bad=good;bad.allocation=127;refuse(bad);
    bad=good;bad.allocation=pixels;refuse(bad); // Offset must be included in AllocSize.
    refuse(good,640,480,4096,pixels+127);
    refuse(good,640,480,4096,pixels+128,4096+pixels+127);
    refuse(good,640,480,std::numeric_limits<uint64_t>::max()-64,pixels+128,
           std::numeric_limits<uint64_t>::max()); // Reject before adding offsets.
    refuse(good,640,480,4096,pixels+128,4095);
    bad=good;bad.format=0x26424741;refuse(bad); // Compressed spelling is not a plain-row contract.
    bad=good;bad.format=0;refuse(bad);
    bad=good;bad.planes=1;refuse(bad);
    bad=good;bad.tile_format=1;refuse(bad);
    bad=good;bad.tile_mode=1;refuse(bad);
    bad=good;bad.bytes_per_element=8;refuse(bad);
    bad=good;bad.element_width=2;refuse(bad);
    bad=good;bad.element_height=2;refuse(bad);
    assert(!dodge_surface_range(good,640,480,4096,pixels+128,4096+pixels+128,nullptr));
    std::printf("PASS: three valid offset/padded layouts, %u invalid layouts without output writes, null output\n",refusals);
}
