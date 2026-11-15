// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <utility>

using NSUInteger = uint64_t;
struct Texture { NSUInteger sampleCount; };
struct Attachment { Texture texture; };
struct Descriptor { Attachment colorAttachments[8], depthAttachment, stencilAttachment; };
struct NmbRenderPassDescriptor { uint64_t samples, tile_width, tile_height; };
struct NBRenderEncoder { uint32_t _tileW, _tileH; };

static std::pair<uint32_t, uint32_t> geometry(const NmbRenderPassDescriptor &pass, const Descriptor &d) {
    NBRenderEncoder encoder{};auto *made = &encoder;
#include "TilePassGeometry.inc"
    return {encoder._tileW, encoder._tileH};
}

int main() {
    unsigned cases = 0;
    auto check = [&](const NmbRenderPassDescriptor &pass, const Descriptor &d, uint32_t width, uint32_t height) {
        assert(geometry(pass, d) == std::make_pair(width, height));++cases;
    };
    for (uint64_t samples : {1, 2, 4}) {
        const uint32_t height = samples == 4 ? 16 : 32;
        const NmbRenderPassDescriptor pass{samples == 4 ? 1u : 4u, 0, 0};
        for (unsigned index = 0; index < 8; ++index) {
            Descriptor d{};d.colorAttachments[index].texture.sampleCount = samples;
            check(pass, d, 32, height);
        }
        Descriptor depth{};depth.depthAttachment.texture.sampleCount = samples;
        check(pass, depth, 32, height);
        Descriptor stencil{};stencil.stencilAttachment.texture.sampleCount = samples;
        check(pass, stencil, 32, height);
        check({samples, 0, 0}, {}, 32, height);
        for (auto [width, explicitHeight] : {std::pair{16u, 16u}, {32u, 16u}, {32u, 32u}}) {
            if (samples == 4 && explicitHeight == 32)continue;
            check({samples, width, explicitHeight}, {}, width, explicitHeight);
        }
    }
    Descriptor colors{};colors.colorAttachments[2].texture.sampleCount = 1;
    colors.colorAttachments[7].texture.sampleCount = 4;colors.depthAttachment.texture.sampleCount = 4;
    colors.stencilAttachment.texture.sampleCount = 4;check({4, 0, 0}, colors, 32, 32);
    Descriptor depth{};depth.depthAttachment.texture.sampleCount = 2;depth.stencilAttachment.texture.sampleCount = 4;
    check({4, 0, 0}, depth, 32, 32);
    assert(cases == 43);
    std::printf("{\"cases\":%u}\n", cases);
}
