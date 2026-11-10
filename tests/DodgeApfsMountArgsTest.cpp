// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "DodgeApfsMountArgs.h"
#include "OriginalApfsMountABI.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv) {
    if (argc == 6 && !std::strcmp(argv[1], "--capture")) {
        std::array<unsigned char, DodgeApfsMountBytes> output{};
        bool okay = dodge_apfs_ordinary_mount_args(output.data(), output.size(), std::strtoull(argv[2], nullptr, 0),
            uint32_t(std::strtoull(argv[3], nullptr, 0)), uint32_t(std::strtoull(argv[4], nullptr, 0)), uint32_t(std::strtoull(argv[5], nullptr, 0)));
        if (!okay) return 2;
        for (auto value : output) std::printf("%02x", value);
        std::puts("");
        return 0;
    }
    assert(argc == 1);
    struct Reject { const char *name; size_t bytes; uint64_t pointer; uint32_t flags, uid, gid; };
    const Reject rejects[] = {
        {"empty-output", 0, 0x1000, 0, 0, 0},
        {"short-output", 335, 0x1000, 0, 0, 0},
        {"long-output", 337, 0x1000, 0, 0, 0},
        {"size-overflow", SIZE_MAX, 0x1000, 0, 0, 0},
        {"null-user-spec", 336, 0, 0, 0, 0},
        {"update", 336, 0x1000, 0x10000, 0, 0},
        {"reload", 336, 0x1000, 0x40000, 0, 0},
        {"opaque-apfs-flags", 336, 0x1000, 0x80000000, 0, 0},
        {"mixed-unsupported-flags", 336, 0x1000, 0x210001, 0, 0},
        {"unresolved-uid", 336, 0x1000, 0, UINT32_MAX, 0},
        {"unresolved-gid", 336, 0x1000, 0, 0, UINT32_MAX},
    };
    unsigned count = 0;
    for (auto item : rejects) {
        std::array<unsigned char, 368> guarded; guarded.fill(0xa5);
        auto before = guarded;
        assert(!dodge_apfs_ordinary_mount_args(guarded.data() + 16, item.bytes, item.pointer, item.flags, item.uid, item.gid));
        assert(guarded == before);
        ++count;
    }
    assert(!dodge_apfs_ordinary_mount_args(nullptr, 336, 0x1000, 0, 0, 0)); ++count;
    for (uint32_t flags : {0u, 1u, 0x200000u, 0x200001u}) {
        std::array<unsigned char, 368> guarded; guarded.fill(0xa5);
        assert(dodge_apfs_ordinary_mount_args(guarded.data() + 16, 336, UINT64_C(0x123456789), flags, 42, 77));
        for (unsigned i = 0; i < 16; ++i) assert(guarded[i] == 0xa5 && guarded[352 + i] == 0xa5);
        DodgeOriginalApfsMountArgs decoded{};
        std::memcpy(&decoded, guarded.data() + 16, sizeof(decoded));
        assert(decoded.fspec == UINT64_C(0x123456789) && decoded.flags == flags && decoded.mode == 1);
        assert(decoded.ownerUID == 42 && decoded.ownerGID == 77 && decoded.tailPadding == 0);
        for (auto value : decoded.opaqueZero) assert(value == 0);
        assert(dodge_apfs_default_mount_owner(flags, 501) == ((flags & 0x200000) ? 99u : 501u));
        ++count;
    }
    std::printf("{\"result\":\"PASS\",\"case_count\":%u}\n", count);
}
