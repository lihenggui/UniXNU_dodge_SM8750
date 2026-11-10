// SPDX-License-Identifier: MIT
#include <IOKit/IOMemoryDescriptor.h>
#include <pexpert/pexpert.h>
#include <cstdio>

extern "C" {
bool dodge_diagnostic_console_attach(IOMemoryMap *);
void native_legacy_overlay_rows(uint32_t *, uint32_t *);
void native_legacy_overlay_preserve(int);
}
static PE_Video video;
static int peStatus, bindResult = 1, preserved;
static unsigned binds, starts, enabled;
static uintptr_t boundAddress;
extern "C" int PE_current_console(PE_Video *out) { *out = video; return peStatus; }
extern "C" int boot_progress_bind_post_vm(uintptr_t p, unsigned w, unsigned h, unsigned pitch, unsigned depth) {
    ++binds; boundAddress = p;
    assert(w == video.v_width && h == video.v_height && pitch == video.v_rowBytes && depth == video.v_depth);
    return bindResult;
}
extern "C" void boot_progress_overlay_rows(uint32_t *first, uint32_t *rows) { *first = 168; *rows = 420; }
extern "C" void boot_progress_overlay_preserve(int value) { preserved = value; }
extern "C" void boot_progress_platform_enable(int value) { assert(value == 1); ++enabled; }
extern "C" void boot_progress_start() { ++starts; }

static void reset() {
    video = {}; peStatus = 0; bindResult = 1;
    binds = starts = enabled = 0; boundAddress = 0;
}
template <class Change> static void refusal(Change change) {
    reset(); IOMemoryMap map; change(map);
    assert(!dodge_diagnostic_console_attach(&map));
    assert(map.refs == 1 && !map.retains && !binds && !enabled && !starts);
}
int main() {
    reset(); assert(!dodge_diagnostic_console_attach(nullptr) && !binds);
    refusal([](auto &) { peStatus = 1; });
    refusal([](auto &) { video.v_baseAddr = 0; });
    refusal([](auto &) { video.v_width = 0; });
    refusal([](auto &) { video.v_height = 0; });
    refusal([](auto &) { video.v_width = 8193; });
    refusal([](auto &) { video.v_height = 8193; });
    refusal([](auto &) { video.v_depth = 16; });
    refusal([](auto &) { video.v_rotate = 1; });
    refusal([](auto &) { video.v_rowBytes = 5759; });
    refusal([](auto &) { video.v_rowBytes = 32769; });
    refusal([](auto &) { video.v_baseAddr = UINT64_MAX - 3; });
    refusal([](auto &map) { --map.bytes; });
    refusal([](auto &map) { map.physical += 4096; });
    refusal([](auto &map) { map.address = 0; });
    reset(); IOMemoryMap rejected;
    bindResult = 0;
    assert(!dodge_diagnostic_console_attach(&rejected));
    assert(rejected.refs == 1 && rejected.retains == 1 && rejected.releases == 1 && binds == 1 && !enabled && !starts);
    reset(); IOMemoryMap accepted;
    assert(dodge_diagnostic_console_attach(&accepted));
    assert(accepted.refs == 2 && accepted.retains == 1 && !accepted.releases && binds == 1 && enabled == 1 && starts == 1);
    assert(boundAddress == accepted.address);
    accepted.release(); // Test teardown represents the boot-lifetime map owner.
    uint32_t first = 0, rows = 0;
    native_legacy_overlay_rows(&first, &rows);
    assert(first == 168 && rows == 420);
    native_legacy_overlay_preserve(7);
    assert(preserved == 7);
    puts("PASS: console adapter map ownership, 15 input refusals, failed bind release and real forwarding calls (software peers)");
}
