// SPDX-License-Identifier: BSD-2-Clause-Patent
// The original regression includes the actual staged renderer. Its software
// clocks/IRQ peers do not enter any production object.
#define main reference_console_main
#include CONSOLE_REFERENCE_TEST
#undef main

int main(void) {
    assert(reference_console_main() == 0);
    boot_args empty = {0};
    early_boot_progress_init(&empty);
    enum { W = 720, H = 720, PITCH = 727, GUARD = 32 };
    uint32_t *memory = malloc((PITCH * H + 2 * GUARD) * sizeof(*memory));
    assert(memory);
    for (unsigned i = 0; i < PITCH * H + 2 * GUARD; ++i) memory[i] = 0x13579bdf;
    uintptr_t base = (uintptr_t)(memory + GUARD);
    assert(!boot_progress_bind_post_vm(0, W, H, PITCH * 4, 32));
    assert(!boot_progress_bind_post_vm(base + 1, W, H, PITCH * 4, 32));
    assert(!boot_progress_bind_post_vm(base, W, H, W * 4 - 1, 32));
    assert(!boot_progress_bind_post_vm(base, W, H, PITCH * 4, 16));
    assert(!framebuffer);
    console_lock = 1;
    assert(!boot_progress_bind_post_vm(base, W, H, PITCH * 4, 32) && console_lock == 1);
    console_lock = 0;
    panic_state = 1;
    assert(!boot_progress_bind_post_vm(base, W, H, PITCH * 4, 32) && !console_lock);
    panic_state = 0; panic_cpu = 1;
    assert(!boot_progress_bind_post_vm(base, W, H, PITCH * 4, 32) && !console_lock);
    panic_cpu = 0;
    assert(boot_progress_bind_post_vm(base, W, H, PITCH * 4, 32));
    assert(framebuffer == base && console_smp && !console_lock);
    assert(!boot_progress_bind_post_vm(base, W, H, PITCH * 4, 32));
    assert(framebuffer == base && !console_lock);
    test_gpu = 1;
    boot_progress_platform_enable(1);
    uint32_t first, rows;
    boot_progress_overlay_rows(&first, &rows);
    assert(first == 4 * LINE && rows == (3 + PAGANI_GPU_ROWS) * LINE);
    assert(boot_progress_display_handoff());
    boot_progress_overlay_preserve(1);
    boot_progress_peripheral_frame();
    unsigned painted = 0;
    for (unsigned y = 0; y < H; ++y) for (unsigned x = 0; x < PITCH; ++x) {
        uint32_t pixel = memory[GUARD + y * PITCH + x];
        if (x >= W || y < first || y >= first + rows) assert(pixel == 0x13579bdf);
        else painted += pixel != 0x13579bdf;
    }
    assert(painted > 1000);
    for (unsigned i = 0; i < GUARD; ++i) {
        assert(memory[i] == 0x13579bdf);
        assert(memory[GUARD + PITCH * H + i] == 0x13579bdf);
    }
    framebuffer = 0; // Software worker is inert; the production map is boot-lived.
    free(memory);
    puts("PASS: post-VM bind refusals, lock/panic ownership, one bind and actual overlay-band pixel bounds");
    return 0;
}
