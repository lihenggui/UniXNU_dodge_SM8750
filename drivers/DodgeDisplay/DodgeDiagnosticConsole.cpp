// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <IOKit/IOMemoryDescriptor.h>
#include <pexpert/pexpert.h>
#include <stdint.h>

extern "C" {
int boot_progress_bind_post_vm(uintptr_t, unsigned, unsigned, unsigned, unsigned);
void boot_progress_overlay_rows(uint32_t *, uint32_t *);
void boot_progress_overlay_preserve(int);
void boot_progress_platform_enable(int);
void boot_progress_start(void);

// The single console retains its real map until kernel shutdown. The renderer
// rejects rebinds; panic and polling may continue to use that mapping.
// Serialize this first attachment before installing console/panic observers.
bool dodge_diagnostic_console_attach(IOMemoryMap *mapping) {
    PE_Video video = {};
    if (!mapping || PE_current_console(&video) || !video.v_baseAddr ||
        !video.v_width || !video.v_height || video.v_width > 8192 || video.v_height > 8192 ||
        video.v_depth != 32 || video.v_rotate || video.v_rowBytes < video.v_width * 4 ||
        video.v_rowBytes > 32768 || video.v_rowBytes > UINT64_MAX / video.v_height ||
        video.v_baseAddr > UINT64_MAX - video.v_rowBytes * video.v_height ||
        mapping->getLength() != video.v_rowBytes * video.v_height ||
        mapping->getPhysicalAddress() != video.v_baseAddr || !mapping->getVirtualAddress()) return false;
    mapping->retain();
    if (!boot_progress_bind_post_vm(mapping->getVirtualAddress(), video.v_width, video.v_height,
                                   video.v_rowBytes, video.v_depth)) {
        mapping->release();
        return false;
    }
    boot_progress_platform_enable(1);
    boot_progress_start();
    return true;
}

void native_legacy_overlay_rows(uint32_t *first, uint32_t *rows) {
    boot_progress_overlay_rows(first, rows);
}

void native_legacy_overlay_preserve(int enabled) {
    boot_progress_overlay_preserve(enabled);
}
}
