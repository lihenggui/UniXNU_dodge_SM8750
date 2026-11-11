// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// One synchronous constructor on one thread. A surface import must consume
// exactly its own pointer/extent; nested calls and unrelated ranges refuse.
// The caller clears this scope even when Vulkan or the bridge refuses it.
struct DodgeSurfaceImportHint {
    uint64_t address=0,bytes=0;
    uint32_t id=0;
    bool used=false;
    bool begin(uint32_t surface,const void *pointer,uint64_t length) {
        const uint64_t start=reinterpret_cast<uintptr_t>(pointer);
        if(id || !surface || !start || !length || ((start|length)&4095) || start>UINT64_MAX-length)return false;
        address=start;bytes=length;id=surface;used=false;return true;
    }
    bool matches(const void *pointer,uint64_t length) const {
        return id && !used && reinterpret_cast<uintptr_t>(pointer)==address && length==bytes;
    }
    bool end() {const bool result=id && used;*this={};return result;}
};
