// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_address_t;
typedef struct { uint64_t value;unsigned char padding[56]; } Slot;
static Slot slots[8];
static struct { vm_offset_t start,end; } percpu_base;
static size_t percpu_section_size(void) { return sizeof(Slot); }
#define percpu_slot_counter slots[0]
#define __unsafe_forge_bidi_indexable(type, pointer, bytes) ((type)(pointer))
#include "PerCpuMacros.inc"

static void setup(unsigned cpus) {
    for(unsigned i=0;i<8;i++)slots[i].value=i+1;
    percpu_base.start=cpus==1?UINT64_C(0xfffffffbffffffff):sizeof(Slot);
    percpu_base.end=cpus==1?0:cpus*sizeof(Slot)-1;
}
static void valid(Slot *slot,unsigned cpus) {
    uintptr_t address=(uintptr_t)slot;
    assert(address>=(uintptr_t)slots && address<(uintptr_t)slots+cpus*sizeof(Slot));
    assert((address-(uintptr_t)slots)%sizeof(Slot)==0);
}
int main(void) {
    const unsigned counts[]={1,2,3,8};unsigned cases=0;
    for(unsigned index=0;index<4;index++) {
        unsigned cpus=counts[index];setup(cpus);unsigned count=0;uint64_t sum=0;
        percpu_foreach(slot,counter) { valid(slot,cpus);sum+=slot->value;count++; }
        assert(count==cpus && sum==cpus*(cpus+1)/2);cases++;
        count=0;sum=0;
        percpu_foreach_secondary(slot,counter) { valid(slot,cpus);sum+=slot->value;count++; }
        assert(count==cpus-1 && sum==cpus*(cpus+1)/2-1);cases++;
        count=0;percpu_foreach_base(base) { assert(base==count*sizeof(Slot));count++; }
        assert(count==cpus);cases++;
        count=0;percpu_foreach_secondary_base(base) { assert(base==(count+1)*sizeof(Slot));count++; }
        assert(count==cpus-1);cases++;
        count=0;percpu_foreach(slot,counter) { valid(slot,cpus);count++;break; }
        assert(count==1);cases++;
        count=0;percpu_foreach(slot,counter) { valid(slot,cpus);if(slot==&slots[0])continue;count++; }
        assert(count==cpus-1);cases++;
        count=0;percpu_foreach(outer,counter) {
            valid(outer,cpus);percpu_foreach(inner,counter) { valid(inner,cpus);count++; }
        }
        assert(count==cpus*cpus);cases++;
        percpu_foreach_secondary(slot,counter) { valid(slot,cpus);slot->value+=10; }
        for(unsigned i=0;i<8;i++)assert(slots[i].value==i+1+(i && i<cpus?10:0));cases++;
    }
    const uintptr_t empty[]={UINTPTR_MAX,UINT64_C(0x8000000000000000),UINT64_C(0xfffffffbffffffff)};
    for(unsigned i=0;i<3;i++) {
        setup(1);percpu_base.start=empty[i];unsigned count=0;
        percpu_foreach_secondary(slot,counter) { (void)slot;count++;break; }
        assert(!count);cases++;
        percpu_foreach(slot,counter) { valid(slot,1);count++; }
        assert(count==1);cases++;
    }
    assert(cases==38);
    printf("{\"cases\":%u,\"cpu_counts\":[1,2,3,8],\"empty_sentinels\":3}\n",cases);
}
