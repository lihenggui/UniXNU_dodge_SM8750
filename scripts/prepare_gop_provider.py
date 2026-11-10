#!/usr/bin/env python3
"""Derive the real iPhone AppleARMIODevice allocation/public-init contract."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, require
from native_prelink import exports
from prepare_graphics_lifecycle import derive as graphics_contract

FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/gop-provider.json'
HEADER = FIXTURE.parent / 'graphics/OriginalGopProviderABI.h'


def derive():
    graphics = graphics_contract()
    classes, raw, image, read = original_input()
    public = exports(raw, image)
    names = {n: a for a, group in public.items() for n in group}

    def words(pc, count):
        return struct.unpack('<' + str(count) + 'I', read(pc, count * 4))

    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Provider ADRP changed')
        immediate = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & ~4095) + ((immediate - (1 << 21) if immediate & (1 << 20) else immediate) << 12)

    def branch(pc):
        word, = words(pc, 1)
        require(word & 0xfc000000 == 0x94000000, 'Provider BL changed')
        value = word & 0x3ffffff
        return pc + 4 * (value - (1 << 26) if value & (1 << 25) else value)

    def stub(pc):
        a, b, c = words(pc, 3)
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200,
                'Provider native import stub changed')
        return struct.unpack('<Q', read(adrp(pc, a) + ((b >> 10) & 4095) * 8, 8))[0]

    setup = int(graphics['provider_requirement']['metadata_constructor']['address'], 16)
    a, b = words(setup + 16, 2)
    parent, = struct.unpack('<Q', read(adrp(setup + 16, a) + ((b >> 10) & 4095) * 8, 8))
    require(parent == names['__ZN9IOService10gMetaClassE'], 'AppleARMIODevice is not a direct IOService subclass')
    require(stub(branch(setup + 28)) == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'Provider metadata constructor changed')
    a, b = words(setup + 32, 2)
    meta_vptr = adrp(setup + 32, a) + ((b >> 10) & 4095)
    allocator, = struct.unpack('<Q', read(meta_vptr + 13 * 8, 8))
    require(allocator == 0xfffffff0055f7ba0, 'Provider metadata allocation dispatch changed')
    w = words(allocator, 21)
    require(w[5] == 0x52801b01 and stub(branch(allocator + 24)) == names['_OSObject_typed_operator_new'] and
            stub(branch(allocator + 44)) == names['__ZN9IOServiceC2EPK11OSMetaClass'] and
            stub(branch(allocator + 64)) == names['__ZNK11OSMetaClass19instanceConstructedEv'],
            'Provider allocation must use the original typed allocation and native constructor/accounting')
    meta = int(graphics['provider_requirement']['metaclass'], 16)
    require(adrp(allocator + 32, w[8]) + ((w[9] >> 10) & 4095) == meta,
            'Provider allocator uses different metadata')
    vptr = adrp(allocator + 48, w[12]) + ((w[13] >> 10) & 4095)
    require(w[14] == 0xf9000008 and vptr == 0xfffffff006c7df38, 'Provider allocator does not install its actual original vtable')
    table = struct.unpack('<178Q', read(vptr, 178 * 8))
    native = struct.unpack('<168Q', read(names['__ZTV9IOService'] + 16, 168 * 8))
    overridden = [i for i in range(168) if table[i] != native[i]]
    require(overridden == [0, 1, 7, 64, 103, 119], 'Provider inherited/public dispatch changed')
    # These are public IOService operations used by the GOP-only factory and
    # display. In particular slot 21 is inherited, not the Apple bus-specific
    # initializer at 168. The latter must never be called with a Qualcomm bus.
    required = ('__ZN9IOService4initEP12OSDictionary', '__ZN9IOService6attachEPS_',
                '__ZN9IOService6detachEPS_', '__ZN9IOService15registerServiceEj',
                '__ZN9IOService15setDeviceMemoryEP7OSArray', '__ZN9IOService20getDeviceMemoryCountEv',
                '__ZN9IOService24getDeviceMemoryWithIndexEj', '__ZN9IOService24mapDeviceMemoryWithIndexEjj')
    slots = {}
    for name in required:
        require(name in names, 'Missing public provider operation: ' + name)
        indices = [i for i, a in enumerate(table) if a == names[name]]
        require(len(indices) == 1, 'Provider public operation is overridden or ambiguous: ' + name)
        slots[name] = indices[0]
    require(slots['__ZN9IOService4initEP12OSDictionary'] == 21 and table[168] == 0xfffffff0055f8178,
            'Provider public initialization path differs')
    # Original getResources returns Success immediately when explicit device
    # memory exists, without traversing an AppleARMIO ancestor.
    get_resources = table[119]
    require(words(get_resources + 20, 4) == (0xf9400008, 0xf941ed08, 0xd63f0100, 0xb50002e0) and
            table[123] == names['__ZN9IOService15getDeviceMemoryEv'],
            'Provider getResources memory-first branch changed')
    # Use complete pinned bodies as evidence, not generated replacements.
    blocks = [('metadata_constructor', setup, 52), ('allocator', allocator, 84),
              ('get_resources', get_resources, 156), ('bus_initializer_not_called', table[168], 564)]
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
            'original_kernelcache_sha256': classes['original_kernelcache_sha256'], 'slide': graphics['slide'],
            'class': 'AppleARMIODevice', 'instance_bytes': 216, 'metaclass': hex(meta),
            'linked_metaclass': hex(meta + int(graphics['slide'], 0)), 'parent': 'IOService',
            'parent_metaclass': hex(parent), 'metadata_vptr': hex(meta_vptr), 'vptr': hex(vptr),
            'vtable_entries': 178, 'vtable_sha256': hashlib.sha256(read(vptr, 178 * 8)).hexdigest(),
            'public_io_service_slots': slots, 'overridden_io_service_slots': overridden,
            'blocks': {name: {'address': hex(a), 'bytes': n, 'sha256': hashlib.sha256(read(a, n)).hexdigest()}
                       for name, a, n in blocks},
            'alias': '_dodge_original_gop_provider_meta', 'public_init_inherited': True,
            'original_bus_initializer_used': False, 'private_fields_written_by_source': False,
            'apple_clock_and_bus_methods_qualified': False, 'hardware_tested': False}


def header(fixture):
    return ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n'
            '// Derived from the pinned iPhone10,3 / 20H392 original class.\n#pragma once\n'
            'extern "C" const unsigned char dodge_original_gop_provider_meta[];\n'
            'constexpr char DodgeGopProviderClass[]="AppleARMIODevice";\n'
            'constexpr unsigned DodgeGopProviderBytes=216;\n')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    fixture = derive()
    if args.write:
        require(not FIXTURE.exists() and not HEADER.exists(), 'Refuse to replace reviewed GOP provider inputs')
        FIXTURE.write_text(json.dumps(fixture, indent=2) + '\n'); HEADER.write_text(header(fixture))
    require(json.loads(FIXTURE.read_text()) == fixture and HEADER.read_text() == header(fixture), 'GOP provider contract changed')
    print('PASS: original AppleARMIODevice allocator, 178 vtable slots and inherited public init derived')


if __name__ == '__main__':
    main()
