#!/usr/bin/env python3
"""Pin the original iPhone surface descriptor getter and prepare-call provenance."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, require, sha
from native_prelink import exports

PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392'
FIXTURE = PROFILE / 'surface-memory.json'
HEADER = PROFILE / 'graphics/OriginalIOSurfaceMemoryABI.h'


def derive():
    classes, raw, image, read = original_input()
    names = {n: a for a, group in exports(raw, image).items() for n in group}
    def words(a, n): return struct.unpack('<' + str(n) + 'I', read(a, n * 4))
    require(words(0xfffffff005a4e724, 2) == (0xf9401c00, 0xd65f03c0), 'Original borrowed descriptor getter changed')
    require(words(0xfffffff005a66ddc, 6) == (0xf9400e60, 0x97ff9e51, 0xf9400008, 0xf9406d08, 0x52800001, 0xd63f0100),
            'Original wired send-right does not prepare the getter result')
    require(words(0xfffffff005a66e48, 6) == (0xf9400e60, 0x97ff9e36, 0xf9400008, 0xf9407108, 0x52800001, 0xd63f0100),
            'Original wired send-right does not complete the getter result')
    slots = struct.unpack('<30Q', read(names['__ZTV18IOMemoryDescriptor'] + 16, 30 * 8))
    require(slots[27] == slots[28] == names['___cxa_pure_virtual'], 'Original descriptor prepare/complete base slots changed')
    blocks = {}
    for name, address, size in (
        ('descriptor', 0xfffffff005a4e724, 8), ('same_descriptor_getter', 0xfffffff005a4e71c, 8),
        ('surface_descriptor_set', 0xfffffff005a4e568, 0x58),
        ('region_subrange', 0xfffffff005a4bf74, 0x68),
        ('client_mapping_descriptor', 0xfffffff005a55400, 0x24),
        ('client_resource_descriptor', 0xfffffff005a5617c, 0x10),
        ('wired_right_prepare', 0xfffffff005a66dc0, 0x60),
        ('wired_right_complete', 0xfffffff005a66e20, 0x54),
    ):
        blocks[name] = {'address': hex(address), 'bytes': size, 'sha256': hashlib.sha256(read(address, size)).hexdigest()}
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': classes['original_kernelcache_sha256'],
        'bindings': {'_native_iphone_surface_memory': hex(0xfffffff005a4e724)}, 'blocks': blocks,
        'surface_descriptor_field': 56, 'surface_region_field': 48, 'getter_retains': False, 'getter_locks': False,
        'descriptor_virtual_slots': {'direction': 21, 'length': 22, 'physical_segment': 19, 'prepare': 27, 'complete': 28},
        'descriptor_source_for_gpu_import_acquired_automatically': False,
        'all_original_backing_mutation_serialization_qualified': False}


def checked():
    contract = derive(); pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_surface_memory']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and sha(FIXTURE) == pin['sha256'] and
            pin['header'] == str(HEADER.relative_to(ROOT)) and sha(HEADER) == pin['header_sha256'] and
            json.loads(FIXTURE.read_text()) == contract, 'Reviewed surface memory ABI changed')
    return contract, pin


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--record-fixture', action='store_true'); a = p.parse_args()
    if a.record_fixture:
        require(not FIXTURE.exists(), 'Surface memory fixture already exists'); FIXTURE.write_text(json.dumps(derive(), indent=2) + '\n')
    else: checked(); print('PASS: pinned original iPhone surface descriptor and prepare/complete provenance')


if __name__ == '__main__': main()
