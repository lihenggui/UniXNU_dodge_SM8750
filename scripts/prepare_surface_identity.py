#!/usr/bin/env python3
"""Pin the original iPhone task-aware IOSurface lookup and custom lifetime."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, require, sha

PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392'
FIXTURE = PROFILE / 'surface-identity.json'
HEADER = PROFILE / 'graphics/OriginalIOSurfaceIdentityABI.h'


def derive():
    classes, _, _, read = original_input()
    def words(address, count): return struct.unpack('<' + str(count) + 'I', read(address, count * 4))
    require(words(0xfffffff005c1531c, 5) == (0x94004854, 0xb9403fe1, 0xaa0003e2, 0xf94023e0, 0x940046e2),
            'Original display no longer calls the task-aware surface resolver')
    # Verify the instance constructor and virtual overrides, not a symbol guess.
    require(words(0xfffffff005a472c4, 3) == (0xf00099e8, 0x91010108, 0xf9000008),
            'Original IOSurface constructor vptr changed')
    vptr = 0xfffffff006d86040
    slots = struct.unpack('<16Q', read(vptr, 128))
    require(slots[4:6] == (0xfffffff005a4c2e4, 0xfffffff005a4c2ec) and
            words(0xfffffff005a4c2dc, 1) == (0x910fa000,) and
            words(0xfffffff005a59ba8, 3) == (0xb9400e68, 0x6b14011f, 0x54001181),
            'Original surface ID / custom reference counter identities differ')
    def import_target(stub):
        x, y, z = words(stub, 3)
        require(x & 0x9f00001f == 0x90000010 and y & 0xffc003ff == 0xf9400210 and z == 0xd61f0200,
                'Original identity import stub changed')
        delta = ((x >> 5) & 0x7ffff) * 4 + ((x >> 29) & 3)
        if delta & (1 << 20): delta -= 1 << 21
        address = (stub & -4096) + (delta << 12) + ((y >> 10) & 4095) * 8
        return struct.unpack('<Q', read(address, 8))[0]
    require(import_target(0xfffffff005c26eb4) == 0xfffffff005a59e04 and
            import_target(0xfffffff005c2746c) == 0xfffffff00722e408,
            'Original display lookup/current_task imports changed')
    blocks = {}
    for name, address, size in (
        ('copy_for_task', 0xfffffff005a59e04, 0xa0),
        ('authorize', 0xfffffff005a59b14, 0x2f0),
        ('copy_task_client', 0xfffffff005a59ea4, 0xcc),
        ('client_has_surface', 0xfffffff005a612b8, 0x24),
        ('client_surface_entry', 0xfffffff005a60d80, 0xf0),
        ('root_singleton', 0xfffffff005a58700, 0xc),
        ('surface_try_retain', 0xfffffff005a4c2dc, 8),
        ('surface_retain', 0xfffffff005a4c2e4, 8),
        ('surface_release', 0xfffffff005a4c2ec, 0x48),
        ('atomic_retain', 0xfffffff005a66464, 0x14),
        ('retain_guard', 0xfffffff005a66478, 0x28),
        ('atomic_try_retain', 0xfffffff005a664a0, 0x6c),
        ('atomic_release', 0xfffffff005a6650c, 0xcc),
        ('surface_constructor', 0xfffffff005a472a4, 0x80),
        ('root_metadata_constructor', 0xfffffff005a5ca04, 0x50),
        ('userclient_metadata_constructor', 0xfffffff005a61f84, 0x3c),
        ('display_lookup_callsite', 0xfffffff005c152f8, 0x50),
        ('display_lookup_import', 0xfffffff005c26eb4, 0xc),
        ('display_current_task_import', 0xfffffff005c2746c, 0xc),
    ):
        blocks[name] = {'address': hex(address), 'bytes': size,
                        'sha256': hashlib.sha256(read(address, size)).hexdigest()}
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': classes['original_kernelcache_sha256'],
        'bindings': {'_native_iphone_surface_copy_for_task': hex(0xfffffff005a59e04)},
        'blocks': blocks, 'surface_vptr': hex(vptr), 'root_singleton_global': hex(0xfffffff007a1e6c8),
        'root_bytes': 1136, 'userclient_bytes': 312, 'surface_bytes': 1168, 'client_entry_bytes': 152,
        'surface_layout': {'id': 12, 'root': 40, 'owner_task': 112, 'restricted': 867, 'references': 1000},
        'root_layout': {'surface_table': 192, 'surface_count': 200, 'surface_lock': 280,
            'policy_flags': 404, 'client_lock': 984, 'client_count': 992, 'next_cache': 1000,
            'cache_task_0': 1008, 'cache_client_0': 1016, 'cache_task_1': 1024,
            'cache_client_1': 1032, 'client_pairs': 1048},
        'userclient_layout': {'lock': 216, 'entry_table': 256, 'entry_count': 264, 'task': 272},
        'client_entry_layout': {'task': 16, 'surface': 64},
        'successful_lookup_owns_reference': True, 'original_authorization_may_allow_global_sharing': True,
        'lookup_holds_backing_stable_after_return': False, 'producer_registered_by_lookup': False}


def checked():
    contract = derive()
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_surface_identity']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and sha(FIXTURE) == pin['sha256'] and
            pin['header'] == str(HEADER.relative_to(ROOT)) and sha(HEADER) == pin['header_sha256'] and
            json.loads(FIXTURE.read_text()) == contract, 'Reviewed IOSurface identity ABI changed')
    return contract, pin


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--record-fixture', action='store_true'); a = p.parse_args()
    if a.record_fixture:
        require(not FIXTURE.exists(), 'Surface identity fixture already exists')
        FIXTURE.write_text(json.dumps(derive(), indent=2) + '\n')
    else:
        contract, _ = checked(); print('PASS: pinned task-aware IOSurface identity /', len(contract['blocks']), 'original blocks')


if __name__ == '__main__': main()
