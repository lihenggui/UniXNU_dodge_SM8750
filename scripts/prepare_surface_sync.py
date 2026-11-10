#!/usr/bin/env python3
"""Derive the pinned iPhone IOSurface access/notification ABI from original code."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, require, sha

PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392'
FIXTURE = PROFILE / 'surface-sync.json'
HEADER = PROFILE / 'graphics/OriginalIOSurfaceSyncABI.h'


def derive():
    classes, _, _, read = original_input()
    def words(address, count): return struct.unpack('<' + str(count) + 'I', read(address, count * 4))
    require(words(0xfffffff005a51aa4, 12) == (
        0xaa0603e8, 0xaa0503e6, 0xaa0403e5, 0xaa0303e4, 0xaa0203e3, 0xaa0103f3,
        0xf90007ff, 0xb90003e7, 0x910023e2, 0xd2800001, 0xaa0803e7, 0x94000007),
        'Original eight-argument wrapper no longer supplies a null registration owner / stacked options')
    require(words(0xfffffff005a51b9c, 5) == (
        0x29046a98, 0xf94023e8, 0xa902ee88, 0xf9001e99, 0x7900a29f),
        'Original label/access/callback/target/context field writes changed')
    require(words(0xfffffff005a5192c, 8) == (
        0x3901429a, 0xf9401688, 0xb40000c8, 0xa9430680,
        0xb9404a83, 0xaa1303e2, 0xd63f0100, 0x14000004),
        'Original root-worker callback register order changed')
    require(words(0xfffffff005a62488, 6) == (
        0xaa0003e8, 0xf9400800, 0xb40000c0, 0xb9004901, 0xaa0803e1, 0x97ffbbef),
        'Original signal status writer / surface dispatch changed')
    require(words(0xfffffff005a621d0, 3) == (0x9126e000, 0x52801b01, 0x94001465),
        'Original notification allocation is no longer 216 bytes')
    blocks = {}
    for name, address, size in (
        ('register', 0xfffffff005a51a94, 0x58),
        ('register_inner', 0xfffffff005a51aec, 0x524),
        ('access_compatible', 0xfffffff005a51564, 0x70),
        ('surface_drain', 0xfffffff005a51680, 0x300),
        ('surface_use_increment', 0xfffffff005a4f3e4, 0xb4),
        ('surface_use_decrement', 0xfffffff005a4f4a0, 0xf8),
        ('notification_record', 0xfffffff005a51628, 0x58),
        ('signal', 0xfffffff005a62480, 0x38),
        ('surface_signal', 0xfffffff005a51458, 0xcc),
        ('root_enqueue', 0xfffffff005a5bd98, 0x70),
        ('root_worker', 0xfffffff005a593b0, 0x120),
        ('notifier_allocate', 0xfffffff005a621c0, 0x5c),
        ('notifier_init', 0xfffffff005a622c4, 0x38),
        ('notifier_retain', 0xfffffff005a62358, 0x18),
        ('notifier_release', 0xfffffff005a62370, 0x30),
        ('notifier_free', 0xfffffff005a6252c, 0x38),
        ('notifier_destroy', 0xfffffff005a620c8, 0x74),
        ('notifier_delete', 0xfffffff005a6213c, 0x30),
        ('family_registration', 0xfffffff005c17020, 0x388),
        ('family_callback', 0xfffffff005c17458, 0x124),
        ('family_enter_gate', 0xfffffff005c0bd38, 0xa8),
        ('family_callback_action', 0xfffffff005c0bde0, 0x1d0),
        ('family_ready_update', 0xfffffff005c0bfb0, 0x454),
    ):
        blocks[name] = {'address': hex(address), 'bytes': size,
                        'sha256': hashlib.sha256(read(address, size)).hexdigest()}
    vptr = 0xfffffff006d88928
    slots = struct.unpack('<16Q', read(vptr, 128))
    require(slots[4:6] == (0xfffffff005a62358, 0xfffffff005a62370) and
            slots[13:16] == (0xfffffff005a622c4, 0xfffffff005a622fc, 0xfffffff005a6252c),
            'Original notifier virtual lifetime identities differ')
    return {
        'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': classes['original_kernelcache_sha256'],
        'bindings': {'_native_iphone_surface_register_sync': hex(0xfffffff005a51a94),
                     '_native_iphone_surface_signal_sync': hex(0xfffffff005a62480)},
        'blocks': blocks,
        'registration_arguments': ['surface', 'retained_ticket_out', 'uint32_access', 'uint32_label',
                                   'callback', 'target', 'context', 'uint32_options'],
        'callback_arguments': ['target', 'context', 'surface', 'int32_status'],
        'tested_access': {'read': 1, 'write': 2}, 'tested_options': 0,
        'notification_bytes': 216, 'surface_bytes': 1168,
        'notification_vptr': hex(vptr), 'notification_metadata': hex(0xfffffff007a1e6f8),
        'notification_metadata_vptr': hex(0xfffffff006d889c0),
        'notification_layout': {'references': 12, 'surface': 16, 'registration_owner': 24,
            'label': 32, 'access': 36, 'callback': 40, 'target': 48, 'context': 56,
            'status': 72, 'completed': 76, 'callback_delivered': 80, 'active': 83,
            'surface_next': 88, 'surface_previous': 96, 'local_next': 104,
            'local_previous': 112, 'root_next': 120, 'root_previous': 128},
        'surface_layout': {'root': 40, 'lock': 128, 'use_state': 192,
            'active_head': 536, 'active_tail': 544, 'pending_head': 552, 'pending_tail': 560,
            'notification_history': 992},
        'root_layout': {'event_source': 432, 'lock': 440, 'head': 448, 'tail': 456},
        'immediate_grant_invokes_own_callback': False,
        'pending_result_can_return_retained_ticket': True,
        'writer_error_automatically_propagates_to_waiting_reader': False,
        'gpu_quiescence_or_cache_visibility_qualified': False,
    }


def checked():
    contract = derive()
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_surface_sync']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and sha(FIXTURE) == pin['sha256'] and
            pin['header'] == str(HEADER.relative_to(ROOT)) and sha(HEADER) == pin['header_sha256'] and
            json.loads(FIXTURE.read_text()) == contract, 'Reviewed iPhone IOSurface sync ABI changed')
    return contract, pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record-fixture', action='store_true')
    args = parser.parse_args()
    if args.record_fixture:
        require(not FIXTURE.exists(), 'Surface sync fixture already exists')
        FIXTURE.write_text(json.dumps(derive(), indent=2) + '\n')
    else:
        contract, _ = checked()
        print('PASS: pinned iPhone IOSurface notification ABI /', len(contract['blocks']), 'original blocks')


if __name__ == '__main__': main()
