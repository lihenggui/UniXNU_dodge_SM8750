#!/usr/bin/env python3
"""Observe original iPhone keybagd using the native VM state service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from build_qemu_keystore import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_exec import REPORT as EXEC_REPORT, check_report as check_exec, execute
from check_qemu_aes import owner_resources, cstring
from check_qemu_systemos import follow_cache
from check_qemu_storage import Remote, ENTRY_REPORT, check_entry
from native_driver_build import ROOT, require, symbols
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha
from qemu_user_state import compile_layout

OUT = ROOT / 'build/cph2653-qemu-keystore-entry'
REPORT = ROOT / 'reports/ios16-qemu-keystore-entry.json'
FIELDS = ('phase', 'result', 'opened', 'refused', 'calls', 'selector', 'call_result')


def state(remote, names):
    return {name: int.from_bytes(remote.memory(names['_dodge_qemu_keystore_' + name], 4), 'little') for name in FIELDS}


def follow_userland(originals, cache, closed, layout):
    dyld = (ROOT / originals['dyld']['local']).read_bytes()
    dyld_names = {row['name']: row['value'] for row in symbols(dyld) if row['kind'] & 14}

    def follow(remote, result, names):
        follow_cache(originals, cache)(remote, result, names)
        slide = int(result['user_entry']['dyld_slide'], 0)
        old_points = [slide + dyld_names[name] for name in
            ('__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE', '__ZN5dyld44haltEPKc')]
        old_points.append(int(result['SystemOS_events'][-1]['pc'], 0))
        for address in old_points:
            require(Remote.packet(remote, f'z1,{address:x},4') == 'OK', 'Cannot release init checkpoint')
        main_pc = old_points[-1]
        require(Remote.packet(remote, 's').startswith('T05'), 'Cannot execute original launchd main')
        after = bytes.fromhex(Remote.packet(remote, 'g'))
        require(struct.unpack_from('<33Q', after)[32] == main_pc + 4 and
            struct.unpack_from('<I', after, 264)[0] & 15 == 0, 'Original launchd main instruction did not execute')
        result['launchd_main_instruction_executed'] = True
        points = {names['_unix_syscall']: 'syscall', names['_dodge_qemu_keystore_call_checkpoint']: 'KeyStore'}
        result['KeyStore_calls'] = [];result['console'] = [];text = '';reached = False
        for address in points:
            require(Remote.packet(remote, f'Z1,{address:x},4') == 'OK', 'Cannot observe original userland')
        for _ in range(12000):
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected userland stop')
            registers = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', registers);pc = values[32]
            if pc == names['_panic']:
                raise ValueError('Kernel panic before the KeyStore checkpoint: ' + cstring(remote, values[0]))
            require(pc in points, 'Userland stopped outside its checkpoints')
            label = points[pc]
            if label == 'syscall' and reached:
                result['KeyStore_state'] = state(remote, names)
                require(result['KeyStore_state']['phase'] == 2 and result['KeyStore_state']['result'] == 0,
                    'Native KeyStore did not register')
                tests = re.findall(r'PASSED: .* - (fipspost_post_\w+)', text)
                require(len(tests) == len(set(tests)) == 20 and 'all tests PASSED' in text and
                    'corecrypto.dylib: result = true' in text, 'Original userspace crypto POST is incomplete')
                result['userspace_crypto_POST'] = tests
                result['system_bag_handle_accepted'] = not closed
                result['stopped_before_reboot_request'] = True
                current = result['KeyStore_state']
                if closed:
                    require(current['opened'] == 0 and current['refused'] > 0 and not result['KeyStore_calls'],
                        'Closed KeyStore did not refuse the original client')
                else:
                    require(current['opened'] == 1 and current['refused'] == 0 and
                        [row['selector'] for row in result['KeyStore_calls']] == [0, 14, 14] and
                        all(row['call_result'] == 0 for row in result['KeyStore_calls']), 'Original libaks handshake differs')
                return
            if label == 'syscall':
                saved = values[0]
                number = int.from_bytes(remote.memory(saved + layout['x'] + 16 * 8, 8), 'little') & 65535
                if number in (4, 397):
                    result['KeyStore_state'] = state(remote, names)
                    svc = int.from_bytes(remote.memory(saved + layout['pc'], 8), 'little') - 4
                    if svc not in points:
                        points[svc] = 'console'
                        require(Remote.packet(remote, f'Z1,{svc:x},4') == 'OK', 'Cannot observe original write')
            elif label == 'KeyStore':
                row = state(remote, names);result['KeyStore_calls'].append(row);result['KeyStore_state'] = row
                require(len(result['KeyStore_calls']) < 256, 'Unbounded KeyStore calls')
                print('QEMU KeyStore:', row['selector'], hex(row['call_result']), flush=True)
            else:
                require(struct.unpack_from('<I', registers, 264)[0] & 15 == 0, 'Console checkpoint is outside EL0')
                try:message = remote.memory(values[1], min(values[2], 4096)).decode(errors='replace')
                except ValueError:message = ''
                if message:
                    result['console'].append({'fd': values[0], 'text': message});text += message
                    require(len(text) <= 262144, 'Unbounded original console output')
                    if 'MKB_INIT:' in message or 'all tests PASSED' in message:
                        print('QEMU userland:', message.strip(), flush=True)
                target = 'failed to load system bag' if closed else 'MKB_INIT: System Keybag loaded'
                reached = target in text
            remote.save()
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release userland checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step userland checkpoint')
            require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore userland checkpoint')
        raise ValueError('Original userland did not reach its KeyStore checkpoint')
    return follow


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_KEYSTORE_HANDSHAKE_AND_REFUSAL_PASS' and
        report['positive']['system_bag_handle_accepted'] and not report['negative_control']['system_bag_handle_accepted'] and
        not report['hardware_tested'] and not report['hardware_data_protection'] and not report['keybag_boot_task_complete'],
        'Incomplete KeyStore execution report')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / path) == digest, 'KeyStore execution input changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original iPhone KeyStore handshake and closed-client refusal');return
    require(60 <= args.timeout <= 1200, 'Choose 60..1200 seconds per userland case')
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);policy = json.loads(POLICY_REPORT.read_text())
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require((cache_input['product'], cache_input['build']) == ('iPhone10,3', '20H392') and
        file_sha(ROOT / cache['path']) == cache['sha256'], 'Wrong original iPhone shared cache')
    volume_path = ROOT / 'reports/ios16-volumes.json';images = json.loads(volume_path.read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original volume changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']];qemu, firmware, variables, rom = emulator
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    anchor = ROOT / policy['images'][0]['anchor'];results = {};source_paths = []
    layout, artifacts = compile_layout(OUT / 'layout')
    for case, closed in (('positive', False), ('closed', True)):
        source_path = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-closed.json') if closed else SOURCE_REPORT
        source = json.loads(source_path.read_text());check_source(source)
        require(source['closed_control'] == closed, 'Wrong KeyStore control kernel')
        result, extra = execute('positive', source, (qemu, firmware, variables, rom.parent), environment, images,
            board_path.read_bytes(), policy, previous['Darwin22_layout'], previous['original_files'], args.timeout,
            directory_root=OUT / case, resource_factory=owner_resources(anchor.read_bytes()),
            after_user_instruction=follow_userland(previous['original_files'], cache, closed, layout))
        results[case] = result;artifacts += extra + [ROOT / source['candidate']];source_paths.append(source_path)
    artifacts += emulator + [board_path, anchor, ROOT / cache['path'], *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_KEYSTORE_HANDSHAKE_AND_REFUSAL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (Path(__file__), *(ROOT / ('scripts/' + name + '.py') for name in
                ('check_qemu_exec', 'check_qemu_aes', 'check_qemu_systemos', 'check_qemu_storage', 'qemu_user_state')))},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (*source_paths, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT, cache_report, volume_path)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'positive': results['positive'], 'negative_control': results['closed'],
        'Darwin22_saved_state_layout': layout,
        'hardware_tested': False, 'hardware_data_protection': False, 'keybag_boot_task_complete': False,
        'phone_operations': 'none',
        'scope': 'Original launchd runs the userspace crypto POST and starts keybagd. Original libaks accepts the '
                 'native open handshake and the system handle. The closed service refuses the same original client. '
                 'Each run stops at its observed result; writable Data, keybag file loading and later services are separate work.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original userspace crypto POST, native KeyStore handshake and closed-client refusal')


if __name__ == '__main__':main()
