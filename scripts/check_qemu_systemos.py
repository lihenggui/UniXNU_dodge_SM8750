#!/usr/bin/env python3
"""Run the iPhone SystemOS union, original shared cache and UUID refusal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from build_qemu_systemos import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_exec import REPORT as EXEC_REPORT, check_report as check_exec, execute
from check_qemu_aes import owner_resources, counters, cstring
from check_qemu_storage import run_case, Remote, ENTRY_REPORT, check_entry
from native_driver_build import ROOT, require, symbols, macho
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha

OUT = ROOT / 'build/cph2653-qemu-systemos-entry'
REPORT = ROOT / 'reports/ios16-qemu-systemos-entry.json'
FIELDS = ('stage', 'status', 'mount_status', 'readonly', 'authorized', 'root_recheck', 'native_union',
    'selected_device', 'mounted_device', 'actual_mount_flags', 'original_root', 'current_root')


def cache_state(remote, names):
    result = {name: int.from_bytes(remote.memory(names['_native_owner_cache_' + name],
        8 if name in ('actual_mount_flags', 'original_root', 'current_root') else 4), 'little') for name in FIELDS}
    result['actual_root_vnode'] = int.from_bytes(remote.memory(names['_rootvnode'], 8), 'little')
    result['dyld_flags'] = int.from_bytes(remote.memory(names['_dyld_flags'], 8), 'little')
    result['verified_blocks'] = int.from_bytes(remote.memory(names['_native_virtio_verified_blocks'], 8), 'little')
    result['integrity_failures'] = int.from_bytes(remote.memory(names['_native_virtio_integrity_failures'], 4), 'little')
    return result


def follow_cache(originals, cache):
    dyld = (ROOT / originals['dyld']['local']).read_bytes()
    dyld_names = {row['name']: row['value'] for row in symbols(dyld) if row['kind'] & 14}
    launchd = (ROOT / originals['launchd']['local']).read_bytes()
    command, = [at for kind, at, _ in macho(launchd)['commands'] if kind == 0x80000028]
    main_offset = struct.unpack_from('<Q', launchd, command + 8)[0]
    with (ROOT / cache['path']).open('rb') as stream:cache_header = stream.read(512)

    def follow(remote, result, names):
        slide = int(result['user_entry']['dyld_slide'], 0)
        points = {names['_unix_syscall']: 'kernel-state',
            slide + dyld_names['__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE']: 'cache-entry',
            slide + dyld_names['__ZN5dyld44haltEPKc']: 'dyld-halt'}
        pending = None;events = [];result['SystemOS_events'] = events;result['launchd_main_entered'] = False
        main_header = int.from_bytes(remote.memory(int(result['after_instruction']['original_sp'], 0), 8), 'little')
        require(main_header > 0 and main_header & 4095 == 0, 'Invalid original init Mach-O address')
        points[main_header + main_offset] = 'launchd-main'
        for address in points:require(Remote.packet(remote, f'Z1,{address:x},4') == 'OK', 'Cannot trace SystemOS cache')
        for _ in range(32):
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected SystemOS execution stop')
            registers = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', registers);pc = values[32]
            require(pc in points, 'SystemOS execution stopped outside its checkpoints')
            label = points[pc];row = {'checkpoint': label, 'pc': hex(pc), 'pstate': hex(struct.unpack_from('<I', registers, 264)[0])}
            if label == 'kernel-state':
                state = cache_state(remote, names);result['SystemOS_state'] = state;result['AES_state'] = counters(remote, names)
                require(state['stage'] == 6 and state['status'] == state['mount_status'] == 0 and
                    state['readonly'] == state['authorized'] == state['root_recheck'] == state['native_union'] == 1 and
                    state['selected_device'] == state['mounted_device'] != 0xffffffff and
                    state['actual_root_vnode'] == state['current_root'] != state['original_root'] != 0 and
                    state['actual_mount_flags'] & 0x21 == 0x21 and state['dyld_flags'] & 8 == 0 and
                    state['verified_blocks'] > 2 and state['integrity_failures'] == 0, 'SystemOS union or owner authorization differs')
                aes = result['AES_state']
                require(aes['native_aes_kat_status'] == aes['native_aes_interface_status'] == aes['native_aes_registered'] == 1 and
                    aes['native_aes_nonce_key_uses'] > 0, 'Original Image4 did not use the software AES provider')
                del points[pc]
            else:
                require(int(row['pstate'], 0) & 15 == 0, 'Original cache checkpoint is outside EL0')
                if label == 'cache-entry':
                    pending = values[1];points[values[30]] = 'cache-return'
                    require(Remote.packet(remote, f'Z1,{values[30]:x},4') == 'OK', 'Cannot trace original cache return')
                elif label == 'cache-return':
                    require(pending is not None, 'Missing original cache output')
                    words = struct.unpack('<3Q', remote.memory(pending, 24))
                    require(values[0] == 1 and words[0] and words[2] == 0 and
                        remote.memory(words[0], 512) == cache_header, 'Original iPhone shared cache did not map')
                    row.update(x0=hex(values[0]), load_address=hex(words[0]), slide=hex(words[1]),
                        header_sha256=hashlib.sha256(cache_header).hexdigest(), original_header_matches=True)
                    result['shared_cache_mapped'] = True;del points[pc]
                elif label == 'launchd-main':
                    try:code = remote.memory(pc, 16)
                    except ValueError:
                        # QEMU can stop on the address before its first fetch
                        # faults the executable page in. Follow that fault.
                        row['fetch_pending'] = True;events.append(row);remote.save()
                        require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release pending init fetch')
                        require(Remote.packet(remote, 's').startswith('T05'), 'Cannot follow pending init fetch')
                        require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore pending init fetch')
                        continue
                    require(result.get('shared_cache_mapped') and pc == main_header + main_offset and
                        code == launchd[main_offset:main_offset + 16], 'Original launchd main entry differs')
                    row['original_entry_code_matches'] = True;result['launchd_main_entered'] = True;events.append(row);return
                else:raise ValueError('Original dyld halted: ' + cstring(remote, values[0]))
            events.append(row);remote.save()
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release cache checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step cache checkpoint')
            if pc in points:require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore cache checkpoint')
        raise ValueError('Original cache observation did not complete')
    return follow


def wrong_uuid(source, paths, environment, images, board, resources, timeout):
    kernel = ROOT / source['candidate'];names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 14}
    result = {};directory = OUT / 'wrong-uuid' / 'enabled';directory.mkdir(parents=True, exist_ok=True)
    trace = directory / 'SystemOS.json'
    class ControlRemote(Remote):
        def packet(self, message):
            reply = super().packet(message)
            if message == 'c' and reply.startswith('T05'):
                pc = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')))[32]
                if pc == names['_panic']:
                    result['state'] = cache_state(self, names);trace.write_text(json.dumps(result, indent=2) + '\n')
            return reply
    result['execution'], _ = run_case('enabled', paths, environment, kernel, names, images, board, timeout,
        directory_root=OUT / 'wrong-uuid', remote_factory=ControlRemote, resource_factory=resources)
    state = result['state'];stop = result['execution']['next_stop']
    require(state['stage'] == 1 and state['status'] == 80 and state['mount_status'] == 0xffffffff and
        state['authorized'] == state['native_union'] == 0 and state['root_recheck'] == 1 and
        state['selected_device'] == 0xffffffff and state['actual_root_vnode'] == state['original_root'] != 0 and
        state['integrity_failures'] == 0 and stop['format'] == 'offline owner SystemOS mount failed: %d @%s:%d' and
        stop['arguments'][0] == '0x50', 'Wrong SystemOS UUID reached a mount or bypassed its owner check')
    trace.write_text(json.dumps(result, indent=2) + '\n')
    return result, [trace, directory / 'serial.log', directory / 'qemu.log', directory / 'observation.json',
        directory / 'qemu.dtb', directory / 'image4-boot-policy.json',
        *sorted(path for path in (directory / 'esp').rglob('*') if path.is_file())]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_SYSTEMOS_UNION_AND_LAUNCHD_MAIN_PASS' and
        report['positive']['shared_cache_mapped'] and report['negative_control']['state']['authorized'] == 0 and
        report['launchd_main_entered'] and not report['system_services_started'] and not report['hardware_tested'], 'Incomplete SystemOS execution')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'SystemOS execution input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=600);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original iPhone SystemOS union and shared-cache execution');return
    require(30 <= args.timeout <= 900, 'Choose 30..900 seconds per SystemOS run')
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    negative_path = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-wrong-uuid.json')
    negative = json.loads(negative_path.read_text());check_source(negative)
    require(not source['wrong_uuid_control'] and negative['wrong_uuid_control'] and
        negative['selected_UUID'] != source['SystemOS_UUID'], 'Wrong SystemOS UUID control')
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require((cache_input['product'], cache_input['build']) == ('iPhone10,3', '20H392') and
        file_sha(ROOT / cache['path']) == cache['sha256'], 'Wrong original iPhone shared-cache input')
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);policy = json.loads(POLICY_REPORT.read_text())
    volume_path = ROOT / 'reports/ios16-volumes.json';images = json.loads(volume_path.read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original iPhone volume changed')
    anchor_path = ROOT / policy['images'][0]['anchor'];resources = owner_resources(anchor_path.read_bytes())
    emulator = [ROOT / name for name in entry['emulator_sha256']]
    qemu, firmware, variables, rom = emulator;paths = qemu, firmware, variables, rom.parent
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt';board = board_path.read_bytes()
    positive, artifacts = execute('positive', source, paths, environment, images, board, policy, previous['Darwin22_layout'],
        previous['original_files'], args.timeout, directory_root=OUT, resource_factory=resources,
        after_user_instruction=follow_cache(previous['original_files'], cache))
    refused, extra = wrong_uuid(negative, paths, environment, images, board, resources, args.timeout);artifacts += extra
    artifacts += emulator + [board_path, anchor_path, ROOT / source['candidate'], ROOT / negative['candidate'],
        ROOT / cache['path'], *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_SYSTEMOS_UNION_AND_LAUNCHD_MAIN_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__), ROOT / 'scripts/check_qemu_exec.py',
            ROOT / 'scripts/check_qemu_aes.py', ROOT / 'scripts/check_qemu_storage.py')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (SOURCE_REPORT, negative_path, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT, cache_report, volume_path)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'positive': positive, 'negative_control': refused,
        'launchd_main_entered': positive['launchd_main_entered'], 'system_services_started': False, 'hardware_tested': False,
        'phone_operations': 'none',
        'scope': 'The signed read-only SystemOS volume forms the native union root while the original OS remains independently verified. '
                 'Original iPhone dyld maps the shared cache; its live 512-byte header matches the pinned original file. '
                 'The original ignition route remains enabled. A wrong SystemOS UUID is refused before mounting. '
                 'The launchd main checkpoint compares the original init entry instructions and stops there.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: iPhone SystemOS union, original shared cache, launchd main and wrong-UUID control')


if __name__ == '__main__':main()
