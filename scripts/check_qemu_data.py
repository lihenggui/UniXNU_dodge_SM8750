#!/usr/bin/env python3
"""Run original iPhone early boot with volatile Data and a wrong-seed control."""
import argparse
from functools import partial
import json
import os
from pathlib import Path
import re
import struct

from build_qemu_data import REPORT as SOURCE_REPORT, check_report as check_source
from prepare_qemu_data import REPORT as DATA_REPORT, check_report as check_data
from check_qemu_exec import REPORT as EXEC_REPORT, check_report as check_exec, execute
from check_qemu_systemos import follow_cache, cache_state
from check_qemu_keystore import state as keystore_state
from check_qemu_aes import owner_resources, cstring
from check_qemu_storage import run_case, Remote, ENTRY_REPORT, check_entry
from image4_boot_policy import encode_tree
from native_driver_build import ROOT, require, symbols
from prepare_device_tree import parse_adt
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha
from qemu_user_state import compile_layout

OUT = ROOT / 'build/cph2653-qemu-data-entry'
REPORT = ROOT / 'reports/ios16-qemu-data-entry.json'
FIELDS = ('phase', 'result', 'entered', 'mounted', 'verified', 'device', 'flags')


def data_state(remote, names):
    data = {name: int.from_bytes(remote.memory(names['_dodge_qemu_data_' + name], 4), 'little') for name in FIELDS}
    data['RamBlock'] = {name: int.from_bytes(remote.memory(names['_native_ram_block_' + name],
        4 if name in ('ready', 'sparse') else 8), 'little') for name in
        ('ready', 'bytes', 'reads', 'writes', 'failures', 'resident_bytes', 'sparse')}
    data['persistent_state'] = int.from_bytes(remote.memory(names['_native_data_persist_state'], 4), 'little')
    return data


def data_resources(anchor):
    owner = owner_resources(anchor)
    def resources(tree, fdt, root_uuid):
        tree, windows = owner(tree, fdt, root_uuid);nodes = parse_adt(tree)
        nodes['/chosen/memory-map']['PackedRAMDisk'] = bytes(16)
        nodes['/defaults']['no-effaceable-storage'] = b''
        return encode_tree(nodes), windows
    return resources


def follow_early_boot(originals, cache, layout):
    dyld = (ROOT / originals['dyld']['local']).read_bytes()
    dyld_names = {row['name']: row['value'] for row in symbols(dyld) if row['kind'] & 14}

    def follow(remote, result, names):
        follow_cache(originals, cache)(remote, result, names)
        slide = int(result['user_entry']['dyld_slide'], 0)
        for address in (slide + dyld_names['__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE'],
            slide + dyld_names['__ZN5dyld44haltEPKc'], int(result['SystemOS_events'][-1]['pc'], 0)):
            require(Remote.packet(remote, f'z1,{address:x},4') == 'OK', 'Cannot release init checkpoint')
        require(Remote.packet(remote, 's').startswith('T05'), 'Cannot continue original main')
        points = {names['_unix_syscall']: 'syscall', names['_dodge_qemu_keystore_call_checkpoint']: 'KeyStore'}
        result['console'] = [];result['KeyStore_calls'] = [];text = '';done = False;first = True
        for address in points:require(Remote.packet(remote, f'Z1,{address:x},4') == 'OK', 'Cannot observe original early boot')
        for _ in range(12000):
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected early-boot stop')
            registers = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', registers);pc = values[32]
            if pc == names['_panic']:raise ValueError('Panic during original early boot: ' + cstring(remote, values[0]))
            require(pc in points, 'Early boot stopped outside its checkpoints')
            label = points[pc]
            if label == 'syscall':
                if first or done:
                    current = data_state(remote, names);result['Data_state'] = current
                    system = cache_state(remote, names);result['SystemOS_final'] = system
                    require(current['phase'] == 2 and current['result'] == 0 and
                        current['entered'] == current['mounted'] == current['verified'] == 1 and
                        current['device'] not in (0xffffffff, system['selected_device'], result['last_state']['native_owner_root_selected_device']) and
                        current['flags'] & 0x200001 == 0 and current['RamBlock']['ready'] == current['RamBlock']['sparse'] == 1 and
                        current['RamBlock']['bytes'] == 2 << 30 and current['RamBlock']['failures'] == 0 and
                        current['persistent_state'] == 0 and system['stage'] == 6 and system['integrity_failures'] == 0,
                        'Original APFS Data mount or independent read-only roots differ')
                    if first:result['Data_at_main'] = current;first = False
                    if done:
                        require(current['RamBlock']['writes'] > 0 and current['RamBlock']['reads'] > 0,
                            'Original APFS did not perform successful volatile I/O')
                        tests = re.findall(r'PASSED: .* - (fipspost_post_\w+)', text)
                        require(len(tests) == len(set(tests)) == 20 and 'all tests PASSED' in text and
                            'corecrypto.dylib: result = true' in text and '****** DONE MKB_INIT ****' in text and
                            '****** DONE UMD_INIT ****' in text and '(usermanagerd)' in text and
                            'Allocated kernel persona with ID:' in text and 'FATAL KEYBAG ERROR' not in text,
                            'Original keybag/persona tasks did not finish')
                        result['userspace_crypto_POST'] = tests;result['KeyStore_final'] = keystore_state(remote, names)
                        result['keybag_boot_task_complete'] = result['usermanager_early_boot_complete'] = True
                        return
                saved = values[0]
                number = int.from_bytes(remote.memory(saved + layout['x'] + 16 * 8, 8), 'little') & 65535
                if number in (4, 397):
                    svc = int.from_bytes(remote.memory(saved + layout['pc'], 8), 'little') - 4
                    if svc not in points:
                        points[svc] = 'console';require(Remote.packet(remote, f'Z1,{svc:x},4') == 'OK', 'Cannot trace original console')
            elif label == 'KeyStore':
                row = keystore_state(remote, names);result['KeyStore_calls'].append(row)
                require(len(result['KeyStore_calls']) <= 256, 'Unbounded native KeyStore calls')
            else:
                require(struct.unpack_from('<I', registers, 264)[0] & 15 == 0, 'Console checkpoint is outside EL0')
                if values[0] in (1, 2):
                    try:message = remote.memory(values[1], min(values[2], 4096)).decode(errors='replace')
                    except ValueError:message = ''
                    if any(marker in message for marker in ('Doing boot task', 'FIPSPOST_USER', 'corecrypto.dylib: result',
                        'MKB_INIT', 'DONE UMD_INIT', 'Allocated kernel persona with ID:')):
                        require(len(message) <= 4096 and len(text) + len(message) <= 65536, 'Unbounded early-boot output')
                        result['console'].append(message);text += message
                        print('QEMU early boot:', message.strip(), flush=True)
                    if 'FATAL KEYBAG ERROR' in text:raise ValueError('Original keybag task failed')
                    done = '****** DONE UMD_INIT ****' in text
            remote.save()
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release early-boot checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step early-boot checkpoint')
            require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore early-boot checkpoint')
        raise ValueError('Original early-boot observation did not complete')
    return follow


def wrong_seed(source, paths, environment, images, board, resources, runner, timeout):
    kernel = ROOT / source['candidate'];names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 14}
    result = {};directory = OUT / 'wrong-seed' / 'enabled';directory.mkdir(parents=True, exist_ok=True)
    trace = directory / 'Data.json'
    class ControlRemote(Remote):
        def packet(self, message):
            reply = super().packet(message)
            if message == 'c' and reply.startswith('T05'):
                pc = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')))[32]
                if pc == names['_panic']:
                    result['Data_state'] = data_state(self, names)
                    result['SystemOS_state'] = cache_state(self, names)
                    trace.write_text(json.dumps(result, indent=2) + '\n')
            return reply
    result['execution'], artifacts = runner('enabled', paths, environment, kernel, names, images, board, timeout,
        directory_root=OUT / 'wrong-seed', resource_factory=resources, remote_factory=ControlRemote)
    state = result['Data_state'];stop = result['execution']['next_stop']
    require(state['phase'] == 0 and state['result'] == 22 and state['entered'] == state['mounted'] == state['verified'] == 0 and
        state['device'] == 0xffffffff and state['flags'] == 0 and state['RamBlock']['ready'] == 1 and state['RamBlock']['writes'] == 0 and
        state['RamBlock']['failures'] == 0 and result['SystemOS_state']['stage'] == 0 and
        stop['format'] == 'dodge Data preparation before init failed: %d @%s:%d' and stop['arguments'][0] == '0x16',
        'Wrong Data identity reached the mount syscall or original userland')
    trace.write_text(json.dumps(result, indent=2) + '\n');return result, [trace, *artifacts]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_VOLATILE_DATA_AND_EARLY_USERLAND_PASS' and
        report['positive']['keybag_boot_task_complete'] and report['positive']['usermanager_early_boot_complete'] and
        report['negative_control']['Data_state']['entered'] == 0 and not report['persistent'] and
        not report['hardware_tested'] and not report['hardware_data_protection'] and not report['full_system_booted'],
        'Wrong volatile Data runtime report')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / path) == digest, 'Data execution input changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=900);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original APFS volatile Data, keybag/persona tasks and wrong seed');return
    require(60 <= args.timeout <= 1200, 'Choose 60..1200 seconds per Data case')
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    negative_path = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-wrong-seed.json')
    negative = json.loads(negative_path.read_text());check_source(negative)
    require(not source['wrong_seed_control'] and negative['wrong_seed_control'] and
        source['selected_seed_sha256'] != negative['selected_seed_sha256'], 'Wrong Data control kernel')
    data = json.loads(DATA_REPORT.read_text());check_data(data)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);policy = json.loads(POLICY_REPORT.read_text())
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require(file_sha(ROOT / cache['path']) == cache['sha256'], 'Wrong iPhone shared cache')
    volume_path = ROOT / 'reports/ios16-volumes.json';images = json.loads(volume_path.read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original volume changed')
    emulator = [ROOT / path for path in entry['emulator_sha256']];qemu, firmware, variables, rom = emulator
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    paths = qemu, firmware, variables, rom.parent
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    anchor = ROOT / policy['images'][0]['anchor'];resources = data_resources(anchor.read_bytes())
    packed = ROOT / data['packed_image'];runner = partial(run_case, packed_data=packed, extra_boot_args=('dodge-data=1', 'dodge-data-mount=1'))
    layout, artifacts = compile_layout(OUT / 'layout')
    positive, extra = execute('positive', source, paths, environment, images, board_path.read_bytes(), policy,
        previous['Darwin22_layout'], previous['original_files'], args.timeout, directory_root=OUT,
        resource_factory=resources, run_storage=runner, after_user_instruction=follow_early_boot(previous['original_files'], cache, layout))
    artifacts += extra
    refused, extra = wrong_seed(negative, paths, environment, images, board_path.read_bytes(), resources, runner, args.timeout);artifacts += extra
    artifacts += [*emulator, board_path, anchor, packed, ROOT / source['candidate'], ROOT / negative['candidate'],
        ROOT / cache['path'], *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_VOLATILE_DATA_AND_EARLY_USERLAND_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (Path(__file__), *(ROOT / ('scripts/' + name + '.py') for name in ('check_qemu_exec', 'check_qemu_storage',
                'check_qemu_systemos', 'check_qemu_aes', 'check_qemu_keystore', 'qemu_user_state')))},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (SOURCE_REPORT, negative_path, DATA_REPORT, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT, cache_report, volume_path)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'positive': positive, 'negative_control': refused,
        'Darwin22_saved_state_layout': layout, 'persistent': False, 'hardware_tested': False,
        'hardware_data_protection': False, 'full_system_booted': False, 'phone_operations': 'none',
        'scope': 'Original APFS mounts the exact separate RAM Data seed read-write while both system disks remain read-only. '
                 'Original keybagd accepts the empty unprotected development state and completes MKB_INIT. '
                 'Original usermanagerd creates kernel personas and completes early boot. Native RamBlock records successful '
                 'reads and writes without a persistent backend. A mismatched seed is refused before the mount syscall. '
                 'The run stops after UMD_INIT; later services and OnePlus hardware are separate work.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original writable volatile APFS Data, keybag/persona boot tasks and wrong-seed refusal')


if __name__ == '__main__':main()
