#!/usr/bin/env python3
"""Check original iPhone Data across two cold VMs and an abrupt power loss."""
import argparse
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from build_qemu_store import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_data import (data_resources, data_state, follow_early_boot, cache_state,
    DATA_REPORT, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT, check_data, check_exec, check_entry)
from check_qemu_exec import execute
from check_qemu_storage import run_case, Remote
from image4_boot_policy import encode_tree
from native_driver_build import ROOT, require, symbols
from prepare_device_tree import parse_adt
from qemu_store_image import file_sha, reconstruct, read_persona_marker
from qemu_user_state import compile_layout

OUT = ROOT / 'build/cph2653-qemu-store-entry'
REPORT = ROOT / 'reports/ios16-qemu-store-entry.json'
CAPACITY = 2147553280


def resources_for_store(anchor):
    owner = data_resources(anchor)
    def resources(tree, fdt, root_uuid):
        tree, windows = owner(tree, fdt, root_uuid);nodes = parse_adt(tree)
        # The pinned QEMU virt machine assigns devices from its last MMIO slot.
        # GET_ID and writable/FLUSH negotiation independently qualify this slot.
        require(len(windows) == 32, 'Unexpected QEMU MMIO slots')
        physical = sorted(int(row['address'], 0) for row in windows)[-3];found = []
        for path, node in nodes.items():
            if not path.startswith('/arm-io/virtio-mmio-'):continue
            if struct.unpack('<QQ', node['reg'])[0] + 0x08000000 != physical:continue
            node['dodge,qemu-store'] = struct.pack('<I', 1)
            node['dodge,qemu-store-bytes'] = struct.pack('<Q', CAPACITY);found.append(path)
        require(len(found) == 1, 'Cannot select the separate QEMU store')
        return encode_tree(nodes), windows
    return resources


def store_state(remote, names):
    backend = {name: int.from_bytes(remote.memory(names['_dodge_qemu_store_' + name],
        8 if name in ('reads', 'writes', 'flushes', 'bytes') else 4), 'little') for name in
        ('phase', 'result', 'error', 'reads', 'writes', 'flushes', 'bytes')}
    overlay = {name: int.from_bytes(remote.memory(names['_native_data_persist_' + name],
        8 if name in ('pages', 'loaded', 'writes', 'syncs', 'errors', 'present') else 4), 'little') for name in
        ('state', 'header', 'gpt', 'gpt_after', 'pages', 'loaded', 'writes', 'syncs', 'errors', 'present')}
    return {'backend': backend, 'overlay': overlay}


def observe(originals, cache, layout, fresh):
    expected = 3 if fresh else 2
    boot = follow_early_boot(originals, cache, layout, persistence=(expected,))
    def follow(remote, result, names):
        boot(remote, result, names);state = store_state(remote, names);result['persistent_Data'] = state
        backend, overlay = state['backend'], state['overlay']
        require(backend['phase'] == 2 and backend['result'] == backend['error'] == 0 and backend['bytes'] == CAPACITY and
            backend['writes'] > 0 and backend['flushes'] >= backend['writes'] and overlay['state'] == expected and
            overlay['header'] == (1 if fresh else 0) and overlay['gpt'] == overlay['gpt_after'] == 255 and
            overlay['pages'] == 524288 and overlay['errors'] == 0 and overlay['writes'] > 0 and overlay['present'] > 0,
            'Persistent Data transport or overlay did not complete its I/O')
        if not fresh:require(overlay['loaded'] > 1, 'Resumed VM did not read saved pages')
        print('QEMU persistent Data:', json.dumps(state), flush=True)
    return follow


def copy_store(source, target):
    require(not target.exists(), 'Store copy already exists')
    subprocess.run(['cp', '--reflink=auto', '--sparse=always', '--', source, target], check=True)
    target.chmod(0o600)


def negative(case, source, paths, environment, images, board, resources, packed, store, directory, timeout):
    serial = 'UNIXNU-DODGE-BAD-1' if case == 'wrong-id' else 'UNIXNU-DODGE-DATA-1'
    runner = partial(run_case, packed_data=packed, data_store=store, data_store_serial=serial,
        extra_boot_args=('dodge-data=1', 'dodge-data-mount=1', 'dodge-qemu-store=1'))
    before = file_sha(store);kernel = ROOT / source['candidate']
    names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 14}
    result = {};trace = directory / case / 'enabled' / 'persistence.json';trace.parent.mkdir(parents=True, exist_ok=True)
    class RefusalRemote(Remote):
        def packet(self, message):
            reply = super().packet(message)
            if message == 'c' and reply.startswith('T05'):
                pc = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')))[32]
                if pc == names['_panic']:
                    result['persistent_Data'] = store_state(self, names)
                    result['Data_state'] = data_state(self, names);result['SystemOS_state'] = cache_state(self, names)
            return reply
    result['execution'], artifacts = runner('enabled', paths, environment, kernel, names, images, board, timeout,
        directory_root=directory / case, resource_factory=resources, remote_factory=RefusalRemote)
    after = file_sha(store);state = result['persistent_Data'];data = result['Data_state'];stop = result['execution']['next_stop']
    require(before == after and state['backend']['writes'] == state['backend']['flushes'] == 0 and
        data['entered'] == data['mounted'] == data['verified'] == 0 and data['RamBlock']['writes'] == 0 and
        result['SystemOS_state']['stage'] == 0 and stop['format'] == 'dodge Data preparation before init failed: %d @%s:%d' and
        stop['arguments'][0] == '0x23', 'Rejected store changed or reached a Data mount')
    if case == 'wrong-id':
        require(state['backend']['phase'] == 3 and state['backend']['error'] == 1 and state['overlay']['state'] == 4,
            'Wrong VirtIO identifier was accepted')
    else:
        require(state['backend']['phase'] == 2 and state['overlay']['state'] == 7 and state['overlay']['header'] == 3,
            'Foreign seed header was accepted')
    result.update(store_sha256_before=before, store_sha256_after=after, writes_refused=True)
    trace.write_text(json.dumps(result, indent=2) + '\n');return result, [trace, store, *artifacts]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_DATA_CRASH_AND_COLD_RESUME_PASS' and
        report['fresh']['execution']['vm_returncode'] == report['resumed']['execution']['vm_returncode'] == -9 and
        report['persona_state_preserved'] and all(row['writes_refused'] for row in report['negative_controls'].values()) and
        not report['hardware_tested'] and not report['physical_storage_enabled'] and not report['hardware_data_protection'],
        'Wrong persistent Data runtime report')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / path) == digest, 'Persistent Data runtime input changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=900);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original Data crash/cold resume, persona state and refusal controls');return
    require(60 <= args.timeout <= 1200, 'Choose 60..1200 seconds per VM')
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    data = json.loads(DATA_REPORT.read_text());check_data(data)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);policy = json.loads(POLICY_REPORT.read_text())
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require(file_sha(ROOT / cache['path']) == cache['sha256'], 'Wrong iPhone shared cache')
    volume_report = ROOT / 'reports/ios16-volumes.json';images = json.loads(volume_report.read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original system disk changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']];qemu, firmware, variables, rom = emulator
    paths = qemu, firmware, variables, rom.parent
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    anchor = ROOT / policy['images'][0]['anchor'];resources = resources_for_store(anchor.read_bytes())
    OUT.mkdir(parents=True, exist_ok=True);directory = Path(tempfile.mkdtemp(prefix='run-', dir=OUT))
    store = directory / 'data.store'
    with store.open('xb') as stream:stream.truncate(CAPACITY)
    store.chmod(0o600);packed = ROOT / data['packed_image'];layout, artifacts = compile_layout(directory / 'layout')
    results = {};snapshots = {};markers = {}
    for case, fresh in (('fresh', True), ('resumed', False)):
        flags = ('dodge-data=1', 'dodge-data-mount=1', 'dodge-qemu-store=1') + (('sheng-data-reset=1',) if fresh else ())
        runner = partial(run_case, packed_data=packed, data_store=store, extra_boot_args=flags, crash_on_stop=True)
        result, extra = execute('positive', source, paths, environment, images, board_path.read_bytes(), policy,
            previous['Darwin22_layout'], previous['original_files'], args.timeout, directory_root=directory / case,
            resource_factory=resources, run_storage=runner, after_user_instruction=observe(previous['original_files'], cache, layout, fresh))
        require(result['execution']['vm_stop_signal'] == 'SIGKILL' and result['execution']['vm_returncode'] == -9,
            'VM did not stop by actual SIGKILL')
        results[case] = result;artifacts += extra
        saved = directory / (case + '.store');copy_store(store, saved);artifacts.append(saved)
        image = directory / (case + '.apfs')
        snapshots[case] = reconstruct(saved, ROOT / data['image'], image, data['image_bytes'], data['image_sha256']);artifacts.append(image)
        markers[case], extra = read_persona_marker(image, directory / (case + '-readback'));artifacts += extra
    before = {row['path']: row['identifiers'] for row in markers['fresh']}
    after = {row['path']: row['identifiers'] for row in markers['resumed']}
    require(before == after and before and snapshots['fresh']['generation'] == snapshots['resumed']['generation'] == 1,
        'Original persona state changed across cold resume')
    controls = {}
    for case in ('wrong-id', 'foreign-seed'):
        control = directory / (case + '.store');copy_store(store, control)
        if case == 'foreign-seed':
            with control.open('r+b') as stream:
                header = bytearray(stream.read(4096));header[24] ^= 1
                struct.pack_into('<I', header, 60, zlib.crc32(header[:60]));stream.seek(0);stream.write(header)
        controls[case], extra = negative(case, source, paths, environment, images, board_path.read_bytes(), resources,
            packed, control, directory, args.timeout);artifacts += extra
    artifacts += [store, *emulator, board_path, anchor, packed, ROOT / source['candidate'], ROOT / cache['path'],
        *(ROOT / image['path'] for image in images)]
    marker_digest = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    report = {'result': 'IOS16_QEMU_DATA_CRASH_AND_COLD_RESUME_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (Path(__file__), *(ROOT / ('scripts/' + name + '.py') for name in
                ('check_qemu_data', 'check_qemu_storage', 'check_qemu_exec', 'check_qemu_systemos', 'qemu_store_image', 'qemu_user_state')))},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (SOURCE_REPORT, DATA_REPORT, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT, cache_report, volume_report)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'fresh': results['fresh'], 'resumed': results['resumed'],
        'snapshots': snapshots, 'negative_controls': controls, 'persona_state_preserved': True,
        'persona_marker_sha256': marker_digest, 'persona_marker_files': sorted(before),
        'Darwin22_saved_state_layout': layout, 'hardware_tested': False, 'physical_storage_enabled': False,
        'hardware_data_protection': False, 'full_system_booted': False, 'phone_operations': 'none',
        'scope': 'Original APFS and RamBlock write a separately identified flat-file overlay with completed VirtIO FLUSH operations. '
                 'After actual SIGKILL, a fresh VM resumes the same overlay without reset, mounts Data and completes the original '
                 'keybag/persona tasks. Independent read-only APFS extraction confirms the same generated persona identifiers. '
                 'Wrong device identity and a valid-CRC foreign seed are refused before Data mounting, without changing either store. '
                 'Both system disks remain read-only. Persona values stay local; this is VM-file persistence, not physical UFS or hardware protection.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: actual Data crash/cold resume, original persona preservation and two write-refusal controls')


if __name__ == '__main__':main()
