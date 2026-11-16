#!/usr/bin/env python3
"""Run the original seed utility through APFS full sync, abrupt VM stop and cold resume."""
import argparse
from functools import partial
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from build_qemu_seed_sync import REPORT as KERNEL_REPORT, check_report as check_kernel
from check_qemu_data import (follow_early_boot, data_state, cache_state, DATA_REPORT, EXEC_REPORT, ENTRY_REPORT,
    POLICY_REPORT, check_data, check_exec, check_entry)
from check_qemu_exec import execute
from check_qemu_services import cstring
from check_qemu_storage import Remote, run_case
from check_qemu_store import CAPACITY, copy_store, resources_for_store, store_state
from native_driver_build import ROOT, build_objects, macho, require, symbols
from native_prelink import backed_offset
from qemu_store_image import file_sha, reconstruct

OUT = ROOT / 'build/cph2653-qemu-seed-sync-entry'
REPORT = ROOT / 'reports/ios16-qemu-seed-sync-entry.json'


def compile_layout(directory):
    directory.mkdir();source = directory / 'SeedReadLayout.c'
    fields = {'bytes': 'sizeof(struct arm_saved_state)', 'x': '__builtin_offsetof(struct arm_saved_state,ss_64.x)',
        'sp': '__builtin_offsetof(struct arm_saved_state,ss_64.sp)', 'pc': '__builtin_offsetof(struct arm_saved_state,ss_64.pc)',
        'cpsr': '__builtin_offsetof(struct arm_saved_state,ss_64.cpsr)', 'x_count': 'sizeof(((struct arm_saved_state *)0)->ss_64.x)/8'}
    source.write_text('#include <kern/thread.h>\nconst unsigned seed_read_layout[]={' + ','.join(fields.values()) + '};\n')
    obj, = build_objects([source], directory);raw = obj.read_bytes();parsed = macho(raw)
    address, = [row['value'] for row in symbols(raw) if row['name'] == '_seed_read_layout']
    offset = backed_offset(parsed['segments'], address, len(fields) * 4, len(raw))
    layout = dict(zip(fields, struct.unpack_from('<' + str(len(fields)) + 'I', raw, offset)))
    require(layout['x_count'] == 29, 'Unexpected saved-state register layout')
    return layout, [source, obj, directory / 'compile-commands.json']


def observe(previous, cache, layout, consumer, prior_seed):
    early = follow_early_boot(previous['original_files'], cache, layout, persistence=(2 if prior_seed else 3,))
    def follow(remote, result, names):
        early(remote, result, names)
        syscall = names['_unix_syscall'];pending = None;seen_original = False;read_prior = False
        fields = ('attempts', 'completed', 'failed', 'last_error')
        addresses = [names['_dodge_seed_sync_' + name] for name in fields];base = min(addresses)
        require(max(addresses) - base <= 64, 'Unexpected seed diagnostic layout')
        summary = {'original_utility_seen': False, 'saved_seed_read_after_cold_resume': False};result['saved_seed'] = summary
        def advance(pc, keep):
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release saved-seed checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step saved-seed checkpoint')
            if keep:require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore saved-seed checkpoint')
        advance(syscall, True)
        for index in range(30000):
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected saved-seed VM stop')
            raw = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', raw);pc = values[32]
            if pc == names['_panic']:raise ValueError('Panic during saved-seed execution: ' + cstring(remote, values[0]))
            if pending and pc == pending[0]:
                pstate, = struct.unpack_from('<I', raw, 264)
                require(pstate & 15 == 0, 'Saved-seed read did not return to EL0')
                # Shared-cache SVC return addresses are shared by processes.
                # Keep watching until this original caller's stack returns.
                if values[31] != pending[2]:advance(pc, True);continue
                if values[0] == 32 and not pstate & (1 << 29):
                    # The actual user return buffer is compared in memory only.
                    # Seed bytes and their digest never enter a diagnostic file.
                    read_prior |= remote.memory(pending[1], 32) == prior_seed
                summary['saved_seed_read_after_cold_resume'] = read_prior
                pending = None;advance(pc, False);continue
            if pc == names['_dodge_qemu_keystore_call_checkpoint']:
                advance(pc, True);continue
            # The storage/early-boot observers leave kernel and shared EL0
            # checkpoints installed. As in the service observer, release each
            # inherited checkpoint once; this changes no guest instruction or
            # syscall result. Panic and the selected read return are handled
            # above, and every unexpected release is retained for review.
            if pc != syscall:
                released = summary.setdefault('released_inherited_checkpoints', [])
                released.append({'pc': hex(pc), 'symbols': [name for name, address in names.items() if address == pc][:8],
                    'execution_mode': struct.unpack_from('<I', raw, 264)[0] & 15})
                require(len(released) <= 128, 'Unbounded inherited checkpoints')
                advance(pc, False);continue
            counters = remote.memory(base, max(addresses) - base + 4)
            state = dict(zip(fields, (struct.unpack_from('<I', counters, address - base)[0] for address in addresses)))
            summary['synchronization'] = state;summary['checkpoints'] = index + 1
            saved = remote.memory(values[0], layout['bytes']);number = struct.unpack_from('<Q', saved, layout['x'] + 128)[0] & 65535
            process = remote.memory(values[2], previous['Darwin22_layout']['proc_bytes']);p = previous['Darwin22_layout']
            comm = process[p['comm']:p['comm'] + p['comm_bytes']].split(b'\0')[0]
            if comm == b'prng_seedctl':
                require(process[p['uuid']:p['uuid'] + 16].hex() == consumer['uuid'], 'Seed utility differs from pinned iPhone input')
                seen_original = True;summary['original_utility_seen'] = True
                if prior_seed is not None and not read_prior and pending is None and number == 3:
                    _, buffer, count = struct.unpack_from('<3Q', saved, layout['x'])
                    if count == 32:
                        returned, = struct.unpack_from('<Q', saved, layout['pc'])
                        require(returned != syscall, 'Invalid seed read user return')
                        user_sp, = struct.unpack_from('<Q', saved, layout['sp'])
                        pending = returned, buffer, user_sp
                        require(Remote.packet(remote, f'Z1,{returned:x},4') == 'OK', 'Cannot observe original saved-seed read return')
            if state['failed']:
                remote.save();raise ValueError('Actual APFS seed synchronization failed with errno ' + str(state['last_error']))
            if seen_original and state['completed'] and (prior_seed is None or read_prior):
                require(state['attempts'] == state['completed'] and not state['last_error'], 'Seed sync has unfinished/failed requests')
                summary['Data'] = data_state(remote, names);summary['SystemOS'] = cache_state(remote, names)
                summary['store'] = store_state(remote, names)
                require(summary['Data']['mounted'] == summary['Data']['verified'] == 1 and
                    not summary['Data']['RamBlock']['failures'] and not summary['SystemOS']['integrity_failures'] and
                    summary['store']['backend']['error'] == 0 and summary['store']['backend']['flushes'] > 0,
                    'Saved-seed execution lost verified storage or flush completion')
                remote.save();print('QEMU saved seed: original utility, APFS full sync and store flush completed', flush=True);return
            if index % 1000 == 0:remote.save();print('QEMU saved-seed checkpoints:', index, state, flush=True)
            advance(pc, True)
        raise ValueError('Original seed utility did not complete the bounded save/read observation')
    return follow


def extract_seed(image, directory, extractor):
    output = directory / 'prng.seed.private'
    process = subprocess.run([extractor, image, '0', '/db/prng.seed', output], capture_output=True)
    require(not process.returncode and output.is_file() and output.stat().st_size == 32, 'Saved seed absent/short after abrupt VM stop')
    output.chmod(0o600)
    return output.read_bytes()  # Local directory is mode 0700; never publish this file or its hash.


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_ORIGINAL_SEED_SAVE_AND_COLD_READ_PASS' and
        not report['hardware_tested'] and not report['physical_storage_enabled'] and report['native_packages_unchanged'],
        'Incomplete seed persistence VM evidence')
    for case in ('fresh', 'resumed'):
        row = report[case];sync = row['saved_seed']['synchronization']
        require(row['saved_seed']['original_utility_seen'] and sync['completed'] > 0 and
            sync['attempts'] == sync['completed'] and sync['failed'] == sync['last_error'] == 0 and
            row['execution']['vm_stop_signal'] == 'SIGKILL' and row['execution']['vm_returncode'] == -9,
            'Seed save/full-sync/crash was not observed')
    require(report['resumed']['saved_seed']['saved_seed_read_after_cold_resume'], 'Original utility did not read the prior saved seed')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Saved-seed VM input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=900);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original seed utility saved and cold-read through actual APFS');return
    require(300 <= args.timeout <= 1800, 'Choose a bounded VM timeout')
    kernel = json.loads(KERNEL_REPORT.read_text());check_kernel(kernel)
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);data = json.loads(DATA_REPORT.read_text());check_data(data)
    policy = json.loads(POLICY_REPORT.read_text());volume_report = ROOT / 'reports/ios16-volumes.json'
    images = json.loads(volume_report.read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original system image changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']];qemu, firmware, variables, rom = emulator
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require(file_sha(ROOT / cache['path']) == cache['sha256'], 'Original shared cache changed')
    extractor = ROOT / cache_input['extractor'];require(file_sha(extractor) == cache_input['extractor_sha256'], 'APFS extractor changed')
    consumer_path = ROOT / 'hardware/dodge-entropy.json';consumer = json.loads(consumer_path.read_text())['iPhone_consumer']
    board = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    anchor = ROOT / policy['images'][0]['anchor'];resources = resources_for_store(anchor.read_bytes())
    OUT.mkdir(parents=True, exist_ok=True);directory = Path(tempfile.mkdtemp(prefix='run-', dir=OUT))
    layout, artifacts = compile_layout(directory / 'layout');store = directory / 'data.store'
    with store.open('xb') as stream:stream.truncate(CAPACITY)
    store.chmod(0o600);results = {};snapshots = {};prior_seed = None
    for case, fresh in (('fresh', True), ('resumed', False)):
        flags = ('dodge-data=1', 'dodge-data-mount=1', 'dodge-qemu-store=1', 'dodge-seed-sync=1') + (('sheng-data-reset=1',) if fresh else ())
        runner = partial(run_case, packed_data=ROOT / data['packed_image'], data_store=store, crash_on_stop=True, extra_boot_args=flags)
        result, extra = execute('positive', kernel, (qemu, firmware, variables, rom.parent), environment, images, board.read_bytes(), policy,
            previous['Darwin22_layout'], previous['original_files'], args.timeout, directory_root=directory / case,
            resource_factory=resources, run_storage=runner, after_user_instruction=observe(previous, cache, layout, consumer, prior_seed))
        results[case] = result;artifacts += extra
        saved = directory / (case + '.store');copy_store(store, saved);snapshot = directory / (case + '.apfs')
        snapshots[case] = reconstruct(saved, ROOT / data['image'], snapshot, data['image_bytes'], data['image_sha256'])
        artifacts += [saved, snapshot];prior_seed = extract_seed(snapshot, directory / case, extractor)
    # No private seed artifact, seed bytes or seed digest is included.
    artifacts += [store, *emulator, board, anchor, ROOT / data['packed_image'], ROOT / kernel['candidate'],
        ROOT / cache['path'], extractor, *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_ORIGINAL_SEED_SAVE_AND_COLD_READ_PASS', **results, 'snapshots': snapshots,
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__), consumer_path,
            *(ROOT / ('scripts/' + name + '.py') for name in ('check_qemu_data', 'check_qemu_exec', 'check_qemu_storage',
                'check_qemu_store', 'check_qemu_services', 'qemu_store_image')))},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (KERNEL_REPORT, EXEC_REPORT, ENTRY_REPORT, DATA_REPORT, POLICY_REPORT, cache_report, volume_report)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'compiler_saved_state_layout': layout,
        'hardware_tested': False, 'physical_storage_enabled': False,
        'native_packages_unchanged': True, 'atomic_replacement_added': False, 'phone_operations': 'none',
        'scope': 'Original iPhone prng_seedctl runs through actual APFS/VFS and VirtIO-backed Data. Each save passes '
        'file/directory fsync and F_FULLFSYNC. The VM is killed without guest shutdown, the saved regular-file overlay '
        'is independently read, and a fresh VM reads those exact private bytes through the original utility. Seed bytes '
        'and seed digests are never published. This qualifies the VM file-backed path, not physical UFS durability, '
        'power-loss atomicity during O_TRUNC/write, hardware entropy quality or hardware data protection.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original seed utility, actual APFS full sync, forced VM stop and unchanged saved-seed cold read')


if __name__ == '__main__':main()
