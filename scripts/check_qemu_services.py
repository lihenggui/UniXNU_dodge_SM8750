#!/usr/bin/env python3
"""Run original iPhone system services past early boot and the mbuf statistics path."""
import argparse
from collections import Counter
from functools import partial
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from build_qemu_store import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_store import resources_for_store, store_state, CAPACITY
from check_qemu_data import (follow_early_boot, data_state, cache_state, DATA_REPORT, EXEC_REPORT, ENTRY_REPORT,
    POLICY_REPORT, check_data, check_exec, check_entry)
from check_qemu_storage import run_case, Remote
from check_qemu_exec import execute
from native_driver_build import ROOT, build_objects, require, symbols, macho
from native_prelink import backed_offset
from qemu_store_image import file_sha

OUT = ROOT / 'build/cph2653-qemu-services-entry'
REPORT = ROOT / 'reports/ios16-qemu-services-entry.json'


def cstring(remote, address, limit=4096):
    result = bytearray()
    while len(result) < limit:
        at = address + len(result);chunk = remote.memory(at, min(128, limit - len(result), 4096 - (at & 4095)))
        result.extend(chunk.split(b'\0')[0])
        if b'\0' in chunk:return result.decode(errors='replace')
    raise ValueError('Unterminated bounded service diagnostic')


def compile_layout(directory):
    directory.mkdir(parents=True, exist_ok=True);source = directory / 'ServiceLayout.c'
    fields = {'bytes': 'sizeof(struct arm_saved_state)', 'x': '__builtin_offsetof(struct arm_saved_state,ss_64.x)',
        'pc': '__builtin_offsetof(struct arm_saved_state,ss_64.pc)', 'cpsr': '__builtin_offsetof(struct arm_saved_state,ss_64.cpsr)',
        'x_count': 'sizeof(((struct arm_saved_state *)0)->ss_64.x)/8',
        'percpu_start': '__builtin_offsetof(struct percpu_base,start)', 'percpu_end': '__builtin_offsetof(struct percpu_base,end)'}
    source.write_text('#include <kern/thread.h>\n#include <kern/percpu.h>\nconst unsigned service_layout[]={' + ','.join(fields.values()) + '};\n')
    obj, = build_objects([source], directory);raw = obj.read_bytes();parsed = macho(raw)
    address, = [row['value'] for row in symbols(raw) if row['name'] == '_service_layout']
    offset = backed_offset(parsed['segments'], address, len(fields) * 4, len(raw))
    result = dict(zip(fields, struct.unpack_from('<' + str(len(fields)) + 'I', raw, offset)))
    require(result['x_count'] == 29 and result['percpu_start'] == 0 and result['percpu_end'] == 8, 'Unexpected service observer ABI')
    return result, [source, obj, directory / 'compile-commands.json']


def original_springboard(images, directory):
    reference = json.loads((ROOT / 'reports/ios16-display-cache.json').read_text());extractor = ROOT / reference['extractor']
    require(file_sha(extractor) == reference['extractor_sha256'], 'APFS extractor changed')
    path = '/System/Library/CoreServices/SpringBoard.app/SpringBoard';output = directory / 'SpringBoard'
    for image in images:
        result = subprocess.run([extractor, ROOT / image['path'], '0', path, output], capture_output=True)
        if not result.returncode:break
    require(not result.returncode, 'Original SpringBoard extraction failed')
    raw = output.read_bytes();parsed = macho(raw)
    require(struct.unpack_from('<3I', raw) == (0xfeedfacf, 0x100000c, 0), 'SpringBoard is not the pinned ordinary arm64 executable')
    at, = [at for command, at, _ in parsed['commands'] if command == 0x1b]
    return {'path': path, 'sha256': file_sha(output), 'uuid': raw[at + 8:at + 24].hex()}, [output, extractor]


def observe(previous, cache, layout, springboard, control, steps):
    early = follow_early_boot(previous['original_files'], cache, layout, persistence=(3,))
    proc_layout = previous['Darwin22_layout']
    def follow(remote, result, names):
        early(remote, result, names)
        points = {names['_unix_syscall']: 'syscall', names['_dodge_qemu_keystore_call_checkpoint']: 'KeyStore',
            names['_mbuf_mtypes_sync']: 'mbuf'}
        mbuf = names['_mbuf_mtypes_sync'];pending = None;counts = Counter();processes = {};console = [];next_snapshot = 0
        result['services'] = {'processes': processes, 'console': console, 'mbuf_entered': 0, 'mbuf_returned': 0}
        observed = result['services'];text = ''
        def advance(pc, keep):
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release service checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step service checkpoint')
            if keep:require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore service checkpoint')
        require(Remote.packet(remote, f'Z1,{mbuf:x},4') == 'OK', 'Cannot observe mbuf statistics')
        advance(names['_unix_syscall'], True)
        for index in range(steps + 1024):
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected service stop')
            raw = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', raw);pc = values[32]
            if pc == names['_panic']:
                args = struct.unpack('<48Q', remote.memory(values[31], 384));observed['panic'] = {
                    'format': cstring(remote, values[0]), 'arguments': [hex(value) for value in args],
                    'saved_pc': hex(args[1]), 'saved_lr': hex(args[2]), 'mbuf_entry': hex(mbuf)}
                require(control and observed['mbuf_entered'] and not observed['mbuf_returned'] and
                    0 <= args[1] - mbuf < 2048 and 'saved state:' in observed['panic']['format'],
                    'Unexpected panic during original system services: ' + observed['panic']['format'])
                observed['old_percpu_fault_reproduced'] = True;remote.save();return
            label = points.get(pc, 'console')
            if label == 'syscall':
                saved = remote.memory(values[0], layout['bytes']);number = struct.unpack_from('<Q', saved, layout['x'] + 16 * 8)[0] & 65535
                require(struct.unpack_from('<I', saved, layout['cpsr'])[0] & 15 == 0, 'System-service syscall did not come from EL0')
                process = remote.memory(values[2], proc_layout['proc_bytes']);pid = struct.unpack_from('<I', process, proc_layout['pid'])[0]
                comm = process[proc_layout['comm']:proc_layout['comm'] + proc_layout['comm_bytes']].split(b'\0')[0].decode(errors='replace')
                uuid = process[proc_layout['uuid']:proc_layout['uuid'] + 16].hex();key = str(pid) + ':' + comm;counts[key] += 1
                if key not in processes:processes[key] = {'pid': pid, 'comm': comm, 'uuid': uuid,
                    'first_syscall': number, 'first_user_pc': hex(struct.unpack_from('<Q', saved, layout['pc'])[0])}
                processes[key]['syscalls'] = counts[key]
                if comm == 'SpringBoard':require(uuid == springboard['uuid'], 'Running SpringBoard differs from the original iPhone executable')
                if number in (4, 397):
                    svc = struct.unpack_from('<Q', saved, layout['pc'])[0] - 4
                    if svc not in points:points[svc] = 'console';require(Remote.packet(remote, f'Z1,{svc:x},4') == 'OK', 'Cannot observe original service output')
            elif label == 'mbuf':
                require(pending is None and values[30] not in points, 'Overlapping mbuf return observation')
                start = int.from_bytes(remote.memory(names['_percpu_base'] + layout['percpu_start'], 8), 'little')
                end = int.from_bytes(remote.memory(names['_percpu_base'] + layout['percpu_end'], 8), 'little')
                require(start > end == 0, 'VM no longer has an empty secondary CPU range')
                observed['percpu_range'] = {'start': hex(start), 'end': hex(end)};observed['mbuf_entered'] += 1
                pending = (values[30], values[31]);points[pending[0]] = 'mbuf-return';del points[mbuf]
                require(Remote.packet(remote, f'Z1,{pending[0]:x},4') == 'OK', 'Cannot trace mbuf return')
            elif label == 'mbuf-return':
                if values[31] == pending[1]:
                    observed['mbuf_returned'] += 1;del points[pc];pending = None;points[mbuf] = 'mbuf'
                    require(Remote.packet(remote, f'Z1,{mbuf:x},4') == 'OK', 'Cannot restore mbuf entry')
            elif label == 'KeyStore':
                pass
            elif struct.unpack_from('<I', raw, 264)[0] & 15 == 0 and values[0] in (1, 2):
                message = remote.memory(values[1], min(values[2], 4096)).decode(errors='replace')
                if any(marker in message for marker in ('Doing boot task', 'Sending validated cache', 'Cache sent to launchd',
                    'Early boot complete', 'FATAL', 'ERROR', 'failed', 'Failed', 'warning:')):
                    require(sum(map(len, console)) + len(message) <= 131072, 'Unbounded system-service output')
                    console.append(message);text += message;print('QEMU services:', message.strip(), flush=True)
            # EL0 output breakpoints use the user translation regime. QEMU
            # cannot read kernel globals there; sample only at the kernel's
            # syscall entry, where the process and saved state were read above.
            if index >= next_snapshot and label == 'syscall':
                observed['checkpoints'] = index;observed['Data'] = data_state(remote, names)
                next_snapshot = index + 1000
                print('QEMU service progress:', index, 'processes', len(processes), 'mbuf returns', observed['mbuf_returned'], flush=True);remote.save()
            if not control and index >= steps and label == 'syscall':break
            advance(pc, pc in points)
        require(not control and index >= steps and label == 'syscall' and observed['mbuf_returned'] > 0 and
            all(any(row['comm'] == name and row['syscalls'] >= minimum for row in processes.values()) for name, minimum in
                (('SpringBoard', 100), ('launchd', 100), ('logd', 100), ('notifyd', 100), ('amfid', 16))) and
            'Sending validated cache to launchd' in text and 'Cache sent to launchd successfully' in text and
            'Early boot complete. Continuing system boot.' in text, 'Original system services did not complete the observed paths')
        observed['Data'] = data_state(remote, names);observed['SystemOS'] = cache_state(remote, names)
        observed['store'] = store_state(remote, names)
        require(observed['Data']['mounted'] == observed['Data']['verified'] == 1 and
            observed['Data']['RamBlock']['failures'] == 0 and observed['store']['backend']['error'] == 0 and
            observed['SystemOS']['stage'] == 6 and observed['SystemOS']['integrity_failures'] == 0, 'Service boot lost storage integrity')
        observed['launchd_early_boot_complete'] = observed['SpringBoard_original_process_executed'] = True
        observed['checkpoints'] = index + 1;remote.save()
    return follow


def check_report(report):
    positive = report['positive']['services'];negative = report['negative']['services']
    require(report['result'] == 'IOS16_QEMU_ORIGINAL_SERVICES_AND_PERCPU_REGRESSION_PASS' and
        (report['product'], report['build']) == ('iPhone10,3', '20H392') and
        positive['mbuf_entered'] >= positive['mbuf_returned'] > 0 and negative['mbuf_entered'] > 0 and
        negative['mbuf_returned'] == 0 and negative['old_percpu_fault_reproduced'] and
        positive['launchd_early_boot_complete'] and positive['SpringBoard_original_process_executed'] and
        positive['percpu_range'] == negative['percpu_range'] and
        int(positive['percpu_range']['start'], 0) > int(positive['percpu_range']['end'], 0) == 0 and
        positive['Data']['mounted'] == positive['Data']['verified'] == 1 and
        positive['Data']['RamBlock']['failures'] == positive['store']['backend']['error'] == 0 and
        positive['SystemOS']['stage'] == 6 and positive['SystemOS']['integrity_failures'] == 0 and
        all(any(row['comm'] == name and row['syscalls'] >= minimum for row in positive['processes'].values())
            for name, minimum in (('SpringBoard', 100), ('launchd', 100), ('logd', 100), ('notifyd', 100), ('amfid', 16))) and
        all(row['uuid'] == report['original_SpringBoard']['uuid'] for row in positive['processes'].values() if row['comm'] == 'SpringBoard') and
        not report['full_system_booted'] and not report['graphical_interface_tested'] and not report['hardware_tested'] and
        not report['physical_storage_enabled'] and not report['hardware_data_protection'] and report['phone_operations'] == 'none',
        'Incomplete system-service report')
    for case, control in (('negative', True), ('positive', False)):
        source = json.loads((ROOT / report['kernel_reports'][case]).read_text());check_source(source)
        loaded, = [digest for name, digest in report['artifacts'].items()
            if name.endswith('/' + case + '/positive/enabled/esp/EFI/UniXNU/Payloads/kernel.macho')]
        require(source['old_percpu_control'] == control and
            source['candidate_sha256'] == loaded,
            'System services used the wrong per-CPU consumer')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'System-service input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--steps', type=int, default=30000);parser.add_argument('--timeout', type=int, default=1200);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original system services and per-CPU regression control');return
    require(20000 <= args.steps <= 80000 and 600 <= args.timeout <= 3600, 'Choose bounded service observations')
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);data = json.loads(DATA_REPORT.read_text());check_data(data)
    policy = json.loads(POLICY_REPORT.read_text());images = json.loads((ROOT / 'reports/ios16-volumes.json').read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original system disk changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']];qemu, firmware, variables, rom = emulator
    environment = dict(os.environ);libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():
        environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    cache_report = ROOT / 'reports/ios16-display-cache.json';cache_input = json.loads(cache_report.read_text())
    cache, = [row for row in cache_input['cache_files'] if Path(row['path']).name == 'dyld_shared_cache_arm64']
    require(file_sha(ROOT / cache['path']) == cache['sha256'], 'iPhone shared cache changed')
    OUT.mkdir(parents=True, exist_ok=True);directory = Path(tempfile.mkdtemp(prefix='run-', dir=OUT))
    layout, artifacts = compile_layout(directory / 'layout');springboard, extra = original_springboard(images, directory);artifacts += extra
    board = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    anchor = ROOT / policy['images'][0]['anchor'];resources = resources_for_store(anchor.read_bytes());results = {};dependencies = [];kernel_reports = {}
    for case, control in (('negative', True), ('positive', False)):
        source_report = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-old-percpu.json') if control else SOURCE_REPORT
        source = json.loads(source_report.read_text());check_source(source)
        require(source['old_percpu_control'] == control, 'Wrong per-CPU kernel selected');dependencies.append(source_report)
        kernel_reports[case] = str(source_report.relative_to(ROOT))
        store = directory / (case + '.store')
        with store.open('xb') as stream:stream.truncate(CAPACITY)
        store.chmod(0o600)
        runner = partial(run_case, packed_data=ROOT / data['packed_image'], data_store=store, crash_on_stop=True,
            extra_boot_args=('dodge-data=1', 'dodge-data-mount=1', 'dodge-qemu-store=1', 'sheng-data-reset=1'))
        result, extra = execute('positive', source, (qemu, firmware, variables, rom.parent), environment, images, board.read_bytes(), policy,
            previous['Darwin22_layout'], previous['original_files'], args.timeout, directory_root=directory / case,
            resource_factory=resources, run_storage=runner,
            after_user_instruction=observe(previous, cache, layout, springboard, control, args.steps))
        results[case] = result;artifacts += [store, ROOT / source['candidate'], *extra]
    artifacts += [*emulator, board, anchor, ROOT / data['packed_image'], ROOT / cache['path'], *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_ORIGINAL_SERVICES_AND_PERCPU_REGRESSION_PASS', **results,
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__),
            *(ROOT / ('scripts/' + name + '.py') for name in ('check_qemu_data', 'check_qemu_store', 'check_qemu_storage',
                'check_qemu_exec', 'check_qemu_systemos', 'check_qemu_keystore', 'check_qemu_aes',
                'qemu_user_state', 'qemu_store_image', 'image4_boot_policy', 'native_driver_build')))},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (*dependencies, EXEC_REPORT, ENTRY_REPORT, DATA_REPORT, POLICY_REPORT, cache_report, ROOT / 'reports/ios16-volumes.json')},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'kernel_reports': kernel_reports,
        'original_SpringBoard': springboard, 'Darwin22_layout': layout, 'hardware_tested': False,
        'physical_storage_enabled': False, 'hardware_data_protection': False,
        'full_system_booted': False, 'graphical_interface_tested': False, 'phone_operations': 'none',
        'scope': 'Original signed launchd configuration completes early boot and original iPhone services execute in EL0 on persistent VM Data. '
                 'The real mbuf statistics function returns across an empty secondary CPU range; compiling only that consumer with the old header '
                 'reproduces its kernel data abort. Process UUID identifies original SpringBoard; no UI or hardware functionality is claimed.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original services, original SpringBoard process and fixed per-CPU statistics; old consumer reproduces its fault')


if __name__ == '__main__':main()
