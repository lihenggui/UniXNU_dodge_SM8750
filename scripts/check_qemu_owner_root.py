#!/usr/bin/env python3
"""Run the iPhone owner-root chain and its signature, DMA and UUID controls."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct

from build_qemu_owner_root import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_storage import run_case, Remote, ENTRY_REPORT, check_entry
from native_driver_build import ROOT, require, symbols
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha

OUT = ROOT / 'build/cph2653-qemu-owner-root-entry'
REPORT = ROOT / 'reports/ios16-qemu-owner-root-entry.json'
ROOT_FIELDS = ('native_owner_root_accepted', 'native_owner_root_trust_enabled', 'native_owner_root_apple_autherr',
    'native_owner_root_decision', 'native_owner_root_readonly', 'native_owner_root_mount_device', 'native_owner_root_selected_device',
    'native_virtio_verified_devices', 'native_virtio_integrity_failures', 'native_verified_block_root_uuid_match',
    'native_verified_block_wrong_uuid_refused', 'native_verified_block_root_media_matches',
    'dodge_qemu_storage_phase', 'dodge_qemu_storage_started', 'native_virtio_read_requests', 'native_virtio_read_failures')


class InitReached(Exception):
    pass


def execute(case, source, paths, environment, images, board, policy, timeout):
    kernel = ROOT / source['candidate']
    names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 14}
    rsa = {int(policy['Darwin22_RSA_contract'][key], 0) - 0x1000000: key
           for key in ('original_make_public', 'original_verify')}
    points = {names[name]: name for name in ('_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint', '_load_init_program')}
    directory = OUT / case / ('enabled' if case in ('positive', 'uuid') else case)
    directory.mkdir(parents=True, exist_ok=True)
    trace_path = directory / 'owner-root.json'
    result = {'case': case, 'RSA_calls': [], 'root_checkpoints': [], 'init_loader_entered': False}

    class OwnerRemote(Remote):
        def save(self):trace_path.write_text(json.dumps(result, indent=2) + '\n')

        def state(self):
            def integer(name, size=4):return int.from_bytes(self.memory(names['_' + name], size), 'little')
            fields = {name: integer(name) for name in ROOT_FIELDS}
            fields['verified_blocks'] = integer('native_virtio_verified_blocks', 8)
            table = integer('g_crypto_funcs', 8)
            fields['RSA_table'] = [hex(value) for value in struct.unpack('<2Q', self.memory(table + 304, 16))]
            require(fields['RSA_table'] == [hex(address) for address in rsa], 'Live original RSA callbacks changed')
            return fields

        def packet(self, message):
            reply = super().packet(message)
            if message == '?':
                for address in points:require(super().packet(f'Z1,{address:x},4') == 'OK', 'Cannot trace owner-root entry')
            if message != 'c':return reply
            while reply.startswith('T05'):
                values = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')))
                pc = values[32]
                if pc == names['_bsd_init']:
                    result['original_RSA_callback_prefix_sha256'] = [hashlib.sha256(self.memory(address, 96)).hexdigest() for address in rsa]
                    require(result['original_RSA_callback_prefix_sha256'] == policy['Darwin22_RSA_contract']['original_callback_prefix_sha256'],
                            'Live original RSA instructions changed')
                    for address in rsa:require(super().packet(f'Z1,{address:x},4') == 'OK', 'Cannot trace original RSA callback')
                if pc not in rsa and pc not in points:
                    if pc == names['_panic'] or pc == names['_IOFindBSDRoot']:
                        result['last_state'] = self.state();self.save()
                    return reply
                if pc in rsa:
                    result['RSA_calls'].append({'callback': rsa[pc], 'pc': hex(pc), 'lr': hex(values[30]),
                        'arguments': [hex(value) for value in values[:7]]})
                    require(len(result['RSA_calls']) <= 64, 'Unbounded original RSA callback trace')
                else:
                    row = {'checkpoint': points[pc], 'pc': hex(pc), 'state': self.state()}
                    result['root_checkpoints'].append(row)
                    print('QEMU owner root:', case, points[pc], flush=True)
                    if points[pc] == '_load_init_program':
                        result['init_loader_entered'] = True;result['last_state'] = row['state'];self.save()
                        raise InitReached()
                self.save()
                require(super().packet(f'z1,{pc:x},4') == 'OK', 'Cannot release owner checkpoint')
                require(super().packet('s').startswith('T05'), 'Cannot step owner checkpoint')
                require(super().packet(f'Z1,{pc:x},4') == 'OK', 'Cannot restore owner checkpoint')
                reply = super().packet('c')
            return reply

    try:
        observation, _ = run_case('enabled' if case in ('positive', 'uuid') else case, paths, environment,
            kernel, names, images, board, timeout, directory_root=OUT / case, remote_factory=OwnerRemote)
        result['execution'] = observation
    except InitReached:
        require(case == 'positive', 'A refused root policy entered the init loader')
        result['execution'] = json.loads((directory / 'observation.json').read_text())
    state = result['last_state']
    require({row['name'] for row in result['execution']['policies']} == {'AppleImage4', 'AMFI', 'Sandbox'} and
            all(row['registered'] for row in result['execution']['policies']), 'Original MAC policies did not register')
    require(Counter(row['callback'] for row in result['RSA_calls']) == {'original_make_public': 2, 'original_verify': 2},
            'Original RSA did not check both actual root policies')
    if case == 'positive':
        require(result['init_loader_entered'] and state['native_owner_root_accepted'] == state['native_owner_root_decision'] == 1 and
                state['native_owner_root_readonly'] == state['native_verified_block_root_uuid_match'] ==
                state['native_verified_block_wrong_uuid_refused'] == state['native_verified_block_root_media_matches'] == 1 and
                state['native_owner_root_mount_device'] == state['native_owner_root_selected_device'] and
                state['native_virtio_verified_devices'] == 2 and state['verified_blocks'] > 2 and
                not state['native_virtio_integrity_failures'] and state['native_owner_root_apple_autherr'] == 80,
                'Owner-root authorization or original Apple refusal differs')
    elif case == 'uuid':
        require(not result['init_loader_entered'] and state['native_owner_root_accepted'] == state['native_owner_root_decision'] == 0 and
                state['native_virtio_verified_devices'] == 2 and state['native_verified_block_root_uuid_match'] == 0 and
                state['native_owner_root_readonly'] == 1 and state['native_owner_root_apple_autherr'] == 80 and
                result['execution']['next_stop']['format'] == 'rootvp not authenticated after mounting @%s:%d',
                'A valid signature for a different volume was accepted')
    else:
        require(not result['init_loader_entered'] and not state['native_owner_root_accepted'] and
                state['dodge_qemu_storage_phase'] == 3 and not state['dodge_qemu_storage_started'] and
                not state['native_virtio_verified_devices'] and
                state['native_virtio_integrity_failures'] == (2 if case == 'dma' else 0) and
                state['native_virtio_read_requests'] == (2 if case == 'dma' else 0), 'Damaged signature or DMA was accepted')
    trace_path.write_text(json.dumps(result, indent=2) + '\n')
    artifacts = [trace_path, directory / 'serial.log', directory / 'qemu.log', directory / 'observation.json',
        directory / 'qemu.dtb', directory / 'image4-boot-policy.json',
        *sorted(path for path in (directory / 'esp').rglob('*') if path.is_file())]
    return result, artifacts


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_OWNER_ROOT_AND_INIT_LOADER_PASS' and
            report['owner_root_authorized'] and not report['Apple_root_authenticated'] and
            not report['userspace_executed'] and not report['hardware_tested'] and
            set(report['negative_controls']) == {'signature', 'dma', 'uuid'}, 'Incomplete owner-root execution')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Owner-root execution input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--timeout', type=int, default=600);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: recorded original RSA, owner root and init-loader entry');return
    require(30 <= args.timeout <= 900, 'Choose 30..900 seconds per owner-root case')
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry)
    policy = json.loads(POLICY_REPORT.read_text())
    images = json.loads((ROOT / 'reports/ios16-volumes.json').read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original volume changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']]
    qemu, firmware, variables, rom = emulator
    paths = qemu, firmware, variables, rom.parent
    env = dict(os.environ)
    libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():env['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    board = (ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt').read_bytes()
    results, artifacts, dependencies = {}, [], [POLICY_REPORT, ENTRY_REPORT]
    for case in ('positive', 'signature', 'dma', 'uuid'):
        path = SOURCE_REPORT if case == 'positive' else SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-' + case + '.json')
        source = json.loads(path.read_text());check_source(source)
        require(source['fault_control'] == (None if case == 'positive' else case), 'Wrong owner-root control kernel')
        results[case], extra = execute(case, source, paths, env, images, board, policy, args.timeout)
        artifacts += extra + [ROOT / source['candidate']];dependencies.append(path)
    artifacts += emulator + [ROOT / image['path'] for image in images]
    report = {'result': 'IOS16_QEMU_OWNER_ROOT_AND_INIT_LOADER_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__),
            ROOT / 'scripts/check_qemu_storage.py', ROOT / 'scripts/check_native_a830_entry.py', ROOT / 'scripts/image4_boot_policy.py')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in dependencies},
        'artifacts': {str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'positive': results['positive'],
        'negative_controls': {case: results[case] for case in ('signature', 'dma', 'uuid')},
        'owner_root_authorized': True, 'Apple_root_authenticated': False, 'userspace_executed': False,
        'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Original iPhone RSA callbacks verify both signed root policies in QEMU. Each block read is checked before use. '
                 'The separate owner policy authorizes only the matching read-only mounted root and reaches load_init_program. '
                 'The original Apple ioctl still returns EAUTH. Signature damage, changed DMA and a genuinely signed wrong UUID '
                 'are refused. This run ends before user instructions execute.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original RSA, owner-verified APFS root, init loader and three actual refusal controls')


if __name__ == '__main__':main()
