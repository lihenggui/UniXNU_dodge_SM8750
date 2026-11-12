#!/usr/bin/env python3
"""Run the iPhone software-AES provider and original dyld past Image4 startup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from build_qemu_aes import REPORT as SOURCE_REPORT, check_report as check_source
from check_qemu_exec import REPORT as EXEC_REPORT, check_report as check_exec, execute
from check_qemu_storage import run_case, virtual_resources, Remote, ENTRY_REPORT, check_entry
from image4_boot_policy import encode_tree
from native_driver_build import ROOT, require, symbols, macho
from native_prelink import backed_offset
from prepare_device_tree import parse_adt
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha

OUT = ROOT / 'build/cph2653-qemu-aes-entry'
REPORT = ROOT / 'reports/ios16-qemu-aes-entry.json'
FIELDS = ('dodge_qemu_aes_phase', 'dodge_qemu_aes_result', 'native_aes_kat_status', 'native_aes_interface_status',
    'native_aes_registered', 'native_aes_completed', 'native_aes_unsupported_key', 'native_aes_nonce_key_uses')
IDENTITY_DOMAIN = b'UniXNU.Dodge.QemuIdentity.v1\0'


def owner_resources(anchor):
    identifier = hashlib.sha256(IDENTITY_DOMAIN + anchor).digest()[:8]
    require(any(identifier), 'Zero owner VM identifier')
    def resources(tree, fdt, uuid):
        tree, windows = virtual_resources(tree, fdt, uuid)
        nodes = parse_adt(tree)
        require(nodes['/chosen']['unique-chip-id'] == bytes(8), 'VM identity contains an existing platform identifier')
        nodes['/chosen']['unique-chip-id'] = identifier
        return encode_tree(nodes), windows
    return resources


def counters(remote, names):
    result = {name: int.from_bytes(remote.memory(names['_' + name], 4), 'little') for name in FIELDS}
    result['native_aes_bytes'] = int.from_bytes(remote.memory(names['_native_aes_bytes'], 8), 'little')
    return result


def cstring(remote, address, maximum=512):
    result = bytearray()
    while len(result) < maximum:
        count = min(64, maximum - len(result), 4096 - (address & 4095))
        chunk = remote.memory(address, count)
        if b'\0' in chunk:return (result + chunk.split(b'\0')[0]).decode(errors='replace')
        result.extend(chunk);address += count
    raise ValueError('Unterminated bounded guest string')


def follow_dyld(originals):
    dyld = (ROOT / originals['dyld']['local']).read_bytes();image = macho(dyld)
    table = {row['name']: row['value'] for row in symbols(dyld) if row['kind'] & 14}
    selected = {'prepare': '__ZN5dyld4L7prepareERNS_4APIsEPKN5dyld313MachOAnalyzerE',
        'cache': '__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE',
        'halt': '__ZN5dyld44haltEPKc', 'sysctlbyname': '_sysctlbyname', 'sysctl': '___sysctl'}

    def follow(remote, result, names):
        slide = int(result['user_entry']['dyld_slide'], 0)
        points = {slide + table[name]: label for label, name in selected.items()}
        points[names['_unix_syscall']] = 'kernel-state'
        states, events = [], [];result['AES_states'] = states;result['dyld_events'] = events
        returns = {};pending_cache = None;ignition_pending = False
        for address in points:require(Remote.packet(remote, f'Z1,{address:x},4') == 'OK', 'Cannot trace original dyld')
        while True:
            require(Remote.packet(remote, 'c').startswith('T05'), 'Unexpected dyld stop')
            registers = bytes.fromhex(Remote.packet(remote, 'g'));values = struct.unpack_from('<33Q', registers);pc = values[32]
            require(pc in points, 'Unrecognized dyld checkpoint')
            label = points[pc];row = {'checkpoint': label, 'pc': hex(pc), 'pstate': hex(struct.unpack_from('<I', registers, 264)[0])}
            if label == 'kernel-state':
                states.append(counters(remote, names))
                require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release AES state observation')
                del points[pc];continue
            require(int(row['pstate'], 0) & 15 == 0, 'Original dyld checkpoint is outside EL0')
            if label in selected:
                address = pc - slide;at = backed_offset(image['segments'], address, 4, len(dyld))
                require(remote.memory(pc, 4) == dyld[at:at + 4], 'Original dyld instruction changed')
                row['original_instruction_matches'] = True
            if label == 'sysctlbyname':
                row['name'] = cstring(remote, values[0], 128)
                if row['name'] == 'security.mac.img4.ignition_blob':
                    returns[values[30]] = 'ignition-return';points[values[30]] = 'ignition-return'
                    require(Remote.packet(remote, f'Z1,{values[30]:x},4') == 'OK', 'Cannot trace ignition query return')
            elif label == 'sysctl':
                require(0 < values[1] <= 24, 'Unbounded original sysctl name')
                row['mib'] = list(struct.unpack('<' + str(values[1]) + 'I', remote.memory(values[0], values[1] * 4)))
                if row['mib'][0] == 0 and values[4] and 0 < values[5] < 128:
                    row['name'] = cstring(remote, values[4], 128)
                    ignition_pending = row['name'] == 'security.mac.img4.ignition_blob'
                elif ignition_pending:
                    returns[values[30]] = 'ignition-return';points[values[30]] = 'ignition-return';ignition_pending = False
                    require(Remote.packet(remote, f'Z1,{values[30]:x},4') == 'OK', 'Cannot trace original ignition return')
            elif label == 'cache':
                pending_cache = values[1];returns[values[30]] = 'cache-return';points[values[30]] = 'cache-return'
                require(Remote.packet(remote, f'Z1,{values[30]:x},4') == 'OK', 'Cannot trace original cache return')
            elif label in ('ignition-return', 'cache-return'):
                row['x0'] = hex(values[0])
                if label == 'cache-return':
                    require(pending_cache is not None, 'Missing original cache output')
                    words = struct.unpack('<3Q', remote.memory(pending_cache, 24))
                    row['output_words'] = [hex(value) for value in words]
                    if words[2]:row['error'] = cstring(remote, words[2], 256)
                del points[pc];del returns[pc]
            elif label == 'halt':
                row['message'] = cstring(remote, values[0])
                events.append(row);break
            events.append(row);require(len(events) <= 64, 'Unbounded dyld observation')
            require(Remote.packet(remote, f'z1,{pc:x},4') == 'OK', 'Cannot release original dyld checkpoint')
            require(Remote.packet(remote, 's').startswith('T05'), 'Cannot step original dyld checkpoint')
            if pc in points:require(Remote.packet(remote, f'Z1,{pc:x},4') == 'OK', 'Cannot restore original dyld checkpoint')
        state, = states
        require(state['dodge_qemu_aes_phase'] == 2 and state['dodge_qemu_aes_result'] == 0 and
            state['native_aes_kat_status'] == state['native_aes_interface_status'] == state['native_aes_registered'] == 1 and
            state['native_aes_nonce_key_uses'] > 0 and state['native_aes_completed'] >= state['native_aes_nonce_key_uses'],
            'Software AES did not complete original Image4 nonce requests')
        require(any(row['checkpoint'] == 'prepare' for row in events) and
            any(row['checkpoint'] == 'ignition-return' for row in events), 'Original dyld did not pass the ignition query')
        cache, = [row for row in events if row['checkpoint'] == 'cache-return']
        require(cache['x0'] == '0x0' and cache['output_words'][:2] == ['0x0', '0x0'] and
            cache['error'] == 'shared cache file open() failed', 'Unexpected original cache-loader result')
        require(row['checkpoint'] == 'halt' and 'Library not loaded: /usr/lib/libSystem.B.dylib' in row['message'] and
            '/sbin/launchd' in row['message'] and 'no such file, no dyld cache' in row['message'], 'Unexpected original dyld stop')
        print('QEMU AES: original dyld passed ignition and prepare; shared-cache input is next', flush=True)
    return follow


class Refused(Exception):
    pass


def control(case, source, paths, environment, images, board, timeout, resource_factory):
    kernel = ROOT / source['candidate'];names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 14}
    point = names['_dodge_qemu_aes_checkpoint'];result = {'case': case}
    directory = OUT / case / 'enabled';directory.mkdir(parents=True, exist_ok=True)
    trace = directory / 'AES.json'
    class ControlRemote(Remote):
        def packet(self, message):
            reply = super().packet(message)
            if message == '?' and case == 'wrong-answer':
                require(super().packet(f'Z1,{point:x},4') == 'OK', 'Cannot trace AES refusal')
            if message == 'c' and reply.startswith('T05'):
                pc = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')))[32]
                if pc in (point, names['_panic']):
                    result['state'] = counters(self, names);trace.write_text(json.dumps(result, indent=2) + '\n')
                    if pc == point:raise Refused()
            return reply
    try:
        result['execution'], _ = run_case('enabled', paths, environment, kernel, names, images, board, timeout,
            directory_root=OUT / case, remote_factory=ControlRemote, resource_factory=resource_factory)
    except Refused:result['execution'] = json.loads((directory / 'observation.json').read_text())
    state = result['state']
    if case == 'wrong-answer':
        require(state['native_aes_kat_status'] == 2 and state['native_aes_registered'] == 0 and
            state['dodge_qemu_aes_phase'] == 3 and state['native_aes_nonce_key_uses'] == 0, 'Wrong AES answer registered a provider')
    else:
        stop = result['execution']['next_stop']
        require(state['native_aes_kat_status'] == state['native_aes_registered'] == 1 and
            state['native_aes_nonce_key_uses'] == 0 and state['native_aes_unsupported_key'] > 1 and
            stop['format'] == 'performAES: %#x' and stop['arguments'][0] == '0xe00002c7',
            'Absent VM identity silently supplied a nonce key')
    trace.write_text(json.dumps(result, indent=2) + '\n')
    return result, [trace, directory / 'serial.log', directory / 'qemu.log', directory / 'observation.json',
        directory / 'qemu.dtb', directory / 'image4-boot-policy.json',
        *sorted(path for path in (directory / 'esp').rglob('*') if path.is_file())]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_SOFTWARE_AES_AND_DYLD_PREPARE_PASS' and
        report['positive']['user_instruction_executed'] and set(report['negative_controls']) == {'wrong-answer', 'missing-vm-identity'} and
        not report['dyld_cache_mapped'] and not report['launchd_main_entered'] and not report['hardware_tested'], 'Incomplete AES execution')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'AES execution input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--timeout', type=int, default=600);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: iPhone software AES, original dyld prepare and two refusal controls');return
    require(30 <= args.timeout <= 900, 'Choose 30..900 seconds per AES run')
    previous = json.loads(EXEC_REPORT.read_text());check_exec(previous)
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    negative_path = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-negative.json')
    negative = json.loads(negative_path.read_text());check_source(negative)
    require(not source['negative_kat'] and negative['negative_kat'], 'Wrong AES control kernels')
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry);policy = json.loads(POLICY_REPORT.read_text())
    images = json.loads((ROOT / 'reports/ios16-volumes.json').read_text())['images']
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original iPhone volume changed')
    anchor_path = ROOT / policy['images'][0]['anchor'];anchor = anchor_path.read_bytes();resources = owner_resources(anchor)
    emulator = [ROOT / name for name in entry['emulator_sha256']]
    qemu, firmware, variables, rom = emulator;paths = qemu, firmware, variables, rom.parent
    environment = dict(os.environ)
    libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt';board = board_path.read_bytes()
    positive, artifacts = execute('positive', source, paths, environment, images, board, policy, previous['Darwin22_layout'],
        previous['original_files'], args.timeout, directory_root=OUT, resource_factory=resources,
        after_user_instruction=follow_dyld(previous['original_files']))
    controls = {}
    for case, candidate, factory in (('wrong-answer', negative, resources), ('missing-vm-identity', source, virtual_resources)):
        controls[case], extra = control(case, candidate, paths, environment, images, board, args.timeout, factory);artifacts += extra
        print('QEMU AES:', case, 'refused', flush=True)
    artifacts += emulator + [board_path, anchor_path, ROOT / source['candidate'], ROOT / negative['candidate'],
        *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_SOFTWARE_AES_AND_DYLD_PREPARE_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__), ROOT / 'scripts/check_qemu_exec.py',
            ROOT / 'scripts/check_qemu_storage.py', ROOT / 'scripts/check_native_a830_entry.py')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (SOURCE_REPORT, negative_path, EXEC_REPORT, ENTRY_REPORT, POLICY_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'VM_identity_domain': IDENTITY_DOMAIN.rstrip(b'\0').decode(),
        'VM_identity_public_anchor_sha256': file_sha(anchor_path), 'positive': positive, 'negative_controls': controls,
        'dyld_cache_mapped': False, 'launchd_main_entered': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'SoftwareAES passes its actual CBC and descriptor self-tests and serves original Image4 nonce requests. '
                 'Its software nonce key uses a separate VM identifier derived from the owner public anchor; it is public development identity. '
                 'The original iPhone dyld returns from its ignition query, enters prepare and reaches the genuine missing shared-cache failure. '
                 'A wrong CBC answer prevents registration, and an absent VM identifier preserves the original unsupported-key panic. '
                 'Apple hardware keys and personalization are outside this VM policy.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: iPhone AES, original dyld prepare/cache failure and two runtime refusal controls')


if __name__ == '__main__':main()
