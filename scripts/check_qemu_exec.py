#!/usr/bin/env python3
"""Run the original iPhone init executable through its first EL0 instruction."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from build_qemu_exec import REPORT as SOURCE_REPORT, check_report as check_source
from build_qemu_owner_root import REPORT as CONTROL_REPORT, check_report as check_control
from check_qemu_owner_root import ROOT_FIELDS
from check_qemu_storage import run_case, Remote, ENTRY_REPORT, check_entry
from native_driver_build import ROOT, build_objects, macho, require, symbols
from native_prelink import backed_offset
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, file_sha

OUT = ROOT / 'build/cph2653-qemu-exec-entry'
REPORT = ROOT / 'reports/ios16-qemu-exec-entry.json'


def compiled_layout():
    directory = OUT / 'layout';directory.mkdir(parents=True, exist_ok=True)
    source = directory / 'ExecLayout.c'
    fields = {
        'proc_bytes': 'sizeof(struct proc)', 'pid': '__builtin_offsetof(struct proc,p_pid)',
        'comm': '__builtin_offsetof(struct proc,p_comm)', 'comm_bytes': 'sizeof(((struct proc *)0)->p_comm)',
        'name': '__builtin_offsetof(struct proc,p_name)', 'name_bytes': 'sizeof(((struct proc *)0)->p_name)',
        'uuid': '__builtin_offsetof(struct proc,p_uuid)', 'registration_bytes': 'sizeof(decmpfs_registration)',
        'version': '__builtin_offsetof(decmpfs_registration,decmpfs_registration)',
        **{name: '__builtin_offsetof(decmpfs_registration,' + name + ')'
           for name in ('validate', 'adjust_fetch', 'fetch', 'free_data', 'get_flags')},
        'compression_types': 'CMP_MAX', 'version_one': 'DECMPFS_REGISTRATION_VERSION_V1',
        'version_three': 'DECMPFS_REGISTRATION_VERSION_V3'}
    source.write_text('#include <sys/proc_internal.h>\n#include <sys/decmpfs.h>\n'
        'const unsigned exec_layout[]={' + ','.join(fields.values()) + '};\n')
    obj, = build_objects([source], directory)
    raw = obj.read_bytes();parsed = macho(raw)
    address, = [row['value'] for row in symbols(raw) if row['name'] == '_exec_layout']
    offset = backed_offset(parsed['segments'], address, len(fields) * 4, len(raw))
    result = dict(zip(fields, struct.unpack_from('<' + str(len(fields)) + 'I', raw, offset)))
    require(result['registration_bytes'] == 48 and result['fetch'] == 24 and result['compression_types'] > 4,
            'Darwin 22 decompression layout changed')
    return result, [source, obj, directory / 'compile-commands.json']


def original_files(images):
    reference = ROOT / 'reports/ios16-display-cache.json'
    recorded = json.loads(reference.read_text());extractor = ROOT / recorded['extractor']
    require(file_sha(extractor) == recorded['extractor_sha256'] and
            file_sha(ROOT / 'tools/ApfsExtract.cpp') == recorded['extractor_source_sha256'], 'APFS extractor changed')
    originals = OUT / 'originals';originals.mkdir(parents=True, exist_ok=True)
    files = {}
    with tempfile.TemporaryDirectory(prefix='extract-', dir=originals) as temporary:
        for path in ('/usr/lib/dyld', '/sbin/launchd'):
            name = Path(path).name;pending = Path(temporary) / name
            subprocess.run([extractor, ROOT / images[0]['path'], '0', path, pending], check=True)
            raw = pending.read_bytes();parsed = macho(raw)
            require(struct.unpack_from('<3I', raw) == (0xfeedfacf, 0x100000c, 0), 'Expected original ordinary arm64 executable')
            uuid_at, = [at for command, at, _ in parsed['commands'] if command == 0x1b]
            pending.replace(originals / name)
            files[name] = {'path': path, 'local': str((originals / name).relative_to(ROOT)),
                'sha256': file_sha(originals / name), 'uuid': raw[uuid_at + 8:uuid_at + 24].hex()}
            if name == 'dyld':
                at, = [at for command, at, _ in parsed['commands'] if command == 5]
                require(struct.unpack_from('<2I', raw, at + 8) == (6, 68), 'Unexpected original dyld thread flavor')
                files[name]['entry'] = struct.unpack_from('<Q', raw, at + 272)[0]
    return files, [reference], [extractor, *(ROOT / row['local'] for row in files.values())]


class UserInstructionReached(Exception):
    pass


def execute(case, source, paths, environment, images, board, policy, layout, originals, timeout, *,
            directory_root=OUT, resource_factory=None, after_user_instruction=None):
    kernel = ROOT / source['candidate'];raw = kernel.read_bytes();parsed = macho(raw)
    names = {row['name']: row['value'] for row in symbols(raw) if row['kind'] & 14}
    start = names['_arm64_thread_exception_return'];offset = backed_offset(parsed['segments'], start, 8192, len(raw))
    eret, = [start + at for at in range(0, 8192, 4) if struct.unpack_from('<I', raw, offset + at)[0] == 0xd69f03e0]
    rsa = {int(policy['Darwin22_RSA_contract'][key], 0) - 0x1000000: key
           for key in ('original_make_public', 'original_verify')}
    points = {names[name]: name for name in ('_native_owner_root_accepted_checkpoint', '_load_init_program')}
    directory = directory_root / case / 'enabled';directory.mkdir(parents=True, exist_ok=True)
    trace_path = directory / 'exec.json'
    result = {'case': case, 'RSA_calls': [], 'init_loader_entered': False, 'EL0_entered': False,
        'user_instruction_executed': False, 'kernel_return': hex(eret),
        'kernel_return_sha256': hashlib.sha256(raw[offset:offset + 8192]).hexdigest()}
    dyld = (ROOT / originals['dyld']['local']).read_bytes();dyld_image = macho(dyld)
    dyld_entry = originals['dyld']['entry'];dyld_offset = backed_offset(dyld_image['segments'], dyld_entry, 64, len(dyld))

    class ExecRemote(Remote):
        def save(self):trace_path.write_text(json.dumps(result, indent=2) + '\n')

        def state(self):
            fields = {name: int.from_bytes(self.memory(names['_' + name], 4), 'little') for name in ROOT_FIELDS}
            fields['verified_blocks'] = int.from_bytes(self.memory(names['_native_virtio_verified_blocks'], 8), 'little')
            table = int.from_bytes(self.memory(names['_g_crypto_funcs'], 8), 'little')
            fields['RSA_table'] = [hex(value) for value in struct.unpack('<2Q', self.memory(table + 304, 16))]
            require(fields['RSA_table'] == [hex(address) for address in rsa], 'Live original RSA callbacks changed')
            result['last_state'] = fields
            registration = int.from_bytes(self.memory(names['_decompressors'] + 4 * 8, 8), 'little')
            result['type_four_registration'] = hex(registration)
            if registration:
                record = self.memory(registration, layout['registration_bytes'])
                version = struct.unpack_from('<I', record, layout['version'])[0]
                require(version in (layout['version_one'], layout['version_three']), 'Unsupported registered decompressor')
                callbacks = {name: struct.unpack_from('<Q', record, layout[name])[0]
                    for name in ('validate', 'adjust_fetch', 'fetch', 'free_data', 'get_flags')}
                require(callbacks['fetch'], 'Original decompressor has no fetch callback')
                spans = source.get('original_decompressor_segments', [])
                for address in filter(None, callbacks.values()):
                    require(any(int(span['address'], 0) <= address < int(span['address'], 0) + span['bytes'] for span in spans),
                            'Decompressor callback lies outside original component code')
                    at = backed_offset(parsed['segments'], address, 32, len(raw))
                    require(self.memory(address, 32) == raw[at:at + 32], 'Live original decompressor instructions changed')
                result['decompressor'] = {'version': version, 'callbacks': {name: hex(address) for name, address in callbacks.items()},
                    'original_callback_instructions_match': True}
            return fields

        def special_registers(self):
            registers = {}
            for include in self.xml('target.xml').iter():
                if not include.tag.endswith('include'):continue
                for reg in self.xml(include.attrib['href']).iter('reg'):
                    if reg.attrib['name'] in ('ELR_EL1', 'SPSR_EL1'):
                        value = super().packet('p' + format(int(reg.attrib['regnum']), 'x'))
                        registers[reg.attrib['name']] = int.from_bytes(bytes.fromhex(value), 'little')
            require(set(registers) == {'ELR_EL1', 'SPSR_EL1'}, 'QEMU omitted exception return registers')
            return registers

        def packet(self, message):
            reply = super().packet(message)
            if message == '?':
                for address in points:require(super().packet(f'Z1,{address:x},4') == 'OK', 'Cannot trace init loading')
            if message != 'c':return reply
            while reply.startswith('T05'):
                values = struct.unpack_from('<33Q', bytes.fromhex(super().packet('g')));pc = values[32]
                if pc == names['_bsd_init']:
                    require([hashlib.sha256(self.memory(address, 96)).hexdigest() for address in rsa] ==
                        policy['Darwin22_RSA_contract']['original_callback_prefix_sha256'], 'Original RSA instructions changed')
                    for address in rsa:require(super().packet(f'Z1,{address:x},4') == 'OK', 'Cannot trace original RSA')
                if pc not in points and pc not in rsa:
                    if pc == names['_panic']:self.state();self.save()
                    return reply
                if pc in rsa:
                    result['RSA_calls'].append({'callback': rsa[pc], 'pc': hex(pc)})
                    require(len(result['RSA_calls']) <= 64, 'Unbounded RSA trace')
                elif points[pc] == '_load_init_program':
                    result['init_loader_entered'] = True
                    points[eret] = 'ERET';require(super().packet(f'Z1,{eret:x},4') == 'OK', 'Cannot trace exception return')
                elif points[pc] == 'ERET':
                    special = self.special_registers()
                    if special['SPSR_EL1'] & 15 == 0:
                        require(case == 'positive', 'Missing decompressor reached user instructions')
                        result['return_registers'] = {key: hex(value) for key, value in special.items()}
                        process = int.from_bytes(self.memory(names['_initproc'], 8), 'little')
                        proc = self.memory(process, layout['proc_bytes'])
                        pid = struct.unpack_from('<I', proc, layout['pid'])[0]
                        comm = proc[layout['comm']:layout['comm'] + layout['comm_bytes']].split(b'\0')[0].decode()
                        name = proc[layout['name']:layout['name'] + layout['name_bytes']].split(b'\0')[0].decode()
                        uuid = proc[layout['uuid']:layout['uuid'] + 16].hex()
                        require(pid == 1 and comm == name == 'launchd' and uuid == originals['launchd']['uuid'],
                                'Init process identity differs from original iPhone launchd')
                        result['process'] = {'pid': pid, 'comm': comm, 'name': name, 'uuid': uuid}
                        self.state()
                        require(super().packet(f'z1,{pc:x},4') == 'OK', 'Cannot release user exception return')
                        require(super().packet('s').startswith('T05'), 'Cannot step exception return')
                        user_raw = bytes.fromhex(super().packet('g'));user = struct.unpack_from('<33Q', user_raw)
                        pstate = struct.unpack_from('<I', user_raw, 264)[0]
                        require(user[32] == special['ELR_EL1'] and pstate & 15 == 0, 'Exception return did not enter EL0')
                        slide = user[32] - dyld_entry
                        require(slide > 0 and slide & 4095 == 0 and
                            self.memory(user[32], 64) == dyld[dyld_offset:dyld_offset + 64], 'User entry differs from original iPhone dyld')
                        result.update(EL0_entered=True,
                            user_entry={'pc': hex(user[32]), 'pstate': hex(pstate), 'dyld_slide': hex(slide),
                                'code': dyld[dyld_offset:dyld_offset + 64].hex(), 'original_entry_code_matches': True})
                        require(dyld[dyld_offset:dyld_offset + 4] == bytes.fromhex('e0030091'), 'Expected original mov x0,sp startup instruction')
                        require(super().packet('s').startswith('T05'), 'Cannot step first user instruction')
                        after_raw = bytes.fromhex(super().packet('g'));after = struct.unpack_from('<33Q', after_raw)
                        after_pstate = struct.unpack_from('<I', after_raw, 264)[0]
                        require(after[32] == user[32] + 4 and after_pstate & 15 == 0 and after[0] == user[31],
                                'First original user instruction did not execute')
                        result['user_instruction_executed'] = True
                        result['after_instruction'] = {'pc': hex(after[32]), 'pstate': hex(after_pstate),
                            'x0': hex(after[0]), 'original_sp': hex(user[31])}
                        if after_user_instruction is not None:after_user_instruction(self, result, names)
                        self.save();raise UserInstructionReached()
                else:self.state()
                self.save()
                require(super().packet(f'z1,{pc:x},4') == 'OK', 'Cannot release exec checkpoint')
                require(super().packet('s').startswith('T05'), 'Cannot step exec checkpoint')
                require(super().packet(f'Z1,{pc:x},4') == 'OK', 'Cannot restore exec checkpoint')
                reply = super().packet('c')
            return reply

    try:
        options = {'resource_factory': resource_factory} if resource_factory is not None else {}
        result['execution'], _ = run_case('enabled', paths, environment, kernel, names, images, board, timeout,
            directory_root=directory_root / case, remote_factory=ExecRemote, **options)
    except UserInstructionReached:
        result['execution'] = json.loads((directory / 'observation.json').read_text())
    state = result['last_state']
    require(Counter(row['callback'] for row in result['RSA_calls']) == {'original_make_public': 2, 'original_verify': 2} and
        result['init_loader_entered'] and state['native_owner_root_accepted'] == state['native_owner_root_readonly'] ==
        state['native_verified_block_root_uuid_match'] == state['native_verified_block_root_media_matches'] == 1 and
        state['native_owner_root_mount_device'] == state['native_owner_root_selected_device'] and
        state['native_owner_root_apple_autherr'] == 80 and state['native_virtio_verified_devices'] == 2 and
        state['verified_blocks'] > 2 and state['native_virtio_integrity_failures'] == 0, 'Owner-root chain changed during exec')
    if case == 'positive':
        require(result['user_instruction_executed'] and 'decompressor' in result, 'Original init did not execute in EL0')
    else:
        stop = result['execution']['next_stop']
        require(not result['EL0_entered'] and result['type_four_registration'] == '0x0' and
            stop['format'] == 'Process 1 exec of %s failed, errno %d @%s:%d' and int(stop['arguments'][1], 0) == 45,
            'Missing decompressor did not produce the original ENOTSUP exec failure')
    require('DARWINBOOT: inputs validated; exiting boot services' in (directory / 'serial.log').read_text(errors='replace'),
            'Incomplete EFI handoff')
    trace_path.write_text(json.dumps(result, indent=2) + '\n')
    return result, [trace_path, directory / 'serial.log', directory / 'qemu.log', directory / 'observation.json',
        directory / 'qemu.dtb', directory / 'image4-boot-policy.json',
        *sorted(path for path in (directory / 'esp').rglob('*') if path.is_file())]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_ORIGINAL_INIT_FIRST_EL0_INSTRUCTION_PASS' and
        report['positive']['process']['pid'] == 1 and report['positive']['user_instruction_executed'] and
        not report['negative_control']['EL0_entered'] and not report['system_booted'] and not report['hardware_tested'],
        'Incomplete original init execution')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Exec input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--timeout', type=int, default=600);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original iPhone launchd PID 1 executed its first dyld instruction');return
    require(30 <= args.timeout <= 900, 'Choose 30..900 seconds per exec case')
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry)
    policy = json.loads(POLICY_REPORT.read_text());volume_report = ROOT / 'reports/ios16-volumes.json'
    volumes = json.loads(volume_report.read_text());images = volumes['images']
    require((volumes['product'], volumes['build']) == ('iPhone10,3', '20H392') and
        [image['name'] for image in images] == ['OS', 'SystemOS'], 'Wrong iPhone volume input')
    for image in images:require(file_sha(ROOT / image['path']) == image['raw_sha256'], 'Original volume changed')
    emulator = [ROOT / name for name in entry['emulator_sha256']]
    qemu, firmware, variables, rom = emulator;paths = qemu, firmware, variables, rom.parent
    environment = dict(os.environ)
    libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    OUT.mkdir(parents=True, exist_ok=True)
    layout, artifacts = compiled_layout();originals, dependencies, extra = original_files(images);artifacts += extra
    dependencies += [SOURCE_REPORT, CONTROL_REPORT, POLICY_REPORT, ENTRY_REPORT, volume_report]
    board_path = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    results = {}
    for case, path, checker in (('positive', SOURCE_REPORT, check_source), ('missing-decompressor', CONTROL_REPORT, check_control)):
        source = json.loads(path.read_text());checker(source)
        results[case], extra = execute(case, source, paths, environment, images, board_path.read_bytes(), policy, layout, originals, args.timeout)
        artifacts += extra + [ROOT / source['candidate']]
        print('QEMU exec:', case, 'first EL0 instruction' if case == 'positive' else 'original ENOTSUP refusal', flush=True)
    artifacts += emulator + [board_path, *(ROOT / image['path'] for image in images)]
    report = {'result': 'IOS16_QEMU_ORIGINAL_INIT_FIRST_EL0_INSTRUCTION_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (Path(__file__),
            ROOT / 'scripts/check_qemu_storage.py', ROOT / 'scripts/check_qemu_owner_root.py',
            ROOT / 'scripts/check_native_a830_entry.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'tools/ApfsExtract.cpp')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in dependencies},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'product': 'iPhone10,3', 'build': '20H392', 'Darwin22_layout': layout, 'original_files': originals,
        'positive': results['positive'], 'negative_control': results['missing-decompressor'],
        'system_booted': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'PID 1 executes the original iPhone dyld entry for launchd in EL0. The process UUID and 64 dyld entry bytes '
                 'match read-only extraction from the pinned OS image. The original type-4 decompressor '
                 'is registered with unchanged callback instructions. Without that component, the same owner-root chain '
                 'fails exec with ENOTSUP before EL0. This check stops after one user instruction.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original iPhone PID 1, dyld EL0 instruction and missing-decompressor control')


if __name__ == '__main__':main()
