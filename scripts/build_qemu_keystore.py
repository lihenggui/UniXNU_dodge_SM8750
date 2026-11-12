#!/usr/bin/env python3
"""Build the native Darwin 22 KeyStore state service for the owner VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_qemu_systemos import OUT as SYSTEM_OUT, REPORT as SYSTEM_REPORT, check_report as check_system
from build_qemu_aes import OUT as AES_OUT, readback as aes_readback
from build_qemu_owner_root import OUT as OWNER_OUT
from build_native_a830_kernel import REPORT as BASE_REPORT
from build_qemu_exec import MODULE, validate_extension
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import run
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import ROOT, TREE, OBJDIR, build_objects, inspect_object, pinned_sources, require, sha, symbols, macho
from native_prelink import backed_offset
from prepare_surface_backing import checked as backing_checked, apply_hooks
from check_keystore_host import prepare_source

OUT = ROOT / 'build/cph2653-qemu-keystore'
REPORT = ROOT / 'reports/ios16-qemu-keystore.json'
INIT = '__GLOBAL__sub_I_DodgeKeyStore.cpp'
VTABLES = ('__ZTV13AppleKeyStore', '__ZTV23AppleKeyStoreUserClient')
LAYOUT = ('service_bytes', 'client_bytes', 'keystore_bytes', 'keystore_client_bytes', 'arguments_bytes',
    'scalar_input', 'scalar_input_count', 'scalar_output', 'scalar_output_count', 'structure_input',
    'structure_input_bytes', 'structure_output', 'structure_output_bytes')


def class_tables(path):
    raw = path.read_bytes();image = inspect_object(raw);table = symbols(raw);result = {}
    for name in VTABLES:
        symbol, = [row for row in table if row['name'] == name]
        section, = [section for segment in image['segments'] for section in segment['sections']
            if section['va'] <= symbol['value'] < section['va'] + section['size']]
        offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56);slots = {}
        for index in range(count):
            address, bits = struct.unpack_from('<2I', raw, offset + index * 8)
            slot = section['va'] + address - symbol['value'] - 16
            if slot < 0:continue
            require(bits >> 24 == 14 and slot % 8 == 0, 'KeyStore vtable relocation changed')
            slots[slot // 8] = table[bits & 0xffffff]['name']
        methods = []
        while len(methods) in slots:methods.append(slots[len(methods)])
        require(168 <= len(methods) <= 256 and '___cxa_pure_virtual' not in methods, 'Incomplete native KeyStore dispatch')
        result[name] = methods
    return result


def layout(path):
    raw = path.read_bytes();image = macho(raw)
    address, = [row['value'] for row in symbols(raw) if row['name'] == '_dodge_keystore_layout']
    at = backed_offset(image['segments'], address, len(LAYOUT) * 4, len(raw))
    fields = dict(zip(LAYOUT, struct.unpack_from('<' + str(len(LAYOUT)) + 'I', raw, at)))
    require(fields['service_bytes'] == fields['keystore_bytes'] == 136 and
        fields['client_bytes'] == fields['keystore_client_bytes'], 'Native KeyStore class layout differs')
    return fields


def readback(raw, tables, expected):
    image = macho(raw);names = {row['name']: row for row in symbols(raw) if not row['kind'] & 0xe0}
    def read(address, count):
        at = backed_offset(image['segments'], address, count, len(raw));return raw[at:at + count]
    require(not any(row['kind'] == 1 for row in names.values()), 'KeyStore kernel has undefined imports')
    for name, methods in tables.items():
        require(struct.unpack('<' + str(len(methods)) + 'Q', read(names[name]['value'] + 16, len(methods) * 8)) ==
            tuple(names[method]['value'] for method in methods), 'Native KeyStore dispatch changed')
    require(struct.unpack('<' + str(len(LAYOUT)) + 'I', read(names['_dodge_keystore_layout']['value'], len(LAYOUT) * 4)) ==
        tuple(expected[name] for name in LAYOUT), 'Native KeyStore argument layout changed')
    for segment in image['segments']:
        for section in segment['sections']:
            if section['name'] == '__mod_init_func' and section['size']:
                require(names[INIT]['value'] not in struct.unpack('<' + str(section['size'] // 8) + 'Q', read(section['va'], section['size'])),
                    'KeyStore initializes before IOKit startup')
    return {'class_slots': {name: len(methods) for name, methods in tables.items()}, 'layout': expected,
        'deferred_initializer': hex(names[INIT]['value'])}


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_NATIVE_KEYSTORE_STATE_KERNEL_PASS' and report['development_only'] and
        not report['hardware_data_protection'] and not report['hardware_tested'] and
        report['source_reference'] == json.loads((ROOT / 'upstream.lock.json').read_text())['apple_keystore_state_reference'], 'Wrong KeyStore fixture')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'KeyStore input changed: ' + name)
    require(readback((ROOT / report['candidate']).read_bytes(), report['class_tables'], report['layout']) == report['class_readback'],
        'KeyStore linked readback changed')


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--closed', action='store_true');args = parser.parse_args()
    if args.closed:
        OUT = OUT.with_name(OUT.name + '-closed');REPORT = REPORT.with_name(REPORT.stem + '-closed.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native iPhone KeyStore state kernel');return
    system = json.loads(SYSTEM_REPORT.read_text());check_system(system)
    require(not system['wrong_uuid_control'], 'Wrong-UUID SystemOS cannot supply KeyStore')
    base = json.loads(BASE_REPORT.read_text());lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reference = pinned_sources(('apple_keystore_state_reference',))['apple_keystore_state_reference']
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / 'host-test.log').open('w') as log:
        process = subprocess.run([sys.executable, ROOT / 'scripts/check_keystore_host.py'], stdout=log, stderr=log)
    require(not process.returncode, 'KeyStore host boundary test failed; inspect host-test.log')
    state_source, state_patch = prepare_source(OUT / 'state-source')[1:]
    cpp = [ROOT / 'drivers/DodgeSecurity/DodgeKeyStore.cpp', ROOT / 'drivers/DodgeSecurity/DodgeQemuKeyStore.cpp']
    obj, lifecycle = build_objects(cpp, OUT, [state_source.parent], ['-DDODGE_QEMU_KEYSTORE_CLOSED=' + str(int(args.closed))])
    tables = class_tables(obj);fields = layout(obj);late = OUT / 'DodgeKeyStore.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, obj, late], check=True)
    archive = OUT / 'libDodgeQemuKeyStore.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, late, lifecycle], check=True)
    pin = lock['dodge_qemu_keystore_overlay'];patch = ROOT / pin['path'];old_bsd = AES_OUT / 'IOKitBSDInit.cpp'
    require(sha(patch) == pin['sha256'] and sha(old_bsd) == pin['base_source_sha256'], 'KeyStore IOBSD overlay changed')
    bsd = OUT / 'IOKitBSDInit.cpp';bsd.write_bytes(old_bsd.read_bytes())
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)], cwd=OUT, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(bsd) == pin['output_source_sha256'], 'KeyStore IOBSD overlay is not exact')
    recipe = json.loads((OBJDIR / 'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json').read_text().strip().rstrip(','));command, index = [], 0
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value == recipe['file']:command.append(str(bsd))
        elif value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):command.append(value)
        index += 1
    bsd_obj = OUT / 'IOKitBSDInit.keystore.cpo';run([*command, '-o', bsd_obj], OUT / 'bsd-compile.log', recipe['directory'])
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    old_observers = str(ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o')
    require(command.count(old_observers) == 1, 'Ambiguous observer input')
    command[command.index(old_observers)] = str(SYSTEM_OUT / 'absent-observers.o')
    rows = (SYSTEM_OUT / 'native.filelist').read_text().splitlines();old_obj = str(AES_OUT / 'IOKitBSDInit.aes.cpo')
    require(rows.count(old_obj) == 1, 'Ambiguous KeyStore IOBSD object')
    filelist = OUT / 'native.filelist';filelist.write_text(''.join((str(bsd_obj) if row == old_obj else row) + '\n' for row in rows))
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(filelist)
    native = OUT / 'mach.keystore'
    command += ['-Wl,-force_load,' + str(OWNER_OUT / 'libDodgeQemuOwnerRoot.a'), '-Wl,-force_load,' + str(AES_OUT / 'libDodgeQemuAES.a'),
        '-Wl,-force_load,' + str(archive), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    data = native.read_bytes();facts = readback(data, tables, fields);aes_readback(data, system['concrete_methods'], system['abi'])
    names = {row['name']: row for row in symbols(data) if not row['kind'] & 0xe0}
    source = {**base, 'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data),
        'actual_init_hook': init_hook_readback(data), 'combined_original_bindings': {**base['combined_original_bindings'], **system['abi']['bindings']},
        'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'],
            '_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint', '_native_virtio_read_checkpoint',
            '_native_verified_block_root_authorized', '_dodge_qemu_aes_start', '_dodge_qemu_aes_checkpoint', '_dodge_aes_allocate',
            '_native_owner_cache_checkpoint', '_dodge_qemu_keystore_start', '_dodge_qemu_keystore_checkpoint', '_native_keyevents_allocate']}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots'];original = ORIGINAL.read_bytes()
    base_context = original_context(original, roots, config)
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE]);context = original_context(original, [*roots, MODULE], config)
    require(not any('AppleKeyStore' in name for name in config['expected_executables']), 'Stock KeyStore conflicts with the native VM service')
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    security_path = OUT / 'security-init.json';security_path.write_text(json.dumps(security, indent=2) + '\n')
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in [*roots, MODULE]:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', security_path]
        process = subprocess.run(command, env=env, capture_output=True, text=True);(OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'KeyStore prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native) and
        record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'KeyStore prelink inputs changed')
    checked = validate_extension(raw, record, data, original, context, base_context, config, source, security)
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    require(readback(candidate.read_bytes(), tables, fields) == facts, 'KeyStore prelink changed native classes')
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/check_keystore_host.py', *cpp, reference / 'NativeKeyStoreEvents.cpp',
        reference / 'test_closed_boundary.py', reference / 'LICENSE', state_source, state_patch, patch, bsd]
    artifacts = [obj, lifecycle, late, archive, bsd_obj, filelist, native, candidate, emission, security_path,
        OUT / 'compile-commands.json', OUT / 'host-test.log']
    report = {'result': 'IOS16_QEMU_NATIVE_KEYSTORE_STATE_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(SYSTEM_REPORT.relative_to(ROOT)): sha(SYSTEM_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'source_reference': lock['apple_keystore_state_reference'],
        'class_tables': tables, 'layout': fields, 'class_readback': facts, 'closed_control': args.closed,
        'security_start_readback': security_readback, **checked, 'development_only': True, 'hardware_data_protection': False,
        'hardware_tested': False,
        'scope': 'Native IOService/IOUserClient state protocol compiled against Darwin 22. The separate owner-identified VM has no passcode or keybag. '
                 'Software key encoding uses its public development identity; unsupported bag, passcode and reference-key operations remain errors. '
                 'Original iPhone kernel components and the existing signed read-only union are retained. Runtime userland acceptance is a separate check.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native Darwin 22 KeyStore state service, class/argument readbacks and strict iPhone prelink')


if __name__ == '__main__':main()
