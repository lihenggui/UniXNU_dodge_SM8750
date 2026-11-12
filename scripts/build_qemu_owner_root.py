#!/usr/bin/env python3
"""Build the iPhone QEMU kernel with immutable owner-verified root blocks."""
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

from build_qemu_storage import (REPORT as STORAGE_REPORT, OUT as STORAGE_OUT, check_report as check_storage,
                                concrete_methods, readback)
from build_native_a830_kernel import REPORT as BASE_REPORT, check_report as check_base, check_firmware
from build_crypto_prelink import validate
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import assemble, run
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import (ROOT, TREE, OBJDIR, archive_imports, build_objects, inspect_object,
                                 pinned_sources, require, sha, symbols, macho)
from native_prelink import backed_offset
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, check_report as check_policy, file_sha
from prepare_storage_abi import HEADER, stage_headers
from prepare_surface_backing import checked as backing_checked, apply_hooks

OUT = ROOT / 'build/cph2653-qemu-owner-root'
REPORT = ROOT / 'reports/ios16-qemu-owner-root.json'
INIT = '__GLOBAL__sub_I_DodgeVirtioBlock.cpp'


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_OWNER_VERIFIED_ROOT_KERNEL_PASS' and not report['hardware_tested'] and
            report['owner_trust_compiled'] and report['Apple_authentication_check_preserved'], 'Invalid owner-root kernel build')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Owner-root build input changed: ' + name)
    require(readback((ROOT / report['candidate']).read_bytes(), report['concrete_methods']) == report['class_readback'],
            'Owner-root class readback changed')


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--fault', choices=('signature', 'dma', 'uuid'));args = parser.parse_args()
    if args.fault:
        OUT = OUT.with_name(OUT.name + '-' + args.fault)
        REPORT = REPORT.with_name(REPORT.stem + '-' + args.fault + '.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: recorded owner-root iPhone kernel');return
    base = json.loads(BASE_REPORT.read_text());check_base(base)
    storage = json.loads(STORAGE_REPORT.read_text());check_storage(storage)
    policy = json.loads(POLICY_REPORT.read_text());check_policy(policy)
    refs = pinned_sources(('verified_root_reference', 'virtio_block_reference'))
    verified, transport = refs['verified_root_reference'], refs['virtio_block_reference']
    OUT.mkdir(parents=True, exist_ok=True)
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_verified_virtio_overlay']
    patch = ROOT / pin['path'];staged = OUT / 'transport';staged.mkdir(exist_ok=True)
    transport_source = staged / 'NativeVirtioBlock.cpp';transport_source.write_bytes((transport / 'NativeVirtioBlock.cpp').read_bytes())
    require(sha(patch) == pin['sha256'] and sha(transport_source) == pin['base_source_sha256'], 'Verified transport patch changed')
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)], cwd=staged, capture_output=True, text=True)
    require(not result.returncode and 'offset' not in result.stdout.lower() and sha(transport_source) == pin['output_source_sha256'],
            'Verified transport overlay does not apply exactly')
    _, include, target = stage_headers(OUT / 'abi')
    cpp = [ROOT / 'drivers/DodgeStorage/DodgeVirtioBlock.cpp', ROOT / 'drivers/DodgeStorage/DodgeQemuStorage.cpp']
    flags = ['-Wno-deprecated-declarations', '-Wno-macro-redefined', '-include', str(target),
             '-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1']
    if args.fault == 'dma':flags.append('-DNATIVE_VERIFIED_BLOCK_INJECT_FAULT=1')
    obj, lifecycle = build_objects(cpp, OUT / 'driver', [include, staged, transport, HEADER.parent, verified / 'include', ROOT / 'drivers/DodgeDisplay'],
        flags)
    methods = concrete_methods(obj)
    require(methods == storage['concrete_methods'], 'Owner verification changed the iPhone virtual interface')
    late = OUT / 'DodgeVirtioBlock.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, obj, late], check=True)
    def code(path):
        raw = path.read_bytes();section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(code(obj) == code(late), 'Verified transport deferral changed instructions')
    crypto = build_objects([verified / 'src/verified_root.c', verified / 'adapters/xnu_crypto.c'], OUT / 'crypto', [verified / 'include'])
    assembly = ['.section __TEXT,__const\n.p2align 12\n']
    fault_inputs = []
    for index, image in enumerate(policy['images']):
        manifest_path = ROOT / image['manifest']
        if args.fault in ('signature', 'uuid'):
            blob = bytearray(manifest_path.read_bytes())
            if args.fault == 'signature':blob[160] ^= 1
            else:
                blob[40] ^= 1
                header, signature = OUT / ('header-' + str(index) + '.bin'), OUT / ('signature-' + str(index) + '.bin')
                header.write_bytes(blob[:160])
                subprocess.run(['openssl', 'dgst', '-sha256', '-sign', ROOT / '.cache/qemu-root-owner/owner.pem',
                    '-out', signature, header], check=True, capture_output=True)
                require(signature.stat().st_size == 384, 'Wrong fault-control signature size')
                blob[160:544] = signature.read_bytes();fault_inputs += [header, signature]
            manifest_path = OUT / ('manifest-' + str(index) + '.bin');manifest_path.write_bytes(blob)
            fault_inputs.append(manifest_path)
        label = '_dodge_root_policy_' + str(index)
        assembly += [f'{label}:\n.incbin {json.dumps(str(manifest_path))}\n{label}_end:\n.p2align 12\n']
    anchor = ROOT / policy['images'][0]['anchor']
    require(all((ROOT / image['anchor']).read_bytes() == anchor.read_bytes() for image in policy['images']), 'Root policies have different anchors')
    assembly += ['.globl _verified_root_key\n_verified_root_key:\n.incbin ' + json.dumps(str(anchor)) + '\n.p2align 3\n',
        '.section __DATA_CONST,__const\n.p2align 3\n.globl _verified_root_policies\n_verified_root_policies:\n']
    for index in range(len(policy['images'])):
        assembly += [f'.quad _dodge_root_policy_{index}\n.quad _dodge_root_policy_{index}_end-_dodge_root_policy_{index}\n']
    assembly += ['.globl _verified_root_policy_count\n_verified_root_policy_count:\n.quad 2\n']
    carrier = assemble(OUT, 'root-policies', ''.join(assembly))
    members = [late, lifecycle, *crypto, carrier]
    imports = archive_imports(members)
    require(set(imports['required_board_or_original_imports']) <= base['combined_original_bindings'].keys() and
            set(imports['optional_weak_imports']) <= {'_native_ufs_block_authenticates'}, 'Unclassified verified-root imports: ' + repr(imports))
    if imports['optional_weak_imports']:
        # The separate VM candidate has no verified physical UFS transport.
        absent = assemble(OUT, 'absent-verified-ufs', '.globl _native_ufs_block_authenticates\n.set _native_ufs_block_authenticates,0\n')
        members.append(absent)
    archive = OUT / 'libDodgeQemuOwnerRoot.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, *members], check=True)
    recipe_path = OBJDIR / 'bsd/DEVELOPMENT/bsd_init.o.json'
    recipe = json.loads(recipe_path.read_text().strip().rstrip(','))
    bsd_source = Path(recipe['file']);bsd_obj = OUT / 'bsd_init.owner.o'
    compile_args, index = [], 0
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):compile_args.append(value)
        index += 1
    compile_args += ['-UXNU_OWNER_ROOT_AUDIT', '-DXNU_OWNER_ROOT_AUDIT=1', '-UXNU_OWNER_ROOT_TRUST', '-DXNU_OWNER_ROOT_TRUST=1', '-o', str(bsd_obj)]
    run(compile_args, OUT / 'bsd-compile.log', recipe['directory'])
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = Path(old_arg.split(',', 2)[2]).read_text().splitlines()
    replace = {str(ROOT / 'build/cph2653-data-startup/IOKitBSDInit.data.cpo'): str(STORAGE_OUT / 'IOKitBSDInit.qemu.cpo'),
               str(OBJDIR / 'bsd/DEVELOPMENT/bsd_init.o'): str(bsd_obj)}
    require(all(rows.count(name) == 1 for name in replace), 'Owner-root native object replacement is ambiguous')
    filelist = OUT / 'native.filelist';filelist.write_text(''.join(replace.get(row, row) + '\n' for row in rows))
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(filelist)
    native = OUT / 'mach.owner-root';command += ['-Wl,-force_load,' + str(archive), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    data = native.read_bytes();facts = readback(data, methods)
    names = {row['name']: row for row in symbols(data) if not row['kind'] & 0xe0}
    image = macho(data);at = backed_offset(image['segments'], names['_native_owner_root_trust_enabled']['value'], 4, len(data))
    require(struct.unpack_from('<I', data, at)[0] == 1, 'Owner trust was not compiled into the separate VM kernel')
    source = {**base, 'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data), 'actual_init_hook': init_hook_readback(data),
        'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'],
            '_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint', '_native_virtio_read_checkpoint',
            '_native_verified_block_root_authorized']}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    security_path = OUT / 'security-init.json';security_path.write_text(json.dumps(security, indent=2) + '\n')
    context = original_context(ORIGINAL.read_bytes(), profile['kernel']['prelink']['roots'] + config['additional_roots'], config)
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in profile['kernel']['prelink']['roots'] + config['additional_roots']:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', security_path]
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Owner-root prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native), 'Owner-root emission differs')
    checked = validate(raw, record, data, ORIGINAL.read_bytes(), context, config, source, security)
    checked.update(native_source_entries_preserved=len(source['combined_native_entries']), original_aliases_preserved=len(source['combined_original_bindings']))
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    require(readback(candidate.read_bytes(), methods) == facts, 'Owner-root prelink changed storage class pointers')
    files = [Path(__file__), ROOT / 'scripts/prepare_qemu_root_policy.py', ROOT / 'scripts/build_qemu_storage.py',
        *cpp, bsd_source, recipe_path, verified / 'src/verified_root.c', verified / 'adapters/xnu_crypto.c',
        verified / 'include/verified_root.h', transport / 'NativeVirtioBlock.cpp', transport / 'VerifiedBlockPolicy.h',
        patch, transport_source, ROOT / 'drivers/DodgeDisplay/DodgeOptionalCalls.h']
    artifacts = [obj, lifecycle, *members, *fault_inputs, archive, OUT / 'root-policies.S', bsd_obj, filelist, native, candidate,
        OUT / 'driver/compile-commands.json', OUT / 'crypto/compile-commands.json', security_path]
    report = {'result': 'IOS16_QEMU_OWNER_VERIFIED_ROOT_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in (BASE_REPORT, STORAGE_REPORT, POLICY_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'class_readback': facts,
        'concrete_methods': methods, 'security_start_readback': security_readback, **checked,
        'firmware_readback': check_firmware(candidate.read_bytes(), base['firmware_pins']),
        'Darwin22_RSA_contract': policy['Darwin22_RSA_contract'], 'owner_trust_compiled': True,
        'fault_control': args.fault,
        'Apple_authentication_check_preserved': True, 'hardware_tested': False,
        'scope': 'Separate QEMU development kernel. The original Apple root-authentication ioctl still executes; '
                 'owner authorization additionally requires a read-only mount bound to a transport whose every read '
                 'is checked against an independently anchored RSA3072 policy. Runtime authorization is not established by this build report.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: strict Darwin 22 owner-root kernel and original iPhone component prelink')


if __name__ == '__main__':main()
