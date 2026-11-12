#!/usr/bin/env python3
"""Build the owner VM kernel against its separate volatile Data seed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

import build_qemu_keystore as keystore
from build_qemu_systemos import OUT as SYSTEM_OUT
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
from native_driver_build import ROOT, TREE, OBJDIR, build_objects, require, sha, symbols
from prepare_surface_backing import checked as backing_checked, apply_hooks
from prepare_qemu_data import REPORT as DATA_REPORT, check_report as check_data

OUT = ROOT / 'build/cph2653-qemu-data'
REPORT = ROOT / 'reports/ios16-qemu-data-kernel.json'


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_VOLATILE_DATA_KERNEL_PASS' and not report['hardware_tested'] and
        report['data_seed_sha256'] == json.loads(DATA_REPORT.read_text())['image_sha256'], 'Wrong QEMU Data kernel')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / path) == digest, 'QEMU Data kernel input changed: ' + path)
    keystore.readback((ROOT / report['candidate']).read_bytes(), report['class_tables'], report['layout'])


def prelink(native, parent, base, out, *, additional_entries=()):
    linked = native.read_bytes();keystore.readback(linked, parent['class_tables'], parent['layout'])
    aes = json.loads((ROOT / 'reports/ios16-qemu-systemos.json').read_text());aes_readback(linked, aes['concrete_methods'], aes['abi'])
    names = {row['name']: row for row in symbols(linked) if not row['kind'] & 0xe0}
    entries = [*base['combined_native_entries'], '_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint',
        '_native_virtio_read_checkpoint', '_native_verified_block_root_authorized', '_dodge_qemu_aes_start',
        '_dodge_qemu_aes_checkpoint', '_dodge_aes_allocate', '_native_owner_cache_checkpoint', '_dodge_qemu_keystore_start',
        '_dodge_qemu_keystore_checkpoint', '_native_keyevents_allocate', '_dodge_qemu_data_checkpoint', '_dodge_qemu_data_mount_impl']
    entries += list(additional_entries)
    source = {**base, 'actual_crypto_hooks': hook_readbacks(linked), 'actual_iobsd_hook': hook_readback(linked),
        'actual_init_hook': init_hook_readback(linked), 'combined_original_bindings': {**base['combined_original_bindings'], **aes['abi']['bindings']},
        'combined_native_entries': {name: hex(names[name]['value']) for name in entries}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots'];original = ORIGINAL.read_bytes()
    base_context = original_context(original, roots, config)
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE]);context = original_context(original, [*roots, MODULE], config)
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    security_path = out / 'security-init.json';security_path.write_text(json.dumps(security, indent=2) + '\n')
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    environment = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=out) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in [*roots, MODULE]:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', security_path]
        process = subprocess.run(command, env=environment, capture_output=True, text=True)
        (out / 'emission.log').write_text(process.stdout + process.stderr);require(not process.returncode, 'QEMU Data prelink failed')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native) and
        record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Data prelink inputs changed')
    checked = validate_extension(raw, record, linked, original, context, base_context, config, source, security)
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = out / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    keystore.readback(candidate.read_bytes(), parent['class_tables'], parent['layout'])
    emission = out / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    return candidate, emission, security_path, security_readback, checked


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--wrong-seed', action='store_true');args = parser.parse_args()
    if args.wrong_seed:
        OUT = OUT.with_name(OUT.name + '-wrong-seed');REPORT = REPORT.with_name(REPORT.stem + '-wrong-seed.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: owner VM volatile Data kernel');return
    parent = json.loads(keystore.REPORT.read_text());keystore.check_report(parent)
    require(not parent['closed_control'], 'Closed KeyStore cannot supply the Data fixture')
    data = json.loads(DATA_REPORT.read_text());check_data(data);base = json.loads(BASE_REPORT.read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    selected_digest = bytearray.fromhex(data['image_sha256'])
    if args.wrong_seed:selected_digest[0] ^= 1
    selected_digest = selected_digest.hex()
    header = OUT / 'DodgeDataMountSeed.h'
    header.write_text('#pragma once\n#include <stdint.h>\nstatic const char dodgeDataMountVolumeUUID[] = "' +
        data['profile']['volume_uuid'] + '";\nstatic const uint64_t dodgeDataMountSeedBytes = UINT64_C(' + str(data['image_bytes']) +
        ');\nstatic const uint8_t dodgeDataMountSeedSHA256[32] = {' + ', '.join('0x' + selected_digest[i:i+2]
            for i in range(0, 64, 2)) + '};\n')
    cpp = ROOT / 'drivers/DodgeStorage/DodgeQemuData.cpp'
    obj, = build_objects([cpp], OUT, [OUT, ROOT / 'drivers/DodgeStorage'])
    raw = obj.read_bytes()
    require(data['profile']['volume_uuid'].encode() + b'\0' in raw and bytes.fromhex(selected_digest) in raw and
        b'DAF0DD2B-1D90-5A73-A426-9306E1F967B5\0' not in raw, 'Data object compiled against another seed')
    original_archive = ROOT / 'build/ios16-apfs-mount-native/libDodgeDataMount.a'
    members = subprocess.check_output(['/usr/bin/llvm-ar-14', 't', original_archive], text=True).splitlines()
    require(members == ['DodgeApfsMountArgs.o', 'DodgeDataMount.o', 'DodgeDataMountSyscall.o'], 'Data archive members changed')
    subprocess.run(['/usr/bin/llvm-ar-14', 'x', original_archive, 'DodgeApfsMountArgs.o', 'DodgeDataMountSyscall.o'], cwd=OUT, check=True)
    archive = OUT / 'libDodgeDataMount.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, OUT / 'DodgeApfsMountArgs.o', obj, OUT / 'DodgeDataMountSyscall.o'], check=True)
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(keystore.OUT / 'native.filelist')
    old_observers = str(ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o')
    require(command.count(old_observers) == 1, 'Ambiguous observer input')
    command[command.index(old_observers)] = str(SYSTEM_OUT / 'absent-observers.o')
    old_mount = '-Wl,-force_load,' + str(original_archive)
    require(command.count(old_mount) == 1, 'Ambiguous Data archive input')
    command[command.index(old_mount)] = '-Wl,-force_load,' + str(archive)
    native = OUT / 'mach.qemu-data'
    for dependency in (OWNER_OUT / 'libDodgeQemuOwnerRoot.a', AES_OUT / 'libDodgeQemuAES.a', keystore.OUT / 'libDodgeQemuKeyStore.a'):
        command += ['-Wl,-force_load,' + str(dependency)]
    command += ['-o', str(native)];run(command, OUT / 'link.log', OBJDIR)
    candidate, emission, security_path, security_readback, checked = prelink(native, parent, base, OUT)
    files = [Path(__file__), cpp, ROOT / 'drivers/DodgeStorage/DodgeDataMount.cpp', ROOT / 'drivers/DodgeStorage/DodgeDataMount.h']
    artifacts = [header, obj, archive, original_archive, native, candidate, emission, security_path, OUT / 'compile-commands.json']
    report = {'result': 'IOS16_QEMU_VOLATILE_DATA_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (keystore.REPORT, DATA_REPORT, BASE_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'class_tables': parent['class_tables'], 'layout': parent['layout'], 'data_seed_sha256': data['image_sha256'],
        'data_volume_uuid': data['profile']['volume_uuid'], 'selected_seed_sha256': selected_digest,
        'wrong_seed_control': args.wrong_seed, 'security_start_readback': security_readback, **checked,
        'hardware_tested': False, 'persistent': False, 'phone_operations': 'none',
        'scope': 'Separate QEMU-only Data mount wrapper retains the existing ordinary APFS mount path and verifies the new seed identity. '
                 'The original 29-component iPhone closure, software AES and native KeyStore dispatch are read back. '
                 'The default payload and original Data seeds are unchanged; runtime is checked separately.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: owner VM kernel with separate volatile Data identity and strict iPhone prelink')


if __name__ == '__main__':main()
