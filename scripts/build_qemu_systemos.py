#!/usr/bin/env python3
"""Enable the pinned Darwin 22 owner-verified SystemOS union in QEMU."""
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

from build_qemu_aes import REPORT as AES_REPORT, OUT as AES_OUT, check_report as check_aes, readback
from build_native_a830_kernel import REPORT as BASE_REPORT
from build_qemu_owner_root import OUT as OWNER_OUT
from build_qemu_exec import MODULE, validate_extension
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import assemble, run
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import ROOT, TREE, OBJDIR, require, sha, symbols, macho
from native_prelink import backed_offset
from prepare_surface_backing import checked as backing_checked, apply_hooks

OUT = ROOT / 'build/cph2653-qemu-systemos'
REPORT = ROOT / 'reports/ios16-qemu-systemos.json'


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_SYSTEMOS_UNION_KERNEL_PASS' and report['original_ignition_retained'] and
        report['SystemOS_UUID'] == '96096b28-b6dc-4bc7-9d3a-2632a0fe53f1' and not report['hardware_tested'], 'Wrong SystemOS fixture')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'SystemOS build input changed: ' + name)


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--wrong-uuid', action='store_true');args = parser.parse_args()
    if args.wrong_uuid:
        OUT = OUT.with_name(OUT.name + '-wrong-uuid');REPORT = REPORT.with_name(REPORT.stem + '-wrong-uuid.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: iPhone SystemOS union kernel');return
    aes = json.loads(AES_REPORT.read_text());check_aes(aes);require(not aes['negative_kat'], 'Wrong-answer AES is not a SystemOS input')
    base = json.loads(BASE_REPORT.read_text());volume_path = ROOT / 'reports/ios16-volumes.json';volumes = json.loads(volume_path.read_text())
    system, = [image for image in volumes['images'] if image['name'] == 'SystemOS']
    volume, = system['apfs']['observed_volumes'];uuid = volume['uuid']
    require((volumes['product'], volumes['build']) == ('iPhone10,3', '20H392'), 'Wrong SystemOS target')
    OUT.mkdir(parents=True, exist_ok=True)
    recipe_path = OBJDIR / 'bsd/DEVELOPMENT/kern_exec.o.json'
    recipe = json.loads(recipe_path.read_text().strip().rstrip(','));command, index = [], 0
    exec_source = ROOT / 'build/ios16-apfs-mount-native/kern_exec.data.c'
    overlay = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_data_mount_init_overlay']
    require(sha(exec_source) == overlay['output_source_sha256'], 'Existing init Data overlay changed')
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value == recipe['file']:command.append(str(exec_source))
        elif value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):command.append(value)
        index += 1
    require(any(value == 'CONFIG_UNION_MOUNTS' or value == '-DCONFIG_UNION_MOUNTS=1' for value in command),
        'Native union mounts are not enabled in the pinned kernel')
    selected_uuid = uuid if not args.wrong_uuid else uuid[:-1] + ('0' if uuid[-1] != '0' else '1')
    settings = {'XNU_OWNER_CACHE_MOUNT': '1', 'XNU_OWNER_UNION_SYSTEMOS': '1',
        'XNU_OWNER_CACHE_STARTUP': '0', 'XNU_OWNER_BOOT_MANIFEST': '0', 'XNU_OWNER_DATA_MOUNT': '0',
        'XNU_OWNER_CRYPTEX_FILES': '0', 'XNU_OWNER_CACHE_VOLUME_UUID': json.dumps(selected_uuid.upper())}
    settings_header = OUT / 'OwnerSystemOSConfig.h'
    settings_header.write_text('/* Applied after the generated owner-volume header. */\n' +
        ''.join('#undef ' + name + '\n#define ' + name + ' ' + value + '\n' for name, value in settings.items()))
    command += ['-include', str(settings_header)]
    obj = OUT / 'kern_exec.systemos.o';command += ['-iquote', str(Path(recipe['file']).parent), '-o', str(obj)]
    compile_path = OUT / 'compile-command.json';compile_path.write_text(json.dumps(command, indent=2) + '\n')
    run(command, OUT / 'compile.log', recipe['directory'])
    object_data = obj.read_bytes()
    strings = b''.join(object_data[section['fileoff']:section['fileoff'] + section['size']]
        for segment in macho(object_data)['segments'] for section in segment['sections'] if section['name'] == '__cstring')
    require(selected_uuid.upper().encode() + b'\0' in strings and
        (not args.wrong_uuid or uuid.upper().encode() + b'\0' not in strings), 'Compiled SystemOS UUID differs from its settings')
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = (AES_OUT / 'native.filelist').read_text().splitlines();old_obj = str(ROOT / 'build/ios16-apfs-mount-native/kern_exec.data.o')
    old_observers = ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o'
    provided = {row['name'] for row in symbols(obj.read_bytes()) if row['kind'] & 14 == 14}
    removed = {row['name'] for row in symbols(old_observers.read_bytes()) if row['kind'] == 3 and row['name'] in provided}
    require(removed == {'_native_owner_cache_stage'}, 'Unexpected absent-observer collision')
    remaining = [row for row in symbols(old_observers.read_bytes()) if row['kind'] == 3 and row['name'] not in removed]
    require(len(remaining) == 3 and all(row['value'] == 0 for row in remaining), 'Absent GPU diagnostics changed')
    observers = assemble(OUT, 'absent-observers', ''.join('.globl ' + row['name'] + '\n.set ' + row['name'] + ',0\n' for row in remaining))
    require(not removed.intersection(row['name'] for row in symbols(observers.read_bytes())), 'Absent cache alias was retained')
    require(rows.count(old_obj) == command.count(str(old_observers)) == 1, 'Ambiguous SystemOS native objects')
    command[command.index(str(old_observers))] = str(observers)
    filelist = OUT / 'native.filelist';filelist.write_text(''.join((str(obj) if row == old_obj else row) + '\n' for row in rows))
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(filelist)
    native = OUT / 'mach.systemos'
    command += ['-Wl,-force_load,' + str(OWNER_OUT / 'libDodgeQemuOwnerRoot.a'),
        '-Wl,-force_load,' + str(AES_OUT / 'libDodgeQemuAES.a'), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    data = native.read_bytes();facts = readback(data, aes['concrete_methods'], aes['abi'])
    names = {row['name']: row for row in symbols(data) if not row['kind'] & 0xe0}
    require('_native_owner_cache_checkpoint' in names and '_native_owner_cache_dyld_flags' not in names,
        'SystemOS mount or retained original ignition differs')
    source = {**base, 'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data),
        'actual_init_hook': init_hook_readback(data),
        'combined_original_bindings': {**base['combined_original_bindings'], **aes['abi']['bindings']},
        'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'],
            '_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint', '_native_virtio_read_checkpoint',
            '_native_verified_block_root_authorized', '_dodge_qemu_aes_start', '_dodge_qemu_aes_checkpoint',
            '_dodge_aes_allocate', '_native_owner_cache_checkpoint']}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots'];original = ORIGINAL.read_bytes()
    base_context = original_context(original, roots, config)
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE])
    context = original_context(original, [*roots, MODULE], config)
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
        require(not process.returncode, 'SystemOS prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native) and
        record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'SystemOS prelink input changed')
    checked = validate_extension(raw, record, data, original, context, base_context, config, source, security)
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    require(readback(candidate.read_bytes(), aes['concrete_methods'], aes['abi']) == facts, 'SystemOS changed AES bindings')
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    files = [Path(__file__), Path(recipe['file']), exec_source, recipe_path, ROOT / overlay['path'], ROOT / 'scripts/build_qemu_aes.py',
        ROOT / 'scripts/build_qemu_exec.py', PROFILE, CONFIG, SECURITY]
    artifacts = [obj, observers, settings_header, compile_path, filelist, native, candidate, emission, security_path]
    report = {'result': 'IOS16_QEMU_SYSTEMOS_UNION_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (AES_REPORT, volume_path)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'SystemOS_UUID': uuid, 'selected_UUID': selected_uuid, 'wrong_uuid_control': args.wrong_uuid,
        'removed_absent_observer_aliases': sorted(removed),
        'compile_settings': settings, 'original_ignition_retained': True,
        'abi': aes['abi'], 'concrete_methods': aes['concrete_methods'], 'class_readback': facts,
        'security_start_readback': security_readback, **checked, 'hardware_tested': False,
        'scope': 'Separate Darwin 22 VM kernel enabling the already-rebased owner SystemOS union mount for the observed iPhone volume UUID. '
                 'Both volumes require their signed read-only transport. The original ignition path remains enabled. '
                 'Actual mounting and shared-cache execution require runtime checks.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: iPhone SystemOS union source, original ignition and strict 29-component prelink')


if __name__ == '__main__':main()
