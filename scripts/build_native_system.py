#!/usr/bin/env python3
"""Build an isolated iPhone owner-development system kernel for native SM8750 UFS."""
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

from build_native_a830_kernel import REPORT as BASE_REPORT, check_report as check_base
from build_qemu_aes import REPORT as AES_REPORT, OUT as AES_OUT, check_report as check_aes, readback as aes_readback
from build_qemu_keystore import REPORT as KEY_REPORT, OUT as KEY_OUT, check_report as check_key, readback as key_readback
from build_qemu_exec import MODULE, validate_extension
from build_platform_calendar import REPORT as CALENDAR_REPORT, check_report as check_calendar
from build_user_entropy import REPORT as ENTROPY_REPORT, check_report as check_entropy
from build_native_entropy import REPORT as TRNG_REPORT, check_report as check_trng
from check_native_store_host import REPORT as STORE_REPORT, CONTRACT as STORE_CONTRACT, check_report as check_store
from prepare_native_root_policies import REPORT as EXTERNAL_REPORT, check_report as check_external
from build_seed_sync import REPORT as SEED_REPORT, check_report as check_seed
from build_ufs_root import concrete_methods
from build_data_source import check_table, concrete_methods as ram_methods
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import assemble, run
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import ROOT, TREE, OBJDIR, build_objects, inspect_object, pinned_sources, require, sha, symbols, macho
from native_prelink import backed_offset
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, check_report as check_policy
from prepare_qemu_data import REPORT as DATA_REPORT, check_report as check_data
from prepare_storage_abi import HEADER, stage_headers
from prepare_surface_backing import checked as backing_checked, apply_hooks

OUT = ROOT / 'build/cph2653-native-system'
REPORT = ROOT / 'reports/ios16-native-system-kernel.json'
IDENTITY_DOMAIN = b'UniXNU.Dodge.NativeDevelopmentIdentity.v1\0'
AR = '/usr/bin/llvm-ar-14'


def archive(path, members):
    path.unlink(missing_ok=True)
    subprocess.run([AR, 'rcsD', path, *members], check=True)
    for member in members:
        require(subprocess.check_output([AR, 'p', path, member.name]) == member.read_bytes(), 'Archive member changed: ' + str(member))
    return path


def member(directory, parent, name):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(subprocess.check_output([AR, 'p', parent, name]))
    inspect_object(path.read_bytes())
    return path


def compile_recipe(recipe, out, *, source=None, extra=(), prepend=()):
    record = json.loads(recipe.read_text().strip().rstrip(','))
    command, index = [], 0
    while index < len(record['arguments']):
        value = record['arguments'][index]
        if value == record['file'] and source is not None:command.append(str(source))
        elif value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):command.append(value)
        index += 1
    # Include precedence matters for the isolated per-CPU header.
    command[1:1] = list(map(str, prepend))
    command += [*map(str, extra), '-o', str(out)]
    run(command, out.with_suffix('.log'), record['directory'])
    inspect_object(out.read_bytes())
    return {'arguments': command, 'recipe': str(recipe.relative_to(ROOT)), 'recipe_sha256': sha(recipe),
            'source': str(Path(record['file']).relative_to(ROOT)), 'source_sha256': sha(Path(record['file']))}


def emit_policies(policy):
    anchor = ROOT / policy['images'][0]['anchor']
    require(all((ROOT / image['anchor']).read_bytes() == anchor.read_bytes() for image in policy['images']), 'Different owner anchors')
    assembly = '.section __TEXT,__const\n.p2align 3\n.globl _verified_root_key\n_verified_root_key:\n.incbin ' + json.dumps(str(anchor)) + '\n'
    return assemble(OUT, 'root-policies', assembly), anchor


def ufs_readback(raw, methods):
    image = macho(raw);names = {row['name']: row for row in symbols(raw) if not row['kind'] & 0xe0}
    require(image['kind'] == 2 and not any(row['kind'] == 1 for row in names.values()), 'Native system has undefined symbols')
    at = backed_offset(image['segments'], names['__ZTV14NativeUfsBlock']['value'] + 16, 190 * 8, len(raw))
    require(struct.unpack_from('<190Q', raw, at) == tuple(names[name]['value'] for name in methods), 'Verified UFS changed original storage dispatch')
    required = ('_native_ufs_block_authenticates', '_native_verified_block_root_authorized',
        '_native_verified_block_manifest_sha384', '_native_verified_block_volume_device',
        '_vr_open', '_vr_verify_block', '_dodge_native_system_prepare', '_dodge_native_security_start',
        '_dodge_native_entropy_start', '_dodge_native_entropy_ready',
        '_dodge_native_root_policies_load', '_dodge_native_root_policy_count', '_dodge_native_root_policy_table',
        '_write_random', '_dodge_write_random_original', '_dodge_seed_close_sync', '_armdt_platform_clock_register',
        '__ZN13ArmDTPlatform15getGMTTimeOfDayEv', '__ZN13ArmDTPlatform15setGMTTimeOfDayEl')
    for name in required:
        require(names[name]['kind'] & 14 == 14 and names[name]['value'], 'Native system missing real implementation: ' + name)
    require(not any(name.startswith(('_native_virtio_', '_dodge_qemu_')) or 'NativeVirtioBlock' in name for name in names),
        'Virtual transport or QEMU guard leaked into the native system')
    require('_native_owner_cache_checkpoint' in names and '_native_owner_cache_dyld_flags' not in names,
        'Native SystemOS or retained original ignition differs')
    address = names['_IOKitBSDInit']['value'];at = backed_offset(image['segments'], address, 100, len(raw))
    calls = []
    for index, word in enumerate(struct.unpack_from('<25I', raw, at)):
        if word & 0xfc000000 == 0x94000000:
            delta = word & 0x3ffffff
            calls.append(address + index * 4 + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta))
    expected = [names[name]['value'] for name in ('__ZN9IOService15publishResourceEPKcP8OSObject',
        '_dodge_native_system_prepare', '_dodge_system_schedule', '_dodge_data_schedule', '_dodge_input_schedule')]
    require(calls[:5] == expected, 'Native owner security is not checked before the existing storage/Data/input schedulers')
    return {'storage_parent_bytes': 144, 'storage_slots': 190, 'verified_functions': list(required),
        'IOBSD_call_targets': [hex(value) for value in expected], 'virtual_storage_absent': True}


def prelink(native, base, aes, key, entropy):
    linked = native.read_bytes();names = {row['name']: row for row in symbols(linked) if not row['kind'] & 0xe0}
    functions = ('_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint',
        '_native_verified_block_root_authorized', '_native_verified_block_manifest_sha384', '_native_verified_block_volume_device',
        '_native_ufs_block_authenticates', '_native_owner_cache_checkpoint', '_dodge_owner_system_allowed',
        '_dodge_owner_security_ready', '_dodge_native_system_prepare', '_dodge_native_security_start',
        '_dodge_native_system_checkpoint', '_dodge_native_security_checkpoint', '_dodge_aes_allocate', '_native_keyevents_allocate')
    functions += ('_dodge_native_entropy_start', '_dodge_native_entropy_ready', '_dodge_native_entropy_checkpoint')
    functions += ('_dodge_native_root_policies_load', '_dodge_native_root_policy_count', '_dodge_native_root_policy_table')
    functions += ('_dodge_seed_close_sync',)
    source = {**base, 'actual_crypto_hooks': hook_readbacks(linked), 'actual_iobsd_hook': hook_readback(linked),
        'actual_init_hook': init_hook_readback(linked),
        'combined_original_bindings': {**base['combined_original_bindings'], **aes['abi']['bindings'], **entropy['original_bindings']},
        'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'], *functions]}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots'];original = ORIGINAL.read_bytes()
    base_context = original_context(original, roots, config)
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE])
    context = original_context(original, [*roots, MODULE], config)
    require(not any('AppleKeyStore' in name for name in config['expected_executables']), 'Conflicting stock KeyStore in native closure')
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    fixture = OUT / 'security-init.json';fixture.write_text(json.dumps(security, indent=2) + '\n')
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    environment = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='prelink-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in [*roots, MODULE]:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', fixture]
        process = subprocess.run(command, env=environment, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Native system prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native) and
        record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Native prelink inputs changed')
    checked = validate_extension(raw, record, linked, original, context, base_context, config, source, security)
    security_facts = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    aes_readback(candidate.read_bytes(), aes['concrete_methods'], aes['abi'])
    key_readback(candidate.read_bytes(), key['class_tables'], key['layout'])
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    return candidate, record, security_facts, checked, source


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_OWNER_SYSTEM_SOURCE_AND_PRELINK_PASS' and
        (report['product'], report['build']) == ('iPhone10,3', '20H392') and report['ufs_verification_compiled'] and
        report['Apple_authentication_check_preserved'] and report['original_ignition_retained'] and
        len(report['components']) == 29 and not report['hardware_tested'] and not report['hardware_data_protection'] and
        not report['physical_storage_written'] and not report['default_kernel_selected'], 'Incomplete native system report')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / path) == digest, 'Native system input changed: ' + path)
    raw = (ROOT / report['candidate']).read_bytes()
    require(ufs_readback(raw, report['ufs_methods']) == report['native_readback'], 'Native system readback changed')
    aes_readback(raw, report['aes_methods'], report['aes_abi'])
    key_readback(raw, report['keystore_tables'], report['keystore_layout'])
    compile_record, = json.loads((ROOT / report['ufs_compile_manifest']).read_text())
    require('-DNATIVE_UFS_READ_ONLY=' + str(int(not report['persistent_store_capable'])) in compile_record['arguments'],
        'Native UFS write capability differs from the actual compilation')


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--persistent-data', action='store_true', help='Build a separate kernel permitting only explicitly opened Data windows')
    args = parser.parse_args()
    if args.persistent_data:
        OUT = OUT.with_name(OUT.name + '-persistent');REPORT = REPORT.with_name(REPORT.stem + '-persistent.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native verified UFS, SystemOS, Data and development security source kernel');return
    base = json.loads(BASE_REPORT.read_text());check_base(base)
    aes = json.loads(AES_REPORT.read_text());check_aes(aes);require(not aes['negative_kat'], 'Invalid AES control input')
    key = json.loads(KEY_REPORT.read_text());check_key(key);require(not key['closed_control'], 'Closed KeyStore input')
    policy = json.loads(POLICY_REPORT.read_text());check_policy(policy)
    data = json.loads(DATA_REPORT.read_text());check_data(data)
    calendar = json.loads(CALENDAR_REPORT.read_text());check_calendar(calendar)
    entropy = json.loads(ENTROPY_REPORT.read_text());check_entropy(entropy)
    trng = json.loads(TRNG_REPORT.read_text());check_trng(trng)
    store = json.loads(STORE_REPORT.read_text());check_store(store)
    external = json.loads(EXTERNAL_REPORT.read_text());check_external(external)
    seed_sync = json.loads(SEED_REPORT.read_text());check_seed(seed_sync)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    refs = pinned_sources(('pagani_reference', 'sm8750', 'verified_root_reference', 'software_aes_reference', 'apple_keystore_state_reference'))
    ufs = refs['pagani_reference'] / 'drivers/NativeUfs';verified = refs['verified_root_reference']
    OUT.mkdir(parents=True, exist_ok=True)
    protected_paths = (ROOT / base['candidate'], ROOT / 'build/cph2653-native-a830-bringup/boot.img')
    protected = {str(path.relative_to(ROOT)): sha(path) for path in protected_paths}
    # Reuse the exact reviewed Darwin 22/SM8750 compatibility overlay, with
    # verified-block support enabled instead of rebuilding an unsigned class.
    pin = lock['dodge_ufs_root_overlay']
    source = OUT / 'ufs-source/NativeUfs.cpp';source.parent.mkdir(exist_ok=True)
    require(sha(ufs / 'NativeUfs.cpp') == pin['base_source_sha256'] and sha(ROOT / pin['path']) == pin['sha256'], 'UFS compatibility source changed')
    source.write_bytes((ufs / 'NativeUfs.cpp').read_bytes())
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', ROOT / pin['path']],
        cwd=source.parent, capture_output=True, text=True)
    (OUT / 'ufs-overlay.log').write_text(process.stdout + process.stderr)
    require(not process.returncode and 'offset' not in process.stdout.lower(), 'Native UFS overlay is not exact')
    store_contract = json.loads(STORE_CONTRACT.read_text());store_patch = ROOT / store_contract['patch']
    require(sha(source) == store_contract['before_sha256'] and sha(store_patch) == store_contract['patch_sha256'], 'Native store window source changed')
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', store_patch], cwd=source.parent, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(source) == store_contract['after_sha256'], 'Native store window patch is not exact')
    external_contract_path = ROOT / 'profiles/os/ios-16.7.16-20H392/external-root-policies.json'
    external_contract = json.loads(external_contract_path.read_text());external_patch = ROOT / external_contract['patch']
    require(sha(source) == external_contract['before_sha256'] and sha(external_patch) == external_contract['patch_sha256'], 'External policy overlay changed')
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', external_patch], cwd=source.parent, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(source) == external_contract['after_sha256'], 'External policy overlay is not exact')
    _, include, target = stage_headers(OUT / 'abi')
    obj, = build_objects([source], OUT / 'ufs', [include, ufs, refs['sm8750'] / 'kits', HEADER.parent,
        verified / 'include', refs['pagani_reference'] / 'drivers/NativeVirtioBlock', ROOT / 'drivers/DodgeStorage'],
        ['-Wno-deprecated-declarations', '-Wno-macro-redefined', '-include', str(target), '-DNATIVE_UFS_PROBE_ONLY=0',
         '-DNATIVE_UFS_SM8750=1', '-DNATIVE_UFS_READ_ONLY=' + str(int(not args.persistent_data)), '-DNATIVE_VERIFIED_BLOCK=1', '-DUFS_ROOT_PARTITION="unixnu"'])
    late = OUT / 'ufs/NativeUfs.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=__GLOBAL__sub_I_NativeUfs.cpp', obj, late], check=True)
    methods = concrete_methods(late)
    previous_ufs = ROOT / 'build/cph2653-ufs-root/libDodgeUfsRoot.a'
    ufs_members = [late, *[member(OUT / 'ufs', previous_ufs, name) for name in
        ('DodgeUfsLifecycle.o', 'DodgeSystemLate.o', 'original-storage-bindings.o')]]
    crypto = build_objects([verified / 'src/verified_root.c', verified / 'adapters/xnu_crypto.c'], OUT / 'verified', [verified / 'include'])
    carrier, anchor = emit_policies(policy)
    anchor_digest = hashlib.sha256(anchor.read_bytes()).digest()
    identity = hashlib.sha256(IDENTITY_DOMAIN + anchor.read_bytes()).digest()[:8]
    identity_header = OUT / 'DodgeOwnerIdentity.h'
    identity_header.write_text('#pragma once\n#include <stdint.h>\n' + ''.join('static const uint8_t ' + name + '[' + str(len(value)) + '] = {' +
        ','.join('0x%02x' % byte for byte in value) + '};\n' for name, value in
        (('dodgeOwnerAnchorSHA256', anchor_digest), ('dodgeOwnerDevelopmentIdentity', identity))))
    with identity_header.open('a') as stream:
        stream.write('static const uint8_t dodgeOwnerRootPolicySHA256[32] = {' + ','.join('0x%02x' % byte for byte in bytes.fromhex(external['container_sha256'])) + '};\n')
        stream.write('static const uint64_t dodgeOwnerRootPolicyBytes = UINT64_C(' + str(external['container_bytes']) + ');\n')
        for name, field in (('dodgeOwnerRootImageBytes', 'image_bytes'), ('dodgeOwnerRootManifestBytes', 'bytes')):
            stream.write('static const uint64_t ' + name + '[2] = {' + ','.join('UINT64_C(' + str(row[field]) + ')' for row in external['policies']) + '};\n')
    security_dir = ROOT / 'drivers/DodgeSecurity';storage_dir = ROOT / 'drivers/DodgeStorage'
    cpp = [security_dir / 'DodgeOwnerSystem.cpp', security_dir / 'DodgeNativeSecurity.cpp',
        storage_dir / 'DodgeNativeSystem.cpp', storage_dir / 'DodgeVerifiedUfsRoot.cpp', storage_dir / 'DodgeRootPolicySource.cpp']
    owner_objects = build_objects(cpp, OUT / 'owner', [OUT, security_dir, storage_dir, refs['pagani_reference'] / 'drivers/NativeVirtioBlock'])
    owner_members = [*owner_objects, *crypto, carrier,
        member(OUT / 'owner', AES_OUT / 'libDodgeQemuAES.a', 'DodgeSoftwareAES.late.o'),
        member(OUT / 'owner', AES_OUT / 'libDodgeQemuAES.a', 'aes-original-bindings.o'),
        member(OUT / 'owner', KEY_OUT / 'libDodgeQemuKeyStore.a', 'DodgeKeyStore.late.o')]
    owner_archive = archive(OUT / 'libDodgeNativeOwner.a', owner_members)
    ufs_archive = archive(OUT / 'libDodgeVerifiedUfs.a', ufs_members)
    seed_header = OUT / 'DodgeDataMountSeed.h'
    seed_header.write_text('#pragma once\n#include <stdint.h>\nstatic const char dodgeDataMountVolumeUUID[] = "' + data['profile']['volume_uuid'] +
        '";\nstatic const uint64_t dodgeDataMountSeedBytes = UINT64_C(' + str(data['image_bytes']) + ');\n' +
        'static const uint8_t dodgeDataMountSeedSHA256[32] = {' + ','.join('0x%02x' % byte for byte in bytes.fromhex(data['image_sha256'])) + '};\n')
    mount_source = storage_dir / 'DodgeNativeData.cpp'
    mount_obj, = build_objects([mount_source], OUT / 'mount', [OUT, storage_dir, security_dir])
    original_mount = ROOT / 'build/ios16-apfs-mount-native/libDodgeDataMount.a'
    mount_archive = archive(OUT / 'libDodgeNativeData.a', [member(OUT / 'mount', original_mount, 'DodgeApfsMountArgs.o'), mount_obj,
        member(OUT / 'mount', original_mount, 'DodgeDataMountSyscall.o')])
    # A new IOBSD guard preserves the established scheduler calls and ordering.
    bsd_source = ROOT / 'build/cph2653-data-startup/IOKitBSDInit.cpp'
    require(sha(bsd_source) == lock['dodge_data_startup_hook_overlay']['output_source_sha256'], 'IOBSD source changed')
    text = bsd_source.read_text();marker = '\tIOService::publishResource("IOBSD");'
    require(text.count(marker) == 1, 'Ambiguous IOBSD publication')
    text = text.replace('kern_return_t\nIOKitBSDInit( void )', 'extern "C" IOReturn dodge_native_system_prepare();\n\nkern_return_t\nIOKitBSDInit( void )')
    text = text.replace(marker, marker + '\n\tif (dodge_native_system_prepare() != kIOReturnSuccess) return KERN_FAILURE;')
    staged_bsd = OUT / 'IOKitBSDInit.cpp';staged_bsd.write_text(text)
    bsd_obj = OUT / 'IOKitBSDInit.native.cpo'
    recipes = [compile_recipe(OBJDIR / 'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json', bsd_obj, source=staged_bsd)]
    root_obj = OUT / 'bsd_init.owner.o'
    recipes += [compile_recipe(OBJDIR / 'bsd/DEVELOPMENT/bsd_init.o.json', root_obj,
        extra=('-UXNU_OWNER_ROOT_AUDIT', '-DXNU_OWNER_ROOT_AUDIT=1', '-UXNU_OWNER_ROOT_TRUST', '-DXNU_OWNER_ROOT_TRUST=1'))]
    volumes_path = ROOT / 'reports/ios16-volumes.json';volumes = json.loads(volumes_path.read_text())
    system, = [row for row in volumes['images'] if row['name'] == 'SystemOS'];volume, = system['apfs']['observed_volumes']
    settings = {'XNU_OWNER_CACHE_MOUNT': '1', 'XNU_OWNER_UNION_SYSTEMOS': '1', 'XNU_OWNER_CACHE_STARTUP': '0',
        'XNU_OWNER_BOOT_MANIFEST': '0', 'XNU_OWNER_DATA_MOUNT': '0', 'XNU_OWNER_CRYPTEX_FILES': '0',
        'XNU_OWNER_CACHE_VOLUME_UUID': json.dumps(volume['uuid'].upper())}
    settings_header = OUT / 'OwnerSystemOSConfig.h'
    settings_header.write_text(''.join('#undef ' + name + '\n#define ' + name + ' ' + value + '\n' for name, value in settings.items()))
    exec_source = ROOT / 'build/ios16-apfs-mount-native/kern_exec.data.c'
    require(sha(exec_source) == lock['dodge_data_mount_init_overlay']['output_source_sha256'], 'Data init source changed')
    exec_obj = OUT / 'kern_exec.systemos.o'
    exec_recipe = compile_recipe(OBJDIR / 'bsd/DEVELOPMENT/kern_exec.o.json', exec_obj, source=exec_source,
        extra=('-include', settings_header, '-iquote', Path(json.loads((OBJDIR / 'bsd/DEVELOPMENT/kern_exec.o.json').read_text().strip().rstrip(','))['file']).parent))
    recipes += [exec_recipe]
    # The per-CPU fix must reach the real mbuf consumer in this native link too.
    pin = lock['dodge_percpu_iteration_patch'];percpu_source = OUT / 'percpu-source'
    header = percpu_source / pin['target'];header.parent.mkdir(parents=True, exist_ok=True)
    header.write_bytes(subprocess.check_output(['git', '-C', ROOT / 'sources/xnu-ios16', 'show', pin['source_revision'] + ':' + pin['target']]))
    require(sha(header) == pin['before_sha256'] and sha(ROOT / pin['path']) == pin['sha256'], 'Per-CPU source pin changed')
    process = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', ROOT / pin['path']], cwd=percpu_source, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(header) == pin['after_sha256'], 'Per-CPU patch failed')
    mbuf = OUT / 'uipc_mbuf.patched.o'
    recipes += [compile_recipe(OBJDIR / 'bsd/DEVELOPMENT/uipc_mbuf.o.json', mbuf, prepend=('-I', percpu_source / 'osfmk'))]
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_list, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = Path(old_list.split(',', 2)[2]).read_text().splitlines()
    replacements = {str(ROOT / 'build/cph2653-data-startup/IOKitBSDInit.data.cpo'): str(bsd_obj),
        str(OBJDIR / 'bsd/DEVELOPMENT/bsd_init.o'): str(root_obj),
        str(ROOT / 'build/ios16-apfs-mount-native/kern_exec.data.o'): str(exec_obj),
        str(OBJDIR / 'bsd/DEVELOPMENT/uipc_mbuf.o'): str(mbuf),
        str(OBJDIR / 'bsd/DEVELOPMENT/vfs_vnops.o'): str(ROOT / seed_sync['vfs_object']),
        str(ROOT / 'build/cph2653-crypto-source/prng_random.crypto.o'): str(ROOT / entropy['original_object'])}
    for name in replacements:require(rows.count(name) == 1, 'Ambiguous native object: ' + name)
    filelist = OUT / 'native.filelist';filelist.write_text(''.join(replacements.get(row, row) + '\n' for row in rows))
    command[command.index(old_list)] = '-Wl,-filelist,' + str(filelist)
    for old, new in ((previous_ufs, ufs_archive), (original_mount, mount_archive),
        (TREE / 'build/armdt-platform/libArmDTPlatform.a', ROOT / calendar['archive'])):
        argument = '-Wl,-force_load,' + str(old);require(command.count(argument) == 1, 'Ambiguous native archive')
        command[command.index(argument)] = '-Wl,-force_load,' + str(new)
    old_observers = ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o'
    remaining = [row for row in symbols(old_observers.read_bytes()) if row['kind'] == 3 and row['name'] != '_native_owner_cache_stage']
    require(len(remaining) == 3 and all(row['value'] == 0 for row in remaining), 'Unexpected absent diagnostics')
    observers = assemble(OUT, 'absent-observers', ''.join('.globl ' + row['name'] + '\n.set ' + row['name'] + ',0\n' for row in remaining))
    require(command.count(str(old_observers)) == 1, 'Ambiguous observer object')
    command[command.index(str(old_observers))] = str(observers)
    native = OUT / 'mach.native-system'
    command += ['-Wl,-force_load,' + str(owner_archive), '-Wl,-force_load,' + str(ROOT / entropy['archive']),
        '-Wl,-force_load,' + str(ROOT / trng['archive']), '-Wl,-force_load,' + str(ROOT / seed_sync['archive']), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    linked = native.read_bytes();facts = ufs_readback(linked, methods)
    aes_readback(linked, aes['concrete_methods'], aes['abi']);key_readback(linked, key['class_tables'], key['layout'])
    ram = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
    require(check_table(linked, ram_methods(ROOT / ram['late_object'])) == 352, 'Native system changed original RamBlock ABI')
    candidate, record, security_facts, checked, source_report = prelink(native, base, aes, key, entropy)
    require(candidate.stat().st_size < 80 << 20, 'Native boot kernel still embeds the large policy tables')
    require(ufs_readback(candidate.read_bytes(), methods) == facts, 'Prelink changed native storage or startup')
    host = OUT / 'owner-policy-test'
    run(['/usr/bin/clang++-14', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', security_dir,
        ROOT / 'tests/DodgeOwnerBootPolicyTest.cpp', '-o', host], OUT / 'host-compile.log')
    result = subprocess.run([host], capture_output=True, text=True, timeout=30)
    (OUT / 'owner-policy-test.log').write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'Owner boot policy refusal test failed')
    commands = OUT / 'adapted-compile-commands.json';commands.write_text(json.dumps(recipes, indent=2) + '\n')
    link_record = OUT / 'link-command.json';link_record.write_text(json.dumps(command, indent=2) + '\n')
    for path, digest in protected.items():require(sha(ROOT / path) == digest, 'Build changed previous native payload: ' + path)
    files = [Path(__file__), *cpp, mount_source, storage_dir / 'DodgeDataMount.cpp', security_dir / 'DodgeOwnerSystem.h',
        security_dir / 'DodgeOwnerBootPolicy.h', ROOT / 'tests/DodgeOwnerBootPolicyTest.cpp', source, bsd_source, exec_source,
        ROOT / 'upstream.lock.json', STORE_CONTRACT, store_patch, external_contract_path, external_patch,
        storage_dir / 'DodgeRootPolicySource.h', storage_dir / 'DodgeRootPolicyFormat.h',
        PROFILE, CONFIG, SECURITY, ROOT / 'scripts/build_qemu_exec.py', ROOT / 'scripts/build_crypto_prelink.py']
    artifacts = [*ufs_members, *owner_members, mount_obj, owner_archive, ufs_archive, mount_archive, identity_header, seed_header,
        bsd_obj, staged_bsd, root_obj, exec_obj, settings_header, header, mbuf, filelist, observers, native, candidate, commands,
        link_record, OUT / 'emission.json', OUT / 'security-init.json', host, OUT / 'owner-policy-test.log']
    artifacts += [OUT / directory / 'compile-commands.json' for directory in ('ufs', 'verified', 'owner', 'mount')]
    report = {'result': 'IOS16_NATIVE_OWNER_SYSTEM_SOURCE_AND_PRELINK_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in
            (BASE_REPORT, AES_REPORT, KEY_REPORT, POLICY_REPORT, DATA_REPORT, CALENDAR_REPORT, ENTROPY_REPORT, TRNG_REPORT, STORE_REPORT, EXTERNAL_REPORT, SEED_REPORT, volumes_path)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'native_kernel': str(native.relative_to(ROOT)),
        'link_command': str(link_record.relative_to(ROOT)), 'components': record['components'], **checked,
        'ufs_methods': methods, 'native_readback': facts, 'aes_methods': aes['concrete_methods'], 'aes_abi': aes['abi'],
        'keystore_tables': key['class_tables'], 'keystore_layout': key['layout'], 'security_start_readback': security_facts,
        'combined_native_entries': source_report['combined_native_entries'], 'combined_original_bindings': source_report['combined_original_bindings'],
        'owner_identity_domain': IDENTITY_DOMAIN.rstrip(b'\0').decode(), 'owner_development_identity_hex': identity.hex(),
        'owner_public_anchor_sha256': anchor_digest.hex(), 'data_seed': data['packed_image'], 'data_seed_sha256': data['packed_metadata']['encoded_sha256'],
        'data_logical_sha256': data['image_sha256'], 'data_uuid': data['profile']['volume_uuid'], 'SystemOS_UUID': volume['uuid'],
        'data_logical_bytes': data['image_bytes'], 'ufs_compile_manifest': str((OUT / 'ufs/compile-commands.json').relative_to(ROOT)),
        'persistent_store_capable': args.persistent_data, 'root_transports_readonly': True,
        'external_root_policy_container_sha256': external['container_sha256'], 'root_policies_embedded_in_kernel': False,
        'native_store_host_cases': store['case_count'],
        'compile_settings': settings, 'ufs_verification_compiled': True, 'Apple_authentication_check_preserved': True,
        'linked_source_and_binding_objects': base['combined_source_objects'] + len(owner_members) + 5,
        'seed_close_sync_compiled': True, 'seed_close_sync_host_cases': seed_sync['host_cases'],
        'platform_calendar_backport': True, 'user_reseed_accounting': True, 'native_TRNG_compiled': True,
        'original_ignition_retained': True, 'host_boot_policy_cases': int(result.stdout.split()[1]),
        'percpu_header_sha256': sha(header), 'protected_previous_artifacts': protected,
        'default_kernel_selected': False, 'hardware_data_protection': False, 'hardware_tested': False,
        'physical_storage_written': False, 'phone_operations': 'none', 'all_ios_port_code_complete': False,
        'scope': 'Isolated native SM8750 source integration: signed read-only UFS OS/SystemOS windows, original root authentication plus '
        'independent owner policy, original SystemOS union/ignition/decompressor, original seed-checked APFS Data mount, '
        'and explicitly selected software development AES/KeyStore loaded before storage/Data/input scheduling. '
        'No VirtIO transport or QEMU startup guard is linked. Native hardware, display/UI, PMGR and hardware keys remain unqualified.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native verified UFS / SystemOS / Data / development security, 29 original components and', checked['pointer_sites_read_back'], 'pointer readbacks')


if __name__ == '__main__':main()
