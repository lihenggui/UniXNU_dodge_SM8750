#!/usr/bin/env python3
"""Package the native owner system and original iPhone root windows locally; no device writes."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tomllib
from types import SimpleNamespace

from build_native_system import REPORT as KERNEL_REPORT, OUT as KERNEL_OUT, check_report as check_kernel
from build_native_a830_payload import REPORT as BASE_REPORT, check_report as check_base
from build_native_a830_firmware import REPORT as FIRMWARE_REPORT, check_report as check_firmware
from build_native_a830_addon import REPORT as ADDON_REPORT, check_report as check_addon
from build_mapped_lease_payload import extract_fat
from boot_entropy_execution import Firmware
from check_boot_entropy_kernel import seed_case
from check_gpu_link import run
from native_driver_build import ROOT, require, sha
from prepare_device_tree import parse_adt
from prepare_qemu_root_policy import file_sha
from image4_boot_policy import encode_tree, strip_policy, prepare_policy, check_policy
from prepare_root_image import digest_extent, make_manifest
from prepare_native_root_policies import REPORT as EXTERNAL_REPORT, CAPACITY, check_report as check_external

OUT = ROOT / 'build/cph2653-native-system-bringup'
REPORT = ROOT / 'reports/ios16-native-system-payload.json'
ROOT_REPORT = EXTERNAL_REPORT
PAYLOAD_BYTES = 88 << 20
BOOT_ARGS = '-v serial=0 debug=0x14e cpus=1 native-ufs-root=1 dodge-owner-system=1 dodge-owner-development=1 dodge-data=1 dodge-data-mount=1 dodge-native-entropy=1'


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'Expected a regular local artifact: ' + str(path))


def verify_root(report):
    require((report['product'], report['build']) == ('iPhone10,3', '20H392') and not report['image_contains_gpt'], 'Wrong native root image')
    path = ROOT / report['image'];regular(path)
    require(path.stat().st_size == report['image_bytes'] and file_sha(path) == report['image_sha256'], 'Original root image changed')
    rows = report['windows'];require([row['name'] for row in rows] == ['OS', 'SystemOS'], 'Wrong root windows')
    with path.open('rb') as stream:
        require(stream.read(4096) == make_manifest(rows, report['image_bytes']), 'Root header/geometry differs')
        for row in rows:require(digest_extent(stream, row['offset'], row['bytes']) == row['sha256'], 'Original root window changed: ' + row['name'])
    return path


def compact_fat(baseline, output):
    import tempfile
    if output.exists() or output.is_symlink():regular(output)
    with output.open('wb') as stream:stream.truncate(PAYLOAD_BYTES)
    subprocess.run(['mkfs.fat', '-F', '32', '-n', 'UNIXNU', output], check=True, capture_output=True)
    with tempfile.TemporaryDirectory(prefix='fat-source-', dir=OUT) as temporary:
        directory = Path(temporary)
        subprocess.run(['mcopy', '-s', '-i', baseline, '::/*', directory], check=True, capture_output=True)
        for path in directory.iterdir():
            subprocess.run(['mcopy', '-s', '-i', output, path, '::/'], check=True, capture_output=True)


def check_boot_guard(nodes, kernel):
    # Call the same policy used by the native registry adapter with the actual
    # generated header and final payload properties, including refusal controls.
    source = OUT / 'OwnerPolicyProbe.cpp';binary = OUT / 'owner-policy-probe.so'
    source.write_text('#include "DodgeOwnerBootPolicy.h"\n#include "DodgeOwnerIdentity.h"\n'
        'extern "C" bool check_owner_payload(const DodgeOwnerBootInputs *in) {\n'
        'return in && dodge_owner_boot_allowed(*in,dodgeOwnerAnchorSHA256,dodgeOwnerDevelopmentIdentity);}\n')
    run(['/usr/bin/clang++-14', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
        '-I', ROOT / 'drivers/DodgeSecurity', '-I', KERNEL_OUT, source, '-o', binary], OUT / 'guard-compile.log')
    class Property(ctypes.Structure):_fields_ = [('data', ctypes.c_void_p), ('bytes', ctypes.c_size_t)]
    class Inputs(ctypes.Structure):
        _fields_ = [('system', ctypes.c_uint), ('development', ctypes.c_uint), ('ufs', ctypes.c_uint),
            *[(name, Property) for name in ('model', 'target', 'compatible', 'bus', 'chip', 'scope', 'anchor', 'identity')]]
    properties = [('model', '/', 'model'), ('target', '/', 'target-type'), ('compatible', '/', 'compatible'),
        ('bus', '/arm-io', 'device_type'), ('chip', '/chosen', 'chip-id'), ('scope', '/chosen', 'dodge-owner-security-scope'),
        ('anchor', '/chosen', 'dodge-owner-root-anchor-sha256'), ('identity', '/chosen', 'unique-chip-id')]
    buffers = [ctypes.create_string_buffer(nodes[path][name], len(nodes[path][name])) for _, path, name in properties]
    values = Inputs(1, 1, 1, *[Property(ctypes.cast(buffer, ctypes.c_void_p), len(buffer)) for buffer in buffers])
    library = ctypes.CDLL(str(binary));check = library.check_owner_payload
    check.argtypes = [ctypes.POINTER(Inputs)];check.restype = ctypes.c_bool
    require(check(ctypes.byref(values)), 'Final payload fails its actual compiled native owner policy')
    controls = []
    for field in ('system', 'development', 'ufs'):
        setattr(values, field, 0);require(not check(ctypes.byref(values)), 'Disabled owner selection accepted')
        controls.append(field + '-disabled');setattr(values, field, 1)
    for field, _, _ in properties:
        saved = getattr(values, field);pointer, count = saved.data, saved.bytes
        setattr(values, field, Property(pointer, count - 1));require(not check(ctypes.byref(values)), 'Truncated identity accepted: ' + field)
        controls.append(field + '-truncated');setattr(values, field, Property(pointer, count))
    require(nodes['/chosen']['unique-chip-id'].hex() == kernel['owner_development_identity_hex'], 'Owner identity differs from the kernel')
    return {'result': 'PASS', 'positive_actual_payload': True, 'refused_controls': controls}, [source, binary]


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_OWNER_SYSTEM_LOCAL_PACKAGE_PASS' and
        (report['product'], report['build']) == ('iPhone10,3', '20H392') and report['boot_header_version'] == 4 and
        report['original_userspace_in_package'] and not report['original_userspace_in_boot_image'] and
        not report['hardware_tested'] and not report['physical_storage_written'] and not report['default_boot_image_replaced'],
        'Incomplete native system package')
    require(report['boot_image_bytes'] <= report['captured_boot_partition_bytes'] and report['payload_bytes'] == PAYLOAD_BYTES,
        'Native boot image does not fit the captured boot slots')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Native system package input changed: ' + name)
    check_policy((ROOT / report['image4_adt']).read_bytes(), report['image4_boot_policy'],
        {name: (ROOT / path).read_bytes() for name, path in report['image4_boot_inputs'].items()})
    manifest = json.loads((ROOT / report['package_manifest']).read_text())
    require(manifest['root']['sha256'] == report['root_image_sha256'] and manifest['root']['partition_label'] == 'unixnu' and
        manifest['Data']['persistent'] is False and manifest['security']['hardware_keys'] is False, 'Native package overstates its scope')


def main():
    global OUT, REPORT, KERNEL_OUT, KERNEL_REPORT, BOOT_ARGS
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--persistent-data', action='store_true');args = parser.parse_args()
    if args.persistent_data:
        OUT = OUT.with_name(OUT.name + '-persistent');REPORT = REPORT.with_name(REPORT.stem + '-persistent.json')
        KERNEL_OUT = KERNEL_OUT.with_name(KERNEL_OUT.name + '-persistent')
        KERNEL_REPORT = KERNEL_REPORT.with_name(KERNEL_REPORT.stem + '-persistent.json')
        BOOT_ARGS += ' sheng-data-persist=2 dodge-seed-sync=1'
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native owner system local boot/root package');return
    kernel = json.loads(KERNEL_REPORT.read_text());check_kernel(kernel)
    require(kernel['persistent_store_capable'] == args.persistent_data, 'Wrong native persistent-store kernel')
    base = json.loads(BASE_REPORT.read_text());check_base(base)
    firmware = json.loads(FIRMWARE_REPORT.read_text());check_firmware(firmware)
    addon = json.loads(ADDON_REPORT.read_text());check_addon(addon)
    root = json.loads(ROOT_REPORT.read_text());check_external(root);root_image = verify_root(root)
    OUT.mkdir(parents=True, exist_ok=True)
    baseline = ROOT / base['payload'];old_files = extract_fat(baseline, OUT / 'base-readback')
    original_adt = OUT / 'base-readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    nodes = strip_policy(parse_adt(original_adt.read_bytes()));chosen = nodes['/chosen']
    require(nodes['/']['model'] == b'iPhone10,3\0' and chosen['chip-id'] == struct.pack('<I', 0x8015) and
        chosen['darwinboot-memory-size'] == struct.pack('<Q', 4 << 30), 'Native source identity/memory differs')
    policy = json.loads((ROOT / 'reports/ios16-qemu-root-policy.json').read_text())
    owner_os, = [image for image in policy['images'] if image['name'] == 'OS']
    root_uuid = owner_os['volume_uuid'].upper()
    chosen['root-matching'] = ('<dict><key>IOProviderClass</key><string>IOMedia</string><key>IOPropertyMatch</key><dict>'
        '<key>UUID</key><string>' + root_uuid + '</string></dict></dict>\0').encode()
    # This package has a separate public development identity; the persisted
    # private platform seed and every iPhone model/chip identity remain untouched.
    chosen['unique-chip-id'] = bytes.fromhex(kernel['owner_development_identity_hex'])
    chosen['dodge-owner-security-scope'] = b'software-development\0'
    chosen['dodge-owner-root-anchor-sha256'] = bytes.fromhex(kernel['owner_public_anchor_sha256'])
    guard, guard_files = check_boot_guard(nodes, kernel)
    stage = OUT / 'stage';stage.mkdir(exist_ok=True)
    candidate = ROOT / kernel['candidate'];trust = ROOT / addon['trust_bundle'];gpu_addon = ROOT / addon['addon'];data = ROOT / kernel['data_seed']
    require(sha(data) == kernel['data_seed_sha256'], 'Native development Data seed changed')
    inputs = {'kernel.macho': candidate, 'kernel.macho.trustcache': trust, 'kernel.macho.gpuaddon': gpu_addon, 'scratch-data.img': data}
    components = {name: path.read_bytes() for name, path in inputs.items()}
    tree, boot_policy = prepare_policy(encode_tree(nodes), components)
    adt = stage / 'kernel.macho.adt';adt.write_bytes(tree)
    policy_path = stage / 'image4-boot-policy.json';policy_path.write_text(json.dumps(boot_policy, indent=2) + '\n')
    menu = stage / 'unixnu.toml'
    menu.write_text('version = 1\n[boot]\ntimeout = 10\ndefault = "owner-system"\n[kits]\nautoload = false\n'
        '[[entry]]\nid = "owner-system"\ntitle = "iPhone iOS 16 / SM8750 development"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\ninitrd = "Payloads/scratch-data.img"\nargs = ' + json.dumps(BOOT_ARGS) + '\n'
        '[[entry]]\nid = "owner-graphics"\ntitle = "iPhone iOS 16 / graphics and input development"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\ninitrd = "Payloads/scratch-data.img"\nargs = ' + json.dumps(BOOT_ARGS + ' dodge-graphics=1 dodge-input=1') + '\n'
        '[[entry]]\nid = "tools"\ntitle = "Tools"\ntype = "action"\naction = "tools"\n')
    require(tomllib.loads(menu.read_text())['entry'][0]['args'] == BOOT_ARGS, 'Native menu argument readback differs')
    fat = OUT / 'payload.img';compact_fat(baseline, fat);expected = dict(old_files)
    copies = [(path, 'Payloads/' + name) for name, path in inputs.items()] + [(adt, 'Payloads/kernel.macho.adt'), (menu, 'unixnu.toml')]
    for path, name in copies:
        subprocess.run(['mcopy', '-o', '-i', fat, path, '::/EFI/UniXNU/' + name], capture_output=True, check=True)
        expected['EFI/UniXNU/' + name] = sha(path)
    actual = extract_fat(fat, OUT / 'readback');require(actual == expected, 'Native system FAT readback differs')
    facts_path = ROOT / 'reports/ios16-boot-entropy-kernel.json';facts = json.loads(facts_path.read_text())['compiler_firmware_layout']
    model_files = {'\\' + name: blob for name, blob in components.items() if name != 'scratch-data.img'}
    model_files['\\kernel.macho.adt'] = adt.read_bytes()
    model = Firmware((ROOT / firmware['efi']).read_bytes(), ROOT / firmware['mapping'], facts, model_files, data.read_bytes(), 'normal')
    handoff, runtime_tree, seed = model.run();check_policy(runtime_tree, boot_policy, components)
    properties = parse_adt(runtime_tree)['/chosen/memory-map'];handoff_files = {}
    for name, path in (('TrustCache', trust), ('GpuAddon', gpu_addon)):
        address, length = struct.unpack('<QQ', properties[name])
        require(length == path.stat().st_size and model.read(address, length) == path.read_bytes(), 'Actual EFI input handoff differs: ' + name)
        handoff_files[name] = {'bytes': length, 'sha256': sha(path)}
    final_seed = seed_case(candidate, runtime_tree, seed, 'normal')
    cpu = OUT / 'efi-cpu-readback.json';cpu.write_text(json.dumps({'handoff': handoff, 'files': handoff_files,
        'native_seed_to_original_crypto': final_seed}, indent=2) + '\n')
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'));from unixnu import bootimg
    board = tomllib.loads((ROOT / 'board.toml').read_text());mu = ROOT / 'uefi/Mu-Silicium';boot = OUT / 'boot.img'
    previous_path = os.environ.get('PATH', '');os.environ['PATH'] = '/usr/lib/llvm-14/bin' + os.pathsep + previous_path
    try:bootimg.build(SimpleNamespace(board=board, work=OUT), mu, ROOT / firmware['firmware'], mu / 'Resources/DTBs/dodge.dtb', ramdisk=fat, output=boot)
    finally:os.environ['PATH'] = previous_path
    container = json.loads((OUT / 'boot.json').read_text())
    require(container['header_version'] == 4 and container['image_sha256'] == sha(boot) and
        container['ramdisk_bytes'] == fat.stat().st_size and boot.stat().st_size <= root['boot_partition_bytes'],
        'Native Android container readback/captured capacity differs')
    bundled_root = OUT / 'iphone-root.img'
    if bundled_root.exists() or bundled_root.is_symlink():
        regular(bundled_root);current_hash = file_sha(bundled_root)
        if current_hash != root['image_sha256']:
            previous = json.loads(REPORT.read_text()) if REPORT.is_file() else {}
            require(previous.get('root_image') == str(bundled_root.relative_to(ROOT)) and
                previous.get('root_image_sha256') == current_hash, 'Refuse an unrelated existing bundled root image')
            bundled_root.unlink();os.link(root_image, bundled_root)
    else:os.link(root_image, bundled_root)
    manifest = {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'boot': {'file': boot.name, 'sha256': sha(boot), 'header_version': 4, 'args': BOOT_ARGS},
        'root': {'file': bundled_root.name, 'sha256': root['image_sha256'], 'bytes': root['image_bytes'],
            'format': 'SHNGROOT-v1', 'contains_gpt': False, 'partition_label': 'unixnu', 'minimum_existing_partition_bytes': root['image_bytes'],
            'windows': [{k: row[k] for k in ('name', 'offset', 'bytes', 'sha256')} for row in root['windows']], 'OS_UUID': root_uuid,
            'SystemOS_UUID': kernel['SystemOS_UUID'], 'signed_read_only_policy_container_offset': root['container_offset'],
            'policy_container_sha256_pinned_in_kernel': root['container_sha256'], 'policy_hash_tables_embedded_in_kernel': False,
            'partition_present_in_capture': root['root_partition_present_in_capture']},
        'Data': {'file_in_boot': 'EFI/UniXNU/Payloads/scratch-data.img', 'uuid': kernel['data_uuid'],
            'seed_sha256': kernel['data_logical_sha256'], 'persistent': False, 'persistent_requested': args.persistent_data,
            'store_capable': kernel['persistent_store_capable'], 'runtime_qualified': False, 'encrypted': False},
        'security': {'scope': 'software-development', 'public_owner_anchor_sha256': kernel['owner_public_anchor_sha256'],
            'hardware_keys': False, 'Apple_personalization': False},
        'hardware_tested': False, 'physical_storage_written': False, 'GPT_modified': False}
    manifest['boot']['captured_partition_bytes'] = root['boot_partition_bytes']
    manifest['boot']['fits_captured_partition'] = boot.stat().st_size <= root['boot_partition_bytes']
    pages = kernel['data_logical_bytes'] // 4096
    store_bytes = (1 + (pages + 32767) // 32768 + pages) * 4096
    manifest['Data'].update(store_window_bytes=store_bytes, store_end_reserve_bytes=1 << 30,
        requires_matching_seed_header=True, reset_existing_overlay=False)
    if args.persistent_data:
        manifest['root']['minimum_existing_partition_bytes'] = max(root['image_bytes'] + (4 << 20) + store_bytes + (1 << 30), store_bytes * 4)
    manifest_path = OUT / 'system-manifest.json';manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    sources = [Path(__file__), ROOT / 'scripts/build_native_system.py', ROOT / 'scripts/prepare_root_image.py', CAPACITY,
        ROOT / 'scripts/image4_boot_policy.py', ROOT / 'scripts/boot_entropy_execution.py', ROOT / 'scripts/check_boot_entropy_kernel.py']
    artifacts = [fat, boot, OUT / 'boot.json', bundled_root, manifest_path, adt, policy_path, menu, cpu, *guard_files]
    report = {'result': 'IOS16_NATIVE_OWNER_SYSTEM_LOCAL_PACKAGE_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in sources},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (KERNEL_REPORT, BASE_REPORT, FIRMWARE_REPORT, ADDON_REPORT, ROOT_REPORT, facts_path)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'boot_image': str(boot.relative_to(ROOT)), 'boot_image_sha256': sha(boot), 'boot_header_version': 4,
        'boot_image_bytes': boot.stat().st_size, 'captured_boot_partition_bytes': root['boot_partition_bytes'],
        'payload': str(fat.relative_to(ROOT)), 'payload_sha256': sha(fat), 'payload_bytes': fat.stat().st_size, 'fat_files': actual,
        'root_image': str(bundled_root.relative_to(ROOT)), 'root_image_sha256': root['image_sha256'], 'root_image_bytes': root['image_bytes'],
        'package_manifest': str(manifest_path.relative_to(ROOT)), 'kernel_args': BOOT_ARGS, 'compiled_boot_guard': guard,
        'image4_adt': str(adt.relative_to(ROOT)), 'image4_boot_policy': boot_policy,
        'image4_boot_inputs': {name: str(path.relative_to(ROOT)) for name, path in inputs.items()},
        'actual_EFI_handoff_model': 'PASS', 'original_POST_tests_in_model': len(final_seed['actual_post_tests']),
        'original_userspace_in_package': True, 'original_userspace_in_boot_image': False,
        'Data_persistent': False, 'hardware_data_protection': False, 'hardware_tested': False,
        'persistent_store_capable': args.persistent_data, 'persistent_Data_requested': args.persistent_data,
        'physical_storage_written': False, 'default_boot_image_replaced': False, 'phone_operations': 'none',
        'scope': 'Separate local boot/root package: verified native UFS kernel and original iPhone OS/SystemOS root windows, '
        'seed-checked volatile development Data, A830 addon/trust and preserved firmware-specific memory layout. '
        'The boot image contains the kernel/addon/Data seed; original OS/SystemOS reside in the separate regular-file root image. '
        'Actual EFI handoff and original crypto POST run in the CPU model. No phone, partition or GPT is changed; native boot/UI remain untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native system boot/root package, exact original iPhone windows, EFI handoff and', report['original_POST_tests_in_model'], 'original POST tests in the CPU model')


if __name__ == '__main__':main()
