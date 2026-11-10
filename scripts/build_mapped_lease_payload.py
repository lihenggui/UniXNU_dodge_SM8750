#!/usr/bin/env python3
"""Package the mapped-resource candidate with the preserved fresh-entropy firmware, offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from types import SimpleNamespace

from build_entropy_payload import REPORT as ENTROPY_REPORT, check_report as check_entropy
from build_mapped_lease_prelink import REPORT as PRELINK_REPORT, check_report as check_prelink
from check_mapped_lease_kernel import REPORT as KERNEL_REPORT, check_report as check_kernel
from check_boot_entropy_kernel import execute_efi
from native_driver_build import ROOT, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-mapped-lease-wait-bringup'
REPORT = ROOT / 'reports/ios16-mapped-lease-payload.json'
RESULT = 'CPH2653_MAPPED_LEASE_ENTROPY_EFI_ANDROID_V4_READBACK_PASS'


def extract_fat(image, destination):
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(['mcopy', '-o', '-s', '-i', image, '::/EFI', destination], capture_output=True, check=True)
    return {str(p.relative_to(destination)): sha(p) for p in destination.rglob('*') if p.is_file()}


def check_report(report):
    require(report['result'] == RESULT and report['boot_header_version'] == 4 and report['payload_bytes'] == 160 << 20 and
            report['linked_source_objects'] == 90 and report['original_aliases'] == 341 and
            report['embedded_efi_cpu']['native_seed_to_crypto']['result'] == 'PASS' and
            len(report['embedded_efi_cpu']['firmware_positive_paths']) == 2 and len(report['embedded_efi_cpu']['firmware_failure_paths']) == 6,
            'Incomplete mapped-resource development payload report')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Mapping lease development payload evidence changed: ' + name)
    require(not any(report[key] for key in ('existing_payloads_replaced', 'source_data_default_enabled',
                'source_data_mount_default_enabled', 'original_userspace_included', 'hardware_tested',
                'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Mapping lease payload exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only or REPORT.exists():
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved separate mapped-resource/FAT/entropy EFI/Android v4 payload'); return
    prelink = json.loads(PRELINK_REPORT.read_text()); check_prelink(prelink)
    kernel = json.loads(KERNEL_REPORT.read_text()); check_kernel(kernel)
    entropy = json.loads(ENTROPY_REPORT.read_text()); check_entropy(entropy)
    require(kernel['candidate_sha256'] == prelink['candidate_sha256'], 'Mapping lease CPU checks use another candidate')
    base_path = ROOT / 'reports/ios16-crypto-payload.json'; base = json.loads(base_path.read_text())
    old_fat = ROOT / base['payload']; require(sha(old_fat) == base['payload_sha256'], 'Preserved source FAT changed')
    OUT.mkdir(exist_ok=True); fat = OUT / 'payload.img'; require(fat != old_fat, 'Refuse to replace a frozen FAT')
    shutil.copyfile(old_fat, fat)
    original_files = extract_fat(old_fat, OUT / 'old-readback')
    config_path = OUT / 'old-readback/EFI/UniXNU/unixnu.toml'; config = tomllib.loads(config_path.read_text())
    entry, = [item for item in config['entry'] if item['id'] == 'xnu']
    require(entry['path'] == 'Payloads/kernel.macho' and entry['initrd'] == 'Payloads/scratch-data.img' and
            entry['args'] == base['kernel_args'] and 'dodge-data=' not in entry['args'] and
            'dodge-data-mount=' not in entry['args'], 'Preserved iPhone payload entry/default arguments differ')
    old_title = 'title = "OnePlus 13: experimental iPhone original crypto development"'
    text = config_path.read_text(); require(text.count(old_title) == 1, 'Preserved development payload title differs')
    configuration = OUT / 'unixnu.toml'
    configuration.write_text(text.replace(old_title, 'title = "OnePlus 13: experimental iPhone mapped GPU resource leases"'))
    candidate = ROOT / prelink['candidate']
    for source, target in ((candidate, 'Payloads/kernel.macho'), (configuration, 'unixnu.toml')):
        subprocess.run(['mcopy', '-o', '-i', fat, source, '::/EFI/UniXNU/' + target], capture_output=True, check=True)
    actual_files = extract_fat(fat, OUT / 'readback'); expected_files = dict(original_files)
    expected_files['EFI/UniXNU/Payloads/kernel.macho'] = sha(candidate)
    expected_files['EFI/UniXNU/unixnu.toml'] = sha(configuration)
    require(actual_files == expected_files, 'Mapping lease FAT changed or omitted an unrelated file')
    adt = OUT / 'readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    disk = OUT / 'readback/EFI/UniXNU/Payloads/scratch-data.img'
    require(sha(adt) == base['adt_sha256'] and disk.stat().st_size == base['packed_seed_bytes'] == 721024,
            'Mapping lease FAT changed the exact iPhone ADT or packed Data input')
    efi = ROOT / entropy['efi']; mapping = efi.with_suffix('.map')
    firmware_layout = json.loads((ROOT / 'reports/ios16-boot-entropy-kernel.json').read_text())['compiler_firmware_layout']
    print('EXECUTE: preserved actual package EFI / mapped-resource kernel / native seed consumption and original POST', flush=True)
    rows = execute_efi(efi, mapping, firmware_layout, candidate, adt, disk)
    evidence = {'firmware_positive_paths': rows[0], 'firmware_failure_paths': rows[1], 'instruction_controls': rows[2],
                'native_seed_to_crypto': rows[3], 'native_seed_failures': rows[4]}
    cpu = OUT / 'embedded-efi-cpu.json'; cpu.write_text(json.dumps(evidence, indent=2) + '\n')
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts')); from unixnu import bootimg
    board = tomllib.loads((ROOT / 'board.toml').read_text()); fd = ROOT / entropy['firmware']; mu = ROOT / 'uefi/Mu-Silicium'
    boot = OUT / 'boot.img'; old_path = os.environ.get('PATH', '')
    os.environ['PATH'] = '/usr/lib/llvm-14/bin' + os.pathsep + old_path
    try: bootimg.build(SimpleNamespace(board=board, work=OUT), mu, fd, mu / 'Resources/DTBs/dodge.dtb', ramdisk=fat, output=boot)
    finally: os.environ['PATH'] = old_path
    manifest = OUT / 'boot.json'; container = json.loads(manifest.read_text())
    require(container['header_version'] == 4 and container['fd_sha256'] == sha(fd) and
            container['image_sha256'] == sha(boot) and container['ramdisk_bytes'] == fat.stat().st_size and
            sha(old_fat) == base['payload_sha256'], 'Mapping lease Android v4/container or frozen FAT identity differs')
    files = [Path(__file__), ROOT / 'scripts/build_entropy_payload.py', ROOT / 'scripts/check_boot_entropy_kernel.py',
             ROOT / 'scripts/boot_entropy_execution.py', ROOT / 'scripts/original_crypto_execution.py', ROOT / 'scripts/native_driver_build.py',
             ROOT / 'scripts/prepare_initial_data.py', ROOT / 'sources/UniXNU/scripts/unixnu/bootimg.py', ROOT / 'board.toml',
             mu / 'BootShim/BootShim.S', mu / 'Resources/DTBs/dodge.dtb', mu / 'Resources/Configs/dodge.toml']
    artifacts = [fat, boot, manifest, configuration, cpu]
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                                    (PRELINK_REPORT, KERNEL_REPORT, ENTROPY_REPORT, base_path, ROOT / 'reports/ios16-boot-entropy-kernel.json')},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'boot_image': str(boot.relative_to(ROOT)), 'boot_image_sha256': sha(boot), 'boot_image_bytes': boot.stat().st_size,
        'payload': str(fat.relative_to(ROOT)), 'payload_sha256': sha(fat), 'payload_bytes': fat.stat().st_size,
        'firmware': str(fd.relative_to(ROOT)), 'firmware_sha256': sha(fd), 'efi': str(efi.relative_to(ROOT)), 'efi_sha256': sha(efi),
        'boot_header_version': 4, 'linked_source_objects': 90, 'original_aliases': 341, 'native_source_entries': 97,
        'original_components': 28, 'original_interfaces': 7, 'fat_files_read_back': actual_files,
        'all_unrelated_fat_file_bytes_preserved': True, 'original_kernel_args_preserved': True,
        'embedded_efi_cpu': evidence, 'existing_payloads_replaced': False, 'source_data_default_enabled': False,
        'source_data_mount_default_enabled': False, 'original_userspace_included': False,
        'iosurface_producer_connected': False, 'producer_cache_visibility_qualified': False, 'gpu_failure_quiescence_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'A new FAT copy contains the 90-object/341-alias mapped-resource lease and fresh-health prelinked iPhone kernel. Only its kernel bytes and '
                 'development menu title differ; every other FAT file, original iPhone ADT, packed 2 GiB Data seed and boot arguments '
                 'are read back unchanged. The previously built full-board fresh-entropy FD/embedded EFI bytes are reused unchanged. '
                 'That actual EFI executes its success/failure/control paths with the new kernel, followed by real native seed '
                 'consumption, all 18 original crypto POST tests and native SHA/random consumers. Android v4 header/gzip/shim/FD/DTB/FAT '
                 'readback passes. The model stops at the DarwinEnter boundary and separately models kernel seed consumption; '
                 'handoff assembly, complete kernel startup, physical firmware RNG health, GPU/cache/quiescence, root/Data/launchd '
                 'and phone functionality remain unqualified. No old payload or phone partition is modified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: separate mapped-resource kernel / exact entropy FD / FAT and Android v4 / original POST 18')


if __name__ == '__main__': main()
