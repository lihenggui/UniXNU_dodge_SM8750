#!/usr/bin/env python3
"""Build a separate dodge firmware and Android v4 development container with fresh boot entropy."""
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

from audit_stock_uefi import Volumes, image_identity
from boot_entropy_overlay import BASE, HEADER, sources
from build_boot_entropy import MU, REPORT as EFI_REPORT, check_report as check_efi, reviewed
from build_uefi import llvm_directory, memory_budget
from check_boot_entropy_kernel import REPORT as CPU_REPORT, check_report as check_cpu, execute_efi, inputs
from native_driver_build import ROOT, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-entropy-firmware'
REPORT = ROOT / 'reports/ios16-entropy-payload.json'
RESULT = 'CPH2653_FRESH_ENTROPY_FIRMWARE_EFI_CPU_CHAIN_AND_ANDROID_V4_READBACK_PASS'


def build_firmware(output=None, expected_images=53):
    pin, changed = reviewed(); budget = memory_budget()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    require(subprocess.check_output(['git', '-C', str(MU), 'rev-parse', 'HEAD'], text=True).strip() == lock['revision'] and
            sha(MU / lock['memory_patch']['target']) == lock['memory_patch']['after_sha256'] and
            sha(MU / lock['simplefb_patch']['target']) == lock['simplefb_patch']['after_sha256'], 'Need the preserved pinned firmware and board patches')
    destination = output or OUT
    destination.mkdir(parents=True, exist_ok=True)
    workspace = destination / 'tree'; workspace.mkdir(parents=True, exist_ok=True)
    package = workspace / 'DarwinBootPkg'; shutil.copytree(BASE, package, dirs_exist_ok=True)
    for name, text in changed.items(): (package / 'Driver' / name).write_text(text)
    shutil.copy2(HEADER, package / 'Driver' / HEADER.name)
    conf = workspace / 'Conf'; conf.mkdir(exist_ok=True)
    for name in ('tools_def.txt', 'build_rule.txt', 'target.txt'): shutil.copy2(MU / 'Conf' / name, conf / name)
    tools = MU / 'Mu_Basecore/BaseTools'; python = ROOT / '.venv-uefi/bin/python'; llvm = llvm_directory(None)
    roots = [workspace, MU, *[MU / name for name in ('Platforms/OnePlus', 'Common/Mu', 'Common/Mu_OEM_Sample', 'Mu_Basecore',
             'Silicon/Qualcomm', 'Silicon/Silicium', 'Silicium-ACPI', 'Silicium-ACPI/Platforms/OnePlus', 'Silicium-ACPI/Silicon/Qualcomm')]]
    env = dict(os.environ, WORKSPACE=str(workspace), EDK_TOOLS_PATH=str(tools), CONF_PATH=str(conf), CLANG_BIN=str(llvm) + '/',
               PYTHON_COMMAND=str(python), PYTHONPATH=str(tools / 'Source/Python'), PACKAGES_PATH=os.pathsep.join(map(str, roots)))
    env['PATH'] = os.pathsep.join([str(python.parent), str(llvm), str(tools / 'Source/C/bin'), str(tools / 'BinWrappers/PosixLike'),
                                 str(tools / 'Bin/Mu-Basetools_extdep/Linux-x86'), env.get('PATH', '')]); env.pop('LD_LIBRARY_PATH', None)
    command = [str(python), str(tools / 'Source/Python/build/build.py'), '-p', 'dodgePkg/dodge.dsc', '-b', 'DEBUG', '-t', 'CLANGPDB',
               '-n', '4', '-a', 'AARCH64', '-y', str(destination / 'BUILD_REPORT.TXT'), '-Y', 'HASH',
               '-D', 'ONE_CRYPTO_PATH=' + str(MU / 'Mu_Basecore/CryptoPkg/Binaries/onecrypto-bin_extdep'),
               '-D', 'BUILDID_STRING=Unknown', '-D', 'MEMORY_PROTECTION=TRUE', '-D', 'SHIP_MODE=FALSE', '-D', 'ENABLE_SECUREBOOT=0',
               '-D', 'FD_BASE=0xa7100000', '-D', 'FD_SIZE=0x300000', '-D', 'FD_BLOCKS=0x300']
    command_path = destination / 'build-command.json'; command_path.write_text(json.dumps(command, indent=2) + '\n')
    print('BUILD: isolated full dodge firmware / exact board patches / new entropy DarwinBoot / four jobs', flush=True)
    with (destination / 'build.log').open('w') as log:
        process = subprocess.run(command, cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=900)
    require(process.returncode == 0, 'Entropy firmware failed; inspect ' + str(destination / 'build.log'))
    built = workspace / 'Build/dodgePkg/DEBUG_CLANGPDB'; module = built / 'AARCH64/DarwinBootPkg/Driver/DarwinBoot'
    makefile = module / 'GNUmakefile'
    require('-DDARWIN_BOOT_COMMAND_LINE_LENGTH=608' in makefile.read_text() and
            str(workspace / 'DarwinBootPkg/Driver') in makefile.read_text(), 'Full firmware used another DarwinBoot source or boot_args ABI')
    fd, efi, mapping = destination / 'SILICIUM_UEFI.fd', destination / 'DarwinBoot.efi', destination / 'DarwinBoot.map'
    for source, destination in ((built / 'FV/SILICIUM_UEFI.fd', fd), (module / 'DEBUG/DarwinBoot.efi', efi),
                                (module / 'DEBUG/DarwinBoot.map', mapping)): shutil.copy2(source, destination)
    require(fd.stat().st_size == 0x300000, 'Entropy FD size differs from the board contract')
    volumes = Volumes(); volumes.volume(fd.read_bytes(), 'entropy-fd')
    matches = [item for item in volumes.modules if item['guid'] == '1b64af87-8415-4b57-9b16-680d70913b9f']
    require(len(matches) == 1 and len(matches[0]['images']) == 1 and matches[0]['images'][0]['data'] == efi.read_bytes(),
            'Actual FD does not embed exactly the checked new DarwinBoot EFI')
    rng, = [item for item in volumes.modules if item['guid'] == 'b0d3689e-11f8-43c6-8ece-023a29cec35b']
    stock_rng = MU / 'Binaries/dodge/QcomPkg/Drivers/RNGDxe/RngDxe.efi'
    require(len(rng['images']) == 1 and rng['images'][0]['data'] == stock_rng.read_bytes(), 'Firmware RNG provider differs from the pinned donor')
    modules = []
    for module in volumes.modules:
        images = []
        for image in module['images']:
            identity = image_identity(image['data'], image['kind']); require(identity['machine'] == '0xaa64', 'Non-AARCH64 firmware executable')
            images.append({'kind': image['kind'], 'sha256': hashlib.sha256(image['data']).hexdigest(), 'bytes': len(image['data']), **identity})
        modules.append({key: module[key] for key in ('guid', 'volume', 'file_type', 'ffs_sha256', 'ui')} | {'images': images})
    source_images = list((built / 'AARCH64').glob('*.efi'))
    require(len(source_images) == expected_images and all(image_identity(path.read_bytes(), 'PE32')['machine'] == '0xaa64' for path in source_images),
            'Full firmware source EFI set differs from the selected modules')
    artifacts = [fd, efi, mapping, command_path, makefile, package / 'Driver/DarwinBoot.c', package / 'Driver/DarwinBoot.inf',
                 package / 'Driver/DodgeBootEntropy.h']
    return fd, efi, mapping, {'source_efi_count': len(source_images), 'volumes': volumes.volumes, 'modules': modules,
           'embedded_executable_count': sum(len(row['images']) for row in modules), 'exact_new_darwinboot_efi_read_back': True,
           'rng_provider_matches_existing_donor': True, 'rng_provider_sha256': sha(stock_rng)}, artifacts, budget


def check_report(report):
    require(report['result'] == RESULT and report['builder_sha256'] == sha(Path(__file__)), 'Entropy firmware/container report is stale')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Entropy firmware/container input/artifact changed: ' + name)
    require(report['firmware_readback']['source_efi_count'] == 53 and report['firmware_readback']['embedded_executable_count'] == 100 and
            report['firmware_readback']['exact_new_darwinboot_efi_read_back'] and report['firmware_readback']['rng_provider_matches_existing_donor'] and
            report['boot_header_version'] == 4 and report['fat_input_bytes'] == 160 << 20 and report['packed_data_bytes'] == 721024 and
            len(report['embedded_efi_cpu']['firmware_positive_paths']) == 2 and len(report['embedded_efi_cpu']['firmware_failure_paths']) == 6 and
            report['embedded_efi_cpu']['native_seed_to_crypto']['result'] == 'PASS', 'Entropy embedded EFI/container evidence is incomplete')
    require(not any(report[key] for key in ('existing_firmware_or_boot_images_replaced', 'hardware_tested', 'physical_entropy_quality_qualified',
            'original_userspace_included', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Entropy container report overstates runtime')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved separate entropy FD/actual embedded EFI CPU paths/Android v4 container'); return
    efi_report = json.loads(EFI_REPORT.read_text()); check_efi(efi_report); cpu_report = json.loads(CPU_REPORT.read_text()); check_cpu(cpu_report)
    _, _, candidate, adt, disk, _, base_dependencies = inputs(); facts = cpu_report['compiler_firmware_layout']
    fd, efi, mapping, firmware, artifacts, budget = build_firmware()
    rows = execute_efi(efi, mapping, facts, candidate, adt, disk)
    evidence = {'firmware_positive_paths': rows[0], 'firmware_failure_paths': rows[1], 'instruction_controls': rows[2],
                'native_seed_to_crypto': rows[3], 'native_seed_failures': rows[4]}
    cpu_path = OUT / 'embedded-efi-cpu.json'; cpu_path.write_text(json.dumps(evidence, indent=2) + '\n'); artifacts.append(cpu_path)
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts')); from unixnu import bootimg
    board = tomllib.loads((ROOT / 'board.toml').read_text()); payload_path = ROOT / 'reports/ios16-crypto-payload.json'
    old = json.loads(payload_path.read_text()); fat = ROOT / old['payload']; require(sha(fat) == old['payload_sha256'], 'Preserved FAT input changed')
    boot = OUT / 'boot.img'; previous_path = os.environ.get('PATH', '')
    os.environ['PATH'] = str(llvm_directory(None)) + os.pathsep + previous_path
    try: bootimg.build(SimpleNamespace(board=board, work=OUT), MU, fd, MU / 'Resources/DTBs/dodge.dtb', ramdisk=fat, output=boot)
    finally: os.environ['PATH'] = previous_path
    manifest = OUT / 'boot.json'; container = json.loads(manifest.read_text()); artifacts += [boot, manifest]
    require(container['header_version'] == 4 and container['fd_sha256'] == sha(fd) and container['image_sha256'] == sha(boot) and
            container['ramdisk_bytes'] == 160 << 20 and sha(fat) == old['payload_sha256'], 'Entropy Android container readback or preserved FAT differs')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text()); pin = lock['dodge_boot_entropy_overlay']
    source_paths = [Path(__file__), ROOT / 'scripts/audit_stock_uefi.py', ROOT / 'scripts/boot_entropy_overlay.py', ROOT / 'scripts/build_boot_entropy.py',
             ROOT / 'scripts/check_boot_entropy_kernel.py', ROOT / 'scripts/boot_entropy_execution.py', ROOT / 'scripts/build_uefi.py',
             ROOT / 'scripts/prepare_initial_data.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'sources/UniXNU/scripts/unixnu/bootimg.py',
             ROOT / 'board.toml', HEADER, ROOT / pin['path'], MU / lock['memory_patch']['target'], MU / lock['simplefb_patch']['target'],
             MU / 'Platforms/OnePlus/dodgePkg/dodge.dsc', MU / 'Platforms/OnePlus/dodgePkg/dodge.fdf', MU / 'BootShim/BootShim.S',
             MU / 'Resources/DTBs/dodge.dtb', MU / 'Resources/Configs/dodge.toml', MU / 'Binaries/dodge/QcomPkg/Drivers/RNGDxe/RngDxe.efi']
    report = {'result': RESULT, 'builder_sha256': sha(Path(__file__)), 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_paths},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dict.fromkeys([*base_dependencies, CPU_REPORT, ROOT / 'reports/uefi-build.json'])},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'firmware': str(fd.relative_to(ROOT)), 'firmware_readback': firmware,
        'embedded_efi_cpu': evidence, 'efi': str(efi.relative_to(ROOT)), 'boot_image': str(boot.relative_to(ROOT)), 'boot_image_bytes': boot.stat().st_size,
        'boot_header_version': 4, 'fat_input': str(fat.relative_to(ROOT)), 'fat_input_sha256': sha(fat), 'fat_input_bytes': fat.stat().st_size,
        'packed_data_bytes': disk.stat().st_size, 'memory_budget': budget, 'compiler_jobs': 4,
        'existing_firmware_or_boot_images_replaced': False, 'hardware_tested': False, 'physical_entropy_quality_qualified': False,
        'original_userspace_included': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'A separate full dodge firmware is built with preserved board memory/SimpleFb patches and the fresh-entropy DarwinBoot source override. '
                 'All 53 generated EFI headers and 100 embedded executable images are structurally checked. Bounded FV/FFS/LZMA/header checksums pass; '
                 'the exact new DarwinBoot EFI and unchanged donor RNG bytes are read back from the actual FD. That embedded EFI, with its actual link map, '
                 'executes the same two success/six failure/two instruction controls and native seed-to-original-18-test-POST/consumer chain. '
                 'An Android v4 container carries this FD and the byte-identical preserved 160 MiB crypto development FAT/packed Data input. '
                 'Actual bootimg gzip/shim/FD/DTB/FAT/header readback passes. Firmware/allocator/RNG/console/ExitBootServices are explicit CPU peers; '
                 'no proprietary provider entropy health, physical services, handoff assembly, full kernel/root/Data/userspace boot or phone operation is qualified. '
                 'Existing firmware, payloads and boot images are preserved.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: isolated full entropy firmware / 53 source EFI / 100 embedded images / exact embedded EFI CPU chain / Android v4 readback')


if __name__ == '__main__': main()
