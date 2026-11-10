#!/usr/bin/env python3
"""Build an isolated Darwin 22 DarwinBoot EFI with fresh raw firmware entropy per handoff."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from boot_entropy_overlay import BASE, HEADER, patch, sources
from build_uefi import llvm_directory, memory_budget
from check_boot_entropy_host import check as host_check
from native_driver_build import ROOT, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-boot-entropy'
REPORT = ROOT / 'reports/ios16-boot-entropy.json'
MU = ROOT / 'uefi/Mu-Silicium'
RESULT = 'CPH2653_IPHONE_DARWIN22_FRESH_BOOT_ENTROPY_SOURCE_EFI_BUILD_PASS'


def reviewed():
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_boot_entropy_overlay']
    original, changed = sources(); path = ROOT / pin['path']
    require(path.read_text() == patch(original, changed) and sha(path) == pin['sha256'] and
            pin['header'] == str(HEADER.relative_to(ROOT)) and sha(HEADER) == pin['header_sha256'], 'Reviewed boot entropy overlay changed')
    for name, item in pin['files'].items():
        require(sha(BASE / 'Driver' / name) == item['base_sha256'], 'DarwinBoot entropy base changed: ' + name)
    require(subprocess.check_output(['git', '-C', str(BASE.parent), 'rev-parse', 'HEAD'], text=True).strip() == pin['revision'],
            'DarwinBoot entropy source revision changed')
    return pin, changed


def geometry(efi):
    raw = efi.read_bytes(); require(raw[:2] == b'MZ' and len(raw) > 256, 'Entropy loader is not PE/COFF')
    pe, = struct.unpack_from('<I', raw, 60); require(raw[pe:pe + 4] == b'PE\0\0', 'Entropy loader PE signature differs')
    machine, = struct.unpack_from('<H', raw, pe + 4); magic, = struct.unpack_from('<H', raw, pe + 24)
    subsystem, = struct.unpack_from('<H', raw, pe + 24 + 68)
    require((machine, magic, subsystem) == (0xaa64, 0x20b, 11), 'Entropy loader must be an AARCH64 EFI boot-service driver')
    return {'machine': hex(machine), 'optional_header_magic': hex(magic), 'subsystem': subsystem, 'bytes': len(raw)}


def check_report(report):
    pin, _ = reviewed()
    require(report['result'] == RESULT and report['builder_sha256'] == sha(Path(__file__)) and report['overlay_pin'] == pin,
            'Fresh entropy loader report is stale')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Entropy loader source/dependency/artifact changed: ' + name)
    require(report['efi_geometry'] == geometry(ROOT / report['efi']) and report['boot_argument_bytes'] == 608 and
            report['raw_rng_bytes_requested_per_handoff'] == 256 and report['host_tests']['provider_and_order_cases'] == 14 and
            report['host_tests']['malformed_or_truncation_cases'] == 408 and report['host_tests']['invalid_parameter_cases'] == 3 and
            report['host_tests']['actual_adt_with_rng_peer_checked'] and report['source_failures_clear_seed_and_refuse_handoff'],
            'Entropy loader build/host evidence is incomplete')
    require(not any(report[key] for key in ('hardware_tested', 'physical_entropy_quality_qualified', 'boot_services_rng_executed_on_target',
            'existing_firmware_or_boot_images_replaced', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Entropy loader scope overstates runtime')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved isolated fresh-entropy EFI and sanitizer evidence'); return
    pin, changed = reviewed(); budget = memory_budget()
    OUT.mkdir(parents=True, exist_ok=True); workspace = OUT / 'tree'; workspace.mkdir(exist_ok=True)
    for name, target in {'MdePkg': MU / 'Mu_Basecore/MdePkg', 'UniXNUPkg': ROOT / 'sources/UniXNU/package/UniXNUPkg'}.items():
        link = workspace / name
        if not link.exists(): link.symlink_to(target, target_is_directory=True)
        require(link.is_symlink() and link.resolve() == target, 'Entropy build package points elsewhere: ' + name)
    package = workspace / 'DarwinBootPkg'; shutil.copytree(BASE, package, dirs_exist_ok=True)
    for name, text in changed.items(): (package / 'Driver' / name).write_text(text)
    shutil.copy2(HEADER, package / 'Driver' / HEADER.name)
    dsc = (BASE / 'DarwinBoot.dsc').read_text().replace('OUTPUT_DIRECTORY = build/DarwinBoot', 'OUTPUT_DIRECTORY = Build/DodgeBootEntropy')
    require(dsc.count('  Test/Validation.inf\n') == 1, 'DarwinBoot standalone component list changed')
    dsc = dsc.replace('  Test/Validation.inf\n', '') + '\n[BuildOptions]\n  *_CLANGPDB_AARCH64_CC_FLAGS = -DDARWIN_BOOT_COMMAND_LINE_LENGTH=608\n'
    platform = workspace / 'DodgeBootEntropy.dsc'; platform.write_text(dsc)
    conf = workspace / 'Conf'; conf.mkdir(exist_ok=True)
    for name in ('target.txt', 'tools_def.txt', 'build_rule.txt'): shutil.copy2(MU / 'Conf' / name, conf / name)
    tools = MU / 'Mu_Basecore/BaseTools'; llvm = llvm_directory(None); python = ROOT / '.venv-uefi/bin/python'
    env = dict(os.environ, WORKSPACE=str(workspace), EDK_TOOLS_PATH=str(tools), CONF_PATH=str(conf), CLANG_BIN=str(llvm) + '/',
               PYTHON_COMMAND=str(python), PYTHONPATH=str(tools / 'Source/Python'), PACKAGES_PATH=str(workspace))
    env['PATH'] = os.pathsep.join([str(python.parent), str(llvm), str(tools / 'Source/C/bin'), str(tools / 'BinWrappers/PosixLike'),
                                  str(tools / 'Bin/Mu-Basetools_extdep/Linux-x86'), env.get('PATH', '')])
    env.pop('LD_LIBRARY_PATH', None)
    command = [str(python), str(tools / 'Source/Python/build/build.py'), '-p', platform.name, '-a', 'AARCH64', '-b', 'DEBUG', '-t', 'CLANGPDB', '-n', '4']
    build_log = OUT / 'edk2-build.log'
    print('BUILD: isolated DarwinBoot EFI / AARCH64 / Darwin22 command line / four jobs', flush=True)
    with build_log.open('w') as log:
        process = subprocess.run(command, cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    require(process.returncode == 0, 'Isolated entropy EFI failed; inspect ' + str(build_log))
    built = workspace / 'Build/DodgeBootEntropy/DEBUG_CLANGPDB/AARCH64/DarwinBootPkg/Driver/DarwinBoot'
    efi = OUT / 'DarwinBoot.efi'; shutil.copy2(built / 'DEBUG/DarwinBoot.efi', efi); facts = geometry(efi)
    dependency = ROOT / 'reports/ios16-crypto-payload.json'; old = json.loads(dependency.read_text())
    adt, = [ROOT / name for name in old['artifacts'] if name.endswith('.adt')]
    require(sha(adt) == old['artifacts'][str(adt.relative_to(ROOT))], 'Need the exact current iPhone payload ADT')
    host = host_check(adt); host_path = OUT / 'host-evidence.json'; host_path.write_text(json.dumps(host, indent=2) + '\n')
    inputs = [Path(__file__), ROOT / 'scripts/boot_entropy_overlay.py', ROOT / 'scripts/check_boot_entropy_host.py',
              ROOT / 'scripts/build_uefi.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_initial_data.py',
              ROOT / 'tests/DodgeBootEntropyTest.c', HEADER, ROOT / pin['path'], BASE / 'DarwinBoot.dsc',
              *[BASE / 'Driver' / name for name in ('DarwinBoot.c', 'DarwinBoot.inf', 'BootArgs.h', 'WindowSize.h')],
              MU / 'Mu_Basecore/MdePkg/Include/Protocol/Rng.h', MU / 'Mu_Basecore/MdePkg/Include/Guid/Rng.h']
    artifacts = [efi, host_path, ROOT / host['binary'], platform, package / 'Driver/DarwinBoot.c', package / 'Driver/DarwinBoot.inf',
                 package / 'Driver/DodgeBootEntropy.h', built / 'DEBUG/DarwinBoot.map', built / 'OUTPUT/DarwinBoot.obj', built / 'DEBUG/AutoGen.c']
    report = {'result': RESULT, 'builder_sha256': sha(Path(__file__)), 'overlay_pin': pin,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in inputs}, 'dependency_report_sha256': {str(dependency.relative_to(ROOT)): sha(dependency)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'efi': str(efi.relative_to(ROOT)), 'efi_geometry': facts,
        'build_command': command, 'memory_budget': budget, 'compiler_jobs': 4, 'host_tests': host, 'boot_argument_bytes': 608,
        'raw_rng_bytes_requested_per_handoff': 256, 'source_failures_clear_seed_and_refuse_handoff': True,
        'refreshes_final_copied_adt_before_memory_map_and_exit_boot_services': True, 'physical_entropy_quality_qualified': False,
        'boot_services_rng_executed_on_target': False, 'hardware_tested': False, 'existing_firmware_or_boot_images_replaced': False,
        'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'An isolated AARCH64 DarwinBoot EFI compiles/links with the exact Darwin22 608-byte command line and the production entropy helper. '
                 'Before handoff the copied final ADT must contain one canonical /chosen and exactly one 256-byte random-seed. '
                 'It is erased and filled by a fresh EFI_RNG_PROTOCOL RAW request; discovery, provider, zero-result and parser errors refuse handoff. '
                 'Partial RNG errors and later loader failure erase the range. No time/CPU/build-seed fallback is installed. '
                 'Fourteen provider/order, 408 malformed/truncation and three parameter cases run with ASan/UBSan/LSan, actual MdePkg headers and explicit RNG peers. '
                 'The actual private iPhone ADT is accepted with a host RNG peer. Code/parser/EFI build evidence does not qualify the proprietary firmware provider, '
                 'physical entropy/health, actual Boot/ExitBootServices execution, kernel consumption or phone boot. Existing firmware, payloads and images are unchanged.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: isolated AARCH64 entropy EFI, actual iPhone ADT and bounded production helper sanitizer checks')


if __name__ == '__main__': main()
