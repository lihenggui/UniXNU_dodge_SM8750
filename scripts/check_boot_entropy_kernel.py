#!/usr/bin/env python3
"""Execute the actual EFI boot C route and native seed consumption through original crypto registration."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from boot_entropy_execution import Firmware
from build_boot_entropy import REPORT as EFI_REPORT, check_report as check_efi
from check_original_crypto_kernel import REPORT as CRYPTO_REPORT, check_report as check_crypto
from native_driver_build import ROOT, TREE, require
from original_crypto_execution import Execution
from prepare_crypto_execution import FIXTURE
from prepare_initial_data import sha
from prepare_ios16_crypto import FIXTURE as OWNER

OUT = ROOT / 'build/cph2653-boot-entropy-kernel'
REPORT = ROOT / 'reports/ios16-boot-entropy-kernel.json'
RESULT = 'IPHONE_REAL_EFI_BOOT_C_FRESH_ENTROPY_NATIVE_SEED_AND_ORIGINAL_POST_ARM64_PASS'
POSITIVE = ('normal', 'exit-stale-key-once')
NEGATIVE = ('rng-missing', 'rng-partial-error', 'rng-zero', 'rng-unsupported', 'missing-seed', 'late-map-failure')


def layout():
    OUT.mkdir(parents=True, exist_ok=True)
    fields = {'boot_services_size': 'sizeof(EFI_BOOT_SERVICES)', 'system_table_size': 'sizeof(EFI_SYSTEM_TABLE)',
              'filesystem_size': 'sizeof(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL)', 'file_protocol_size': 'sizeof(EFI_FILE_PROTOCOL)',
              'rng_size': 'sizeof(EFI_RNG_PROTOCOL)',
        **{'bs_' + key: 'OFFSET_OF(EFI_BOOT_SERVICES,' + name + ')' for key, name in {
            'handle_protocol': 'HandleProtocol', 'locate_protocol': 'LocateProtocol', 'memory_map': 'GetMemoryMap',
            'allocate_pages': 'AllocatePages', 'free_pages': 'FreePages', 'allocate_pool': 'AllocatePool',
            'free_pool': 'FreePool', 'exit_services': 'ExitBootServices'}.items()},
        'fs_open_volume': 'OFFSET_OF(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL,OpenVolume)',
        **{'file_' + key: 'OFFSET_OF(EFI_FILE_PROTOCOL,' + name + ')' for key, name in {
            'open': 'Open', 'close': 'Close', 'get_info': 'GetInfo', 'read': 'Read'}.items()},
        'rng_get': 'OFFSET_OF(EFI_RNG_PROTOCOL,GetRNG)', 'file_info_size': 'sizeof(EFI_FILE_INFO)',
        'info_file_size': 'OFFSET_OF(EFI_FILE_INFO,FileSize)', 'info_attributes': 'OFFSET_OF(EFI_FILE_INFO,Attribute)',
        'memory_descriptor_size': 'sizeof(EFI_MEMORY_DESCRIPTOR)', 'descriptor_physical': 'OFFSET_OF(EFI_MEMORY_DESCRIPTOR,PhysicalStart)',
        'descriptor_pages': 'OFFSET_OF(EFI_MEMORY_DESCRIPTOR,NumberOfPages)', 'request_size': 'sizeof(UNIXNU_LOADER_BOOT_REQUEST)',
        **{'request_' + key: 'OFFSET_OF(UNIXNU_LOADER_BOOT_REQUEST,' + name + ')' for key, name in {
            'volume': 'Volume', 'path': 'KernelPath', 'ramdisk': 'Ramdisk', 'ramdisk_size': 'RamdiskSize'}.items()},
        **{'args_' + key: 'OFFSET_OF(DARWIN_BOOT_ARGS,' + name + ')' for key, name in {
            'tree': 'DeviceTree', 'tree_size': 'DeviceTreeLength', 'virtual_base': 'VirtualBase'}.items()}}
    source = OUT / 'FirmwareLayout.c'
    source.write_text('#include <Uefi.h>\n#include <Guid/FileInfo.h>\n#include <Protocol/SimpleFileSystem.h>\n'
                      '#include <Protocol/Rng.h>\n#include <Protocol/UniXNULoader.h>\n#include "BootArgs.h"\n'
                      'const UINT64 dodge_firmware_layout[]={' + ','.join(fields.values()) + '};\n')
    mde = ROOT / 'uefi/Mu-Silicium/Mu_Basecore/MdePkg'; obj = OUT / 'FirmwareLayout.obj'
    command = ['/usr/lib/llvm-14/bin/clang', '-target', 'aarch64-unknown-windows-msvc', '-c', '-fshort-wchar',
        '-DDARWIN_BOOT_COMMAND_LINE_LENGTH=608', '-I' + str(mde / 'Include'), '-I' + str(mde / 'Include/AArch64'),
        '-I' + str(ROOT / 'sources/UniXNU/package/UniXNUPkg/Include'),
        '-I' + str(ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver'), str(source), '-o', str(obj)]
    subprocess.run(command, check=True, cwd=ROOT); raw = obj.read_bytes()
    machine, sections = struct.unpack_from('<2H', raw); require(machine == 0xaa64, 'Firmware ABI probe is not native AARCH64 COFF')
    optional, = struct.unpack_from('<H', raw, 16); found = []
    for index in range(sections):
        section = 20 + optional + index * 40
        if raw[section:section + 8].rstrip(b'\0') == b'.rdata':
            size, offset = struct.unpack_from('<2I', raw, section + 16)
            require(size == len(fields) * 8, 'Firmware ABI probe extent changed')
            found.append(dict(zip(fields, struct.unpack_from('<' + str(len(fields)) + 'Q', raw, offset))))
    require(len(found) == 1, 'Firmware ABI probe section is ambiguous'); facts = found[0]
    require(facts['bs_locate_protocol'] == 320 and facts['rng_get'] == 8 and facts['request_size'] == 72 and
            facts['args_tree'] == 96 and facts['args_tree_size'] == 104, 'Actual EFI/loader/boot_args ABI differs')
    commands = OUT / 'compile-command.json'; commands.write_text(json.dumps(command, indent=2) + '\n')
    return facts, [source, obj, commands]


def inputs():
    efi = json.loads(EFI_REPORT.read_text()); check_efi(efi)
    crypto = json.loads(CRYPTO_REPORT.read_text()); check_crypto(crypto)
    payload_path = ROOT / 'reports/ios16-crypto-payload.json'; payload = json.loads(payload_path.read_text())
    prelink_path = ROOT / 'reports/ios16-crypto-prelink.json'; prelink = json.loads(prelink_path.read_text())
    data_path = ROOT / 'reports/ios16-data-volatile-image.json'; data = json.loads(data_path.read_text())
    candidate = ROOT / prelink['candidate']; adt = ROOT / 'build/cph2653-crypto-bringup/kernel.macho.adt'; disk = ROOT / data['packed_image']
    require(sha(candidate) == prelink['candidate_sha256'] and sha(adt) == payload['artifacts'][str(adt.relative_to(ROOT))] and
            sha(disk) == data['artifacts'][data['packed_image']], 'Need exact preserved crypto kernel, ADT and packed Data input')
    mapping, = [ROOT / name for name in efi['artifacts'] if name.endswith('/DEBUG/DarwinBoot.map')]
    return efi, crypto, candidate, adt, disk, mapping, [EFI_REPORT, CRYPTO_REPORT, payload_path, prelink_path, data_path]


def seed_case(candidate, tree, seed, mode):
    run = Execution(candidate, json.loads(FIXTURE.read_text()), json.loads(OWNER.read_text()), 'normal'); m = run.model
    # Restore the static BSS initial state instead of supplying the direct
    # 32-byte seed used by the older standalone original-POST fixture.
    m.put(m.names['_bootseed'], bytes(32)); require(m.read(m.names['_early_random.init'], 4) == bytes(4), 'Native early PRNG was already initialized')
    offset = tree.find(seed); require(offset >= 4 and tree.count(seed) == 1, 'Fresh firmware seed is not unique in the handoff tree')
    modified = bytearray(tree)
    if mode == 'zero-seed': modified[offset:offset + 256] = bytes(256)
    elif mode == 'short-seed':
        struct.pack_into('<I', modified, offset - 4, 63); modified[offset + 63] = 0; del modified[offset + 64:offset + 256]
    else: require(mode == 'normal', 'Unknown native seed fixture')
    address = run.allocate(len(modified)); m.put(address, bytes(modified)); calls, generators = [], []
    run.observe(m.names['_PE_get_random_seed'], lambda cpu, pc, count, ignored: calls.append(m.register(1)))
    generator = int(run.owner['prng_functions']['pointers'][4], 16) + run.slide
    run.observe(generator, lambda cpu, pc, count, ignored: generators.append(m.register(2)))
    for name in ('_SecureDTInit', '_SecureDTLookupEntry', '_SecureDTGetProperty', '_PE_get_random_seed', '_early_random'):
        require(m.names[name] not in m.peers, 'Native entropy consumption was replaced with a peer')
    m.call('_SecureDTInit', [address, len(modified)]); m.call('_early_random', limit=3000000)
    if mode != 'normal':
        require(len(run.panics) == 1 and 'seed bytes from bootloader' in run.panics[0] and calls == [64] and
                m.read(m.names['_bootseed'], 32) == bytes(32) and not run.post_returns and
                run.counts['native_prng'] == run.counts['native_table'] == 0,
                'Native early_random accepted missing/short bootloader entropy')
        return {'case': mode, 'result': 'REJECTED', 'actual_panic_formats': run.panics,
                'actual_bootloader_seed_requests': calls, 'original_post_or_registration_started': False}
    require(not run.panics and m.read(m.names['_bootseed'], 32) == hashlib.sha256(seed[:64]).digest() and
            m.read(address + offset, 64) == bytes(64) and m.read(address + offset + 64, 192) == seed[64:],
            'Actual native PE/early PRNG did not consume, clear and hash the exact 64 seed bytes')
    m.call('_early_random', limit=3000000); require(calls == [64] and not run.panics, 'Repeated early_random consumed bootloader entropy twice')
    run.bootstrap(); passed = [text.rsplit(' - ', 1)[-1].strip() for text in run.logs if 'PASSED:' in text]
    table, = struct.unpack('<Q', m.read(m.names['_g_crypto_funcs'], 8))
    require(not run.panics and passed == run.contract['required_passed_tests'] and run.post_returns == [0] and
            m.call('_dodge_crypto_prng_ready') == 1 and m.call('_dodge_crypto_prng_matches', [m.names['_dodge_original_crypto_prng_context']]) == 1 and
            table == m.names['_dodge_original_crypto_functions'] and m.read(m.names['_bootseed'], 32) == bytes(32),
            'Fresh EFI-derived native boot seed did not support actual original POST/PRNG/table registration')
    before = len(generators); m.call('_early_random', limit=3000000)
    require(calls == [64] and generators[before:] == [8], 'Post-registration early_random did not delegate to the actual original generator')
    context = json.loads(CRYPTO_REPORT.read_text())['compiler_layout']; sha_rows, random_rows = run.consumers(tuple(context.values()))
    for buffer, size in run.allocations.items(): run.check_buffer(buffer, size)
    require(not any(run.locks.values()), 'Native seed chain left a peer mutex owned')
    return {'case': mode, 'result': 'PASS', 'actual_native_secure_dt_and_pe_and_early_prng_executed': True,
            'actual_bootloader_seed_requests': calls, 'native_sha256_bootseed_matches_fresh_first_64_bytes': True,
            'native_pe_consumed_seed_bytes_cleared': 64, 'remaining_dt_seed_bytes_untouched_by_native_pe': 192,
            'native_bootseed_32_bytes_cleared_after_registration': True, 'post_registration_early_random_original_generator_bytes': 8,
            'actual_post_tests': passed, 'actual_post_return': run.post_returns, 'native_sha_vectors': sha_rows,
            'native_read_random_transfers': random_rows, 'actual_initializer_registration_counts': run.counts,
            'explicit_platform_peers_visited': sorted(m.visited), 'physical_entropy_quality_qualified': False}


def check_report(report):
    require(report['result'] == RESULT and report['builder_sha256'] == sha(Path(__file__)), 'Entropy boot/seed CPU report is stale')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Entropy boot/seed CPU input/artifact changed: ' + name)
    require([row['case'] for row in report['firmware_positive_paths']] == list(POSITIVE) and
            all(row['result'] == 'PASS' for row in report['firmware_positive_paths']) and
            [row['case'] for row in report['firmware_failure_paths']] == list(NEGATIVE) and
            all(row['result'] == 'REJECTED' for row in report['firmware_failure_paths']) and
            report['native_seed_to_crypto']['result'] == 'PASS' and len(report['native_seed_to_crypto']['actual_post_tests']) == 18 and
            len(report['native_seed_to_crypto']['native_sha_vectors']) == 18 and
            [row['case'] for row in report['native_seed_failures']] == ['zero-seed', 'short-seed'] and
            all(row['result'] == 'REJECTED' for row in report['native_seed_failures']) and
            len(report['instruction_controls']) == 2 and all(row['result'] == 'REJECTED' for row in report['instruction_controls']),
            'Actual firmware/native seed execution evidence is incomplete')
    require(not any(report[key] for key in ('hardware_tested', 'physical_entropy_quality_qualified', 'actual_exit_boot_services_qualified',
            'handoff_assembly_executed', 'full_kernel_boot_executed', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Entropy CPU evidence overstates runtime')


def execute_efi(efi, mapping, facts, candidate, adt, disk):
    raw = Path(efi).read_bytes(); files = {'\\kernel.macho': candidate.read_bytes(), '\\kernel.macho.adt': adt.read_bytes()}
    encoded = disk.read_bytes(); positives, negatives = [], []; private_tree = private_seed = None
    for scenario in (*POSITIVE, *NEGATIVE):
        selected = dict(files)
        if scenario == 'missing-seed':
            require(selected['\\kernel.macho.adt'].count(b'random-seed\0') == 1, 'ADT seed key is ambiguous')
            selected['\\kernel.macho.adt'] = selected['\\kernel.macho.adt'].replace(b'random-seed\0', b'random-dead\0')
        firmware = Firmware(raw, mapping, facts, selected, encoded, scenario); row, tree, seed = firmware.run()
        if scenario in POSITIVE: positives.append(row)
        else: negatives.append(row)
        if scenario == 'normal': private_tree, private_seed = tree, seed
        print(row['result'] + ': actual EFI Boot C:', scenario, flush=True)
    controls = []
    for mutation in ('erase-RET', 'Boot-RET'):
        firmware = Firmware(raw, mapping, facts, files, encoded, 'normal')
        firmware.put(firmware.names['DodgeBootEntropyErase' if mutation == 'erase-RET' else 'Boot'], struct.pack('<I', 0xd65f03c0))
        try: firmware.run()
        except ValueError as error: controls.append({'case': mutation, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Altered actual EFI code was accepted: ' + mutation)
    native = seed_case(candidate, private_tree, private_seed, 'normal')
    native_failures = [seed_case(candidate, private_tree, private_seed, mode) for mode in ('zero-seed', 'short-seed')]
    return positives, negatives, controls, native, native_failures


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved actual EFI boot C/native seed/original POST chain CPU evidence'); return
    efi, _, candidate, adt, disk, mapping, dependencies = inputs(); facts, artifacts = layout()
    positives, negatives, controls, native, native_failures = execute_efi(ROOT / efi['efi'], mapping, facts, candidate, adt, disk)
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({'firmware_positive_paths': positives,
                'firmware_failure_paths': negatives, 'instruction_controls': controls, 'native_seed_to_crypto': native,
                'native_seed_failures': native_failures}, indent=2) + '\n'); artifacts.append(evidence)
    sources = [Path(__file__), ROOT / 'scripts/boot_entropy_execution.py', ROOT / 'scripts/check_data_mount_kernel.py',
               ROOT / 'scripts/original_crypto_execution.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_initial_data.py',
               TREE / '.cache/xnu-work/pexpert/gen/device_tree.c', TREE / '.cache/xnu-work/pexpert/gen/pe_gen.c',
               ROOT / 'build/cph2653-crypto-source/prng_random.crypto.c']
    report = {'result': RESULT, 'builder_sha256': sha(Path(__file__)), 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'compiler_firmware_layout': facts,
        'firmware_positive_paths': positives, 'firmware_failure_paths': negatives, 'instruction_controls': controls,
        'native_seed_to_crypto': native, 'native_seed_failures': native_failures, 'private_seed_bytes_serialized': False,
        'actual_exit_boot_services_qualified': False, 'handoff_assembly_executed': False, 'full_kernel_boot_executed': False,
        'physical_entropy_quality_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The actual linked AARCH64 PE firmware Boot C body, parsers, inlined entropy logic and cleanup run to the DarwinEnter boundary. '
                 'Two success paths include a stale memory-map key retry; six failure paths refuse/clean up before exit. Two instruction controls are rejected. '
                 'EFI file/protocol/RNG/memory/console/ExitBootServices and EL1 availability are explicit peers, with an absent GOP fixture and private host RNG bytes. '
                 'The emitted final ADT is passed unchanged into a separate model of the exact prelinked kernel. Native SecureDT, PE_get_random_seed, '
                 'early_random and its SHA/DRBG consume and clear the first 64 bytes, derive the 32-byte bootseed, and consume no second bootloader seed. '
                 'The actual original initializer/all 18 default POST tests/native registration succeed using that derived seed; the native bootseed is cleared. '
                 'Post-registration early_random delegates to the real original generator; 18 native SHA vectors and four read_random transfers pass. '
                 'Two native missing/short entropy paths panic before POST/registration. Native PE leaves the remaining 192 DT bytes unchanged. '
                 'No private seed bytes are recorded. Full firmware services, handoff assembly, physical entropy health, VM/CPU setup, complete kernel boot, '
                 'original policy/root/Data integration or phone operation is qualified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: actual EFI Boot C paths 2+6 / instruction controls 2 / real native seed-to-18-test-POST chain / native seed failures 2')


if __name__ == '__main__': main()
