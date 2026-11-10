#!/usr/bin/env python3
"""Build the real post-VM diagnostic renderer and its two display adapters."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import capstone
from native_driver_build import ROOT, NATIVE, archive_imports, build_objects, inspect_object, pinned_sources, require, sha


def added_header(patch, name, destination):
    text = patch.read_text()
    marker = '+++ b/' + name + '\n'
    require(text.count(marker) == 1, 'Expected one pinned added diagnostic header')
    lines = text.split(marker, 1)[1].splitlines(True)
    result = []
    for line in lines:
        if line.startswith('--- ') or line.startswith('diff --git '):
            break
        if line.startswith('@@'):
            continue
        require(line.startswith('+'), 'Diagnostic header is not a standalone added file')
        result.append(line[1:])
    require(result and result[-1].strip() == '#endif', 'Incomplete diagnostic header')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(''.join(result))


def main():
    sources = pinned_sources(('pagani_reference', 'oneplus13t_reference'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    out = ROOT / 'build/ios16-diagnostic-console'
    stage = out / 'source'
    stage.mkdir(parents=True, exist_ok=True)
    reference = sources['pagani_reference'] / 'drivers/BootProgress'
    source = stage / 'BootProgress.c'
    shutil.copyfile(reference / source.name, source)
    pin = lock['dodge_diagnostic_console_patch']
    patch = ROOT / pin['path']
    require(sha(patch) == pin['sha256'] and pin['source_revision'] == lock['pagani_reference']['revision'],
            'Console overlay differs from reviewed source')
    subprocess.run(['git', 'apply', '--check', '--directory=' + str(stage.relative_to(ROOT)), patch], cwd=ROOT, check=True)
    subprocess.run(['git', 'apply', '--directory=' + str(stage.relative_to(ROOT)), patch], cwd=ROOT, check=True)
    added_header(ROOT / 'sources/UniXNU/patches/xnu/zzz-boot-progress.patch', 'osfmk/kern/boot_progress.h',
                 stage / 'kern/boot_progress.h')
    added_header(sources['oneplus13t_reference'] / 'patches/xnu/zzzz-early-boot-progress.patch',
                 'osfmk/kern/early_boot_progress.h', stage / 'kern/early_boot_progress.h')
    font = ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver/DiagFont.h'
    adapter = ROOT / 'drivers/DodgeDisplay/DodgeDiagnosticConsole.cpp'
    test_source = stage / 'Test/console.c'
    test_source.parent.mkdir(exist_ok=True)
    shutil.copyfile(reference / 'Test/console.c', test_source)
    host_results = []
    for bits in (25, 26):
        binary = out / ('console-host-' + str(bits))
        command = ['/usr/bin/clang-14', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-DT0SZ_BOOT=' + str(bits),
                   '-DCONSOLE_REFERENCE_TEST="' + str(test_source) + '"',
                   '-I', str(font.parent), '-I', str(reference),
                   str(ROOT / 'tests/DodgeConsoleBindTest.c'), '-o', str(binary)]
        subprocess.run(command, check=True)
        result = subprocess.check_output([binary], text=True,
            env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'})
        print(result, end='')
        host_results.append({'t0sz_boot': bits, 'output': result.strip(), 'sha256': sha(binary)})
    peer = ROOT / 'tests/diagnostic_console_include'
    provider_test = ROOT / 'tests/DodgeDiagnosticConsoleTest.cpp'
    provider_binary = out / 'console-provider-host'
    subprocess.run(['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
                    '-fno-pie', '-no-pie', '-I', peer, provider_test, adapter, '-o', provider_binary], check=True)
    provider_output = subprocess.check_output([provider_binary], text=True,
        env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'})
    print(provider_output, end='')
    objects = build_objects([source, adapter], out, [stage, reference, font.parent],
                            ['-DDODGE_POST_VM_CONSOLE=1', '-UXNU_BOOT_PROGRESS', '-DXNU_BOOT_PROGRESS=1',
                             '-UXNU_EARLY_BOOT_PROGRESS', '-DXNU_EARLY_BOOT_PROGRESS=1'])
    imports = archive_imports(objects)
    require(not imports['required_board_or_original_imports'], 'Console has unresolved strong platform imports: ' +
            repr(imports['required_board_or_original_imports']))
    expected = {'_native_legacy_overlay_rows', '_native_legacy_overlay_preserve', '_dodge_diagnostic_console_attach'}
    require(expected <= set(imports['defined']), 'Real console adapters are absent')
    require(not any(name.startswith('_early_boot_progress_') for name in imports['defined']),
            'An early-entry routine escaped the post-VM candidate guard')
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    instruction_count, counters = 0, {'cntvct_el0': 0, 'cntfrq_el0': 0}
    for obj in objects:
        data = obj.read_bytes()
        image = inspect_object(data)
        for segment in image['segments']:
            for section in segment['sections']:
                if section['name'] != '__text':
                    continue
                code = data[section['fileoff']:section['fileoff'] + section['size']]
                instructions = list(decoder.disasm(code, section['va']))
                require(len(instructions) * 4 == len(code), 'Undecoded native console instruction')
                for instruction in instructions:
                    operands = instruction.op_str.lower()
                    require(not re.search(r'\b(?:[vqdsh][0-9]+)(?:\.|\b)', operands), 'SIMD/FP in native console')
                    require(not (instruction.mnemonic == 'msr' and
                                 re.search(r'\b(?:tcr_el1|ttbr0_el1|ttbr1_el1|sctlr_el1)\b', operands)),
                            'Translation register write in post-VM console')
                    for name in counters:
                        counters[name] += instruction.mnemonic == 'mrs' and name in operands
                instruction_count += len(instructions)
    require(all(counters.values()), 'Actual architectural elapsed-time counter reads are absent')
    archive = out / 'libDodgeDiagnosticConsole.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, *objects], check=True)
    report = {'result': 'DARWIN22_POST_VM_DIAGNOSTIC_CONSOLE_BUILD_PASS', 'target': 'arm64-apple-ios16.0',
              'native_kernel_sha256': sha(NATIVE), 'builder_sha256': sha(Path(__file__)),
              'source_revision': lock['pagani_reference']['revision'], 'patch': pin,
              'source_sha256': sha(source), 'adapter_sha256': sha(adapter), 'font_sha256': sha(font),
              'headers': {str(path.relative_to(stage)): sha(path) for path in (stage / 'kern').glob('*.h')},
              'objects': [{'path': str(path.relative_to(ROOT)), 'sha256': sha(path)} for path in objects],
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive), 'imports': imports,
              'overflow_instrumentation_retained': True, 'early_boot_entry_selected': False,
              'native_instruction_count': instruction_count, 'actual_elapsed_counter_reads': counters,
              'native_fp_simd_absent': True, 'native_translation_register_writes_absent': True,
              'first_binding_before_observers_required': True,
              'host_renderer_tests': host_results, 'reference_console_test_sha256': sha(test_source),
              'bind_test_sha256': sha(ROOT / 'tests/DodgeConsoleBindTest.c'),
              'provider_host_test': provider_output.strip(),
              'provider_test_sha256': sha(provider_test),
              'software_peer_headers': {str(path.relative_to(ROOT)): sha(path) for path in peer.rglob('*.h')},
              'console_map_lifetime': 'One verified IOMemoryMap retained until shutdown; no rebind.',
              'default_kernel_selected': False, 'hardware_execution': False,
              'scope': 'Actual diagnostic renderer and map-retaining adapters compiled against Darwin22. '
                       'No early MMU-off hooks, original display completion, refresh generator or physical rendering qualification.'}
    (ROOT / 'reports/ios16-diagnostic-console.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: real post-VM renderer and both overlay adapters compile; no early-entry hooks or hardware access')


if __name__ == '__main__':
    main()
