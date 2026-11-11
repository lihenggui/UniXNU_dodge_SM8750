#!/usr/bin/env python3
"""Check the CPH2653 native A830 adapter with software peers and optional local firmware."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_native_a830 import apply_overlay, stage_source
from native_driver_build import ROOT, pinned_sources, require, sha
from prepare_native_a830 import INPUTS, FIRMWARE, FILES, prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-dir', type=Path, help='verify the pinned CPH2653 stock files with production parsers')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    refs = pinned_sources(('native_a830_reference', 'native_a830_smmu_reference'))
    source = refs['native_a830_reference']
    out = ROOT / 'build/cph2653-native-a830-board-host'
    stage = out / 'source'
    files = stage_source(source, stage, lock['native_a830_darwin22_overlay'])
    firmware_patch = apply_overlay(stage, lock['native_a830_firmware_overlay'])
    _, generated = prepare(out / 'generated')
    include = out / 'host-include'
    for name, content in {
        'IOKit/IOTypes.h': '#include "XnuMemoryFixture.h"\n',
        'IOKit/IOLib.h': '''#pragma once
#include "XnuMemoryFixture.h"
#include <limits>
inline size_t IOMallocArraySize(size_t h,size_t e,size_t n) {
 return e && n>(std::numeric_limits<size_t>::max()-h)/e?std::numeric_limits<size_t>::max():h+e*n;
}
template<class T> T *os_ptr_load_and_erase(T *&p) {T *v=p;p=nullptr;return v;}
inline void IOFreeData(void *p,size_t) {fixtureMetadataFree(p);}
''',
        'pexpert/pexpert.h': '#pragma once\nbool PE_parse_boot_argn(const char *,void *,int);\n',
        'Sm8750GpuFirmware.h': '#include <stdint.h>\nextern "C" {\n' + ''.join(
            f'extern const uint8_t sm8750_gpu_{n}[];\nextern const uint64_t sm8750_gpu_{n}_size;\n'
            for n in ('gmu', 'sqe', 'aqe', 'zap')) + '}\n',
    }.items():
        path = include / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    cc, cxx = shutil.which('clang-14') or shutil.which('clang'), shutil.which('clang++-14') or shutil.which('clang++')
    require(cc and cxx, 'Install Clang for native A830 adapter tests')
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
             '-fno-pie', '-ffunction-sections', '-fdata-sections', '-Wno-missing-field-initializers']
    includes = [include, out / 'generated', source / 'tests', stage, stage / 'platform/sm8750',
                ROOT / 'drivers/DodgeGpu', refs['native_a830_smmu_reference'],
                ROOT / 'sources/UniXNU/kits/AdrenoPM4']
    for path in includes:
        flags += ['-I', str(path)]
    production = [stage / name for name in ('NativeAdrenoFirmware.cpp', 'NativeAdrenoSha256.cpp',
                  'A830Votes.cpp', 'A830GmuFirmware.cpp', 'A830Zap.cpp', 'platform/sm8750/Sm8750SocInfo.c')]
    production += [ROOT / 'drivers/DodgeGpu/DodgeNativeA830Board.cpp', ROOT / 'tests/DodgeNativeA830BoardTest.cpp']
    objects = [out / (p.stem + '.o') for p in production]
    commands = []
    for path, obj in zip(production, objects):
        cpp = path.suffix == '.cpp'
        commands.append([cxx if cpp else cc, '-std=c++2b' if cpp else '-std=c11', *flags,
                         '-DADRENO830_HOST_TEST', '-DNATIVE_ADRENO_FIRMWARE_PINS="DodgeNativeA830FirmwarePins.inc"',
                         '-c', str(path), '-o', str(obj)])

    def compile_one(item):
        cmd, obj = item
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        obj.with_suffix('.log').write_text(result.stdout + result.stderr)
        return obj.name, result.returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(compile_one, zip(commands, objects)))
    require(all(r == 0 for r in results.values()), 'Board host compilation failed: ' + str(results))
    binary = out / 'board-test'
    link = [cxx, '-fsanitize=address,undefined', '-no-pie', '-pthread', '-Wl,--gc-sections',
            *map(str, objects), '-o', str(binary)]
    result = subprocess.run(link, capture_output=True, text=True)
    (out / 'link.log').write_text(result.stdout + result.stderr)
    require(result.returncode == 0, 'Native A830 board host link failed; see ' + str(out / 'link.log'))
    run = [str(binary)]
    if args.firmware_dir:
        pins = json.loads(FIRMWARE.read_text())['firmware']['files']
        for name in FILES:
            file = args.firmware_dir / name
            require(file.stat().st_size == pins[name]['bytes'] and sha(file) == pins[name]['sha256'],
                    'Local CPH2653 firmware differs: ' + name)
        run.append(str(args.firmware_dir.resolve()))
    result = subprocess.run(run, capture_output=True, text=True, timeout=30,
                            env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1', 'UBSAN_OPTIONS': 'halt_on_error=1'})
    (out / 'test.log').write_text(result.stdout + result.stderr)
    require(result.returncode == 0, 'Native A830 board tests failed; see ' + str(out / 'test.log'))
    files += [INPUTS, FIRMWARE, firmware_patch, Path(__file__), ROOT / 'scripts/prepare_native_a830.py',
              ROOT / 'scripts/build_native_a830.py', ROOT / 'tests/DodgeNativeA830BoardTest.cpp',
              *sorted((ROOT / 'drivers/DodgeGpu').glob('DodgeNativeA830*'))]
    report = {'result': 'CPH2653_NATIVE_A830_BOARD_HOST_PASS', 'source_revision': lock['native_a830_reference']['revision'],
              'output': result.stdout.strip(), 'sanitizers': ['address', 'undefined', 'leak'],
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'stock_firmware_tested': args.firmware_dir is not None,
              'generated_sha256': {p.name: sha(p) for p in generated},
              'entry_startup_peer': True, 'hardware_tested': False,
              'scope': 'Actual board adapter, frequency selection, firmware validation and parsers. '
                       'Startup uses an explicit peer; no power, MMIO or secure calls execute.'}
    (out / 'compile-commands.json').write_text(json.dumps(commands + [link], indent=2) + '\n')
    (ROOT / 'reports/native-a830-board-host.json').write_text(json.dumps(report, indent=2) + '\n')
    print(result.stdout.strip())


if __name__ == '__main__':
    main()
