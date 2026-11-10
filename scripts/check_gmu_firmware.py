#!/usr/bin/env python3
"""Run the existing SM8750 loader failures against actual target GMU bytes, offline."""
import json
import os
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha


def main():
    source = pinned_sources(('sm8750', 'a830_firmware_reference', 'a830_backend_reference', 'oneplus13t_reference'))
    soc = source['sm8750'] / 'kits/Sm8750Platform'
    fw = source['a830_firmware_reference']
    gpu = source['a830_backend_reference']
    board = source['oneplus13t_reference'] / 'package'
    firmware = ROOT / 'build/cph2653-gpu-firmware/gen80000_gmu.bin'
    pins = json.loads((ROOT / 'hardware/dodge-gpu-firmware.json').read_text())
    require(sha(firmware) == pins['firmware']['files'][firmware.name]['sha256'], 'GMU test input differs from target')
    out = ROOT / 'build/cph2653-gmu-tests'
    out.mkdir(parents=True, exist_ok=True)
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined']
    for path in (soc, fw, gpu, board):
        flags += ['-I', str(path)]
    files = [soc / 'Sm8750Gmu.c', fw / 'AdrenoFirmware.c', fw / 'AdrenoHfi.c', fw / 'AdrenoHfiStartup.c',
             fw / 'AdrenoHfiVotes.c', soc / 'Sm8750GmuCommandDb.c', soc / 'Sm8750SocInfo.c',
             soc / 'Sm8750GpuZap.c', soc / 'Sm8750GpuPower.c', board / 'PaganiGpuVotes.c']
    objects = []
    log_path = out / 'tests.log'
    with log_path.open('w') as log:
        for file in files:
            obj = out / (file.stem + '.o')
            subprocess.run(['gcc', '-std=c11', *flags, '-DSM8750_GMU_HOST_TEST', '-DADRENO_HFI_HOST_TEST',
                            '-c', file, '-o', obj], check=True, stdout=log, stderr=subprocess.STDOUT, timeout=30)
            objects.append(obj)
        binary = out / 'gmu'
        subprocess.run(['g++', '-std=c++17', *flags, soc / 'Test/gmu.cpp', gpu / 'NativeAdrenoSha256.cpp',
                        *objects, '-o', binary], check=True, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        subprocess.run([binary, firmware], check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    report = {'result': 'TARGET_GMU_FIRMWARE_HOST_TEST_PASS', 'firmware_sha256': sha(firmware),
              'source_revisions': {name: lock[name]['revision'] for name in source},
              'test_sha256': sha(soc / 'Test/gmu.cpp'), 'log': str(log_path.relative_to(ROOT)), 'log_sha256': sha(log_path),
              'sanitizers': ['address', 'undefined'], 'hardware_tested': False,
              'scope': 'Actual target GMU hash/loader/readback and failure quarantine over software MMIO; OPP and command-db are fixtures.'}
    (ROOT / 'reports/gmu-firmware-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print(log_path.read_text().strip())


if __name__ == '__main__':
    main()
