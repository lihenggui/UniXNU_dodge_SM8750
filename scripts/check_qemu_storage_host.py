#!/usr/bin/env python3
"""Check the storage coordinator against loader and changing-registry peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = ('success', 'platform-delay', 'platform-timeout', 'snapshot-invalidation', 'concurrent-entry',
    'flag-missing', 'flag-zero', 'flag-two', 'no-platform', 'inactive-platform', 'wrong-bus', 'missing-bus',
    'inactive-device', 'too-many', 'load-failure', 'parent-identity', 'parent-size', 'pre-failure', 'post-failure',
    'child-identity', 'child-size', 'allocation-failure', 'partial-allocation', 'init-failure', 'attach-failure',
    'start-failure', 'apfs-failure')


def check(out):
    out.mkdir(parents=True, exist_ok=True)
    source = (ROOT / 'drivers/DodgeStorage/DodgeQemuStorage.cpp').read_text()
    extracted = out / 'DodgeQemuStorage.extracted.h'
    extracted.write_text(''.join(line for line in source.splitlines(True) if not line.startswith('#include ')))
    binary = out / 'qemu-storage-host'
    subprocess.run(['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
        '-fno-pie', '-no-pie', '-pthread', '-I', out,
        '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/storage', ROOT / 'tests/DodgeQemuStorageTest.cpp', '-o', binary], check=True)
    results, logs = [], []
    for case in CASES:
        process = subprocess.run([binary, case], capture_output=True, text=True, timeout=10,
            env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        logs.append(case + '\n' + process.stdout + process.stderr)
        (out / 'qemu-storage-host.log').write_text('\n'.join(logs))
        if process.returncode or process.stderr:raise ValueError('Storage coordinator failed: ' + case + '; inspect qemu-storage-host.log')
        row = json.loads(process.stdout)
        if row != {'case': case, 'result': 'PASS'}:raise ValueError('Invalid coordinator result')
        results.append(row)
    return {'result': 'PASS', 'cases': results, 'case_count': len(results), 'binary': str(binary.relative_to(ROOT)),
        'scope': 'Actual coordinator source with explicit registry, loader, clock and driver-init/start peers. No native ABI, MMIO, DMA or APFS result.'}


if __name__ == '__main__':
    result = check(ROOT / 'build/qemu-storage-host')
    print('PASS:', result['case_count'], 'storage coordinator sanitizer cases')
