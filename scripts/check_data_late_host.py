#!/usr/bin/env python3
"""Check the Data scheduler's bounded waits, ownership and concurrency."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = ('disabled', 'missing', 'other', 'success', 'no-platform', 'inactive-platform', 'no-root', 'provider-late',
         'wait-storage', 'wait-graphics', 'both-workers', 'storage-timeout', 'graphics-timeout', 'thread-failure',
         'thread-retry', 'eager', 'concurrent', 'busy', 'prestart-timeout', 'unsupported', 'allocation-failed',
         'metadata-failed', 'init-failed', 'start-failed', 'null-driver', 'driver-with-error',
         'reentry-queue', 'reentry-sleep', 'reentry-start', 'reentry-release')


def check(out):
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'data-late-host'
    command = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-pthread']
    includes = [ROOT / 'tests/ufs_lifecycle_include', ROOT / 'tests/graphics_late_include', ROOT / 'drivers/DodgeStorage', ROOT / 'drivers/DodgeDisplay']
    for include in includes:
        command += ['-I', include]
    command += [ROOT / 'tests/DodgeDataLateTest.cpp', ROOT / 'drivers/DodgeStorage/DodgeDataLate.cpp', '-o', binary]
    subprocess.run(command, check=True)
    cases, logs = [], []
    for case in CASES:
        result = subprocess.run([binary, case], capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        logs.append(case + '\n' + result.stdout + result.stderr)
        (out / 'data-late-host.log').write_text('\n'.join(logs))
        if result.returncode or result.stderr:
            raise ValueError('Data scheduler sanitizer failure: ' + case + '; see ' + str(out / 'data-late-host.log'))
        item = json.loads(result.stdout)
        if item['case'] != case or item['result'] != 'PASS':
            raise ValueError('Invalid Data scheduler case')
        cases.append(item)
    return {'result': 'PASS', 'case_count': len(cases), 'cases': cases, 'binary': str(binary.relative_to(ROOT)),
            'iokit_threads_earlier_workers_and_data_starter_are_explicit_peers': True, 'hardware_tested': False}


if __name__ == '__main__':
    results = check(ROOT / 'build/cph2653-data-startup')
    print('PASS:', results['case_count'], 'actual Data scheduler sanitizer cases, with explicit peers')
