#!/usr/bin/env python3
"""Exercise actual Data registration/one-shot-start source with explicit peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = ('success', 'null-out', 'null-provider', 'flag-missing', 'flag-zero', 'flag-two', 'wrong-provider', 'no-platform',
         'inactive-provider', 'inactive-platform', 'load-failure', 'parent-symbol-failure', 'parent-missing',
         'parent-identity', 'parent-size', 'pre-failure', 'post-failure', 'child-symbol-failure', 'child-missing',
         'child-identity', 'child-size', 'allocation-failure', 'init-failure', 'attach-failure', 'start-failure',
         'reentry-prepare', 'reentry-init', 'reentry-attach', 'reentry-start', 'concurrent-start')


def check(out):
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'data-lifecycle-host'
    command = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-pthread',
               '-I', ROOT / 'tests/ufs_lifecycle_include', '-I', ROOT / 'tests/graphics_lifecycle_include',
               '-I', ROOT / 'drivers/DodgeStorage', '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/storage',
               ROOT / 'tests/DodgeRamBlockLifecycleTest.cpp', ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.cpp', '-o', binary]
    subprocess.run(command, check=True)
    results, logs = [], []
    for case in CASES:
        result = subprocess.run([binary, case], capture_output=True, text=True, timeout=30,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        logs.append(case + '\n' + result.stdout + result.stderr)
        (out / 'data-lifecycle-host.log').write_text('\n'.join(logs))
        if result.returncode or result.stderr:
            raise ValueError('Data lifecycle sanitizer failed: ' + case + '; see ' + str(out / 'data-lifecycle-host.log'))
        item = json.loads(result.stdout)
        if item['result'] != 'PASS' or item['case'] != case:
            raise ValueError('Invalid Data lifecycle result')
        results.append(item)
    return {'result': 'PASS', 'case_count': len(results), 'cases': results, 'binary': str(binary.relative_to(ROOT)),
            'loader_iokit_allocation_and_original_init_start_are_explicit_peers': True,
            'failure_retention_checked_before_harness_only_reclamation': True, 'hardware_tested': False}


if __name__ == '__main__':
    results = check(ROOT / 'build/cph2653-data-source')
    print('PASS:', results['case_count'], 'actual Data lifecycle sanitizer cases, with explicit peers')
