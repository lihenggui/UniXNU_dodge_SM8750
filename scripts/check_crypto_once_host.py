#!/usr/bin/env python3
"""Sanitize the production original-crypto single-owner state machine."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CASES = ('null-module', 'wrong-module', 'invalid-record-retry', 'existing-crypto', 'existing-prng', 'existing-both',
         'success', 'success-cached', 'entry-failure', 'entry-partial-failure', 'missing-crypto', 'missing-prng',
         'wrong-owner', 'owner-lost-after-success', 'record-changed-after-success', 'recursive', 'concurrent-success', 'concurrent-failure')


def check(out):
    out.mkdir(parents=True, exist_ok=True); binary = out / 'crypto-once-host'
    command = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
               '-I', ROOT / 'drivers/DodgeSecurity', ROOT / 'tests/DodgeCryptoOnceTest.cpp', '-o', binary]
    subprocess.run(command, check=True)
    rows, logs = [], []
    for case in CASES:
        process = subprocess.run([binary, case], capture_output=True, text=True, timeout=30,
                    env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        logs.append(case + '\n' + process.stdout + process.stderr)
        (out / 'crypto-once-host.log').write_text('\n'.join(logs))
        if process.returncode or process.stderr: raise ValueError('Crypto once sanitizer failure: ' + case)
        row = json.loads(process.stdout)
        if row['case'] != case or row['result'] != 'PASS': raise ValueError('Invalid crypto once evidence')
        rows.append(row)
    return {'result': 'PASS', 'case_count': len(rows), 'cases': rows, 'binary': str(binary.relative_to(ROOT)),
            'module_metadata_and_crypto_prng_entry_are_explicit_peers': True,
            'original_crypto_or_post_executed': False, 'hardware_tested': False}


if __name__ == '__main__':
    report = check(ROOT / 'build/cph2653-crypto-source')
    print('PASS:', report['case_count'], 'production crypto once sanitizer cases; explicit module/crypto peers')
