#!/usr/bin/env python3
"""Run the ordinary-request sanitizer checks without requiring original Apple images."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sanitizer_environment():
    return dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')


def check(out):
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'apfs-mount-args-host'
    storage = ROOT / 'drivers/DodgeStorage'
    abi = ROOT / 'profiles/os/ios-16.7.16-20H392/storage'
    command = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I' + str(storage), '-I' + str(abi),
               str(storage / 'DodgeApfsMountArgs.cpp'), str(ROOT / 'tests/DodgeApfsMountArgsTest.cpp'), '-o', str(binary)]
    subprocess.run(command, check=True)
    result = subprocess.run([binary], capture_output=True, text=True, check=True, env=sanitizer_environment())
    if result.stderr:
        raise ValueError('APFS request sanitizer diagnostics: ' + result.stderr)
    report = json.loads(result.stdout)
    if report != {'result': 'PASS', 'case_count': 16}:
        raise ValueError('Unexpected APFS request test result')
    return {**report, 'binary': str(binary.relative_to(ROOT))}


if __name__ == '__main__':
    report = check(ROOT / 'build/ios16-apfs-mount-host')
    print('PASS:', report['case_count'], 'actual ordinary APFS request ASan/UBSan cases')
