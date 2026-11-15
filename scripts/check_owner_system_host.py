#!/usr/bin/env python3
"""Portable source checks for owner boot policy, calendar, user entropy and native TRNG."""
import argparse
import concurrent.futures
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/owner-system-host'
REPORT = ROOT / 'reports/ios16-owner-system-host.json'
TESTS = ('DodgeOwnerBootPolicyTest', 'DodgeCalendarTest', 'DodgeUserEntropyTest', 'DodgeTrngTest', 'DodgeRootPolicyFormatTest')


def digest(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_report(report):
    if report['result'] != 'OWNER_SYSTEM_PORTABLE_SANITIZERS_PASS' or set(report['tests']) != set(TESTS):
        raise ValueError('Incomplete owner-system portable checks')
    for name, value in {**report['source_sha256'], **report['artifacts']}.items():
        if digest(ROOT / name) != value:raise ValueError('Portable owner-system input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: owner-system portable source sanitizer checks');return
    compiler = shutil.which('clang++-14') or shutil.which('clang++') or shutil.which('g++')
    if not compiler:raise ValueError('Need a C++17 compiler with ASan/UBSan')
    OUT.mkdir(parents=True, exist_ok=True)
    def compile_one(name):
        binary = OUT / name;log = OUT / (name + '.compile.log')
        command = [compiler, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
            '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
            '-I', str(ROOT / 'drivers/DodgeSecurity'), '-I', str(ROOT / 'drivers/DodgePlatform'),
            '-I', str(ROOT / 'drivers/DodgeStorage'),
            '-I', str(ROOT / 'tests/entropy_include'), str(ROOT / 'tests' / (name + '.cpp')), '-o', str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120);log.write_text(result.stdout + result.stderr)
        if result.returncode:raise ValueError('Portable owner-system compilation failed: ' + name)
        return binary
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:binaries = list(pool.map(compile_one, TESTS))
    rows, artifacts = {}, []
    for binary in binaries:
        result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
        log = binary.with_suffix('.log');log.write_text(result.stdout + result.stderr)
        if result.returncode or not result.stdout.startswith('PASS:'):raise ValueError('Portable owner-system test failed: ' + binary.name)
        rows[binary.name] = result.stdout.strip();artifacts += [binary, log]
    files = [Path(__file__), *[ROOT / 'tests' / (name + '.cpp') for name in TESTS],
        ROOT / 'drivers/DodgeSecurity/DodgeOwnerBootPolicy.h', ROOT / 'drivers/DodgeSecurity/DodgeTrngRead.h',
        ROOT / 'drivers/DodgeSecurity/DodgeUserEntropy.c', ROOT / 'drivers/DodgePlatform/DodgeCalendar.h',
        ROOT / 'drivers/DodgePlatform/DodgePlatformClock.inc', *sorted((ROOT / 'tests/entropy_include').rglob('*.h'))]
    report = {'result': 'OWNER_SYSTEM_PORTABLE_SANITIZERS_PASS', 'tests': rows,
        'source_sha256': {str(path.relative_to(ROOT)): digest(path) for path in files},
        'artifacts': {str(path.relative_to(ROOT)): digest(path) for path in artifacts},
        'compiler': compiler, 'build_jobs': 4, 'original_system_inputs_required': False,
        'hardware_tested': False, 'phone_operations': 'none'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    for line in rows.values():print(line)


if __name__ == '__main__':main()
