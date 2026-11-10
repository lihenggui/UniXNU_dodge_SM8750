#!/usr/bin/env python3
"""Sanitizer checks of actual RamBlock helpers using both prepared APFS seeds."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from native_driver_build import ROOT, pinned_sources, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-data-seed-host'
REPORT = ROOT / 'reports/ios16-data-seed-host.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    reference = pinned_sources(('ramblock_reference',))['ramblock_reference']
    inputs = {}
    for variant in ('', '-volatile'):
        path = ROOT / ('reports/ios16-data' + variant + '-image.json')
        subprocess.run([sys.executable, ROOT / 'scripts/prepare_data_image.py', '--check-only', *(['--volatile'] if variant else [])], check=True)
        inputs[variant] = json.loads(path.read_text())
    if args.check_only:
        report = json.loads(REPORT.read_text())
        require(report['builder_sha256'] == sha(Path(__file__)) and report['case_count'] == 47 and
                all(value['result'] == 'PASS' for value in report['tests'].values()), 'Data seed host stage is stale')
        for name, digest in {**report['source_sha256'], **report['artifacts'], **report['dependency_report_sha256']}.items():
            require(sha(ROOT / name) == digest, 'Data seed host source/artifact changed: ' + name)
        print('PASS: 47 actual RamBlock seed/layout/volatile-I/O sanitizer cases, with both original-content APFS seeds')
        return
    OUT.mkdir(exist_ok=True)
    binary = OUT / 'data-seed-test'
    compiler = Path('/usr/bin/g++').resolve()
    command = [compiler, '-std=c++17', '-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I' + str(reference),
               ROOT / 'tests/DodgeDataSeedTest.cpp', '-lcrypto', '-o', binary]
    subprocess.run(command, check=True)
    tests = {}
    for variant, data in inputs.items():
        name = 'volatile-2GiB' if variant else 'compact-3GiB'
        result = subprocess.run([binary, ROOT / data['packed_image'], data['image_sha256'], data['packed_metadata']['sha256']],
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                         UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1'), capture_output=True, text=True)
        (OUT / (name + '.json')).write_text(result.stdout)
        (OUT / (name + '.log')).write_text(result.stderr)
        require(result.returncode == 0 and not result.stderr, 'Data source sanitizer failed: ' + name + '\n' + result.stderr)
        test = json.loads(result.stdout)
        require(test['result'] == 'PASS' and test['case_count'] == len(test['cases']) == (29 if variant else 18) and
                test['encoded_input_sha256'] == data['artifacts'][data['packed_image']] and
                test['logical_bytes'] == data['image_bytes'], 'Actual seed source results differ')
        tests[name] = test
    source_files = [Path(__file__), ROOT / 'tests/DodgeDataSeedTest.cpp', ROOT / 'scripts/prepare_data_image.py',
                    *[reference / name for name in ('SparseDisk.h', 'SeedDisk.h', 'LICENSE')]]
    artifacts = [binary, OUT / 'volatile-2GiB.json', OUT / 'compact-3GiB.json']
    report = {'result': 'IOS16_ACTUAL_DATA_SEED_SOURCE_SANITIZERS_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392', 'source_reference': json.loads((ROOT / 'upstream.lock.json').read_text())['ramblock_reference'],
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {str((ROOT / ('reports/ios16-data' + variant + '-image.json')).relative_to(ROOT)):
                                           sha(ROOT / ('reports/ios16-data' + variant + '-image.json')) for variant in inputs},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
              'host_compiler': str(compiler), 'host_compiler_sha256': sha(compiler),
              'host_crypto_library': '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
              'host_crypto_library_sha256': sha(Path('/usr/lib/x86_64-linux-gnu/libcrypto.so.3')),
              'sanitizers': ['ASan', 'UBSan', 'LeakSanitizer'], 'case_count': sum(t['case_count'] for t in tests.values()),
              'tests': tests, 'entire_2GiB_image_read_through_actual_ramSparseIO_and_hashed': True,
              'actual_source_helpers_unmodified': True, 'actual_sparse_writes_and_truthful_short_completion_checked': True,
              'physical_storage_used': False, 'filesystem_mounted': False, 'phone_operations': 'none',
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'scope': 'Actual pinned RamBlock header implementations, real APFS seeds and host allocation/descriptor/SHA callbacks. '
                       'Volatile writes, failure cleanup by the owning harness, boundaries and short transfers are checked in host RAM. '
                       'This does not execute the complete original IOKit/APFS stack or qualify writable Data on the phone.'}
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 47 actual RamBlock helper cases under ASan/UBSan/LeakSanitizer; full 2 GiB read-back and in-memory writes')


if __name__ == '__main__':
    main()
