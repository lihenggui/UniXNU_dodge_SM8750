#!/usr/bin/env python3
"""Run the actual external-policy loader with explicit VM/read peers and host SHA-256."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, pinned_sources, require, sha

OUT = ROOT / 'build/cph2653-root-policy-source-host'
REPORT = ROOT / 'reports/ios16-root-policy-source-host.json'


def check_report(report):
    require(report['result'] == 'NATIVE_ROOT_POLICY_SOURCE_HOST_PASS' and report['case_count'] == 13 and
        not report['hardware_tested'], 'Incomplete root-policy loader checks')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Root-policy source check changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual external-policy loader failure/immutability paths');return
    reference = pinned_sources(('pagani_reference',))['pagani_reference'] / 'drivers/NativeVirtioBlock'
    OUT.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which('clang++-14') or shutil.which('clang++') or shutil.which('g++');require(compiler, 'Need C++17 compiler')
    peers = ROOT / 'tests/root_policy_include';test = ROOT / 'tests/DodgeRootPolicySourceTest.cpp';binary = OUT / 'root-policy-source-host'
    run([compiler, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
        '-I', peers, '-I', reference, test, '-lcrypto', '-o', binary], OUT / 'compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'Root-policy loader checks failed; inspect host.log')
    files = [Path(__file__), test, *sorted(peers.rglob('*.h')), reference / 'VerifiedBlockPolicy.h',
        *[ROOT / 'drivers/DodgeStorage' / name for name in ('DodgeRootPolicySource.cpp', 'DodgeRootPolicySource.h', 'DodgeRootPolicyFormat.h')]]
    report = {'result': 'NATIVE_ROOT_POLICY_SOURCE_HOST_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in (binary, log)},
        'case_count': int(result.stdout.split()[1]), 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Actual source loader runs with synthetic public policy bytes, host SHA-256, explicit UFS-read/VM peers and '
        'real host read-only mappings. Bad format/identity/digest, header/data mutation, read/alloc/protection failures, '
        'single-attempt latches, chunk bounds and immutable snapshot retention are checked. '
        'This does not execute Darwin VM, physical UFS or the separate RSA verification performed by each root window.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(result.stdout.strip())


if __name__ == '__main__':main()
