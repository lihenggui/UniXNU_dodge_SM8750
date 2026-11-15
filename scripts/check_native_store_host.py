#!/usr/bin/env python3
"""Check actual native UFS Data-window and SCSI write boundaries without hardware."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, pinned_sources, require, sha

OUT = ROOT / 'build/cph2653-native-store-host'
REPORT = ROOT / 'reports/ios16-native-store-host.json'
CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/native-store-window.json'


def check_report(report):
    require(report['result'] == 'NATIVE_UFS_DATA_STORE_BOUNDARIES_HOST_PASS' and len(report['variants']) == 6 and
        report['case_count'] >= 130 and not report['hardware_tested'] and not report['physical_storage_written'], 'Incomplete native UFS store checks')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native store input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual native UFS Data-store window/write boundaries');return
    reference = pinned_sources(('pagani_reference',))['pagani_reference'] / 'drivers/NativeUfs'
    source = reference / 'NativeUfs.cpp';lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    contract = json.loads(CONTRACT.read_text());pin = lock['dodge_ufs_root_overlay']
    require(sha(source) == pin['base_source_sha256'] and sha(ROOT / pin['path']) == pin['sha256'], 'Native UFS overlay/base changed')
    OUT.mkdir(parents=True, exist_ok=True);work = OUT / 'source';work.mkdir(exist_ok=True)
    staged = work / 'NativeUfs.cpp';staged.write_bytes(source.read_bytes())
    for patch, digest, expected in ((ROOT / pin['path'], pin['sha256'], contract['before_sha256']),
        (ROOT / contract['patch'], contract['patch_sha256'], contract['after_sha256'])):
        require(sha(patch) == digest, 'Native UFS source patch changed')
        process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch], cwd=work, capture_output=True, text=True)
        require(not process.returncode and 'offset' not in process.stdout.lower() and sha(staged) == expected, 'Native UFS store patch is not exact')
    text = staged.read_text()
    start = text.index('namespace {\nstruct StoreGeometry {')
    end = text.index('// ---- Diagnostic log window', start)
    extracted = OUT / 'NativeStore.extracted.h'
    extracted.write_text('static int PE_parse_boot_argn(const char *, void *, int);\n' + text[start:end])
    rows, artifacts = [], [extracted, staged]
    compiler = shutil.which('clang++-14') or shutil.which('clang++') or shutil.which('g++')
    require(compiler, 'Need a C++17 compiler with sanitizers')
    for readonly in (0, 1):
        binary = OUT / ('native-store-' + str(readonly));log = OUT / ('compile-' + str(readonly) + '.log')
        run([compiler, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
            '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
            '-DNATIVE_UFS_SM8750=1', '-DNATIVE_UFS_READ_ONLY=' + str(readonly), '-I', reference / 'tests', '-I', OUT,
            ROOT / 'tests/DodgeNativeStoreTest.cpp', '-o', binary], log)
        artifacts.append(binary)
        for mode in (0, 1, 2):
            result = subprocess.run([binary, str(mode)], capture_output=True, text=True, timeout=30)
            path = OUT / ('run-' + str(readonly) + '-' + str(mode) + '.log');path.write_text(result.stdout + result.stderr)
            require(not result.returncode and result.stdout.startswith('PASS:'), 'Native UFS store test failed: ' + path.name)
            rows.append({'read_only': readonly, 'mode': mode, 'cases': int(result.stdout.split()[1]), 'result': 'PASS'});artifacts.append(path)
    files = [Path(__file__), CONTRACT, ROOT / pin['path'], ROOT / contract['patch'], ROOT / 'tests/DodgeNativeStoreTest.cpp', source, reference / 'RootCommands.h',
        reference / 'RootQueue.h', reference / 'RootTransportLayout.h', reference / 'RootDiagnostics.h',
        reference / 'TransferPoll.h', reference / 'tests/RootCommandsBridge.cpp']
    report = {'result': 'NATIVE_UFS_DATA_STORE_BOUNDARIES_HOST_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'variants': rows, 'case_count': sum(row['cases'] for row in rows),
        'hardware_tested': False, 'physical_storage_written': False, 'phone_operations': 'none',
        'scope': 'Exact pinned NativeUfs store geometry/open/read/write/sync functions plus production SCSI/UPIU/DMA code. '
        'Six read-only/write-capable and disabled/probe/write-mode combinations test non-overlap, root guard, first/last writes, '
        'FUA, cache sync, invalid LUN and out-of-window/overflow/null refusals. MMIO, DMA/cache and lock operations are explicit host peers.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', report['case_count'], 'actual native UFS store/window cases across six variants')


if __name__ == '__main__':main()
