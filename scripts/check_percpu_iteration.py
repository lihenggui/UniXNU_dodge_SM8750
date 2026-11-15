#!/usr/bin/env python3
"""Check the patched Darwin 22 per-CPU macros across compiler optimization levels."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/ios16-percpu-iteration-host'
REPORT = ROOT / 'reports/ios16-percpu-iteration-host.json'
MACROS = ('PERCPU_GET_WITH_BASE', 'percpu_foreach', 'percpu_foreach_base', 'percpu_foreach_secondary',
          'percpu_foreach_secondary_base', '__PERCPU_NAME', '__PERCPU_ADDR', '__PERCPU_TYPE', '__PERCPU_CAST')


def selected(header):
    lines = header.splitlines(True);result = []
    for name in MACROS:
        at, = [index for index, line in enumerate(lines) if line.startswith('#define ' + name + '(')]
        while True:
            result.append(lines[at]);at += 1
            if not result[-1].rstrip().endswith('\\'):break
        result.append('\n')
    return ''.join(result)


def check_report(report):
    require(report['result'] == 'DARWIN22_UNSIGNED_PERCPU_ITERATION_HOST_PASS' and report['cases_per_optimization'] == 38 and
        report['optimizations'] == [0, 1, 2, 3] and report['languages'] == ['c', 'c++'] and
        not report['hardware_tested'], 'Wrong per-CPU iteration result')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Per-CPU iteration input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: unsigned per-CPU iteration, master slot and empty secondary ranges');return
    OUT.mkdir(parents=True, exist_ok=True);lock = json.loads((ROOT / 'upstream.lock.json').read_text());pin = lock['dodge_percpu_iteration_patch']
    source = ROOT / lock['xnu_ios16']['path'];patch = ROOT / pin['path']
    require(sha(patch) == pin['sha256'], 'Per-CPU patch changed')
    raw = subprocess.check_output(['git', '-C', source, 'show', pin['source_revision'] + ':' + pin['target']])
    directory = OUT / 'source';header = directory / pin['target'];header.parent.mkdir(parents=True, exist_ok=True);header.write_bytes(raw)
    require(sha(header) == pin['before_sha256'], 'Per-CPU source revision changed')
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', patch], cwd=directory, check=True, capture_output=True)
    require(sha(header) == pin['after_sha256'], 'Per-CPU patched header differs')
    include = OUT / 'PerCpuMacros.inc';include.write_text(selected(header.read_text()))
    fixture = ROOT / 'tests/DodgePerCpuIterationTest.c';compiler = shutil.which('clang-14') or shutil.which('clang')
    require(compiler, 'Install Clang for per-CPU iteration tests');artifacts = [header, include];rows = []
    for language in ('c', 'c++'):
        for optimization in (0, 1, 2, 3):
            binary = OUT / ('test-' + language.replace('+', 'p') + '-O' + str(optimization));log = binary.with_suffix('.log')
            subprocess.run([compiler, *(['--driver-mode=g++'] if language == 'c++' else []),
                '-x', language, '-std=' + ('gnu11' if language == 'c' else 'gnu++17'),
                '-O' + str(optimization), '-g', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-pie', '-no-pie', '-I', OUT, fixture, '-o', binary], check=True)
            result = subprocess.run([binary], capture_output=True, text=True, timeout=30);log.write_text(result.stdout + result.stderr)
            require(not result.returncode, 'Per-CPU range failed at O' + str(optimization) + '; inspect ' + str(log.relative_to(ROOT)))
            require(json.loads(result.stdout)['cases'] == 38, 'Incomplete per-CPU range cases');artifacts += [binary, log]
            if language == 'c':rows.append(optimization)
    report = {'result': 'DARWIN22_UNSIGNED_PERCPU_ITERATION_HOST_PASS', 'cases_per_optimization': 38, 'optimizations': rows,
        'languages': ['c', 'c++'], 'total_cases': 304,
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (Path(__file__), fixture, patch)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'sanitizers': ['address', 'undefined'], 'hardware_tested': False,
        'scope': 'Actual patched Darwin 22 macros over 1/2/3/8 synthetic per-CPU slots, master/secondary iteration, break, continue, nesting '
                 'and three high unsigned sentinels for empty secondary ranges. Kernel execution is verified separately.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 304 production per-CPU macro cases in C/C++ at O0/O1/O2/O3 under sanitizers')


if __name__ == '__main__':main()
