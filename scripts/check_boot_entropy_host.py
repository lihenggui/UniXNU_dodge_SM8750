#!/usr/bin/env python3
"""Check the production entropy handoff helper using actual EFI headers and explicit RNG peers."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-boot-entropy-host'
MDE = ROOT / 'uefi/Mu-Silicium/Mu_Basecore/MdePkg'


def check(adt=None):
    OUT.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'tests/DodgeBootEntropyTest.c'; header = ROOT / 'drivers/DodgeBoot/DodgeBootEntropy.h'
    compiler = shutil.which('clang') or shutil.which('clang-14')
    require(compiler is not None and (MDE / 'Include/Uefi.h').is_file(), 'Need clang and the pinned UEFI MdePkg headers')
    binary = OUT / 'boot-entropy-test'
    command = [compiler, '-std=c11', '-O1', '-g', '-fshort-wchar', '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-pie', '-no-pie',
               '-Wall', '-Wextra', '-Werror', '-I' + str(MDE / 'Include'), '-I' + str(MDE / 'Include/X64'),
               '-I' + str(header.parent), str(source), '-o', str(binary)]
    subprocess.run(command, check=True, cwd=ROOT)
    result = subprocess.run([str(binary), *([str(adt)] if adt else [])], capture_output=True, text=True, cwd=ROOT,
                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
    require(result.returncode == 0 and not result.stderr, 'Boot entropy sanitizer failure: ' + result.stdout + result.stderr[-4000:])
    print(result.stdout, end='', flush=True)
    match = re.search(r'PASS: (\d+) provider/order cases, (\d+) malformed/truncation cases', result.stdout)
    require(match is not None and tuple(map(int, match.groups())) == (14, 408), 'Entropy host case coverage changed')
    return {'result': 'PASS', 'provider_and_order_cases': int(match[1]), 'malformed_or_truncation_cases': int(match[2]),
            'invalid_parameter_cases': 3, 'actual_adt_with_rng_peer_checked': adt is not None,
            'sanitizers': ['address', 'undefined', 'leak'], 'binary': str(binary.relative_to(ROOT)), 'binary_sha256': sha(binary),
            'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (source, header)},
            'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
            'command': command, 'physical_entropy_quality_qualified': False, 'hardware_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--adt', type=Path); args = parser.parse_args()
    result = check(args.adt); (OUT / 'host-evidence.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__': main()
