#!/usr/bin/env python3
"""Exercise the QEMU Data transport with a VirtIO device model and sanitizers."""
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    out = ROOT / 'build/qemu-store-host';out.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which('clang++') or '/usr/bin/clang++-14'
    subprocess.run([compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
        '-I', ROOT / 'drivers/DodgeStorage', ROOT / 'tests/DodgeQemuStoreTest.cpp',
        '-o', out / 'transport'], check=True)
    subprocess.run([out / 'transport'], check=True)
    print('PASS: 23 QEMU store transport cases under ASan/UBSan')
