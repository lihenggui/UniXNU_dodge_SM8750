#!/usr/bin/env python3
"""Run the actual swap bridge with software peers and real bounded pixel copies."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True)
    binary=out/'swap-bridge-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
             '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',
             '-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/gpu_swap_include','-I',ROOT/'drivers/DodgeDisplay',
             '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',
             '-I',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/NativeMobileDisplay',
             ROOT/'tests/DodgeGpuSwapBridgeTest.cpp',ROOT/'drivers/DodgeDisplay/DodgeGpuSwapBridge.cpp',
             '-o',binary]
    subprocess.run(command,check=True)
    completed=subprocess.run([binary],capture_output=True,text=True,timeout=30,
        env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'host-tests.log').write_text(completed.stdout+completed.stderr)
    if completed.returncode:
        raise RuntimeError('Swap bridge host test failed; see '+str(out/'host-tests.log'))
    result=json.loads(completed.stdout)
    if result['result']!='PASS' or not result['cases'] or len(set(result['cases']))!=len(result['cases']):
        raise ValueError('Incomplete or duplicate swap bridge cases')
    print(f"PASS: {len(result['cases'])} actual bridge cases with ASan/UBSan; private completion is a software callee peer")
    return result


if __name__=='__main__':
    check(ROOT/'build/ios16-gpu-swap-bridge')
