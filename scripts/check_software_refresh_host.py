#!/usr/bin/env python3
"""Exercise the actual software-refresh controller with explicit scheduler peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'software-refresh-host'
    subprocess.run(['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
        '-I',ROOT/'tests/gpu_swap_include','-I',ROOT/'drivers/DodgeDisplay',
        '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',
        ROOT/'tests/DodgeSoftwareRefreshTest.cpp',ROOT/'drivers/DodgeDisplay/DodgeSoftwareRefresh.cpp','-o',binary],check=True)
    completed=subprocess.run([binary],capture_output=True,text=True,timeout=30,
        env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'host-tests.log').write_text(completed.stdout+completed.stderr)
    if completed.returncode:raise RuntimeError('Software refresh test failed; see '+str(out/'host-tests.log'))
    result=json.loads(completed.stdout)
    if result['result']!='PASS' or not result['cases'] or len(set(result['cases']))!=len(result['cases']):
        raise ValueError('Incomplete or duplicate software refresh cases')
    print(f"PASS: {len(result['cases'])} actual software-refresh cases with ASan/UBSan; kernel scheduler and original sender are peers")
    return result


if __name__=='__main__':check(ROOT/'build/ios16-software-refresh')
