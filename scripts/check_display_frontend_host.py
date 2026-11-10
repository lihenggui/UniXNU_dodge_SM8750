#!/usr/bin/env python3
"""Run actual guarded display frontend/bridge against explicit software peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'display-frontend-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
        '-I',ROOT/'tests/gpu_swap_include','-I',ROOT/'drivers/DodgeDisplay','-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',
        '-I',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/NativeMobileDisplay',ROOT/'tests/DodgeDisplayFrontendTest.cpp',
        ROOT/'drivers/DodgeDisplay/DodgeDisplayFrontend.cpp',ROOT/'drivers/DodgeDisplay/DodgeGpuSwapBridge.cpp',
        ROOT/'drivers/DodgeDisplay/DodgeSoftwareRefresh.cpp','-o',binary]
    subprocess.run(command,check=True)
    result=subprocess.run([binary],capture_output=True,text=True,timeout=60,
        env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'host-tests.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('Display frontend sanitized tests failed; see '+str(out/'host-tests.log'))
    report=json.loads(result.stdout)
    if report['result']!='PASS' or len(set(report['cases']))!=len(report['cases']):raise ValueError('Incomplete/duplicate frontend cases')
    print('PASS: '+str(len(report['cases']))+' actual frontend/bridge sanitized cases and 1124 noncanonical packet mutations')
    return report


if __name__=='__main__':check(ROOT/'build/ios16-display-frontend')
