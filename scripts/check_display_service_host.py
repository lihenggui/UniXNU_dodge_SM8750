#!/usr/bin/env python3
"""Exercise the actual display lifecycle coordinator with explicit software peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True)
    binary=out/'display-service-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
             '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/gpu_swap_include','-I',ROOT/'drivers/DodgeDisplay',
             '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',ROOT/'tests/DodgeDisplayServiceTest.cpp',
             ROOT/'drivers/DodgeDisplay/DodgeDisplayService.cpp','-o',binary]
    subprocess.run(command,check=True)
    result=subprocess.run([binary],capture_output=True,text=True,timeout=60,
                          env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'host-tests.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('Display service sanitizer tests failed; see '+str(out/'host-tests.log'))
    report=json.loads(result.stdout)
    if report['result']!='PASS' or len(set(report['cases']))!=len(report['cases']):raise ValueError('Incomplete/duplicate display service cases')
    print('PASS: '+str(len(report['cases']))+' actual display service coordinator sanitizer cases (frontend/IOKit peers)')
    return report


def check_integration(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'display-service-integration-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-DDODGE_DISPLAY_SERVICE_INTEGRATION=1',
             '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/gpu_swap_include','-I',ROOT/'drivers/DodgeDisplay','-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',
             '-I',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/NativeMobileDisplay',ROOT/'tests/DodgeDisplayFrontendTest.cpp',
             *[ROOT/'drivers/DodgeDisplay'/name for name in ('DodgeDisplayService.cpp','DodgeDisplayFrontend.cpp','DodgeGpuSwapBridge.cpp','DodgeSoftwareRefresh.cpp')],
             '-o',binary]
    subprocess.run(command,check=True)
    result=subprocess.run([binary],capture_output=True,text=True,timeout=60,
                          env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'integration-tests.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('Display service integration sanitizer tests failed; see '+str(out/'integration-tests.log'))
    report=json.loads(result.stdout)
    if report['result']!='PASS' or len(set(report['cases']))!=len(report['cases']):raise ValueError('Incomplete/duplicate integration cases')
    print('PASS: '+str(len(report['cases']))+' actual coordinator/frontend/bridge/refresh integration sanitizer cases')
    return report


if __name__=='__main__':
    check(ROOT/'build/ios16-display-service')
    check_integration(ROOT/'build/ios16-display-service')
