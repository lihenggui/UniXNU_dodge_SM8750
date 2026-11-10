#!/usr/bin/env python3
"""Test actual surface-range/provider source using software IOKit peers; no private inputs needed."""
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True)
    driver=ROOT/'drivers/DodgeDisplay'
    shim=ROOT/'tests/surface_backing_include'
    graphics=ROOT/'profiles/os/ios-16.7.16-20H392/graphics'
    flags=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
           '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    tests=[('layout',[*flags,'-I',driver,ROOT/'tests/DodgeSurfaceLayoutTest.cpp']),
           ('ownership',[*flags,'-Wno-invalid-offsetof','-I',shim,'-I',driver,'-I',graphics,
                         ROOT/'tests/DodgeSurfaceBackingTest.cpp',driver/'DodgeSurfaceBacking.cpp'])]
    env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
    results={}
    for name,command in tests:
        binary=out/('surface-'+name+'-test')
        subprocess.run([*command,'-o',binary],check=True)
        result=subprocess.run([binary],env=env,capture_output=True,text=True,timeout=30)
        log=out/(name+'-tests.log');log.write_text(result.stdout+result.stderr)
        if result.returncode:raise RuntimeError('Surface host test failed; see '+str(log))
        results[name]=result.stdout.strip()
        print(results[name])
    return results


if __name__=='__main__':
    check(ROOT/'build/surface-backing-host')
