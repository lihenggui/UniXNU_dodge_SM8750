#!/usr/bin/env python3
"""Check actual UFS loader/one-shot controller ownership with explicit API peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES=('success','null-out','null-provider','flag-missing','flag-zero','wrong-provider','no-platform','inactive-provider','inactive-platform',
       'load-failure','symbol-failure','parent-missing','parent-identity','parent-size','pre-failure','post-failure',
       'driver-missing','driver-identity','driver-size','block-missing','block-identity','block-size',
       'allocation-failure','init-failure','attach-failure','start-failure','reentry-prepare','reentry-init','reentry-attach',
       'reentry-start','reentry-release','concurrent-start')


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'ufs-lifecycle-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/ufs_lifecycle_include','-I',ROOT/'tests/graphics_lifecycle_include',
             '-I',ROOT/'drivers/DodgeStorage','-I',ROOT/'profiles/os/ios-16.7.16-20H392/storage',
             ROOT/'tests/DodgeUfsLifecycleTest.cpp',ROOT/'drivers/DodgeStorage/DodgeUfsLifecycle.cpp','-o',binary]
    subprocess.run(command,check=True);results=[];logs=[]
    for case in CASES:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
                              env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs.append(case+'\n'+result.stdout+result.stderr);(out/'ufs-lifecycle-host.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('UFS lifecycle sanitizer failure: '+case+'; see '+str(out/'ufs-lifecycle-host.log'))
        item=json.loads(result.stdout)
        if item['case']!=case or item['result']!='PASS':raise ValueError('Invalid UFS lifecycle case record')
        results.append(item)
    print(f'PASS: {len(results)} actual UFS loader/start ownership sanitizer cases; loader, metadata, allocation and controller start are peers')
    return {'result':'PASS','case_count':len(results),'cases':results,'loader_metadata_allocation_controller_and_iokit_are_peers':True,'hardware_tested':False}


if __name__=='__main__':check(ROOT/'build/cph2653-ufs-root')
