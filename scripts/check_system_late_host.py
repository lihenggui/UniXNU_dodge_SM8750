#!/usr/bin/env python3
"""Check source storage-before-graphics scheduling with explicit API peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES=('success','root-absent','root-zero','root-other','thread-failure','thread-retry','eager-worker','no-platform',
       'inactive-platform','no-root','delayed','timeout','metadata-failed','hardware-failed','unsupported','null-driver','driver-with-error',
       'graphics-disabled','graphics-queue-failed','reentry-queue','reentry-root','reentry-release','reentry-graphics','reentry-sleep','concurrent-queue')


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'system-late-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/ufs_lifecycle_include','-I',ROOT/'tests/graphics_late_include','-I',ROOT/'drivers/DodgeStorage',
             ROOT/'tests/DodgeSystemLateTest.cpp',ROOT/'drivers/DodgeStorage/DodgeSystemLate.cpp','-o',binary]
    subprocess.run(command,check=True);results=[];logs=[]
    for case in CASES:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
                              env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs.append(case+'\n'+result.stdout+result.stderr);(out/'system-late-host.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('Combined startup sanitizer failure: '+case+'; see '+str(out/'system-late-host.log'))
        item=json.loads(result.stdout)
        if item['case']!=case or item['result']!='PASS':raise ValueError('Invalid combined startup case record')
        results.append(item)
    print(f'PASS: {len(results)} actual combined scheduling cases; scheduler/storage/graphics and IOKit are peers')
    return {'result':'PASS','case_count':len(results),'cases':results,'scheduler_storage_graphics_and_iokit_are_peers':True,'hardware_tested':False}


if __name__=='__main__':check(ROOT/'build/cph2653-ufs-root')
