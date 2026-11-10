#!/usr/bin/env python3
"""Sanitize actual startup ordering with explicit module/GPU/display API peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES=('success','null-out','null-provider','prepare-cold-error','prepare-loading-busy','prepare-latched-error',
    'root-missing','root-wrong-provider','root-allocation-fail','root-null-on-success','gpu-failure','gpu-refused',
    'attach-failure','display-null-on-success','root-disappears-after-gpu','retry-root','retry-prepare',
    'reentry-prepare','reentry-root','reentry-gpu','reentry-attach','reentry-retain','reentry-release','concurrent-gpu')


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'graphics-boot-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
        '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
        '-I',ROOT/'tests/graphics_lifecycle_include','-I',ROOT/'drivers/DodgeDisplay',
        ROOT/'tests/DodgeGraphicsBootTest.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.cpp','-o',binary]
    subprocess.run(command,check=True);results=[];logs=[]
    for case in CASES:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
            env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs.append(case+'\n'+result.stdout+result.stderr);(out/'boot-host-tests.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('Graphics boot sanitizer failure: '+case+'; see '+str(out/'boot-host-tests.log'))
        item=json.loads(result.stdout)
        if item['result']!='PASS' or item['case']!=case:raise ValueError('Invalid graphics boot case record')
        results.append(item)
    print(f'PASS: {len(results)} actual graphics boot ordering/ownership sanitizer cases; module/GPU/display peers')
    return {'result':'PASS','case_count':len(results),'cases':results,'module_gpu_display_and_iokit_are_peers':True,
        'real_hardware_started':False}


if __name__=='__main__':check(ROOT/'build/ios16-graphics-lifecycle')
