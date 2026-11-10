#!/usr/bin/env python3
"""Fault-check actual module/attach orchestration with explicit loader peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'graphics-lifecycle-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
        '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
        '-I',ROOT/'tests/graphics_lifecycle_include','-I',ROOT/'drivers/DodgeDisplay',
        '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',ROOT/'tests/DodgeGraphicsLifecycleTest.cpp',
        ROOT/'drivers/DodgeDisplay/DodgeGraphicsLifecycle.cpp','-o',binary]
    subprocess.run(command,check=True)
    cases=[(name,str(i)) for name in ('loader-failure','symbol-failure','metadata-missing','metadata-wrong','metadata-size') for i in range(3)]
    cases += [(name,) for name in ('success','reentrant-prepare','concurrent-prepare','pre-failure','constructor-refused','post-failure',
        'registration-missing','allocate-failure','init-failure','attach-failure','start-failure','deferred-start-failure','reentrant-attach',
        'surface-root-missing','surface-root-inactive','surface-root-wrong-class','matching-allocation-failed','provider-wrong-class')]
    results=[];logs=[]
    for case in cases:
        result=subprocess.run([binary,*case],capture_output=True,text=True,timeout=30,
            env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs += [str(case)+'\n'+result.stdout+result.stderr];(out/'host-tests.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('Graphics lifecycle sanitizer failure: '+str(case)+'; see '+str(out/'host-tests.log'))
        item=json.loads(result.stdout)
        if item['result']!='PASS':raise ValueError('Graphics lifecycle case failed')
        results.append(item)
    if len({item['case'] for item in results})!=len(cases):raise ValueError('Duplicate lifecycle case')
    print(f'PASS: {len(cases)} actual graphics preparation/attachment sanitizer cases with explicit OSKext/metadata/IOKit peers')
    return {'result':'PASS','cases':results,'case_count':len(cases),'loader_metadata_and_concrete_display_are_peers':True}


if __name__=='__main__':check(ROOT/'build/ios16-graphics-lifecycle')
