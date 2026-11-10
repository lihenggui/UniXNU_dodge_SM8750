#!/usr/bin/env python3
"""Sanitize target input register policy and actual loader/start coordinator."""
import json
import os
from pathlib import Path
import subprocess
from native_driver_build import ROOT,require,sha

POWER=('enable','already-on','version','count-zero','count-large','absent','foreign-owner','duplicate','owner-changed',
       'type','subtype','input','mux','open-drain','no-drive','disabled','status-error','timeout','readback','window','level',
       'write-error','write-timeout','sequence','vdd-failure','avdd-failure')
LIFECYCLE=('success','dual','null-out','null-provider','flag-missing','flag-zero','wrong-provider','no-platform','inactive-provider','inactive-platform',
           'load-failure','symbol-failure','parent-missing','parent-identity','parent-size','pre-failure','post-failure',
           'driver-missing','driver-identity','driver-size','allocation-failure','init-failure','attach-failure','start-failure',
           'reentry-prepare','reentry-init','reentry-attach','reentry-start','dual-init-failure','concurrent-start')
LATE=('success','disabled','missing','other','thread-failure','thread-retry','eager','concurrent','no-platform','inactive-platform','no-root',
      'wait-storage','wait-graphics','storage-timeout','graphics-timeout','busy','prestart-timeout','unsupported','metadata-failed',
      'init-failed','keys-failed','touch-failed','null-driver','driver-with-error','reentry-queue','reentry-start','reentry-release','reentry-sleep')

def check(out):
    out.mkdir(parents=True,exist_ok=True)
    common=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
            '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread']
    groups=[('power',POWER,[ROOT/'tests/DodgeTouchPowerTest.cpp'],[ROOT/'drivers/DodgeInput',ROOT/'sources/UniXNU-sm8750-common/kits/Sm8750Platform']),
            ('lifecycle',LIFECYCLE,[ROOT/'tests/DodgeInputLifecycleTest.cpp',ROOT/'drivers/DodgeInput/DodgeInputLifecycle.cpp'],
             [ROOT/'tests/input_lifecycle_include',ROOT/'tests/ufs_lifecycle_include',ROOT/'tests/graphics_lifecycle_include',ROOT/'drivers/DodgeInput']),
            ('late',LATE,[ROOT/'tests/DodgeInputLateTest.cpp',ROOT/'drivers/DodgeInput/DodgeInputLate.cpp'],
             [ROOT/'tests/ufs_lifecycle_include',ROOT/'tests/graphics_late_include',ROOT/'drivers/DodgeInput',ROOT/'drivers/DodgeStorage',ROOT/'drivers/DodgeDisplay'])]
    result={}
    for name,cases,sources,includes in groups:
        binary=out/('input-'+name+'-host');command=common[:]
        for directory in includes:command+=['-I',str(directory)]
        subprocess.run([*command,*sources,'-o',binary],check=True)
        logs=[];records=[]
        for case in cases:
            ran=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
                env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
            logs.append(case+'\n'+ran.stdout+ran.stderr);(out/('input-'+name+'-host.log')).write_text('\n'.join(logs))
            require(ran.returncode==0,'Input '+name+' failed: '+case+'; inspect host log')
            record=json.loads(ran.stdout);require(record['case']==case and record['result']=='PASS','Invalid input host result');records.append(record)
        result[name]={'result':'PASS','case_count':len(records),'cases':records,'binary':str(binary.relative_to(ROOT)),'sha256':sha(binary)}
    result['result']='PASS';result['mmio_loader_metadata_and_iokit_are_peers']=True
    return result

if __name__=='__main__':
    out=ROOT/'build/cph2653-input-native';r=check(out)
    (out/'host-cases.json').write_text(json.dumps(r,indent=2)+'\n')
    print('PASS: input power/lifecycle/worker sanitizer cases: '+str(sum(r[n]['case_count'] for n in ('power','lifecycle','late'))))
