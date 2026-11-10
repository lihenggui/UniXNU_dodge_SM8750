#!/usr/bin/env python3
"""Sanitize the production CPH2653 QUP1 SE4 clock/ownership code."""
import json
import os
from pathlib import Path
import subprocess
from native_driver_build import ROOT,require,sha

OUT=ROOT/'build/cph2653-input-takeover'

def check(out=OUT):
    out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'drivers/DodgeInput/DodgeTouchClock.cpp'
    test=ROOT/'tests/DodgeTouchClockTest.cpp'
    shared=ROOT/'sources/UniXNU-sm8750-common/kits/Sm8750Platform'
    geni=ROOT/'sources/UniXNU/drivers/QcomGeniSpi'
    binary=out/'touch-clock-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
             '-fsanitize=address,undefined','-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer','-fno-pie','-no-pie',
             '-I',str(source.parent),'-I',str(shared),'-I',str(geni),str(test),str(source),'-o',str(binary)]
    subprocess.run(command,check=True)
    run=subprocess.run([binary],capture_output=True,text=True,timeout=60,
                       env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'touch-clock-host.log').write_text(run.stdout+run.stderr)
    require(run.returncode==0,'Touch clock sanitizer failed; inspect '+str(out/'touch-clock-host.log'))
    result=json.loads(run.stdout);require(result['result']=='PASS','Clock host cases failed')
    files=[Path(__file__),source,source.with_suffix('.h'),test,shared/'PeripheralIO.h',geni/'GeniSpi.h']
    report={**result,'binary':str(binary.relative_to(ROOT)),'sha256':sha(binary),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
            'mmio_clock_and_pll_behavior_are_peers':True,'hardware_tested':False}
    (out/'clock-host-cases.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(result['case_count'])+' target clock/ownership sanitizer cases, 16 vendor frequencies and four write failures; no hardware')
    return report

if __name__=='__main__':check()
