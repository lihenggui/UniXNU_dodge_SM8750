#!/usr/bin/env python3
"""Sanitize the actual edge-origin policy, independent of IOKit."""
import json
import os
from pathlib import Path
import subprocess
from native_driver_build import ROOT,require,sha


def main():
    out=ROOT/'build/cph2653-hid-edge';out.mkdir(parents=True,exist_ok=True)
    header=ROOT/'drivers/DodgeInput/DodgeHidEdgePolicy.h';test=ROOT/'tests/DodgeHidEdgeTest.cpp';binary=out/'hid-edge-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-I',str(header.parent),str(test),'-o',str(binary)]
    subprocess.run(command,check=True)
    process=subprocess.run([binary],capture_output=True,text=True,timeout=60,
                           env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'hid-edge-host.log').write_text(process.stdout+process.stderr)
    require(not process.returncode,'HID edge sanitizer failed; inspect '+str(out/'hid-edge-host.log'))
    result=json.loads(process.stdout);require(result['result']=='PASS' and result['identities_exhausted']==256,'HID edge policy coverage incomplete')
    report={**result,'builder_sha256':sha(Path(__file__)),'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),header,test)},
            'binary':str(binary.relative_to(ROOT)),'binary_sha256':sha(binary),'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual edge policy with geometry bounds, all 256 identities, down/move/lift/reuse, exact edge boundaries, high masks and unchanged invalid outputs under ASan/UBSan/LeakSanitizer. No original events or UI.'}
    (ROOT/'reports/ios16-hid-edge-host.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(result['case_count'])+' source edge-origin sanitizer cases, including all 256 identities')


if __name__=='__main__':main()
