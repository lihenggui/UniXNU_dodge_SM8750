#!/usr/bin/env python3
"""Check the actual GOP provider factory with explicit IOKit/PE peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES=('success','null-out','null-platform','modules-not-ready','wrong-platform','platform-inactive','platform-hierarchy',
       'console-failure','zero-base','zero-width','zero-height','oversize-width','oversize-height','depth','rotation',
       'short-stride','long-stride','physical-overflow','symbol-failure','metadata-missing','metadata-identity','metadata-size',
       'metadata-parent','allocation-failure','allocation-wrong-class','object-wrong-metadata','init-failure','name-failure',
       'memory-allocation-failure','memory-address-mismatch','memory-length-mismatch','array-allocation-failure','array-insert-failure',
       'memory-install-failure','memory-count-mismatch','memory-index-mismatch','resources-failure','attach-failure',
       'platform-dies-at-attach','mode-change-at-attach','mode-change-at-register','provider-dies-at-register','memory-change-at-register',
       'cache-mode-change','cache-provider-inactive','cache-platform-inactive','cache-memory-change',
       'cache-wrong-platform','reentry-metadata','reentry-init','reentry-attach','reentry-register','reentry-release',
       'concurrent-create','concurrent-cold-start','wrapper-success','wrapper-prepare-failure','wrapper-publish-failure','wrapper-boot-failure','wrapper-retry')


def check(out):
    out.mkdir(parents=True,exist_ok=True);binary=out/'gop-provider-host'
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/gop_provider_include','-I',ROOT/'drivers/DodgeDisplay',
             '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics',
             ROOT/'tests/DodgeGopProviderTest.cpp',ROOT/'drivers/DodgeDisplay/DodgeGopProvider.cpp','-o',binary]
    subprocess.run(command,check=True);results=[];logs=[]
    for case in CASES:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
                              env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs.append(case+'\n'+result.stdout+result.stderr);(out/'provider-host-tests.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('GOP provider sanitizer failure: '+case+'; see '+str(out/'provider-host-tests.log'))
        item=json.loads(result.stdout)
        if item['case']!=case or item['result']!='PASS':raise ValueError('Invalid provider case record')
        results.append(item)
    print(f'PASS: {len(results)} actual GOP factory/wrapper sanitizer cases; IOKit/PE/original metadata and boot are peers')
    return {'result':'PASS','case_count':len(results),'cases':results,'iokit_pe_allocation_and_boot_are_peers':True,
            'original_allocator_executed':False,'hardware_tested':False}


if __name__=='__main__':check(ROOT/'build/ios16-gop-provider')
