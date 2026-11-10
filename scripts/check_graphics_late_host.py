#!/usr/bin/env python3
"""Exercise actual opt-in late scheduling and the staged IOBSD hook with peers."""
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CASES=('success','flag-absent','flag-zero','flag-other','thread-failure','thread-failure-retry','eager-worker','platform-missing',
       'platform-inactive','root-delay','busy-delay','root-timeout','unsupported','latched-failure','hardware-failure','hardware-busy',
       'null-display','display-with-error','reentry-queue','reentry-deallocate','reentry-boot','reentry-sleep','reentry-terminate','concurrent-queue')


def check(out,patched):
    out.mkdir(parents=True,exist_ok=True);binary=out/'graphics-late-host'
    text=patched.read_text();start=text.index('kern_return_t\nIOKitBSDInit( void )\n{');end=text.index('\n}\n',start)+3
    body=text[start:end]
    if body.count('IOService::publishResource("IOBSD");\n\t(void)dodge_graphics_schedule();')!=1:
        raise ValueError('Staged real IOBSD hook does not publish before scheduling')
    extract=out/'IOKitBSDInit.extracted.cpp'
    extract.write_text('#include "DodgeGraphicsLate.h"\n#include <kern/thread.h>\n#define IOPOLLED_COREFILE 0\n'+body+'\n')
    command=['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-pthread',
             '-I',ROOT/'tests/graphics_late_include','-I',ROOT/'drivers/DodgeDisplay',ROOT/'tests/DodgeGraphicsLateTest.cpp',
             ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.cpp',extract,'-o',binary]
    subprocess.run(command,check=True);results=[];logs=[]
    for case in CASES:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
                              env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        logs.append(case+'\n'+result.stdout+result.stderr);(out/'late-host-tests.log').write_text('\n'.join(logs))
        if result.returncode:raise RuntimeError('Late graphics sanitizer failure: '+case+'; see '+str(out/'late-host-tests.log'))
        item=json.loads(result.stdout)
        if item['case']!=case or item['result']!='PASS':raise ValueError('Invalid late scheduling case record')
        results.append(item)
    print(f'PASS: {len(results)} actual IOBSD hook/late-worker sanitizer cases; kernel thread/boot/IOKit are peers')
    return {'result':'PASS','case_count':len(results),'cases':results,'kernel_thread_boot_and_iokit_are_peers':True,
            'actual_staged_iobsd_function_extracted':True,'polled_corefile_branch_executed':False,'hardware_tested':False}


if __name__=='__main__':
    import argparse
    from graphics_late_overlay import stage
    parser=argparse.ArgumentParser();parser.add_argument('--reference-source',action='store_true');args=parser.parse_args()
    out=ROOT/('build/ios16-graphics-late-public' if args.reference_source else 'build/ios16-graphics-late')
    patched,_=stage(out,reference_only=args.reference_source);check(out,patched)
