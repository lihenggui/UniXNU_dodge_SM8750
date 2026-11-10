#!/usr/bin/env python3
"""Check the actual public board metal() body with explicit loader/IOKit peers."""
import json
import os
from pathlib import Path
import subprocess

from native_driver_build import ROOT,pinned_sources,require,sha

CASES=('success','loader-failed','symbol-allocation-failed','parent-missing','parent-size-wrong',
    'preModLoad-failed','postModLoad-failed','owned-instance-size-wrong','accelerator-allocation-failed',
    'accelerator-init-failed','plugin-name-property-failed','plugin-class-property-failed','sandbox-property-failed',
    'accelerator-attach-failed','platform-missing')


def check_startup(out,source):
    text=source.read_text();begin=text.index('extern "C" int dodge_gpu_start() {');end=text.index('\nextern "C" int pagani_gpu_status(',begin)
    snippet=out/'PaganiGpuStartup.inc';snippet.write_text(text[begin:end]+'\n')
    test=ROOT/'tests/DodgeGpuStartupTest.cpp';binary=out/'gpu-startup-host'
    subprocess.run(['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie',
        '-pthread','-I',str(out),str(test),'-o',str(binary)],check=True)
    cases=('success','failure','concurrent-success','concurrent-failure','callbacks-success','callbacks-failure')
    for case in cases:
        result=subprocess.run([binary,case],capture_output=True,text=True,timeout=30,
            env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'})
        require(result.returncode==0,'GPU startup one-shot case failed: '+case+'\n'+result.stdout+result.stderr)
    print('PASS: 6 actual board startup entry sanitizer cases, including 16-way races; hardware/logging peers')
    return {'result':'PASS','case_count':len(cases),'cases':[{'case':name,'result':'PASS'} for name in cases],
        'host_binary':str(binary.relative_to(ROOT)),'host_binary_sha256':sha(binary),
        'snippet':str(snippet.relative_to(ROOT)),'snippet_sha256':sha(snippet),'concurrent_callers':16,
        'hardware_and_logging_are_peers':True}


def check(out,source):
    body=source.read_text();start=body.index('int metal() {');end=body.index('\nint start() {',start)
    snippet=out/'PaganiGpuMetal.inc';snippet.write_text(body[start:end]+'\n')
    compiler=Path('/usr/bin/g++');require(compiler.is_file(),'Need g++ for sanitized board checks')
    test=ROOT/'tests/DodgeGpuMetalRegistrationTest.cpp';binary=out/'gpu-metal-registration-host'
    command=[str(compiler),'-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fno-omit-frame-pointer','-fno-pie','-no-pie',
        '-fsanitize=address,undefined','-I',str(out),str(test),'-o',str(binary)]
    subprocess.run(command,check=True)
    env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'}
    for index,name in enumerate(CASES):
        result=subprocess.run([binary,str(index)],capture_output=True,text=True,env=env)
        require(result.returncode==0,'Board metal registration case failed: '+name+'\n'+result.stdout+result.stderr)
    startup=check_startup(out,source)
    report={'result':'PASS','case_count':len(CASES),'cases':[{'case':name,'result':'PASS'} for name in CASES],'startup_tests':startup,
        'actual_staged_board_metal_body_sha256':sha(snippet),'actual_staged_board_source_sha256':sha(source),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),test,ROOT/'tests/DodgeGpuStartupTest.cpp')},
        'host_binary':str(binary.relative_to(ROOT)),'host_binary_sha256':sha(binary),
        'snippet':str(snippet.relative_to(ROOT)),'snippet_sha256':sha(snippet),
        'loader_metadata_accelerator_and_registry_are_peers':True,'real_iokit_or_gpu_execution':False}
    (out/'metal-registration-host-cases.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(CASES)} actual board metal registration/cleanup sanitizer cases with explicit loader/IOKit peers')
    return report


def main():
    reference=pinned_sources(('oneplus13t_reference',))['oneplus13t_reference']
    lock=json.loads((ROOT/'upstream.lock.json').read_text());spec=lock['dodge_gpu_board_patch'];patch=ROOT/spec['path']
    require(sha(patch)==spec['sha256'] and spec['source_revision']==lock['oneplus13t_reference']['revision'],
        'Board overlay does not match its pinned reference')
    out=ROOT/'build/cph2653-gpu-metal-host';stage=out/'source';stage.mkdir(parents=True,exist_ok=True)
    source=stage/'PaganiGpu.cpp';source.write_bytes((reference/'package/PaganiGpu.cpp').read_bytes())
    subprocess.run(['git','apply','--check','--directory='+str(stage.relative_to(ROOT)),str(patch)],cwd=ROOT,check=True)
    subprocess.run(['git','apply','--directory='+str(stage.relative_to(ROOT)),str(patch)],cwd=ROOT,check=True)
    check(out,source)


if __name__=='__main__':main()
