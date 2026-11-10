#!/usr/bin/env python3
"""Sanitize the lifecycle observer, owned acquisition and actual page adapter."""
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def run(out):
    out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'drivers/DodgeGpu/DodgeSurfaceBacking.cpp';test=ROOT/'tests/DodgeSurfaceAcquireTest.cpp'
    pages=ROOT/'drivers/DodgeGpu/DodgeSurfacePages.cpp'
    flags=['/usr/bin/g++','-std=c++17','-pthread','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
        '-fno-pie','-no-pie','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',
        '-I',ROOT/'tests/surface_acquire_include','-I',ROOT/'tests/surface_pages_include','-I',source.parent,
        '-I',ROOT/'profiles/os/ios-16.7.16-20H392/graphics']
    env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1',UBSAN_OPTIONS='halt_on_error=1')
    binary=out/'acquire-test';subprocess.run([*flags,test,source,pages,'-o',binary],check=True)
    process=subprocess.run([binary],env=env,capture_output=True,text=True,timeout=45)
    log=out/'acquire-tests.log';log.write_text(process.stdout+process.stderr)
    if process.returncode or 'PASS: 25 actual surface observer/acquisition cases' not in process.stdout:
        raise ValueError('Surface ownership sanitizer cases failed: '+str(log))
    controls=[];body=source.read_text()
    for name,before,after in (
        ('unowned-init-descriptor-stored','if(backing)backing->retain();\n        observe(surface,backing);','observe(surface,backing);'),
        ('copy-does-not-retain','{backing=entry->backing;backing->retain();}','{backing=entry->backing;}'),
        ('final-free-does-not-forget','forget(surface);dodge_original_surface_free(surface);','dodge_original_surface_free(surface);'),
        ('stale-descriptor-accepted','if(native_iphone_surface_memory(identity->surface)!=backing)',
         'if(native_iphone_surface_memory(identity->surface)==nullptr && backing==nullptr)'),
        ('registry-limit-ignored','fresh && entryCount<maxEntries','fresh && (entryCount<maxEntries || maxEntries)'),
        ('identity-failure-cleanup-lost','dodge_release_surface_identity(&identity);','(void)identity;'),
    ):
        if body.count(before)!=1:raise ValueError('Surface ownership mutation site changed: '+name)
        changed=out/(name+'.cpp');changed.write_text(body.replace(before,after));exe=out/name
        subprocess.run([*flags,test,changed,pages,'-o',exe],check=True)
        result=subprocess.run([exe],env=env,capture_output=True,text=True,timeout=45)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode==0:raise ValueError('Surface ownership checker accepted source defect: '+name)
        controls.append({'case':name,'result':'REJECTED'})
    return {'cases':25,'source_controls':controls,'sanitizers':['address','undefined','leak'],
        'lock_original_descriptor_and_identity_primitives_are_host_peers':True,'artifacts':[binary,log]}


if __name__=='__main__':print(run(ROOT/'build/cph2653-surface-acquire/host'))
