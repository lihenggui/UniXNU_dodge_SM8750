#!/usr/bin/env python3
"""Build selected HID start/stop serialization while preserving the existing input baseline."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, build_objects, inspect_object, require, sha
from prepare_hid_event_abi import HEADER, methods

OUT=ROOT/'build/ios16-hid-lifecycle'
REPORT=ROOT/'reports/ios16-hid-lifecycle-source.json'
CONTRACT=ROOT/'profiles/os/ios-16.7.16-20H392/hid-lifecycle.json'
CASES=('normal','init-failure','init-repeat','free-untouched','stop-before-start','null-start','wrong-provider','no-loop',
    'bad-geometry','rotated','video-error','start-parent-failure','stop-during-video','start-reentrant-stop',
    'start-reentrant-stop-twice','start-failure-reentrant-stop','start-event-stop','stop-parent-reentry',
    'concurrent-dispatch-stop','concurrent-stops','dispatch-reentrant-stop','dispatch-reentrant-stop-twice',
    'nested-dispatch-stop','foreign-stop','null-stop','inactive','null-event','concurrent-starts','concurrent-start-stop','original-control',
    'cleanup-allocation-failure','cleanup-attach-failure','producer-reentrant-stop','producer-stop-tail',
    'producer-start-stop','producer-nested-dispatch','producer-external-stop','producer-start-failure',
    'interface-stop-control','interface-close-reentry','interface-foreign-client','will-before-start','will-dispatch',
    'will-start','will-parent-failure','will-foreign','did-normal','did-repeat','did-after-stop','did-foreign',
    'did-null-output','did-no-loop','did-cleanup-failure','did-start','did-producer','did-reentrant-notify',
    'did-during-stop','did-caller-lifetime','producer-concurrent-stop','did-during-close','start-busy-interface')


def stage(directory):
    facts=json.loads(CONTRACT.read_text());source=ROOT/facts['source'];patch=ROOT/facts['patch']
    require(sha(source)==facts['before_sha256'] and sha(patch)==facts['patch_sha256'],'HID lifecycle base/patch changed')
    directory.mkdir(parents=True,exist_ok=True);staged=directory/source.name;staged.write_bytes(source.read_bytes())
    result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',patch],cwd=directory,capture_output=True,text=True)
    require(not result.returncode and 'offset' not in result.stdout.lower() and sha(staged)==facts['after_sha256'],
        'Selected HID lifecycle patch is not exact')
    previous=directory/'DodgeHidEventDriver.previous.cpp';previous.write_bytes(staged.read_bytes())
    followup=facts['followup'];next_patch=ROOT/followup['patch']
    require(sha(staged)==followup['before_sha256'] and sha(next_patch)==followup['patch_sha256'],
        'HID producer-drain base/patch changed')
    result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',next_patch],cwd=directory,capture_output=True,text=True)
    require(not result.returncode and 'offset' not in result.stdout.lower() and sha(staged)==followup['after_sha256'],
        'Selected HID producer-drain patch is not exact')
    interface_before=directory/'DodgeHidEventDriver.interface-before.cpp';interface_before.write_bytes(staged.read_bytes())
    terminal=facts['interface_lifecycle'];last_patch=ROOT/terminal['patch']
    require(sha(staged)==terminal['before_sha256'] and sha(last_patch)==terminal['patch_sha256'],
        'HID interface/termination base changed')
    result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',last_patch],cwd=directory,capture_output=True,text=True)
    require(not result.returncode and 'offset' not in result.stdout.lower() and sha(staged)==terminal['after_sha256'],
        'HID interface/termination patch is not exact')
    return staged,source,[patch,next_patch,last_patch]


def host_checks(staged,before,directory):
    directory.mkdir(exist_ok=True);selected=directory/'selected';control=directory/'control'
    selected.mkdir(exist_ok=True);control.mkdir(exist_ok=True)
    include=selected/'HidDriverSource.inc';include.write_bytes(staged.read_bytes())
    old=control/'HidDriverSource.inc';old.write_bytes(before.read_bytes())
    previous=directory/'previous';previous.mkdir(exist_ok=True)
    previous_source=previous/'HidDriverSource.inc';previous_source.write_bytes((staged.parent/'DodgeHidEventDriver.previous.cpp').read_bytes())
    interface=directory/'interface-control';interface.mkdir(exist_ok=True)
    interface_source=interface/'HidDriverSource.inc';interface_source.write_bytes((staged.parent/'DodgeHidEventDriver.interface-before.cpp').read_bytes())
    compiler=shutil.which('clang++-14') or shutil.which('clang++');require(compiler,'Need Clang sanitizers')
    peers=ROOT/'tests/hid_lifecycle_include';test=ROOT/'tests/DodgeHidLifecycleTest.cpp'
    flags=[compiler,'-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined',
        '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-I',peers,'-I',before.parent]
    binaries=[]
    for path in (selected,control,previous,interface):
        binary=path/'hid-lifecycle';run([*flags,'-I',path,test,'-o',binary],path/'compile.log');binaries.append(binary)
    results=[]
    for case in CASES:
        result=subprocess.run([binaries[0],case],capture_output=True,text=True,timeout=15)
        (selected/(case+'.log')).write_text(result.stdout+result.stderr)
        require(not result.returncode and result.stdout==f'PASS: {case}\n','HID lifecycle host case failed: '+case)
        results.append({'case':case,'result':'PASS'})
    bad=subprocess.run([binaries[1],'original-control'],capture_output=True,text=True,timeout=15)
    (control/'old-stop.log').write_text(bad.stdout+bad.stderr)
    require(bad.returncode!=0 and 'parent stop overlapped admitted work' in bad.stderr,
        'Old direct-stop control did not reproduce the dispatch/stop overlap')
    producer=subprocess.run([binaries[2],'producer-reentrant-stop'],capture_output=True,text=True,timeout=15)
    (previous/'producer-stop.log').write_text(producer.stdout+producer.stderr)
    require(producer.returncode!=0 and 'parent stop overlapped original producer' in producer.stderr,
        'Previous source did not reproduce stop inside the outer producer')
    terminal_controls=[]
    for case,reason in [('interface-stop-control','parent stop retained interface callback'),
        ('will-dispatch','termination admitted event dispatch'),('producer-concurrent-stop','parent stop overlapped original producer')]:
        result=subprocess.run([binaries[3],case],capture_output=True,text=True,timeout=15)
        (interface/(case+'.log')).write_text(result.stdout+result.stderr)
        require(result.returncode!=0 and reason in result.stderr,'Old interface control failed for another reason: '+case)
        terminal_controls.append({'case':case,'result':'REJECTED','check':reason})
    return results,[include,old,previous_source,interface_source,*binaries],{'case':'old-direct-stop-during-parent-dispatch','result':'REJECTED',
        'check':'parent stop overlapped admitted work'}, {'result':'REJECTED','check':'parent stop overlapped original producer'},terminal_controls


def check_report(report):
    require(report['result']=='IOS16_SELECTED_HID_LIFECYCLE_SOURCE_PASS' and len(report['host_cases'])==len(CASES) and
        report['old_stop_control']['result']=='REJECTED' and report['previous_producer_control']['result']=='REJECTED' and
        len(report['interface_controls'])==3 and all(c['result']=='REJECTED' for c in report['interface_controls']) and
        report['failed_original_initialization_remains_pinned'] and
        not report['hardware_tested'],'Incomplete selected HID lifecycle checks')
    for name,digest in {**report['source_sha256'],**report['artifacts'],**report['dependency_report_sha256']}.items():
        require(sha(ROOT/name)==digest,'Selected HID lifecycle input changed: '+name)


def main():
    global OUT,REPORT
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--host-only',action='store_true')
    parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if args.host_only:OUT=OUT.with_name(OUT.name+'-host');REPORT=REPORT.with_name(REPORT.stem+'-host.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: selected HID gate, reentrant drain and old stop control');return
    OUT.mkdir(parents=True,exist_ok=True);staged,before,patches=stage(OUT/'source')
    cases,artifacts,control,producer_control,interface_controls=host_checks(staged,before,OUT/'host');native={};dependencies={}
    if not args.host_only:
        obj,=build_objects([staged],OUT/'native',[HEADER.parent,before.parent])
        objcopy=ROOT/'.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
        late=OUT/'DodgeHidEventDriver.late.o'
        subprocess.run([objcopy,'--remove-section=__DATA,__mod_init_func',
            '--globalize-symbol=__GLOBAL__sub_I_DodgeHidEventDriver.cpp',obj,late],check=True)
        def text(path):
            data=path.read_bytes();section=next(s for seg in inspect_object(data)['segments'] for s in seg['sections'] if s['name']=='__text')
            return data[section['fileoff']:section['fileoff']+section['size']]
        require(text(obj)==text(late),'HID lifecycle deferral changed source instructions')
        table=methods(late,'DodgeHidEventDriver',219)
        require([i for i,n in enumerate(table) if '19DodgeHidEventDriver' in n]==[0,1,7,14,21,76,77,86,87,198],
            'Selected HID lifecycle changed the original virtual interface')
        original=ROOT/'build/cph2653-input-native/libDodgeInput.a';digest=sha(original)
        members=subprocess.check_output(['/usr/bin/llvm-ar-14','t',original],text=True).splitlines()
        require(len(members)==len(set(members)) and members.count(late.name)==1 and all(Path(n).name==n for n in members),
            'Ambiguous original input archive')
        directory=OUT/'members';directory.mkdir(exist_ok=True);paths=[];preserved={}
        for name in members:
            path=directory/name
            path.write_bytes(late.read_bytes() if name==late.name else subprocess.check_output(['/usr/bin/llvm-ar-14','p',original,name]))
            paths.append(path)
            if name!=late.name:preserved[name]=sha(path)
        archive=OUT/'libDodgeInputLifecycle.a';archive.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*paths],check=True)
        require(sha(original)==digest,'HID lifecycle build changed the baseline archive')
        native={'archive':str(archive.relative_to(ROOT)),'object':str(obj.relative_to(ROOT)),
            'late_object':str(late.relative_to(ROOT)),'preserved_archive_members':preserved,'concrete_methods':table,
            'concrete_vtable_entries':219,'original_parent_instance_bytes':264}
        artifacts += [obj,late,archive,*paths,OUT/'native/compile-commands.json']
        dependencies={'reports/ios16-input-native.json':sha(ROOT/'reports/ios16-input-native.json')}
    files=[Path(__file__),CONTRACT,HEADER,before,*patches,ROOT/'tests/DodgeHidLifecycleTest.cpp',
        *[p for p in (ROOT/'tests/hid_lifecycle_include').rglob('*.h')],before.with_suffix('.h'),before.parent/'DodgeHidEdgePolicy.h']
    report={'result':'IOS16_SELECTED_HID_LIFECYCLE_SOURCE_PASS',
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'artifacts':{str(p.relative_to(ROOT)):sha(p) for p in [staged,*artifacts]},'dependency_report_sha256':dependencies,
        'host_cases':cases,'old_stop_control':control,'previous_producer_control':producer_control,**native,'native_compiled':not args.host_only,
        'interface_controls':interface_controls,
        'failed_original_initialization_remains_pinned':True,'source_base_and_baseline_artifacts_preserved':True,
        'hardware_tested':False,'phone_operations':'none',
        'scope':'Selected source serializes start, stop and dispatch on the provider workloop. Stop closes admission before '
        'waiting; gate-held stop queues a software interrupt source so parent cleanup runs after the outer gate action. '
        'External stop can complete cleanup first; a stale queued callback cannot repeat it. Source and gated producer '
        'drains defer by default while external stop waits for the gate. willTerminate closes admission before the native '
        'notification; didTerminate copies options, queues completion and never retains caller output pointers. Owned '
        'interfaces close before parent stop; already-closed/foreign ownership delegates termination to the native base '
        'without reentering the original unconditional close. The weak parent interface remains pinned in that path. '
        'frames are covered, while original callbacks which leave/reenter the gate remain unqualified. Failed init '
        'cannot start, duplicate/foreign stops cannot repeat cleanup, and existing partial-init instance/provider/loop pins '
        'remain. Actual patched production source runs with sanitizer IOKit peers and concurrent threads; the old source '
        'reproduces overlapping parent stop. This does not qualify full original parent startup, producer callback/client '
        'lifetime, matching, final free, '
        'physical input or graphical UI.'}
    check_report(report);REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(CASES)} HID source cases; old producer/interface/termination controls rejected')


if __name__=='__main__':main()
