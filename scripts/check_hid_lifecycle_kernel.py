#!/usr/bin/env python3
"""Execute selected native HID admission/drain with unchanged original init/stop and event bodies."""
import argparse
import gc
import json
from pathlib import Path

from build_native_system import REPORT as KERNEL_REPORT, check_report as check_kernel
from build_hid_lifecycle import REPORT as SOURCE_REPORT, check_report as check_source
from check_hid_original_lifecycle import REPORT as ORIGINAL_REPORT, check_report as check_original
from hid_lifecycle_layout import compile_layout
from hid_lifecycle_model import HidModel, SERVICE_STOP
from check_hid_parser import SLIDE
from native_driver_build import ROOT, require, sha

OUT=ROOT/'build/ios16-hid-lifecycle-kernel'
REPORT=ROOT/'reports/ios16-hid-lifecycle-kernel.json'
METHODS={name:'__ZN19DodgeHidEventDriver'+signature for name,signature in
    (('ctor','C1Ev'),('init','4initEP12OSDictionary'),('start','5startEP9IOService'),('stop','4stopEP9IOService'),
     ('dispatch','13dispatchEventEP10IOHIDEventj'),('free','4freeEv'))}
CASES=('normal','init-parent-failure','init-service-allocation-failure','init-driver-allocation-failure',
    'init-dictionary-failure','free-untouched','stop-before-start','null-provider','wrong-provider','no-loop',
    'bad-geometry','rotated','video-error','start-parent-failure','start-reentrant-stop','start-reentrant-stop-twice',
    'start-failure-reentrant-stop','start-event-stop','dispatch-reentrant-stop','dispatch-reentrant-stop-twice',
    'nested-dispatch-stop','queued-dispatch-stop','stop-parent-reentry','foreign-stop','inactive')


class SourceModel(HidModel):
    def __init__(self,raw,facts,case,*,old=False):
        super().__init__(raw,facts,shift=SLIDE,source=True,case=case)
        self.old=old;self.starts=self.forwards=0;self.triggered=False;self.queued=False
        self.putq(self.provider,self.parent_vptr);self.putq(self.loop,self.names['__ZTV10IOWorkLoop']+16)
        run='__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_'
        self.bind(run,self.run_action)
        self.bind('__ZNK10IOWorkLoop6inGateEv',lambda args:self.returned(args[0]==self.loop and bool(self.gate)))
        self.bind('__ZN10IOWorkLoop17removeEventSourceEP13IOEventSource',self.remove_source)
        self.bind('__ZN8OSObject4freeEv',self.untouched_free)
        start=int(self.contract['classes']['IOHIDEventDriver']['methods'][86]['address'],16)+SLIDE
        self.peers[start]=('original-parent-start-peer',self.parent_start)
        dispatch=int(self.contract['classes']['IOHIDEventService']['methods'][198]['address'],16)+SLIDE
        self.peers[dispatch]=('final-event-service-dispatch-peer',self.forward)
        self.dispatch_action=next(address for name,address in self.names.items() if 'DodgeHidEventDriver14dispatchAction' in name)
        if case=='stop-parent-reentry':
            self.on_native_stop=lambda:self.invoke(self.names[METHODS['stop']],[self.obj,self.provider],lambda rc:self.returned())
        self.call(METHODS['ctor'],[self.obj])
        require(self.qword(self.obj)==self.source_vptr,'Selected HID constructor installed another class')
        require(self.call('_dodge_hid_edge_driver_bytes')==facts['instance_bytes'],'Selected HID allocation extent differs')

    def source_call(self,method,*args):return self.call(METHODS[method],list(args))
    def sequence(self,calls,done):
        if not calls:done();return
        name,args=calls[0];self.invoke(self.names[METHODS[name]],args,lambda rc:self.sequence(calls[1:],done))
    def run_action(self,args):
        require(args[0]==self.loop and args[2]==self.obj,'Selected HID changed workloop/target')
        def enter():
            self.gate+=1
            def finished(rc):self.gate-=1;self.returned(rc)
            self.invoke(args[1],[args[2],*args[3:7]],finished)
        if self.case=='queued-dispatch-stop' and args[1]==self.dispatch_action and not self.queued:
            self.queued=True;self.sequence([('stop',[self.obj,self.provider])],enter)
        else:enter()
    def parent_start(self,args):
        require(args[:2]==[self.obj,self.provider] and (self.old or self.gate),'Selected HID parent start escaped its gate')
        self.starts+=1;self.active_start+=1;calls=[]
        if self.case in ('start-reentrant-stop','start-failure-reentrant-stop','start-reentrant-stop-twice'):
            calls=[('stop',[self.obj,self.provider])]*(2 if self.case=='start-reentrant-stop-twice' else 1)
        if self.case=='start-event-stop':calls=[('dispatch',[self.obj,self.event,0x80000001])]
        def done():
            self.active_start-=1;self.returned(self.case not in ('start-parent-failure','start-failure-reentrant-stop'))
        self.sequence(calls,done)
    def forward(self,args):
        require(args[:3]==[self.obj,self.event,0x80000001] and self.gate,'Original event forwarding ABI/gate changed')
        self.forwards+=1;self.active_dispatch+=1;calls=[]
        if self.case=='nested-dispatch-stop':
            calls=[('dispatch',[self.obj,self.event,0x80000001])] if self.forwards==1 else [('stop',[self.obj,self.provider])]
        elif self.case in ('dispatch-reentrant-stop','dispatch-reentrant-stop-twice','start-event-stop'):
            calls=[('stop',[self.obj,self.provider])]*(2 if self.case=='dispatch-reentrant-stop-twice' else 1)
            calls.append(('dispatch',[self.obj,self.event,0x80000001]))
        def done():self.active_dispatch-=1;self.returned()
        self.sequence(calls,done)
    def untouched_free(self,args):
        require(args[0]==self.obj and not self.value('initAttempted'),'Attempted original HID init entered untouched free')
        self.native_frees+=1;self.returned()


def execute_case(raw,facts,case):
    m=SourceModel(raw,facts,case)
    if case=='free-untouched':
        m.source_call('free',m.obj);require(m.native_frees==1 and not m.typed_calls,'Untouched free entered original private lifecycle')
    else:
        initialized=m.source_call('init',m.obj,0);failed=case.startswith('init-')
        require(initialized==int(not failed) and m.refs[m.obj]==2,'Selected HID init/result pin differs')
        if case=='stop-before-start':m.source_call('stop',m.obj,m.provider)
        started=m.source_call('start',m.obj,0 if case=='null-provider' else m.provider)
        allowed=not failed and case not in ('stop-before-start','null-provider','wrong-provider','no-loop','bad-geometry','rotated',
            'video-error','start-parent-failure','start-reentrant-stop','start-reentrant-stop-twice','start-failure-reentrant-stop','start-event-stop')
        require(started==int(allowed),'Selected HID start result differs: '+case)
        if allowed:
            if case=='foreign-stop':
                foreign=m.heap+0x8000;m.put(foreign,bytes(128));m.putq(foreign,m.parent_vptr)
                m.source_call('stop',m.obj,foreign);require(not m.value('stopRequested'),'Foreign provider stopped selected HID')
            m.source_call('dispatch',m.obj,m.event,0x80000001)
        for _ in range(2):m.source_call('stop',m.obj,m.provider)
        before=m.forwards;m.source_call('dispatch',m.obj,m.event,0x80000001)
        require(m.forwards==before and not m.gate and not m.active_start and not m.active_dispatch,'HID dispatch survived stop or left admitted work')
        require(m.original_stop_calls==m.native_stops==int(bool(m.starts)),'Original HID parent stop was skipped/repeated')
        expected=2 if case=='nested-dispatch-stop' else 0 if case in ('queued-dispatch-stop','inactive') or not allowed else 1
        if case=='start-event-stop':expected=1
        require(m.forwards==expected,'Selected HID event admission count differs')
        if m.forwards:
            p=m.contract['compiler_public_layout'];mask=int.from_bytes(m.read(m.event+0x100+p['mask'],4),'little')
            require(mask==0x802,'Selected lifecycle broke original event accessors or edge annotation')
        m.source_call('free',m.obj);require(not m.native_frees,'Selected HID dropped its partial-lifecycle quarantine')
        require(m.refs[m.obj]==2 and m.refs[m.event]==1,'Selected HID lost its init/event reference')
        require(m.refs[m.provider]==(1 if failed or case in ('stop-before-start','null-provider','wrong-provider') else 2),
            'Selected HID provider ownership differs')
        require(m.refs[m.loop]==(2 if m.qword(m.obj+facts['loop']) else 1),'Selected HID workloop ownership differs')
    m.canaries()
    return {'case':case,'result':'PASS','original_instructions_executed':len(m.original_visits),
        'parent_start_peers':m.starts,'original_parent_stop_calls':m.original_stop_calls,'forwarded_events':m.forwards,
        'retained_init_references':m.refs[m.obj]-1,'retained_provider_references':m.refs[m.provider]-1}


def check_report(report):
    require(report['result']=='IOS16_SELECTED_HID_ORIGINAL_INIT_STOP_AND_DRAIN_CPU_PASS' and len(report['cases'])==len(CASES) and
        report['old_direct_stop_control']['result']=='REJECTED' and not report['hardware_tested'],'Incomplete selected HID CPU evidence')
    for name,digest in {**report['source_sha256'],**report['dependency_report_sha256'],**report['artifacts']}.items():
        require(sha(ROOT/name)==digest,'Selected HID CPU input changed: '+name)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual native HID gate/drain and original init/stop/event bodies');return
    kernel=json.loads(KERNEL_REPORT.read_text());check_kernel(kernel)
    source=json.loads(SOURCE_REPORT.read_text());check_source(source)
    original=json.loads(ORIGINAL_REPORT.read_text());check_original(original);OUT.mkdir(parents=True,exist_ok=True)
    facts,artifacts=compile_layout(OUT/'abi');candidate=ROOT/kernel['candidate'];raw=candidate.read_bytes();cases=[]
    for case in CASES:
        try:cases.append(execute_case(raw,facts,case))
        except Exception as error:raise ValueError('Selected HID '+case+': '+str(error)) from error
        gc.collect()
    old_report=ROOT/'reports/ios16-input-prelink.json';old=json.loads(old_report.read_text());old_candidate=ROOT/old['candidate']
    require(sha(old_candidate)==old['candidate_sha256'],'Old HID control image changed')
    old_layout_report=ROOT/'reports/ios16-hid-edge-kernel.json';old_facts={**facts,**json.loads(old_layout_report.read_text())['compiler_derived_layout']}
    try:
        control=SourceModel(old_candidate.read_bytes(),old_facts,'dispatch-reentrant-stop',old=True)
        require(control.source_call('init',control.obj,0)==1 and control.source_call('start',control.obj,control.provider)==1,'Old HID control could not start')
        control.source_call('dispatch',control.obj,control.event,0x80000001)
    except ValueError as error:
        require(str(error)=='Original parent stop overlapped admitted work','Old HID control failed for another reason: '+str(error))
    else:raise ValueError('Old HID direct stop was accepted during dispatch')
    files=[Path(__file__),ROOT/'scripts/hid_lifecycle_layout.py',ROOT/'scripts/hid_lifecycle_model.py',
        ROOT/'scripts/check_data_mount_kernel.py',ROOT/'scripts/check_hid_parser.py']
    report={'result':'IOS16_SELECTED_HID_ORIGINAL_INIT_STOP_AND_DRAIN_CPU_PASS','compiler_layout':facts,'cases':cases,
        'old_direct_stop_control':{'result':'REJECTED','check':'Original parent stop overlapped admitted work'},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'dependency_report_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            (KERNEL_REPORT,SOURCE_REPORT,ORIGINAL_REPORT,old_report,old_layout_report)},
        'artifacts':{str(p.relative_to(ROOT)):sha(p) for p in [candidate,old_candidate,*artifacts]},
        'original_parent_init_and_stop_are_not_peers':True,'full_original_parent_startup_remains_peer_bound':True,
        'hardware_tested':False,'phone_operations':'none',
        'scope':'Actual selected native constructor/init/start/dispatch/stop/free instructions, unchanged original full '
        'EventDriver/EventService init/stop and event access/default dispatch bodies execute. Reentrant/queued stop '
        'cannot overlap admitted work or repeat parent cleanup. The old compiled source reproduces overlap. '
        'Public IOKit allocation/lock/gate/registry/refcount/video primitives, original full startup and final event '
        'service delivery are explicit peers. This drain covers the source start/dispatch frames; full original producer '
        'callback, matching/client/final-free and physical input lifetime remain unqualified.'}
    check_report(report);REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 25 actual native HID admission/drain paths, full original init/stop and old direct-stop rejection')


if __name__=='__main__':main()
