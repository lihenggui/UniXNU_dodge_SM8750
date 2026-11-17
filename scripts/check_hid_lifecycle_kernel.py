#!/usr/bin/env python3
"""Execute selected native HID admission/drain with unchanged original init/stop and event bodies."""
import argparse
import gc
import json
from pathlib import Path
import struct

from build_native_system import REPORT as KERNEL_REPORT, check_report as check_kernel
from build_hid_lifecycle import REPORT as SOURCE_REPORT, CONTRACT, check_report as check_source
from check_hid_original_lifecycle import REPORT as ORIGINAL_REPORT, check_report as check_original
from check_hid_interface_kernel import REPORT as INTERFACE_REPORT, check_report as check_interface
from hid_lifecycle_layout import compile_layout
from hid_lifecycle_model import HidModel, SERVICE_STOP, branch
from hid_interface_model import InterfacePeers
from check_hid_parser import SLIDE
from native_driver_build import ROOT, require, sha

OUT=ROOT/'build/ios16-hid-lifecycle-kernel'
REPORT=ROOT/'reports/ios16-hid-lifecycle-kernel.json'
METHODS={name:'__ZN19DodgeHidEventDriver'+signature for name,signature in
    (('ctor','C1Ev'),('init','4initEP12OSDictionary'),('start','5startEP9IOService'),('stop','4stopEP9IOService'),
     ('dispatch','13dispatchEventEP10IOHIDEventj'),('free','4freeEv'),
     ('will','13willTerminateEP9IOServicej'),('did','12didTerminateEP9IOServicejPb'))}
CASES=('normal','init-parent-failure','init-service-allocation-failure','init-driver-allocation-failure',
    'init-dictionary-failure','free-untouched','stop-before-start','null-provider','wrong-provider','no-loop',
    'bad-geometry','rotated','video-error','start-parent-failure','start-reentrant-stop','start-reentrant-stop-twice',
    'start-failure-reentrant-stop','start-event-stop','dispatch-reentrant-stop','dispatch-reentrant-stop-twice',
    'nested-dispatch-stop','queued-dispatch-stop','stop-parent-reentry','foreign-stop','inactive',
    'cleanup-allocation-failure','cleanup-attach-failure','producer-reentrant-stop','producer-stop-tail',
    'producer-start-stop','producer-nested-dispatch','producer-external-stop','original-producer-stop',
    'original-producer-stop-twice','original-producer-external-stop','original-producer-not-ready','original-producer-wrong-type',
    'original-producer-tail-stop','producer-start-failure','interface-close-reentry','interface-foreign-client',
    'interface-owner-failure','will-before-start','will-start','will-dispatch','will-parent-failure','will-foreign',
    'did-normal','did-repeat','did-after-stop','did-foreign','did-null-output','did-no-loop','did-cleanup-failure',
    'did-start','did-producer','did-reentrant-notify','did-during-stop','did-during-close','did-caller-output',
    'did-original-producer','did-original-after-stop','producer-concurrent-stop','start-busy-interface')


class SourceModel(InterfacePeers,HidModel):
    def __init__(self,raw,facts,case,*,old=False):
        super().__init__(raw,facts,shift=SLIDE,source=True,case=case)
        self.old=old;self.starts=self.forwards=0;self.triggered=False;self.queued=False
        self.cleanup_source=self.cleanup_action=self.cleanup_pending=self.cleanup_signals=self.cleanup_callbacks=0
        self.simulating_external=False;self.external_stop_context=None
        self.term_output=self.heap+0xe000;self.put(self.term_output,bytes(128))
        self.putq(self.provider,self.parent_vptr);self.putq(self.loop,self.names['__ZTV10IOWorkLoop']+16)
        run='__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_'
        self.bind(run,self.run_action)
        self.bind('__ZNK10IOWorkLoop6inGateEv',lambda args:self.returned(args[0]==self.loop and bool(self.gate) and not self.simulating_external))
        self.bind('__ZN10IOWorkLoop17removeEventSourceEP13IOEventSource',self.remove_source)
        self.bind('__ZN10IOWorkLoop14addEventSourceEP13IOEventSource',self.add_cleanup)
        self.bind('__ZN22IOInterruptEventSource20interruptEventSourceEP8OSObjectPFvS1_PS_iEP9IOServicei',self.create_cleanup)
        self.bind('__ZN22IOInterruptEventSource17interruptOccurredEPvP9IOServicei',self.signal_cleanup)
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
        self.setup_interface(self.provider,self.obj)
        if case=='interface-owner-failure':self.interface_fail_open=self.interface_owner
        if case=='start-busy-interface':
            foreign=self.resource('already-open-client')
            require(self.call('_interface_open',[self.provider,foreign,0,0x12345678,0x99])==1,'Could not prepare busy interface')
        if old:
            for method,slot in (('will',76),('did',77)):
                if METHODS[method] not in self.names:self.names[METHODS[method]]=self.qword(self.source_vptr+slot*8)

    def source_call(self,method,*args):return self.call(METHODS[method],list(args))
    def request_termination(self,options=0xa5000002,*,provider=None,output=None):
        output=self.term_output if output is None else output
        self.put(output-16,b'\xa5'*33);self.put(output,b'\0')
        requested=self.provider if provider is None else provider;opened=(requested,self.obj) in self.interface_opened
        result=self.source_call('did',self.obj,requested,options,output)
        require(self.read(output-16,16)==self.read(output+1,16)==b'\xa5'*16,'Termination overwrote caller output bounds')
        deferred=self.read(output,1)[0]
        require(not opened or not deferred,'Termination requested extra deferral despite an open connection')
        return result,int(bool(deferred or opened))
    def resume_external_stop(self):
        require(self.external_stop_context is not None and not self.gate and not self.active_producer,'No blocked guest stop to resume')
        self.cpu.context_restore(self.external_stop_context)
        self.cpu.emu_start(self.cpu.reg_read(self.arm.UC_ARM64_REG_PC),self.stop,count=200000)
        require(self.cpu.reg_read(self.arm.UC_ARM64_REG_PC)==self.stop,'Blocked guest stop did not finish')
    def create_cleanup(self,args):
        require(args[0]==self.obj and args[2:4]==[0,0] and self.gate,'HID cleanup source is not a software event')
        self.cleanup_action=args[1]
        if self.case in ('cleanup-allocation-failure','did-cleanup-failure'):self.returned();return
        self.cleanup_source=self.resource('source-cleanup-event')
        self.putq(self.cleanup_source,self.names['__ZTV22IOInterruptEventSource']+16);self.returned(self.cleanup_source)
    def add_cleanup(self,args):
        require(args[:2]==[self.loop,self.cleanup_source] and self.gate,'HID cleanup source escaped its loop')
        if self.case=='cleanup-attach-failure':self.returned(0xe00002bd);return
        self.refs[self.cleanup_source]+=1;self.returned()
    def signal_cleanup(self,args):
        require(args[:4]==[self.cleanup_source,0,0,0] and self.gate,'HID cleanup signal changed')
        self.cleanup_signals+=1;self.cleanup_pending+=1;self.returned()
    def drain_cleanup(self):
        require(not self.gate and not self.active_producer,'HID cleanup entered an active producer action')
        if not self.cleanup_pending:return
        count=self.cleanup_pending;self.cleanup_pending=0;self.cleanup_callbacks+=1
        self.names['_cleanup_callback']=self.cleanup_action;self.gate+=1
        self.call('_cleanup_callback',[self.obj,self.cleanup_source,count]);self.gate-=1
    def producer(self,method='dispatch'):
        self.gate+=1;self.active_producer+=1
        if method=='start':result=self.source_call('start',self.obj,self.provider);require(not result,'Reentrant startup stop was accepted')
        else:self.source_call('dispatch',self.obj,self.event,0x80000001)
        if self.case=='producer-stop-tail':self.source_call('stop',self.obj,self.provider)
        require(not self.original_stop_calls,'Parent stop ran before original producer returned')
        self.source_call('stop',self.obj,self.provider)
        require(not self.original_stop_calls,'Repeated stop ran inside original producer')
        self.active_producer-=1;self.gate-=1
    def original_producer(self):
        stops_before=self.original_stop_calls
        entry=int(self.contract['classes']['IOHIDEventDriver']['methods'][218]['address'],16)
        require(entry==0xfffffff0057444e8,'Original interrupt-report entry changed')
        ready=branch(self.original_read,entry+0x28)
        load,ret=struct.unpack('<2I',self.original_read(ready,8))
        require(load&0xffc003ff==0x39400000 and ret==0xd65f03c0,'Original report admission no longer loads its own byte')
        ready_offset=(load>>10)&4095
        self.put(self.obj+ready_offset,bytes([self.case!='original-producer-not-ready']))
        clock=branch(self.original_read,entry+0x34)+SLIDE
        def clock_peer(args):
            self.triggered=True
            calls=[('dispatch',[self.obj,self.event,0x80000001])]
            if self.case=='original-producer-tail-stop':calls.append(('stop',[self.obj,self.provider]))
            self.sequence(calls,lambda:self.returned(0x12345678))
        self.peers[clock]=('public-continuous-clock-reentrant-stop',clock_peer)
        self.names['_original_report_callback']=self.interface['handle_report']+SLIDE
        require(entry+SLIDE not in self.peers and ready+SLIDE not in self.peers,'Original producer body or readiness is a peer')
        self.gate+=1;self.active_producer+=1
        self.call('_original_report_callback',[self.provider,0x12345678,self.event,1 if self.case=='original-producer-wrong-type' else 0,1,0])
        require(self.original_stop_calls==stops_before,'Parent stop ran inside unchanged original report callback')
        self.active_producer-=1;self.gate-=1
        return {'address':hex(entry),'bytes':0x1d8,'interface_report_entry':hex(self.interface['handle_report']),
            'callback_entered':entry+SLIDE in self.original_visits,'ready_offset':ready_offset,
            'clock_boundary_reentered_source':self.triggered,'original_body_and_subhandlers_are_not_peers':True}
    def sequence(self,calls,done):
        if not calls:done();return
        name,args=calls[0];self.invoke(self.names[METHODS[name]],args,lambda rc:self.sequence(calls[1:],done))
    def run_action(self,args):
        require(args[0]==self.loop and args[2]==self.obj,'Selected HID changed workloop/target')
        if self.simulating_external:
            require(self.value('stopRequested') and not self.value('ready') and self.gate,
                'Blocked guest stop did not close admission before waiting')
            self.external_stop_context=self.cpu.context_save();self.simulating_external=False
            self.cpu.context_restore(self.producer_forward_context);self.active_dispatch-=1;self.returned();return
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
        if self.case in ('start-reentrant-stop','start-failure-reentrant-stop','start-reentrant-stop-twice','producer-start-stop'):
            calls=[('stop',[self.obj,self.provider])]*(2 if self.case=='start-reentrant-stop-twice' else 1)
        if self.case=='start-event-stop':calls=[('dispatch',[self.obj,self.event,0x80000001])]
        if self.case=='will-start':calls=[('will',[self.obj,self.provider,0xa5000001])]
        if self.case=='did-start':calls=[('did',[self.obj,self.provider,0xa5000002,self.term_output])]
        self.putq(self.obj+self.interface['driver_interface'],self.provider)
        def opened(result):
            def done():
                self.active_start-=1;self.returned(bool(result) and self.case not in ('start-parent-failure','start-failure-reentrant-stop','producer-start-failure'))
            self.sequence(calls,done)
        self.invoke(self.interface['open']+SLIDE,[self.provider,self.obj,0,
            int(self.contract['classes']['IOHIDEventDriver']['methods'][218]['address'],16)+SLIDE,0],opened)

    def native_stop(self,args):
        require((self.provider,self.obj) not in self.interface_opened,'Original interface remained open during parent stop')
        super().native_stop(args)
    def forward(self,args):
        require(args[:3]==[self.obj,self.event,0x80000001] and self.gate,'Original event forwarding ABI/gate changed')
        self.forwards+=1;self.active_dispatch+=1;calls=[]
        if self.case=='producer-concurrent-stop':
            self.producer_forward_context=self.cpu.context_save();self.simulating_external=True
            self.cpu.reg_write(self.arm.UC_ARM64_REG_SP,self.stack+0x40000)
            self.cpu.reg_write(self.arm.UC_ARM64_REG_LR,self.stop)
            self.cpu.reg_write(self.arm.UC_ARM64_REG_X0,self.obj);self.cpu.reg_write(self.arm.UC_ARM64_REG_X1,self.provider)
            self.cpu.reg_write(self.arm.UC_ARM64_REG_PC,self.names[METHODS['stop']]);return
        if self.case in ('nested-dispatch-stop','producer-nested-dispatch'):
            calls=[('dispatch',[self.obj,self.event,0x80000001])] if self.forwards==1 else [('stop',[self.obj,self.provider])]
        elif self.case in ('dispatch-reentrant-stop','dispatch-reentrant-stop-twice','start-event-stop','producer-reentrant-stop','producer-external-stop',
            'original-producer-stop','original-producer-stop-twice','original-producer-external-stop'):
            calls=[('stop',[self.obj,self.provider])]*(2 if self.case in ('dispatch-reentrant-stop-twice','original-producer-stop-twice') else 1)
            calls.append(('dispatch',[self.obj,self.event,0x80000001]))
        if self.case=='will-dispatch':calls=[('will',[self.obj,self.provider,0xa5000001])]
        if self.case in ('did-producer','did-original-producer'):
            calls=[('did',[self.obj,self.provider,0xa5000002,self.term_output])]
        def done():self.active_dispatch-=1;self.returned()
        self.sequence(calls,done)
    def untouched_free(self,args):
        require(args[0]==self.obj and not self.value('initAttempted'),'Attempted original HID init entered untouched free')
        self.native_frees+=1;self.returned()


def execute_producer(raw,facts,case,*,legacy=False):
    m=SourceModel(raw,facts,case,old=legacy)
    require(m.source_call('init',m.obj,0)==1,'Producer fixture original init failed')
    callback={}
    if case in ('producer-start-stop','producer-start-failure'):m.producer('start')
    else:
        require(m.source_call('start',m.obj,m.provider)==1,'Producer fixture source did not start')
        if case.startswith('original-') or case=='producer-concurrent-stop':callback=m.original_producer()
        else:m.producer()
    if case=='producer-concurrent-stop':m.resume_external_stop()
    if case in ('producer-external-stop','original-producer-external-stop','original-producer-not-ready','original-producer-wrong-type'):
        m.source_call('stop',m.obj,m.provider);require(m.original_stop_calls==1,'External stop did not finish pending cleanup')
    m.drain_cleanup();require(m.original_stop_calls==m.native_stops==1,'Deferred producer cleanup skipped/repeated parent stop')
    for _ in range(2):m.source_call('stop',m.obj,m.provider);m.drain_cleanup()
    count=m.forwards;m.source_call('dispatch',m.obj,m.event,0x80000001)
    require(count==m.forwards and not m.gate and not m.active_producer,'Source admitted work after producer stop')
    m.source_call('free',m.obj);m.canaries();require(not m.native_frees,'Producer drain removed final-free quarantine')
    m.interface_canaries()
    queued=case not in ('original-producer-not-ready','original-producer-wrong-type')
    require(m.cleanup_signals==m.cleanup_callbacks==int(queued),'Producer cleanup did not coalesce into one software event')
    return {'case':case,'result':'PASS','original_instructions_executed':len(m.original_visits),
        'original_parent_stop_calls':m.original_stop_calls,'software_cleanup_signals':m.cleanup_signals,
        'software_cleanup_callbacks':m.cleanup_callbacks,'forwarded_events':m.forwards,**({'original_report_callback':callback} if callback else {})}


def execute_termination(raw,facts,case,*,legacy=False):
    m=SourceModel(raw,facts,case,old=legacy);options=0xa5000002;callback={}
    require(m.source_call('init',m.obj,0)==1,'Termination fixture original init failed')
    if case=='will-before-start':
        require(m.source_call('will',m.obj,m.provider,0xa5000001)==1 and m.source_call('start',m.obj,m.provider)==0,
            'willTerminate did not close startup admission')
    elif case=='start-busy-interface':
        before=m.interface_callbacks()
        require(m.source_call('start',m.obj,m.provider)==0 and not m.starts,'Busy interface entered original parent startup')
        m.source_call('stop',m.obj,m.provider);require(m.request_termination()==(1,1),'Busy-interface termination failed')
        m.drain_cleanup()
        require(m.interface_callbacks()==before and not m.interface_close_calls,'Busy interface callback was replaced/closed')
    elif case=='did-no-loop':
        require(m.request_termination()==(1,0) and m.source_call('start',m.obj,m.provider)==0,'Pre-start termination changed native deferral')
    else:
        started=m.source_call('start',m.obj,m.provider)
        expected=case not in ('will-start','did-start','did-cleanup-failure','interface-owner-failure')
        require(started==int(expected),'Termination fixture startup result differs: '+case)
        m.drain_cleanup()
        foreign=m.resource('foreign-client')
        if case=='interface-close-reentry':
            m.interface_on_owner_close=lambda:m.invoke(m.names[METHODS['stop']],[m.obj,m.provider],lambda rc:m.returned())
            m.source_call('stop',m.obj,m.provider);m.drain_cleanup()
        elif case=='interface-foreign-client':
            m.call('_interface_close',[m.provider,m.obj,0])
            require(m.call('_interface_open',[m.provider,foreign,0,0x12345678,0x99])==1,'Foreign fixture could not open its own session')
            before=m.interface_callbacks();m.source_call('stop',m.obj,m.provider)
            require(m.request_termination()==(1,1),'Closed interface termination was not deferred')
            m.drain_cleanup()
            require((m.provider,foreign) in m.interface_opened and m.interface_callbacks()==before and m.interface_close_calls==1,
                'Stopping/terminating source destroyed another interface client')
        elif case=='interface-owner-failure':
            require(not m.interface_callbacks()[0] and not m.interface_opened,'Failed owner open retained callback ownership')
        elif case.startswith('will-'):
            if case=='will-dispatch':m.source_call('dispatch',m.obj,m.event,0x80000001)
            elif case!='will-start':
                result=m.source_call('will',m.obj,foreign if case=='will-foreign' else m.provider,0xa5000001)
                require(result==int(case not in ('will-foreign','will-parent-failure')),'willTerminate changed parent result')
            before=m.forwards;m.source_call('dispatch',m.obj,m.event,0x80000001)
            require(m.forwards==before+int(case=='will-foreign'),'willTerminate admitted event dispatch or stopped a foreign provider')
            m.source_call('stop',m.obj,m.provider);m.drain_cleanup()
        elif case in ('did-foreign','did-null-output'):
            if case=='did-foreign':require(m.request_termination(provider=foreign)==(0,0),'Foreign termination was accepted')
            else:require(m.source_call('did',m.obj,m.provider,options,0)==0,'Null termination output was accepted')
            require(not m.interface_termination_calls,'Rejected termination notified native base')
            m.source_call('dispatch',m.obj,m.event,0x80000001);require(m.forwards==1,'Rejected termination closed valid event admission')
            m.source_call('stop',m.obj,m.provider)
        elif case=='did-start':
            require(len(m.interface_termination_calls)==1 and m.interface_termination_calls[0]['options']==options and
                m.read(m.term_output,1)==b'\x00','Startup termination lost notification/options/output')
        else:
            if case in ('did-after-stop','did-original-after-stop'):m.source_call('stop',m.obj,m.provider)
            if case=='did-reentrant-notify':
                m.interface_on_did=lambda:m.invoke(m.names[METHODS['did']],[m.obj,m.provider,0xffffffff,m.term_output+64],lambda rc:m.returned(1))
            if case in ('did-during-stop','did-during-close'):
                request=lambda:m.invoke(m.names[METHODS['did']],[m.obj,m.provider,options,m.term_output],lambda rc:m.returned())
                if case=='did-during-stop':m.on_native_stop=request
                else:m.interface_on_owner_close=request
                m.source_call('stop',m.obj,m.provider)
            elif case=='did-producer':m.producer()
            elif case=='did-original-producer':callback=m.original_producer()
            else:
                require(m.request_termination()==(1,int(case!='did-cleanup-failure')),'Termination request result/output differs')
                if case=='did-repeat':require(m.request_termination(options+1)==(1,1),'Repeated pending termination was refused')
                if case=='did-caller-output':m.put(m.term_output,b'\x7d')
            m.drain_cleanup()
            require(len(m.interface_termination_calls)==1 and m.interface_termination_calls[0]['options']==options and
                not m.interface_termination_calls[0]['defer_on_entry'],'Native completion changed latched options/local deferral')
            if case=='did-caller-output':require(m.read(m.term_output,1)==b'\x7d','Deferred completion retained caller output pointer')
            if case=='did-original-after-stop':
                callback=m.original_producer();require(not callback['callback_entered'],'Closed original interface delivered another report')
            if case=='did-repeat':
                require(m.request_termination(options+2)==(1,1),'Later termination notification was refused')
                m.drain_cleanup();require(len(m.interface_termination_calls)==2 and m.interface_close_calls==1,'Later notification closed the interface twice')
    m.drain_cleanup();m.source_call('stop',m.obj,m.provider);m.drain_cleanup()
    if case.startswith('will-'):
        require(len(m.interface_will_calls)==int(case!='will-foreign'),'willTerminate skipped/repeated native notification')
    no_parent=case in ('will-before-start','did-no-loop','did-cleanup-failure','start-busy-interface')
    require(m.original_stop_calls==int(not no_parent),'Termination repeated/skipped parent stop')
    if case not in ('did-foreign','did-null-output'):require(m.value('stopRequested') and not m.value('ready'),'Termination admission stayed open')
    require((m.provider,m.obj) not in m.interface_opened,'Terminated source retained its interface open')
    m.source_call('free',m.obj);m.canaries();m.interface_canaries();require(not m.native_frees,'Termination removed lifetime quarantine')
    return {'case':case,'result':'PASS','original_instructions_executed':len(m.original_visits),
        'original_interface_close_calls':m.interface_close_calls,'original_parent_stop_calls':m.original_stop_calls,
        'native_will_notifications':len(m.interface_will_calls),'native_did_notifications':len(m.interface_termination_calls),
        'software_cleanup_signals':m.cleanup_signals,**({'original_report_callback':callback} if callback else {})}


def execute_case(raw,facts,case):
    if case.startswith(('will-','did-','interface-')) or case=='start-busy-interface':return execute_termination(raw,facts,case)
    if case.startswith(('producer-','original-producer-')):return execute_producer(raw,facts,case)
    m=SourceModel(raw,facts,case)
    if case=='free-untouched':
        m.source_call('free',m.obj);require(m.native_frees==1 and not m.typed_calls,'Untouched free entered original private lifecycle')
    else:
        initialized=m.source_call('init',m.obj,0);failed=case.startswith('init-')
        require(initialized==int(not failed) and m.refs[m.obj]==2,'Selected HID init/result pin differs')
        if case=='stop-before-start':m.source_call('stop',m.obj,m.provider)
        started=m.source_call('start',m.obj,0 if case=='null-provider' else m.provider)
        m.drain_cleanup()
        allowed=not failed and case not in ('stop-before-start','null-provider','wrong-provider','no-loop','bad-geometry','rotated',
            'video-error','start-parent-failure','start-reentrant-stop','start-reentrant-stop-twice','start-failure-reentrant-stop','start-event-stop',
            'cleanup-allocation-failure','cleanup-attach-failure','producer-start-stop')
        require(started==int(allowed),'Selected HID start result differs: '+case)
        if allowed:
            if case=='foreign-stop':
                foreign=m.heap+0x8000;m.put(foreign,bytes(128));m.putq(foreign,m.parent_vptr)
                m.source_call('stop',m.obj,foreign);require(not m.value('stopRequested'),'Foreign provider stopped selected HID')
            m.source_call('dispatch',m.obj,m.event,0x80000001)
        for _ in range(2):m.source_call('stop',m.obj,m.provider)
        m.drain_cleanup()
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
    m.interface_canaries()
    return {'case':case,'result':'PASS','original_instructions_executed':len(m.original_visits),
        'parent_start_peers':m.starts,'original_parent_stop_calls':m.original_stop_calls,'forwarded_events':m.forwards,
        'retained_init_references':m.refs[m.obj]-1,'retained_provider_references':m.refs[m.provider]-1}


def check_report(report):
    require(report['result']=='IOS16_SELECTED_HID_ORIGINAL_INIT_STOP_AND_DRAIN_CPU_PASS' and len(report['cases'])==len(CASES) and
        report['old_direct_stop_control']['result']=='REJECTED' and report['old_producer_control']['result']=='REJECTED' and
        len(report['old_interface_controls'])==3 and all(c['result']=='REJECTED' for c in report['old_interface_controls']) and
        not report['hardware_tested'],'Incomplete selected HID CPU evidence')
    for name,digest in {**report['source_sha256'],**report['dependency_report_sha256'],**report['artifacts']}.items():
        require(sha(ROOT/name)==digest,'Selected HID CPU input changed: '+name)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual native HID gate/drain and original init/stop/event bodies');return
    kernel=json.loads(KERNEL_REPORT.read_text());check_kernel(kernel)
    source=json.loads(SOURCE_REPORT.read_text());check_source(source)
    original=json.loads(ORIGINAL_REPORT.read_text());check_original(original);OUT.mkdir(parents=True,exist_ok=True)
    check_interface(json.loads(INTERFACE_REPORT.read_text()))
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
    try:execute_producer(old_candidate.read_bytes(),old_facts,'original-producer-tail-stop',legacy=True)
    except ValueError as error:
        require(str(error)=='Original parent stop overlapped original producer','Old producer control failed for another reason: '+str(error))
    else:raise ValueError('Old direct stop was accepted inside original producer')
    interface_controls=[]
    for case,reason in [('interface-close-reentry','Original interface remained open during parent stop'),
        ('did-original-producer','Interface close overlapped an admitted producer'),
        ('will-dispatch','willTerminate admitted event dispatch or stopped a foreign provider')]:
        try:execute_termination(old_candidate.read_bytes(),old_facts,case,legacy=True)
        except ValueError as error:require(str(error)==reason,'Old interface control failed for another reason: '+str(error))
        else:raise ValueError('Old interface/termination control was accepted: '+case)
        interface_controls.append({'case':case,'result':'REJECTED','check':reason})
    files=[Path(__file__),ROOT/'scripts/hid_lifecycle_layout.py',ROOT/'scripts/hid_lifecycle_model.py',
        ROOT/'scripts/check_data_mount_kernel.py',ROOT/'scripts/check_hid_parser.py',ROOT/'scripts/hid_interface_model.py']
    report={'result':'IOS16_SELECTED_HID_ORIGINAL_INIT_STOP_AND_DRAIN_CPU_PASS','compiler_layout':facts,'cases':cases,
        'old_direct_stop_control':{'result':'REJECTED','check':'Original parent stop overlapped admitted work'},
        'old_producer_control':{'result':'REJECTED','check':'Original parent stop overlapped original producer',
            'image':'existing frozen input baseline','startup_gate_check_disabled_only_for_legacy_control':True},
        'old_interface_controls':interface_controls,'original_interface_bodies_are_not_peers':True,
        'deferred_termination_retains_caller_output_pointer':False,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'dependency_report_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            (KERNEL_REPORT,SOURCE_REPORT,ORIGINAL_REPORT,INTERFACE_REPORT,old_report,old_layout_report)},
        'artifacts':{str(p.relative_to(ROOT)):sha(p) for p in [candidate,old_candidate,*artifacts]},
        'original_parent_init_and_stop_are_not_peers':True,'full_original_parent_startup_remains_peer_bound':True,
        'hardware_tested':False,'phone_operations':'none',
        'scope':'Actual selected native constructor/init/start/dispatch/stop/free instructions, unchanged original full '
        'EventDriver/EventService init/stop and event access/default dispatch bodies execute. Reentrant/queued stop '
        'cannot overlap admitted work or repeat parent cleanup. The old compiled source reproduces overlap. '
        'Public IOKit allocation/lock/gate/registry/refcount/video primitives, original full startup and final event '
        'service delivery, IOService arbitration/termination notification and software-event scheduling are explicit peers. '
        'Original interface open/close/block/handleReport and Driver didTerminate bodies execute. Only an owned interface '
        'is closed; already-closed/foreign ownership notifies the native base with the weak original pointer kept pinned. '
        'Termination defers copied options without retaining caller output. Both blocked guest stop and a real-thread host '
        'control cover the admission-before-gate window. Additional cases execute unchanged original '
        'report readiness/callback and subhandlers on an empty-element fixture; a public clock boundary reenters actual source '
        'dispatch/stop. Gate-held original producers return before queued cleanup; an external stop may finish first without '
        'duplicate cleanup. Original producers which drop/reenter the workloop gate, complete startup/element/client/matching '
        'and final-free/hardware lifetime remain unqualified.'}
    check_report(report);REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(CASES)} native HID paths, original interface/termination bodies and old lifecycle controls rejected')


if __name__=='__main__':main()
