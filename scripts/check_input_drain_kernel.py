#!/usr/bin/env python3
"""Execute the actual native input stop/timer paths with explicit IOKit peers."""
import json
from pathlib import Path
import struct
import subprocess
from native_driver_build import ROOT,require,sha,symbols,macho,inspect_object
from build_input_native import fresh
from native_prelink import backed_offset

FIELDS=('loop','timer','touch','running','timerAdded','starting','parentCleanupPending','tickActive','stopRequested',
        'parentStopping','pendingStopProvider','hardwareTouched','previous','lastButtons','controller','touchPhase')
CASES=('stop-keys','stop-touch','stop-repeat','stop-unadded-timer','stop-no-timer','stop-parent-not-started',
       'stop-no-loop','stop-null-provider','stop-reentrant-parent','tick-after-stop','tick-already-active',
       'tick-touch-normal','tick-touch-send-failed','tick-touch-reentrant-stop','tick-touch-reentrant-stop-send-failed',
       'tick-touch-reentrant-stop-twice','tick-touch-error','start-null-provider','start-existing-loop','start-stop-requested',
       'start-live-success','start-live-parent-failure','start-live-parent-failure-stop','start-live-parent-failure-stop-twice',
       'start-live-parent-success-stop','start-live-timer-failure','start-live-add-failure')


def layout():
    """Access annotation only; require identical real production __text bytes."""
    out=ROOT/'build/ios16-input-drain-abi';out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'drivers/DodgeInput/DodgeInput.cpp';annotated=out/'DodgeInput.cpp'
    before=source.read_text();needle='    OSDeclareDefaultStructors(DodgeInput)\n'
    require(before.count(needle)==1,'Source class annotation anchor changed')
    labels=['instance_bytes',*FIELDS,'controller_ready','attn_base','frame_bytes','contact_bytes']
    values=['sizeof(DodgeInput)',*[f'offsetof(DodgeInput,{n})' for n in FIELDS],
            'offsetof(DodgeInput,controller)+offsetof(s3910,ready)',
            'offsetof(DodgeInput,pins)+5*sizeof(PeripheralWindow)+offsetof(PeripheralWindow,base)',
            'sizeof(s3910_frame)','sizeof(s3910_contact)']
    annotated.write_text(before.replace(needle,needle+'public: // layout annotation only\n')+
                         '\nextern "C" const unsigned dodge_input_drain_layout[]={'+','.join(values)+'};\n')
    commands=json.loads((ROOT/'build/cph2653-input-native/compile-commands.json').read_text())
    recipe=next(c for c in commands if c['source']==str(source));args=recipe['arguments'][:]
    obj=out/'DodgeInput.o';args[args.index(str(source))]=str(annotated);args[args.index('-o')+1]=str(obj)
    args+=['-Wno-invalid-offsetof','-I',str(source.parent)]
    with (out/'compile.log').open('w') as log:
        result=subprocess.run(args,cwd=recipe['directory'],stdout=log,stderr=subprocess.STDOUT)
    require(not result.returncode,'Input drain annotation compile failed; inspect '+str(out/'compile.log'))
    (out/'compile-command.json').write_text(json.dumps(args,indent=2)+'\n')
    def text(path):
        data=path.read_bytes();s=next(s for seg in inspect_object(data)['segments'] for s in seg['sections'] if s['name']=='__text')
        return data[s['fileoff']:s['fileoff']+s['size']]
    require(text(obj)==text(ROOT/'build/cph2653-input-native/DodgeInput.o'),'Access-only annotation changed production machine code')
    raw=obj.read_bytes();im=inspect_object(raw);s,=[s for s in symbols(raw) if not s['kind']&0xe0 and s['name']=='_dodge_input_drain_layout']
    section=next(t for seg in im['segments'] for t in seg['sections'] if t['va']<=s['value']<t['va']+t['size'])
    values=struct.unpack_from('<'+str(len(labels))+'I',raw,section['fileoff']+s['value']-section['va'])
    return dict(zip(labels,values)),obj


def emulate(candidate,case,facts,control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=candidate.read_bytes();im=macho(raw);table=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14]
    names={s['name']:s['value'] for s in table};addresses={s['value'] for s in table}
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(address,value=b'',size=0):
        p=address&~4095;end=(address+max(len(value),size)+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            stop=p+4096
            while stop<end and stop not in pages:stop+=4096
            uc.mem_map(p,stop-p);pages.update(range(p,stop,4096));p=stop
        if value:uc.mem_write(address,value)
    for seg in im['segments']:
        if seg['size'] and seg['initprot']:put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
    obj,loop,timer,provider,stack,halt,attn=0x100040,0x110040,0x120040,0x130040,0x200000,0x300000,0x400000
    for address,size in ((obj,facts['instance_bytes']),(loop,128),(timer,128),(provider,128)):
        put(address-64,b'\xa5'*(size+128));put(address,bytes(size))
    put(stack,size=65536);put(halt,size=65536);put(attn,size=4096)
    for address,typename in ((obj,'10DodgeInput'),(loop,'10IOWorkLoop'),(timer,'18IOTimerEventSource'),(provider,'9IOService')):
        put(address,struct.pack('<Q',names['__ZTV'+typename]+16))
    def field(name,value,width=1):put(obj+facts[name],int(value).to_bytes(width,'little'))
    def value(name,width=1):return int.from_bytes(bytes(uc.mem_read(obj+facts[name],width)),'little')
    field('loop',0 if case=='stop-no-loop' else loop,8);field('timer',0 if case=='stop-no-timer' else timer,8)
    field('touch','touch' in case);field('hardwareTouched',1);field('running',1)
    field('parentCleanupPending',case!='stop-parent-not-started');field('timerAdded',case not in ('stop-unadded-timer','stop-no-timer'))
    field('attn_base',attn,8)
    if case in ('tick-after-stop','start-stop-requested'):field('running',0);field('stopRequested',1)
    if case=='tick-already-active':field('tickActive',1)
    if case.startswith('tick-touch'):field('controller_ready',1)
    if case=='stop-touch':
        previous=bytearray(facts['frame_bytes']);struct.pack_into('<HHB',previous,3*facts['contact_bytes'],100,200,1);put(obj+facts['previous'],bytes(previous))
    live_start=case.startswith('start-live-')
    if live_start:
        for name in ('loop','timer','running','parentCleanupPending','timerAdded','hardwareTouched'):field(name,0,8 if name in ('loop','timer') else 1)
    events=[];reports=[];refs={loop:1,timer:1,provider:1};peers={};continuations={};gate_depth=0;triggered=False
    mapped=[];descriptors=[];map_bases={};observer=[0]
    callbacks=0;native=set()
    def args():return [uc.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(result=0):uc.reg_write(arm.UC_ARM64_REG_X0,result&((1<<64)-1));uc.reg_write(arm.UC_ARM64_REG_PC,uc.reg_read(arm.UC_ARM64_REG_LR))
    def invoke(entry,arguments,done):
        nonlocal callbacks
        callbacks+=1;return_pc=halt+callbacks*16;context=uc.context_save()
        def finish():
            result=uc.reg_read(arm.UC_ARM64_REG_X0);uc.context_restore(context);done(result)
        continuations[return_pc]=finish
        uc.reg_write(arm.UC_ARM64_REG_SP,uc.reg_read(arm.UC_ARM64_REG_SP)-4096)
        uc.reg_write(arm.UC_ARM64_REG_LR,return_pc)
        for i,v in enumerate(arguments):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
        uc.reg_write(arm.UC_ARM64_REG_PC,entry)
    def bind(name,fn):require(name in names,'Missing input drain public peer: '+name);peers[names[name]]=fn
    def retain(a):
        require(a[0] in refs,'Unclassified source retention')
        refs[a[0]]+=1;events.append(('retain',a[0]));ret()
    def release(a):
        require(a[0] in refs and refs[a[0]]>0,'Source release without a retained input')
        refs[a[0]]-=1;events.append(('release',a[0]));ret()
    bind('__ZNK8OSObject6retainEv',retain);bind('__ZNK8OSObject7releaseEv',release)
    bind('__ZNK8OSObject7releaseEi',release)
    bind('__ZN10IOWorkLoop8workLoopEv',lambda a:ret(loop))
    def map_factory(a):
        require(gate_depth and a[0] in (0x0c400000,0x0c42d000,0x0c440000),'Unexpected button mapping address: '+hex(a[0]))
        index=len(mapped);descriptor=0x500040+index*0x10000;mapping=descriptor+0x1000;base=descriptor+0x2000
        for address,typename in ((descriptor,'18IOMemoryDescriptor'),(mapping,'11IOMemoryMap')):
            put(address-64,b'\xa5'*384);put(address,bytes(256));put(address,struct.pack('<Q',names['__ZTV'+typename]+16));refs[address]=1
        descriptors.append(descriptor);mapped.append(mapping);map_bases[mapping]=base
        put(base,size=a[1])
        if a[0]==0xc400000:
            put(base,struct.pack('<2I',0x70000000,3));put(base+0x2004,struct.pack('<2I',(0x13<<8)|1,(0x18d<<8)|1))
        if a[0]==0xc440000:observer[0]=base
        events.append(('memory',a[0],a[1]));ret(descriptor)
    bind('__ZN14IODeviceMemory9withRangeEyy',map_factory)
    def map_memory(a):
        require(a[0] in descriptors,'Button map uses unowned descriptor');ret(mapped[descriptors.index(a[0])])
    bind('__ZN18IOMemoryDescriptor3mapEj',map_memory)
    bind('__ZN11IOMemoryMap17getVirtualAddressEv',lambda a:ret(map_bases[a[0]]))
    def observer_write(engine,access,address,size,data,user):
        if not observer[0] or not observer[0]<=address<observer[0]+0x80000:return
        offset=address-observer[0];apid=offset//0x20;register=(data>>4)&255
        require(gate_depth and size==4 and offset%0x20==0 and data==(1<<27)|(register<<4),'Unexpected source SPMI observer command')
        expected={(1,5):9,(2,4):0x10,(2,5):0x10,(2,0x40):0,(2,0x46):0x80}
        require((apid,register) in expected,'Unexpected button setup register read: '+repr((apid,register)))
        put(address+8,struct.pack('<I',1));put(address+0x18,struct.pack('<I',expected[(apid,register)]));events.append(('spmi-command',apid,register))
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,observer_write)
    def original_start(a):
        require(a[:2]==[obj,provider] and gate_depth and value('starting') and value('parentCleanupPending'),'Parent cleanup obligation was not latched before original HID start')
        events.append(('parent-start',));ok='parent-failure' not in case
        if case.endswith('stop') or case.endswith('stop-twice'):
            def stopped(rc):
                require(value('pendingStopProvider',8)==provider and refs[provider]==2 and not any(e[0]=='parent-stop' for e in events),
                        'Original start virtual stop was not deferred with its provider retained')
                if case.endswith('twice'):invoke(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider),lambda rc:ret(int(ok)))
                else:ret(int(ok))
            invoke(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider),stopped)
        else:ret(int(ok))
    parent_start=struct.unpack('<Q',bytes(uc.mem_read(names['__ZTV11IOHIDDevice']+16+86*8,8)))[0];peers[parent_start]=original_start
    def create_timer(a):
        require(a[:2]==[obj,names['__ZN10DodgeInput4tickEP8OSObjectP18IOTimerEventSource']] and gate_depth,'Input timer uses wrong callback/owner')
        events.append(('timer-create',));ret(0 if case=='start-live-timer-failure' else timer)
    bind('__ZN18IOTimerEventSource16timerEventSourceEP8OSObjectPFvS1_PS_E',create_timer)
    def add_timer(a):require(a[:2]==[loop,timer] and gate_depth,'Input timer added on wrong loop');events.append(('add',));ret(0xe00002be if case=='start-live-add-failure' else 0)
    bind('__ZN10IOWorkLoop14addEventSourceEP13IOEventSource',add_timer)
    def run_action(a):
        nonlocal gate_depth
        require(a[0]==loop and a[2]==obj,'Source input gate target/loop changed')
        gate_depth+=1;events.append(('gate-enter',gate_depth))
        def done(rc):
            nonlocal gate_depth
            events.append(('gate-leave',gate_depth));gate_depth-=1;ret(rc)
        invoke(a[1],(a[2],*a[3:7]),done)
    bind('__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_',run_action)
    def in_gate(a):require(a[0]==loop,'Source inGate queried foreign loop');ret(int(gate_depth>0))
    bind('__ZNK10IOWorkLoop6inGateEv',in_gate)
    def cancel(a):require(a[0]==timer and gate_depth,'Timer cancel was not serialized');events.append(('cancel',));ret()
    bind('__ZN18IOTimerEventSource13cancelTimeoutEv',cancel)
    def remove(a):require(a[:2]==[loop,timer] and gate_depth,'Timer removal was not serialized');events.append(('remove',));ret()
    bind('__ZN10IOWorkLoop17removeEventSourceEP13IOEventSource',remove)
    def schedule(a):require(a[0]==timer and gate_depth and value('running') and not value('stopRequested'),'Stopped input rescheduled its timer');events.append(('reschedule',a[1]));ret()
    bind('__ZN18IOTimerEventSource12setTimeoutMSEj',schedule)
    def original_stop(a):
        nonlocal triggered
        require(a[:2]==[obj,provider] and gate_depth and not value('tickActive') and not value('starting') and not value('parentCleanupPending') and value('parentStopping'),
                'Original HID parent stop ran before source callback drain or without gate')
        events.append(('parent-stop',))
        if case=='stop-reentrant-parent' and not triggered:
            triggered=True;invoke(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider),lambda rc:ret())
        else:ret()
    parent_stop=struct.unpack('<Q',bytes(uc.mem_read(names['__ZTV11IOHIDDevice']+16+87*8,8)))[0]
    peers[parent_stop]=original_stop
    def send(a):
        nonlocal triggered
        require(a[0]==obj and gate_depth,'Input report emitted outside its lifecycle gate')
        data=bytes(uc.mem_read(a[1],a[2]));reports.append(data);events.append(('report',data.hex()))
        ok='send-failed' not in case
        if 'reentrant-stop' in case and not triggered:
            triggered=True
            def stopped(rc):
                require(not any(e[0]=='parent-stop' for e in events) and value('pendingStopProvider',8)==provider and refs[provider]==2,
                        'Reentrant stop did not retain provider and defer parent until tick exit')
                if case.endswith('twice'):invoke(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider),lambda rc:ret(int(ok)))
                else:ret(int(ok))
            invoke(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider),stopped)
        else:ret(int(ok))
    bind('__ZN10DodgeInput4sendEPKvm',send)
    def poll(a):
        require(a[0]==obj+facts['controller'] and gate_depth and value('tickActive'),'Touch poll ran without an active serialized callback')
        frame=bytearray(facts['frame_bytes']);struct.pack_into('<HHB',frame,9*facts['contact_bytes'],1234,5678,1);put(a[1],bytes(frame));events.append(('poll',));ret(-71 if case=='tick-touch-error' else 1)
    bind('_s3910_poll',poll)
    bind('__ZN10DodgeInput15showTouchEventsEv',lambda a:ret())
    bind('__ZN10DodgeInput12observeTouchEi',lambda a:ret())
    bind('_dodge_input_observe',lambda a:ret())
    def diagnostic(a):
        require(a[0]==obj+facts['touchPhase'] and a[1]==24,'Source diagnostic escaped its fixed buffer')
        put(a[0],bytes(a[1]));ret()
    bind('_snprintf',diagnostic)
    bind('__ZN15IORegistryEntry11setPropertyEPKcyj',lambda a:ret(1))
    bind('__ZN15IORegistryEntry11setPropertyEPKcb',lambda a:ret(1))
    def zero(a):
        require(stack<=a[0]<=a[0]+a[1]<=stack+65536 or obj<=a[0]<=a[0]+a[1]<=obj+facts['instance_bytes'],'Drain zero peer escaped source allocation')
        put(a[0],bytes(a[1]));ret()
    bind('_bzero',zero)
    allowed=[]
    for filename in ('DodgeInput.o','S3910.o'):
        data=(ROOT/'build/cph2653-input-native'/filename).read_bytes();oi=inspect_object(data);sections=[s for seg in oi['segments'] for s in seg['sections']]
        for s in symbols(data):
            if s['kind']&0xe0 or s['kind']&14!=14 or not s['section'] or sections[s['section']-1]['name']!='__text' or s['name'].startswith('ltmp'):continue
            if filename=='S3910.o' and s['name']!='_s3910_hid_report':continue
            start=names[s['name']];allowed.append((start,min(v for v in addresses if v>start)))
    def hook(engine,address,size,user):
        if address in continuations:continuations.pop(address)();return
        if address in peers:peers[address](args());return
        require(any(a<=address<b for a,b in allowed),'Unclassified input drain implementation: '+hex(address)+' '+str([n for n,a in names.items() if a==address]))
        native.add(address)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def execute(entry,arguments):
        uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
        for i,v in enumerate(arguments):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
        uc.emu_start(entry,halt,timeout=5000000,count=1000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt and not continuations,'Input drain path did not return within bounds')
        return uc.reg_read(arm.UC_ARM64_REG_X0)&0xffffffff
    if control:
        start=names['__ZN10DodgeInput4stopEP9IOService']
        put(start,struct.pack('<I',0xd65f03c0))
    if case.startswith('tick-'):
        gate_depth=1;execute(names['__ZN10DodgeInput4tickEP8OSObjectP18IOTimerEventSource'],(obj,timer));gate_depth=0
        stopped='reentrant-stop' in case
        if stopped:
            require(not value('running') and not value('tickActive') and not value('parentCleanupPending') and not value('pendingStopProvider',8) and refs[provider]==1,
                    'Deferred input stop did not finish exactly after tick and balance its provider reference')
            require(sum(e[0]=='parent-stop' for e in events)==1 and sum(e[0]=='remove' for e in events)==1 and not any(e[0]=='reschedule' for e in events),
                    'Reentrant input stop repeated parent/remove or restarted timer')
            if 'send-failed' not in case:
                require(len(reports)==2 and reports[0][1]&1 and not reports[1][1]&1 and reports[1][2]==9 and reports[1][61]==1,
                        'Deferred stop did not release the latest successfully reported contact')
            else:require(len(reports)==1,'Failed touch delivery generated a fictitious release')
        elif case in ('tick-after-stop','tick-already-active'):require(not events,'Stopped or reentrant tick touched input state')
        else:require(sum(e[0]=='reschedule' for e in events)==1 and not value('tickActive') and not any(e[0]=='parent-stop' for e in events),'Normal source tick did not exit and reschedule exactly once')
    elif live_start:
        rc=execute(names['__ZN10DodgeInput5startEP9IOService'],(obj,provider));ok=case=='start-live-success'
        require(rc==int(ok) and not value('starting') and not value('pendingStopProvider',8) and refs[provider]==1,
                'Concrete gated start returned wrong state or leaked deferred provider')
        require(sum(e[0]=='parent-start' for e in events)==1 and sum(e[0]=='parent-stop' for e in events)==int(not ok),
                'Concrete parent start failure/reentrant stop did not clean up exactly once')
        require(bool(value('running'))==ok and bool(value('parentCleanupPending'))==ok and bool(value('timerAdded'))==ok,
                'Concrete start did not publish exact running/parent/timer state')
        require(sum(e[0]=='reschedule' for e in events)==int(ok),'Failed source start scheduled a timer')
        require(len(mapped)==3 and all(refs[d]==0 for d in descriptors) and all(refs[m]==1 for m in mapped),'Start mapping refs were not retained/released as intended')
        if ok:
            execute(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider))
            require(sum(e[0]=='parent-stop' for e in events)==1 and not value('running'),'Started concrete device did not stop normally')
    elif case.startswith('start-'):
        if case=='start-stop-requested':field('loop',0,8)
        require(execute(names['__ZN10DodgeInput5startEP9IOService'],(obj,0 if case=='start-null-provider' else provider))==0 and not events,
                'One-shot/invalid source start entered hardware or IOKit')
    else:
        execute(names['__ZN10DodgeInput4stopEP9IOService'],(obj,0 if case=='stop-null-provider' else provider))
        if case=='stop-repeat':
            for _ in range(3):execute(names['__ZN10DodgeInput4stopEP9IOService'],(obj,provider))
        if case in ('stop-no-loop','stop-null-provider'):require(not events and value('parentCleanupPending'),'Invalid stop changed source state')
        else:
            require(not value('running') and not value('parentCleanupPending') and value('stopRequested') and not value('timerAdded'),
                    'Source stop did not serialize and drain the active device')
            require(sum(e[0]=='parent-stop' for e in events)==int(case!='stop-parent-not-started'),'Source stop repeated/omitted original parent stop')
            require(sum(e[0]=='remove' for e in events)==int(case not in ('stop-unadded-timer','stop-no-timer')),'Source stop removed timer more than once')
    expected_refs={loop:1,timer:1,provider:1,**{d:0 for d in descriptors},**{m:1 for m in mapped}}
    require(refs==expected_refs and not gate_depth,'Input drain changed pinned resource/provider ownership: '+repr(refs))
    for address,size in ((obj,facts['instance_bytes']),(loop,128),(timer,128),(provider,128)):
        require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+size,64))==b'\xa5'*64,'Input drain allocation canary changed')
    return {'case':case,'result':'PASS','events':events,'reports':[r.hex() for r in reports],'native_instructions_visited':len(native),
            'provider_and_resource_references_balanced':True,'actual_source_stop_and_tick':True}


def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json'
    source=fresh(source_path);prelink=fresh(prelink_path);candidate=ROOT/prelink['candidate']
    require(prelink['input_source_report_sha256']==sha(source_path) and sha(candidate)==prelink['candidate_sha256'],'Input drain source/prelink stale')
    facts,obj=layout();require(facts['instance_bytes']==source['compiled_instance_bytes'],'Input drain source annotation size differs')
    cases=[emulate(candidate,name,facts) for name in CASES];controls=[]
    try:emulate(candidate,'stop-keys',facts,True)
    except ValueError as error:
        require(str(error)=='Source stop did not serialize and drain the active device','Input stop control failed for unrelated reason: '+str(error))
        controls.append({'case':'source-stop-return-without-drain','result':'REJECTED','check':str(error)})
    else:raise ValueError('Missing native input stop was accepted')
    out=ROOT/'build/cph2653-input-prelink/drain-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeInput/DodgeInput.cpp',
           ROOT/'sources/UniXNU-Pagani-Drivers/drivers/PaganiInput/S3910.c',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/PaganiInput/Mapping.h']
    report={'result':'IOS16_PRELINKED_INPUT_GATED_STOP_AND_REENTRANT_TICK_DRAIN_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':sha(candidate),'case_count':len(cases),'cases':cases,'negative_controls':controls,
            'compiler_derived_layout':facts,'access_annotation_text_identical_to_production':True,
            'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),
            'gated_stop_and_tick_drain_implemented':True,'reentrant_stop_defers_parent_until_tick_exit':True,
            'deferred_provider_pin_balanced':True,'no_timer_reschedule_after_stop':True,
            'iokit_gate_timer_mapping_lifetime_original_parent_start_stop_and_hid_submission_are_peers':True,
            'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual current linked ARM64 source stop/actions/cleanup/timer callbacks and S3910 report construction, '
                    'with production-identical compiler access annotation and owned allocation canaries. '
                    'Reentrant report and parent-stop callbacks exercise deferred stop, final release, provider retention, repeats and timer policy. '
                    'Concrete source key startup and SPMI discovery/read helper execute against an observer bus peer. '
                    'IOKit gate/timer/mapping/refcount, native touch poll, HID submission, diagnostic formatting and original parent start/stop are explicit peers; '
                    'no scheduler, full original start/stop or hardware qualification.'}
    (ROOT/'reports/ios16-input-drain-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(cases))+' actual source ARM64 stop/tick/drain cases and missing-stop rejection')


if __name__=='__main__':main()
