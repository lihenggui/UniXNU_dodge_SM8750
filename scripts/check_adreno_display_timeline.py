#!/usr/bin/env python3
"""Execute the actual linked A830 display snapshot over bounded CPU/lock peers."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import unicorn
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
import unicorn.arm64_const as reg

from native_driver_build import ROOT,macho,require,sha,symbols
from native_prelink import backed_offset


def parse_layout(log,name,fields):
    for block in log.split('*** Dumping AST Record Layout'):
        lines=block.splitlines();title=next((line for line in lines if re.match(r'\s*0 \| (?:class|struct) ',line)),None)
        if title is None or not re.fullmatch(r'\s*0 \| (?:class|struct) '+re.escape(name),title):continue
        size=re.search(r'\[sizeof=(\d+),',block);require(size is not None,'Missing native sizeof: '+name)
        offsets={}
        for line in lines:
            match=re.fullmatch(r'\s*(\d+) \| {3}(\S.*?)\s+([A-Za-z_]\w*)',line)
            if match and match[3] in fields:offsets[match[3]]=int(match[1])
        require(set(offsets)==set(fields),'Incomplete native field layout: '+name+' / '+str(offsets))
        return {'bytes':int(size[1]),'fields':offsets}
    raise ValueError('Native compiler did not report used record: '+name)


def native_layouts(out,backend):
    commands_path=ROOT/'build/cph2653-a830-backend/compile-commands.json'
    commands=json.loads(commands_path.read_text());record,=[r for r in commands if Path(r['source']).name=='NativeAdrenoPublish.cpp']
    source=ROOT/record['source'] if not Path(record['source']).is_absolute() else Path(record['source'])
    require(sha(source)==backend['source_sha256'][str(source.relative_to(ROOT))],'Native publisher source changed')
    original_object=ROOT/'build/cph2653-a830-backend/NativeAdrenoPublish.o';probe=out/'publisher-layout.o'
    args=[];index=0
    while index<len(record['arguments']):
        value=record['arguments'][index]
        if value=='-o':args+=['-o',str(probe)];index+=2;continue
        args.append(value);index+=1
    args+=['-Xclang','-fdump-record-layouts']
    result=subprocess.run(args,cwd=record['directory'],capture_output=True,text=True)
    log=result.stdout+result.stderr;(out/'compiler-layouts.log').write_text(log)
    require(result.returncode==0,'Native record-layout compilation failed; see '+str(out/'compiler-layouts.log'))
    def text(path):
        data=path.read_bytes();image=macho(data);section,=[s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
        return data[section['fileoff']:section['fileoff']+section['size']]
    require(text(probe)==text(original_object),'Record-layout probe differs from actual production publisher instructions')
    layouts={key:parse_layout(log,name,fields) for key,name,fields in (
        ('published','(anonymous namespace)::Published',('published','ring','submit','lock')),
        ('ring','NativeAdrenoRing',('poisoned_','seqno_')),
        ('submit','NativeAdrenoSubmit',('preempt_on_','ring_count_')),
        ('snapshot','DodgeAdrenoTimeline',('epoch','submitted','retired')))}
    require(layouts['snapshot']=={'bytes':16,'fields':{'epoch':0,'submitted':8,'retired':12}},'Native scalar snapshot layout differs')
    require(all(0<v['bytes']<=16*1024*1024 for v in layouts.values()),'Unexpectedly unbounded native fixture layout')
    return layouts,{'object':str(probe.relative_to(ROOT)),'object_sha256':sha(probe),'production_object_sha256':sha(original_object),
        'compiler_layout_log':str((out/'compiler-layouts.log').relative_to(ROOT)),'compiler_layout_log_sha256':sha(out/'compiler-layouts.log'),
        'compile_record_sha256':sha(commands_path),'production_instruction_bytes_equal':True}


def functions(raw,image,table):
    executable=[s for s in image['segments'] if s['size'] and s['initprot']&4]
    values=sorted({s['value'] for s in table if not s['kind']&0xe0 and s['kind']&14==14 and
        any(seg['va']<=s['value']<seg['va']+seg['filesize'] for seg in executable)})
    def body(name):
        matches={s['value'] for s in table if not s['kind']&0xe0 and s['kind']&14==14 and name in s['name']}
        require(len(matches)==1,'Ambiguous/missing native timeline function: '+name)
        start,=matches;segment,=[s for s in executable if s['va']<=start<s['va']+s['filesize']]
        end=next((v for v in values if v>start),segment['va']+segment['filesize'])
        at=backed_offset(image['segments'],start,end-start,len(raw));return start,raw[at:at+end-start]
    return body


def cpu_cases(raw,image,table,layouts):
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    defined={s['name']:s for s in table if not s['kind']&0xe0 and s['kind']&14}
    entry=defined['_dodge_adreno_display_timeline']['value'];counter=defined['_native_adreno_recovery']['value']
    globals_=sorted({s['value'] for s in table if s['name']=='__ZN12_GLOBAL__N_11gE' and not s['kind']&0xe0 and s['kind']&14==14})
    require(globals_,'No linked private state globals to classify')
    lock_tries={defined[name]['value'] for name in ('_IOLockTryLock','_lck_mtx_try_lock') if name in defined}
    lock_releases={defined[name]['value'] for name in ('_IOLockUnlock','_lck_mtx_unlock') if name in defined}
    require(lock_tries and lock_releases,'Real native mutex imports absent')
    ubsan_addresses={s['value'] for name,s in defined.items() if 'ubsan' in name}
    fence=defined['__ZN16NativeAdrenoRing10fenceValueEPj']['value']
    ring,submit,lock,output,stack,stop=0x200000,0x1800000,0x3000000,0x3100000,0x3200000,0x3300000
    def create():
        engine=Uc(UC_ARCH_ARM64,UC_MODE_ARM);regions=[]
        for segment in image['segments']:
            if segment['size']:
                require(segment['size']<=256*1024*1024 and not segment['va']&4095,'Unbounded/misaligned native segment')
                regions.append((segment['va'],(segment['va']+segment['size']+4095)&~4095))
        merged=[]
        for start,end in sorted(regions):
            if merged and start<=merged[-1][1]:merged[-1]=(merged[-1][0],max(merged[-1][1],end))
            else:merged.append((start,end))
        for start,end in merged:engine.mem_map(start,end-start)
        for segment in image['segments']:
            if segment['filesize']:engine.mem_write(segment['va'],raw[segment['fileoff']:segment['fileoff']+segment['filesize']])
        for address,size in ((ring,layouts['ring']['bytes']),(submit,layouts['submit']['bytes']),(lock,64),(output,32),(stack,65536),(stop,4096)):
            engine.mem_map(address,(size+4095)&~4095)
        return engine
    def run(published,case,discovery=False):
        settings={'published':True,'lock_present':True,'lock_available':True,'ring_present':True,'submit_present':True,
            'poisoned':False,'preempt':False,'rings':1,'generation':0,'submitted':7,'retired':6,'fence_status':0,'out':output,**case}
        engine=create();fields=layouts['published']['fields']
        def put(address,fmt,*values):engine.mem_write(address,struct.pack(fmt,*values))
        put(published+fields['published'],'<B',int(settings['published']))
        for name,value in (('ring',ring if settings['ring_present'] else 0),('submit',submit if settings['submit_present'] else 0),
                ('lock',lock if settings['lock_present'] else 0)):put(published+fields[name],'<Q',value)
        put(ring+layouts['ring']['fields']['poisoned_'],'<B',int(settings['poisoned']))
        put(ring+layouts['ring']['fields']['seqno_'],'<I',settings['submitted'])
        put(submit+layouts['submit']['fields']['preempt_on_'],'<B',int(settings['preempt']))
        put(submit+layouts['submit']['fields']['ring_count_'],'<I',settings['rings'])
        put(counter,'<8I',settings['generation'],0,0,0,0,0,0,0);engine.mem_write(output,b'\xcc'*32)
        allowed=[(p,layouts['published']['bytes']) for p in (globals_ if discovery else [published])]+[
            (counter,32),(ring,layouts['ring']['bytes']),(submit,layouts['submit']['bytes']),(stack,65536),(output,32)]
        state={'held':False,'tries':0,'unlocks':0,'fences':0,'writes':0,'instructions':0}
        def memory(uc,kind,address,size,value,user):
            require(any(start<=address and address+size<=start+length for start,length in allowed),'Native snapshot escaped bounded state/stack/output windows')
            if kind==UC_MEM_WRITE:
                require(stack<=address and address+size<=stack+65536 or output<=address and address+size<=output+16,
                    'Read-only snapshot wrote backend state or an output guard')
                if output<=address<output+16:state['writes']+=1
        def returned(uc,value):uc.reg_write(reg.UC_ARM64_REG_X0,value&0xffffffffffffffff);uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
        def instruction(uc,address,size,user):
            state['instructions']+=1
            if address in lock_tries:
                require(uc.reg_read(reg.UC_ARM64_REG_X0)==lock and not state['held'],'Native snapshot tried the wrong/recursive mutex')
                state['tries']+=1;state['held']=settings['lock_available'];returned(uc,int(state['held']))
            elif address in lock_releases:
                require(uc.reg_read(reg.UC_ARM64_REG_X0)==lock and state['held'],'Native snapshot unlocked an unowned mutex')
                state['held']=False;state['unlocks']+=1;returned(uc,0)
            elif address==fence:
                require(state['held'] and uc.reg_read(reg.UC_ARM64_REG_X0)==ring,'Native snapshot queried fences outside its held mutex')
                target=uc.reg_read(reg.UC_ARM64_REG_X1);require(stack<=target<=stack+65536-4,'Fence output escaped its native local')
                state['fences']+=1;put(target,'<I',settings['retired']);returned(uc,settings['fence_status'])
            elif address in ubsan_addresses:
                raise ValueError('Native snapshot reached an overflow/type failure')
        engine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory);engine.hook_add(UC_HOOK_CODE,instruction)
        engine.reg_write(reg.UC_ARM64_REG_X0,settings['out']);engine.reg_write(reg.UC_ARM64_REG_SP,stack+65024);engine.reg_write(reg.UC_ARM64_REG_LR,stop)
        engine.emu_start(entry,stop,timeout=1000000,count=4096)
        require(engine.reg_read(reg.UC_ARM64_REG_PC)==stop and not state['held'],'Native snapshot failed to return/unlock')
        value=engine.reg_read(reg.UC_ARM64_REG_X0);payload=bytes(engine.mem_read(output,32))
        require(payload[16:]==b'\xcc'*16,'Native snapshot overwrote its output canary')
        return value,payload,state,settings
    candidates=[]
    for address in globals_:
        value,payload,_,_=run(address,{},discovery=True)
        if value==1 and payload[:16]==struct.pack('<QII',1,7,6):candidates.append(address)
    require(len(candidates)==1,'Actual linked snapshot did not identify exactly one published-state global')
    published,=candidates;results=[]
    cases=[('pending-fence-is-a-valid-snapshot',{},True),('completed-fence',{'retired':7},True),('empty-ring',{'submitted':0,'retired':0},True),
        ('new-recovery-epoch-same-fence',{'generation':1,'retired':7},True),('high-32-bit-fences',{'submitted':0xfffffffe,'retired':0xfffffffd},True),
        ('single-ring-preempt-flag-without-second-ring',{'preempt':True,'rings':1},True),
        ('unpublished',{'published':False},False),('no-lock',{'lock_present':False},False),('busy-lock',{'lock_available':False},False),
        ('no-ring',{'ring_present':False},False),('no-submit',{'submit_present':False},False),('poisoned-ring',{'poisoned':True},False),
        ('active-two-ring-preemption',{'preempt':True,'rings':2},False),('epoch-saturated',{'generation':0xffffffff},False),
        ('cache-fence-read-failed',{'fence_status':-1},False),('retired-beyond-submitted',{'retired':8},False),
        ('null-output',{'out':0},False),('unaligned-output',{'out':output+1},False),('wrapping-output',{'out':0xfffffffffffffff8},False)]
    for name,arguments,expected in cases:
        value,payload,state,settings=run(published,arguments)
        require(value==int(expected),'Actual snapshot success/refusal differs: '+name)
        require(state['unlocks']==int(state['tries'] and settings['lock_available']),'Snapshot mutex lifetime differs: '+name)
        if expected:require(payload[:16]==struct.pack('<QII',settings['generation']+1,settings['submitted'],settings['retired']),'Actual snapshot scalar output differs: '+name)
        else:require(payload[:16]==b'\xcc'*16 and not state['writes'],'Failed snapshot changed caller output: '+name)
        results.append({'case':name,'result':'PASS','snapshot_available':expected,**state})
    body=functions(raw,image,table);helper,helper_code=body('dodgeDisplayRecoveryEpoch');hang,hang_code=body('nativeAdrenoHangcheck')
    recover,=set(s['value'] for s in table if not s['kind']&0xe0 and s['kind']&14 and 'NativeAdrenoSubmit7recover' in s['name'])
    def calls(start,code,target):
        result=[]
        for at,(word,) in enumerate(struct.iter_unpack('<I',code)):
            if word&0xfc000000!=0x94000000:continue
            offset=word&0x3ffffff;offset=offset-(1<<26) if offset&(1<<25) else offset
            if start+at*4+offset*4==target:result.append(start+at*4)
        return result
    note,=calls(hang,hang_code,helper);recover_site,=calls(hang,hang_code,recover)
    require(note<recover_site,'Native recovery does not advance the epoch before recover()')
    for before,after in ((0,1),(0xfffffffe,0xffffffff),(0xffffffff,0xffffffff)):
        engine=create();engine.mem_write(counter,struct.pack('<8I',before,11,12,13,14,15,16,17))
        def memory(uc,kind,address,size,value,user):
            require(stack<=address and address+size<=stack+65536 or counter<=address and address+size<=counter+32,'Native epoch helper escaped counter/stack')
            if kind==UC_MEM_WRITE and not stack<=address<stack+65536:require(address==counter and size==4,'Epoch helper wrote another counter')
        engine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory);engine.reg_write(reg.UC_ARM64_REG_SP,stack+65024);engine.reg_write(reg.UC_ARM64_REG_LR,stop)
        engine.emu_start(helper,stop,timeout=100000,count=256)
        require(engine.reg_read(reg.UC_ARM64_REG_PC)==stop and struct.unpack('<8I',engine.mem_read(counter,32))==(after,11,12,13,14,15,16,17),
            'Actual recovery epoch counter did not advance/saturate exactly')
        results.append({'case':'recovery-counter-'+hex(before),'result':'PASS','before':before,'after':after})
    return results,{'published_state':hex(published),'recovery_counter':hex(counter),'snapshot_entry':hex(entry),
        'epoch_helper':hex(helper),'epoch_helper_sha256':hashlib.sha256(helper_code).hexdigest(),'native_recovery_note_call':hex(note),'native_recover_call':hex(recover_site)}


def main():
    backend=json.loads((ROOT/'reports/a830-backend.json').read_text());link=json.loads((ROOT/'reports/gpu-link-probe.json').read_text())
    require(backend['result']=='NATIVE_A830_BACKEND_ARCHIVE_PASS' and link['strict_no_undefined'] and
        link['candidate_report_sha256']==sha(ROOT/'reports/gpu-kernel-candidate.json'),'Need current native backend and actual candidate link')
    path=ROOT/link['isolated_kernel'];require(sha(path)==link['isolated_kernel_sha256'],'Linked native GPU kernel changed')
    out=ROOT/'build/cph2653-adreno-display-timeline';out.mkdir(parents=True,exist_ok=True)
    layouts,probe=native_layouts(out,backend);raw=path.read_bytes();image=macho(raw);table=symbols(raw)
    cases,trace=cpu_cases(raw,image,table,layouts)
    sources=[Path(__file__),ROOT/'scripts/adreno_display_timeline.py',ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeDisplay/DodgeAdrenoTimeline.h']
    report={'result':'A830_COHERENT_DISPLAY_TIMELINE_NATIVE_CPU_PASS','builder_sha256':sha(Path(__file__)),
        'backend_report_sha256':sha(ROOT/'reports/a830-backend.json'),'link_report_sha256':sha(ROOT/'reports/gpu-link-probe.json'),
        'native_kernel':str(path.relative_to(ROOT)),'native_kernel_sha256':sha(path),'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sources},
        'timeline_overlay':backend['display_timeline_overlay'],'native_layouts':layouts,'native_layout_probe':probe,'trace':trace,'cases':cases,
        'case_count':len(cases),'native_instruction_bytes_changed':False,'nonblocking_mutex_and_fence_peers':True,'failure_preserves_output':True,
        'publisher_recovery_advances_saturating_epoch':True,'multi_ring_preemption_refused':True,'actual_cache_or_mmio_executed':False,
        'original_iokit_mutex_executed':False,'reset_hardware_qualified':False,'external_reset_paths_qualified':False,'hardware_tested':False,
        'scope':'Actual linked native snapshot and recovery epoch helper execute over compiler-derived bounded Published/Ring/Submit records. '
                'Only native mutex entry points and the cache/fence read are explicit peers. Nineteen snapshot cases and three epoch counter cases cover '
                'busy/unpublished/poisoned/preempted/refused paths, unchanged output and recovery sequence reuse. Native recovery calls the saturating epoch helper before recover(). '
                'No GPU reset, MMIO, original mutex, cache ownership or full kernel executes.'}
    (ROOT/'reports/adreno-display-timeline.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(cases)} actual linked A830 snapshot/epoch CPU cases; native compiler layouts match production; no hardware access')


if __name__=='__main__':main()
