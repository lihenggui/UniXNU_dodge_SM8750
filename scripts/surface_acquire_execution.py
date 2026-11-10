#!/usr/bin/env python3
"""Execute actual observer/acquisition and original setter/free dispatch on ARM64."""
import json
from pathlib import Path
import struct
import subprocess

from check_adreno_display_timeline import parse_layout
from native_driver_build import ROOT,require,macho
from prepare_surface_backing import checked,hook_readbacks,branch
from surface_pages_execution import Execution as PageExecution,layouts as page_layouts
from surface_identity_execution import SourceExecution


def layouts(out):
    facts,artifacts,old_recipe=page_layouts(out)
    recipe=ROOT/'build/cph2653-surface-acquire/native/compile-commands.json'
    record,=json.loads(recipe.read_text());command=record['arguments'][:]
    production=Path(command[command.index('-o')+1]);obj=out/'backing-layout.o';log=out/'backing-layout.log'
    command[command.index('-o')+1]=str(obj);command+=['-Xclang','-fdump-record-layouts']
    result=subprocess.run(command,cwd=record['directory'],capture_output=True,text=True)
    log.write_text(result.stdout+result.stderr)
    def text(path):
        raw=path.read_bytes();image=macho(raw);s,=[s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
        return raw[s['fileoff']:s['fileoff']+s['size']]
    require(not result.returncode and text(production)==text(obj),'Backing ownership layout probe changed production instructions')
    facts['observer_entry']=parse_layout(log.read_text(),'(anonymous namespace)::Entry',('surface','backing','next'))
    require(facts['observer_entry']=={'bytes':24,'fields':{'surface':0,'backing':8,'next':16}},'Observer entry layout changed')
    return facts,[*artifacts,obj,log],[old_recipe,recipe]


class Execution(PageExecution):
    def __init__(self,raw,facts,probe,contract,control=None):
        self.registry_ranges=[];self.registry_mutexes=set();self.freed_entries=set();self.allocated_entries=set()
        super().__init__(raw,facts,probe)
        m=self.m;self.ownership_contract=contract;hook_readbacks(raw,contract)
        self.registry=m.names['__ZN12_GLOBAL__N_17entriesE'];self.count=m.names['__ZN12_GLOBAL__N_110entryCountE']
        self.lock_pointer=m.names['__ZN12_GLOBAL__N_112registryLockE']
        self.registry_ranges=[(self.registry,512),(self.count,4),(self.lock_pointer,8)]
        self.alloc_fail=self.lock_fail=self.init_fail=self.cas_race=False
        self.original_init_calls=self.original_final_calls=self.entry_frees=self.lock_frees=0
        self.registry_depth=0;self.second=self.allocate(facts['descriptor']['bytes'],'replacement-descriptor')
        self.p64(self.second,self.table_md);self.p32(self.second+8,1)
        self.p32(self.backing+8,2) # external owner and original surface field ownership
        self.copy_output=self.allocate(8,'owned-descriptor-output')
        for name,h in contract['hooks'].items():
            entry=self.a(int(h['entry'],16));self.blocks[entry]='hooked-original-'+name
            self.blocks[entry+4]='original-'+name+'-body'
            self.source_entries[m.names[h['wrapper']]]=h['wrapper']
            self.source_entries[m.names[h['trampoline']]]=h['trampoline']
        for name in ('_dodge_copy_surface_backing','_dodge_surface_pages_acquire'):
            self.source_entries[m.names[name]]=name
        for name,fn in (('_IOLockAlloc',self.lock_alloc),('_IOLockFree',self.lock_free),
            ('_lck_mtx_lock',self.registry_lock),('_lck_mtx_unlock',self.registry_unlock),
            ('_IOMalloc_internal',self.entry_alloc),('_IOFree',self.entry_free)):
            self.peer('observer-primitive-'+name,fn,m.names[name])
        # Only original init's remainder is a peer. The real patched entry,
        # wrapper, trampoline and displaced SUB execute before reaching it.
        init_resume=self.a(int(contract['hooks']['init']['entry'],16))+4
        self.blocks.pop(init_resume)
        self.peer('original-init-remainder',self.init_remainder,init_resume)
        self.stub('original-descriptor-debug-address',0xfffffff005a67534,lambda a:self.m.returned(0))
        self.stub('original-lifecycle-kdebug',0xfffffff005a67738,lambda a:self.m.returned(0))
        self.stub('original-lifecycle-accounting',0xfffffff005a678ac,self.accounting)
        self.stub('original-root-final-unregister',0xfffffff005a5b488,self.unregister)
        self.stub('original-surface-final-destructor',0xfffffff005a4c414,self.final_destructor)
        # Metadata is a peer, native tagged retain/release and reference-zero
        # dispatch execute. Concrete descriptor free is a separate boundary.
        self.p64(self.table_md+14*8,self.peer('concrete-descriptor-final-free',self.descriptor_free))
        self.kernel=self.allocate(32,'kernel-task');self.current_task=self.task
        self.matching=self.allocate(32,'matching-dictionary');self.refs[self.root]=self.refs[self.matching]=1
        self.matching_failed=self.root_missing=self.root_inactive=self.root_wrong=self.surface_wrong=self.terminate_late=False
        self.match_calls=self.inactive_calls=0
        for obj in (self.root,self.matching):
            table=self.allocate(16*8,'source-provider-vtable');self.p64(obj,table)
            self.p64(table+40,self.peer('provider-release-'+hex(obj),self.provider_release))
        self.p64(m.names['_kernel_task'],self.kernel)
        for name,fn in (('_current_task',lambda a:m.returned(self.current_task)),
            ('__ZN9IOService12nameMatchingEPKcP12OSDictionary',self.match),
            ('__ZN9IOService19copyMatchingServiceEP12OSDictionary',self.matching_service),
            ('__ZNK9IOService10isInactiveEv',self.inactive)):
            self.peer('acquire-source-primitive-'+name,fn,m.names[name])
        m.peers[m.names['__ZNK15OSMetaClassBase8metaCastEPKc']]=('acquire-metacast',self.meta_cast)
        if control:
            name,words=control;m.put(m.names[name],struct.pack('<'+str(len(words))+'I',*words))

    provider_release=SourceExecution.provider_release
    match=SourceExecution.match
    matching_service=SourceExecution.matching_service
    inactive=SourceExecution.inactive

    def memory(self,cpu,kind,address,size,value,ignored):
        if any(at<=address and address+size<=at+n for at,n in self.registry_ranges):
            if self.registry<=address<self.registry+512 or self.count<=address<self.count+4:
                require(self.registry_depth,'Observer table/count accessed without its mutex')
            return
        require(not any(at<=address<at+24 for at in self.freed_entries),'Observer touched a freed registry entry')
        super().memory(cpu,kind,address,size,value,ignored)

    def lock_alloc(self,args):
        require(not self.registry_depth,'Observer allocated a mutex under its mutex')
        if self.lock_fail:self.m.returned(0);return
        result=self.allocate(64,'observer-mutex');self.registry_mutexes.add(result)
        if self.cas_race and not self.u64(self.lock_pointer):
            winner=self.allocate(64,'competing-observer-mutex');self.registry_mutexes.add(winner)
            self.p64(self.lock_pointer,winner)
        self.m.returned(result)
    def lock_free(self,args):
        require(args[0] in self.registry_mutexes and args[0]!=self.u64(self.lock_pointer) and not self.registry_depth,
            'Observer freed its winning mutex or freed under a lock')
        self.registry_mutexes.remove(args[0]);self.lock_frees+=1;self.m.returned()
    def registry_lock(self,args):
        require(args[0]==self.u64(self.lock_pointer) and args[0] in self.registry_mutexes and not self.registry_depth and
            not any(self.locks.values()),'Observer mutex entered with original lookup locks held')
        self.registry_depth=1;self.m.returned()
    def registry_unlock(self,args):
        require(args[0]==self.u64(self.lock_pointer) and self.registry_depth==1,'Observer mutex imbalance')
        self.registry_depth=0;self.m.returned()
    def entry_alloc(self,args):
        require(not self.registry_depth and args[1:3]==[24,0],'Observer entry allocation shape/lock changed')
        if self.alloc_fail:self.m.returned(0);return
        result=self.allocate(24,'observer-entry');self.allocated_entries.add(result);self.m.returned(result)
    def entry_free(self,args):
        require(not self.registry_depth and args[:2]==[args[0],24] and args[0] in self.allocated_entries and
            args[0] not in self.freed_entries,'Observer freed an unknown entry or freed under its mutex')
        self.freed_entries.add(args[0]);self.entry_frees+=1;self.m.returned()
    def init_remainder(self,args):
        require(args[:5]==[self.surface,self.root,self.task,0,0] and not self.registry_depth,'Original init call ABI/locking changed')
        self.original_init_calls+=1
        # The displaced instruction already reserved the original 96-byte frame.
        sp=self.m.cpu.reg_read(self.m.arm.UC_ARM64_REG_SP)
        self.m.cpu.reg_write(self.m.arm.UC_ARM64_REG_SP,sp+96)
        self.m.returned(0 if self.init_fail else 1)
    def accounting(self,args):
        require(args[0] in (0,self.backing,self.second),'Original descriptor accounting saw an unowned pointer')
        self.p64(args[1],0);self.m.returned()
    def unregister(self,args):
        require(args[:2]==[self.root,self.surface] and not self.registry_depth,'Original root final-unregister peer ABI changed')
        self.p64(self.table+self.id*8,0);self.m.returned()
    def final_destructor(self,args):
        require(args[0]==self.surface and not self.registry_depth and not self.observed(),'Observer survived into final original destructor')
        self.original_final_calls+=1
        # The concrete surface destructor/allocator is explicitly a peer. Drop
        # only its fixture ownership; normal clears above use real ARM64 release.
        md=self.u64(self.surface+56)
        if md:self.p32(md+8,self.u32(md+8)-1);self.p64(self.surface+56,0)
        self.m.returned()
    def descriptor_free(self,args):
        require(args[0] in (self.backing,self.second) and not self.registry_depth,'Concrete descriptor final free boundary changed')
        self.m.returned()
    def meta_cast(self,args):
        name=self.m.string(args[1]);allowed={(self.root,'IOSurfaceRoot'),(self.surface,'IOSurface'),
            (self.backing,'IOMemoryDescriptor'),(self.second,'IOMemoryDescriptor')}
        require((args[0],name) in allowed,'Unexpected acquisition metadata check')
        wrong=self.root_wrong if args[0]==self.root else self.surface_wrong if args[0]==self.surface else False
        self.m.returned(0 if wrong else args[0])
    def observed(self):
        entry=self.u64(self.registry+((self.surface>>4)&63)*8)
        while entry:
            require(entry in self.allocated_entries and entry not in self.freed_entries,'Registry links escaped live entries')
            if self.u64(entry)==self.surface:return entry
            entry=self.u64(entry+16)
        return 0
    def original_call(self,name,args):
        h=self.ownership_contract['hooks'][name];self.m.names['original-hook-call']=self.a(int(h['entry'],16))
        return self.m.call('original-hook-call',args)
    def start(self):return self.original_call('init',[self.surface,self.root,self.task,0,0])
    def replace(self,md):return self.original_call('replace',[self.surface,md])
    def clear(self):return self.original_call('clear',[self.surface])
    def copy(self,identity=None,output=None):
        return self.m.call('_dodge_copy_surface_backing',[self.identity if identity is None else identity,self.copy_output if output is None else output])
    def drop_copy(self):
        md=self.u64(self.copy_output);require(md in (self.backing,self.second),'No owned descriptor to release')
        self.m.call('__ZNK8OSObject7releaseEv',[md]);self.p64(self.copy_output,0)
    def acquire(self,id=None):return self.m.call('_dodge_surface_pages_acquire',[self.id if id is None else id,self.memory_object,self.association])
    def finish(self,name,quarantine=False):
        require(not self.registry_depth and not any(self.locks.values()) and
            self.refs=={self.client:1,self.root:1,self.matching:1},'Acquisition leaked a primitive provider/lookup mutex')
        if not quarantine and self.u64(self.copy_output):self.drop_copy()
        if not quarantine and self.u64(self.surface+56):self.clear()
        require(not self.observed() and not self.u32(self.count),'Acquisition leaked a registry entry')
        if not quarantine:
            require(self.u32(self.backing+8)==self.u32(self.second+8)==1 and not self.prepared and
                not self.field('memory','device_references_'),'Acquisition leaked actual native descriptor/device ownership')
        row=self.result(name);row.update({'original_init_remainder_is_peer':True,'original_final_destructor_is_peer':True,
            'original_final_free_bodies':self.original_final_calls,'observer_entry_frees':self.entry_frees,
            'observer_mutex_loser_frees':self.lock_frees,'retained_quarantine':quarantine})
        return row


def cases(raw,facts,probe,contract,control=None):
    rows=[]
    def new():return Execution(raw,facts,probe,contract,control)
    e=new();require(e.start()==1 and e.u32(e.backing+8)==3 and e.observed(),'Original init entry failed to capture ownership')
    require(not e.copy() and e.u64(e.copy_output)==e.backing and e.u32(e.backing+8)==4,'Actual source did not copy an owned descriptor')
    rows.append(e.finish('hooked-init-owned-reference-copy-and-clear'))
    e=new();require(e.start()==1 and not e.copy(),'Owned copy before clear failed');e.clear()
    require(e.u32(e.backing+8)==2,'Original clear dropped a copied descriptor too early');e.drop_copy();rows.append(e.finish('copy-survives-original-clear'))
    e=new();require(e.start()==1 and not e.copy(),'Owned copy before replacement failed');e.replace(e.second)
    require(e.u32(e.backing+8)==2 and e.u32(e.second+8)==3,'Original replace/observer ownership changed');e.drop_copy()
    require(not e.copy() and e.u64(e.copy_output)==e.second,'Replacement not observed');rows.append(e.finish('copy-survives-original-replacement'))
    e=new();e.init_fail=True;require(e.start()==0 and not e.observed() and e.u32(e.backing+8)==2,'Failed init was observed');rows.append(e.finish('failed-init-never-captured'))
    e=new();e.alloc_fail=True;require(e.start()==1 and not e.observed() and e.copy()==0xe00002d8,'Missing registry allocation did not refuse');rows.append(e.finish('observer-entry-OOM-refuses-copy'))
    e=new();e.lock_fail=True;require(e.start()==1 and not e.observed() and e.copy()==0xe00002bd,'Missing mutex did not refuse copy')
    e.lock_fail=False;rows.append(e.finish('observer-mutex-OOM-preserves-original-init'))
    e=new();e.p32(e.count,4096);require(e.start()==1 and not e.observed() and e.copy()==0xe00002d8,'Full registry did not refuse')
    e.p32(e.count,0);rows.append(e.finish('registry-capacity-boundary-with-explicit-count-fixture'))
    e=new();require(e.start()==1,'Init failed');e.alloc_fail=True;e.replace(e.second)
    require(not e.copy() and e.u64(e.copy_output)==e.second,'Existing observer update incorrectly depends on fresh allocation')
    rows.append(e.finish('existing-entry-replacement-despite-OOM'))
    e=new();require(e.start()==1,'Init failed');e.p64(e.surface+56,0xdeadbeef)
    require(e.copy()==0xe00002d8 and not e.u64(e.copy_output),'Arbitrary borrowed pointer was retained or accepted')
    e.p64(e.surface+56,e.backing);rows.append(e.finish('unowned-arbitrary-getter-value-compared-only'))
    e=new();require(e.start()==1,'Init failed');e.clear()
    require(e.copy()==0xe00002d8 and not e.u64(e.copy_output),'Cleared surface still acquires');rows.append(e.finish('copy-after-clear-refused'))
    e=new();require(e.start()==1,'Init failed');e.replace(0)
    require(e.copy()==0xe00002d8 and e.u32(e.backing+8)==1,'Null replacement still acquires');e.clear();rows.append(e.finish('null-replacement-owned-reference-removed'))
    e=new();require(e.start()==1,'Init failed');e.p64(e.copy_output,e.second)
    require(e.copy()==0xe00002c2 and e.u64(e.copy_output)==e.second and e.u32(e.second+8)==1,'Occupied output ownership changed')
    e.p64(e.copy_output,0);rows.append(e.finish('occupied-copy-output-refused'))
    e=new();require(e.copy(identity=0)==0xe00002c2 and e.copy(output=0)==0xe00002c2,'Null acquisition inputs accepted');rows.append(e.finish('null-copy-inputs-refused'))
    e=new();e.cas_race=True;require(e.start()==1 and e.lock_frees==1 and not e.copy(),'Losing mutex initialization was not balanced')
    rows.append(e.finish('actual-CAS-loser-with-explicit-competing-winner-fixture'))
    e=new();require(e.start()==1,'Init failed');e.p32(e.surface+1000,1);e.m.put(e.identity,bytes(16))
    e.m.call('_dodge_identity_release',[e.surface])
    require(e.original_final_calls==1 and e.u32(e.backing+8)==1 and not e.observed(),'Reference-zero virtual free did not erase observer')
    rows.append(e.finish('original-custom-reference-zero-through-hooked-free'))
    e=new();require(e.start()==1,'Init failed');e.original_call('free',[e.surface])
    require(not e.observed() and e.u32(e.backing+8)==1,'Free left an old pointer identity')
    # New construction at the same address is an explicit allocator fixture.
    e.p32(e.surface+12,e.id);e.p32(e.surface+1000,2);e.p64(e.surface+56,e.second);e.p32(e.second+8,2)
    require(e.start()==1 and not e.copy() and e.u64(e.copy_output)==e.second,'Surface address reuse inherited stale backing')
    rows.append(e.finish('surface-address-reuse-explicit-allocator-fixture'))
    e=new();require(e.start()==1 and not e.acquire(),'Current-task -> owned backing -> exact GPU pages failed')
    require(e.field('memory','device_references_')==1 and e.u32(e.backing+8)==4 and e.u32(e.surface+1000)==3,
        'Integrated acquisition lost owners');require(not e.release(),'Integrated association release failed')
    rows.append(e.finish('actual-current-task-original-lookup-owned-copy-and-page-association'))
    e=new();require(e.start()==1,'Init failed');e.client_mode('dynamic');e.m.put(e.surface+867,b'\1')
    require(not e.acquire() and not e.release(),'Original registered client authorization failed in acquisition')
    rows.append(e.finish('registered-client-permission-through-original-task-cache-and-member-table'))
    e=new();require(e.start()==1,'Init failed');e.p64(e.surface+112,e.foreign);e.m.put(e.surface+867,b'\1')
    require(e.acquire()==0xe00002e2 and e.u32(e.backing+8)==3 and e.u32(e.surface+1000)==2,'Unauthorized task copied backing')
    rows.append(e.finish('foreign-task-refused-before-copy'))
    e=new();require(e.start()==1,'Init failed');e.current_task=e.kernel
    require(e.acquire()==0xe00002e2 and not e.match_calls,'Kernel worker impersonated user task');rows.append(e.finish('kernel-task-refused-before-lookup'))
    e=new();require(e.acquire()==0xe00002d8 and e.u32(e.surface+1000)==2,'Untracked acquisition leaked lookup result')
    rows.append(e.finish('untracked-original-surface-refused-and-identity-balanced'))
    e=new();require(e.start()==1,'Init failed');e.physical[1]+=4096
    require(e.acquire()==0xe00002e2 and e.u32(e.backing+8)==3 and e.u32(e.surface+1000)==2,'Page mismatch acquisition lost owners')
    rows.append(e.finish('integrated-physical-page-mismatch-rolls-back'))
    e=new();require(e.start()==1,'Init failed');e.prepare_failed=True
    require(e.acquire()==0xe00002ca and e.u32(e.backing+8)==3 and e.u32(e.surface+1000)==2,'Prepare failure leaked acquisition ownership')
    rows.append(e.finish('integrated-prepare-failure-rolls-back'))
    e=new();require(e.start()==1,'Init failed');e.complete_failed=True;e.physical[1]+=4096
    require(e.acquire()==0xe00002ca and e.field('association','quarantined') and e.field('memory','quarantined_') and
        e.u32(e.backing+8)==4 and e.u32(e.surface+1000)==3,'Quarantine lost acquired owners')
    e.clear();rows.append(e.finish('integrated-complete-error-retains-quarantined-association',True))
    e=new();require(e.start()==1 and not e.acquire(),'Acquisition before additional native hold failed')
    require(not e.call_part('NativeAdrenoMemory13holdForDevice',[e.memory_object]) and e.release()==0xe00002d5 and not e.complete_calls,
        'Additional native reference did not defer unprepare')
    require(not e.call_part('NativeAdrenoMemory21retireAfterQuiescence',[e.memory_object]) and not e.release(),'Real native reference retirement failed')
    rows.append(e.finish('integrated-extra-native-device-hold-defers-release'))
    e=new();e.p64(e.surface+56,0);e.p32(e.backing+8,1);require(e.start()==1 and e.copy()==0xe00002d8,'Empty initial backing accepted')
    e.replace(e.second);require(not e.copy() and e.u64(e.copy_output)==e.second,'Later owned replacement was not captured')
    rows.append(e.finish('initially-empty-surface-later-original-replacement'))
    require(len(rows)==26,'Unexpected owned acquisition case inventory')
    return rows


def controls(raw,facts,probe,contract):
    from check_data_mount_kernel import Model
    m=Model(raw);names=m.names;rows=[]
    settings=[('copy-false-success','_dodge_copy_surface_backing',(0x52800000,0xd65f03c0)),
        ('init-observation-skipped','_dodge_iphone_surface_init',(branch(names['_dodge_iphone_surface_init'],names['_dodge_original_surface_init']),)),
        ('final-forget-skipped','_dodge_iphone_surface_free',(branch(names['_dodge_iphone_surface_free'],names['_dodge_original_surface_free']),)),
        ('replacement-observation-skipped','_dodge_iphone_surface_replace',(branch(names['_dodge_iphone_surface_replace'],names['_dodge_original_surface_replace']),)),
        ('page-acquisition-false-success','_dodge_surface_pages_acquire',(0x52800000,0xd65f03c0))]
    for label,name,words in settings:
        try:cases(raw,facts,probe,contract,(name,words))
        except ValueError as error:rows.append({'case':label,'result':'REJECTED','reason':str(error)})
        else:raise ValueError('Surface ownership checker accepted broken source instructions: '+label)
    return rows
