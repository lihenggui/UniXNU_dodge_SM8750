#!/usr/bin/env python3
"""Execute linked GOP factory guards and the real original provider allocation."""
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT,NATIVE,TREE,macho,require,sha,symbols,inspect_object
from native_prelink import backed_offset
from prepare_gop_provider import FIXTURE

DEPENDENCIES=('ios16-gop-provider','ios16-graphics-late','ios16-display-kernel','ios16-display-prelink')
CASES=('factory-null-out','factory-null-platform','unpublished-status','factory-wrong-platform','factory-modules-not-ready',
       'factory-metadata-identity','factory-metadata-size','factory-metadata-parent','factory-init-failure',
       'factory-memory-allocation-failure','original-allocation-and-d0','original-allocation-and-d1',
       'original-resources-existing-memory','original-resources-missing-memory',
       'late-hook-default-disabled','late-hook-explicit-zero','late-hook-explicit-other','late-hook-opt-in-queued')


def emulate(path,case,control=None):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw);fixture=json.loads(FIXTURE.read_text());slide=int(fixture['slide'],0)
    named=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14]
    names={s['name']:s['value'] for s in named};reverse={}
    for s in named:reverse.setdefault(s['value'],[]).append(s['name'])
    def read(a,n):return raw[backed_offset(image['segments'],a,n,len(raw)):][:n]
    def q(a):return struct.unpack('<Q',read(a,8))[0]
    def table(vptr,slot):return q(vptr+8*slot)
    meta=int(fixture['linked_metaclass'],16);vptr=int(fixture['vptr'],16)+slide
    meta_vptr=int(fixture['metadata_vptr'],16)+slide
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
    def put(a,data=b'',size=0):
        p=a&~4095;last=(a+max(size,len(data))+4095)&~4095
        while p<last:
            if p in pages:p+=4096;continue
            end=p+4096
            while end<last and end not in pages:end+=4096
            uc.mem_map(p,end-p);pages.update(range(p,end,4096));p=end
        if data:uc.mem_write(a,data)
    data_ranges=[]
    for seg in image['segments']:
        if not seg['size'] or not seg['initprot']:continue
        require(seg['size']<256*1024*1024,'Unexpected provider candidate segment size')
        put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
        if seg['initprot']&2:data_ranges.append((seg['va'],seg['size']))
    storage,instance,platform,symbol,array,buffer,stack,halt=0x200000,0x200040,0x210000,0x220000,0x230000,0x240000,0x300000,0x400000
    for a,n in ((storage,4096),(platform,4096),(symbol,4096),(array,4096),(buffer,4096),(stack,65536),(halt,4096)):put(a,size=n)
    put(storage,b'\xa5'*(216+128));put(platform,struct.pack('<Q',names['__ZTV9IOService']+16)+bytes(128))
    put(symbol,struct.pack('<Q',names['__ZTV8OSObject']+16))
    # Lookup/registration is an explicit peer. This data-only vptr represents
    # that registered metaclass, not execution of its real loader constructor.
    put(meta,struct.pack('<Q',meta_vptr));put(buffer+1024,b'dodge-gop\0')
    refs={platform:1,symbol:0};events=[];visits=[];allocation_view=[None];constructed=[False];freed=[False]
    handlers={}
    def args(n=8):return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(n)]
    def returned(value=0):
        uc.reg_write(reg.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def cstring(a):
        out=bytearray()
        for i in range(256):
            value=bytes(uc.mem_read(a+i,1))
            if value==b'\0':return out.decode()
            out+=value
        raise ValueError('Unbounded provider string peer')
    def bind(name,action):
        require(name in names,'Missing native provider API: '+name);a=names[name]
        require(a not in handlers,'Provider API peers collide: '+name);handlers[a]=(name,action)
    def retain(a):
        require(a[0] in refs and refs[a[0]]>0,'Retain of unknown provider peer');refs[a[0]]+=1;returned()
    def release(a):
        require(a[0] in refs and refs[a[0]]>0,'Release of dead provider peer');refs[a[0]]-=1
        if a[0]==instance and not refs[instance]:
            # Execute the actual original deleting destructor after the public
            # release peer decides it is last. Full IOService::free is a peer.
            uc.reg_write(reg.UC_ARM64_REG_PC,table(vptr,1));return
        returned()
    bind('__ZNK8OSObject6retainEv',retain);bind('__ZNK8OSObject7releaseEv',release)
    def allocated(a):
        require(a[1]==216 and not constructed[0] and not refs.get(instance),'Original typed allocation receiver/size changed')
        allocation_view[0]=a[0];events.append('typed-allocation')
        put(instance,(b'\x5a' if control=='nonzero-typed-allocation' else b'\0')*216);refs[instance]=1;returned(instance)
    if control!='unknown-native-allocator':bind('_OSObject_typed_operator_new',allocated)
    def instance_constructed(a):
        require(a[0]==meta and refs.get(instance)==1,'Original provider instance accounting changed')
        constructed[0]=True;events.append('instance-constructed');returned()
    bind('__ZNK11OSMetaClass19instanceConstructedEv',instance_constructed)
    def deallocated(a):
        require(a[:3]==[allocation_view[0],instance,216] and not freed[0],'Original deleting destructor changed typed free arguments')
        require(bytes(uc.mem_read(instance,8))==b'\xff'*8,'Actual native destructor did not poison the vptr')
        freed[0]=True;events.append('typed-free');returned()
    bind('_OSObject_typed_operator_delete',deallocated)
    def provider_of(a):returned(platform if a[0]==instance else 0)
    bind('__ZNK9IOService11getProviderEv',provider_of)
    bind('__ZN9IOService15getDeviceMemoryEv',lambda a:returned(0 if case=='original-resources-missing-memory' else array))
    def safe_cast(a):
        if a[0]==instance:
            require(a[1]==names['__ZN9IOService10gMetaClassE'] and constructed[0],'Source factory cast lost the real native parent')
            returned(instance)
        else:returned(0)
    bind('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass',safe_cast)
    bind('__ZN9IOService11getPlatformEv',lambda a:returned(0 if case=='factory-wrong-platform' else platform))
    def meta_cast(a):
        require(a[0]==platform and cstring(a[1])=='IODTPlatformExpert','Factory accepted a non-DT platform peer');returned(platform)
    bind('__ZNK15OSMetaClassBase8metaCastEPKc',meta_cast)
    bind('__ZNK9IOService10isInactiveEv',lambda a:returned(0))
    def status(a):put(a[0],struct.pack('<3I',0 if case=='factory-modules-not-ready' else 2,0,0));returned()
    bind('_dodge_graphics_status',status)
    def console(a):
        # PE_Video layout is from the actual source-kernel public header.
        value=struct.pack('<6Q',0x123400000,5760,1440,3168,32,1)+bytes(96)
        put(a[0],value);returned(0)
    bind('_PE_current_console',console)
    def new_symbol(a):
        require(cstring(a[0])=='AppleARMIODevice','Factory metadata name differs');refs[symbol]=1;returned(symbol)
    bind('__ZN8OSSymbol17withCStringNoCopyEPKc',new_symbol)
    other_meta=meta+0x1000
    def copy_meta(a):
        require(a[0]==symbol and refs[symbol]==1,'Factory metadata lookup ownership differs')
        refs[meta]=1;returned(other_meta if case=='factory-metadata-identity' else meta)
        if case=='factory-metadata-identity':refs[other_meta]=1;refs[meta]=0
    bind('__ZN11OSMetaClass21copyMetaClassWithNameEPK8OSSymbol',copy_meta)
    bind('__ZNK11OSMetaClass12getClassSizeEv',lambda a:returned(217 if case=='factory-metadata-size' else 216))
    bind('__ZNK11OSMetaClass13getSuperClassEv',lambda a:returned(0 if case=='factory-metadata-parent' else names['__ZN9IOService10gMetaClassE']))
    def release_meta(a):
        require(a[0] in (meta,other_meta) and refs[a[0]]==1,'Factory did not balance its original metadata pin');refs[a[0]]=0;returned()
    bind('__ZNK11OSMetaClass16releaseMetaClassEv',release_meta)
    def init(a):
        require(a[0]==instance and a[1]==0 and constructed[0] and q(vptr+21*8)==names['__ZN9IOService4initEP12OSDictionary'],
                'Factory used an Apple bus initializer instead of inherited public init')
        events.append('public-init-peer');returned(case=='factory-memory-allocation-failure')
    bind('__ZN9IOService4initEP12OSDictionary',init)
    # Resolve the public name methods by symbol instead of assuming slots.
    for name in names:
        if name.startswith('__ZN15IORegistryEntry7setNameEPKc'):
            bind(name,lambda a:returned());break
    def get_name(a):returned(buffer+1024)
    bind('__ZNK15IORegistryEntry7getNameEPK15IORegistryPlane',get_name)
    bind('_strcmp',lambda a:returned(0 if cstring(a[0])==cstring(a[1]) else 1))
    bind('__ZN14IODeviceMemory9withRangeEyy',lambda a:returned(0))
    late_state={'published':False,'queued':0,'deallocated':0}
    def publish_iobsd(a):
        require(cstring(a[0])=='IOBSD' and not a[1],'Actual late hook published a different resource')
        late_state['published']=True;returned()
    bind('__ZN9IOService15publishResourceEPKcP8OSObject',publish_iobsd)
    def boot_arg(a):
        require(late_state['published'] and cstring(a[0])=='dodge-graphics' and a[2]==4,'Late scheduling ran before actual IOBSD publication')
        value=1 if case=='late-hook-opt-in-queued' else 2 if case=='late-hook-explicit-other' else 0
        put(a[1],struct.pack('<I',value));returned(case!='late-hook-default-disabled')
    bind('_PE_parse_boot_argn',boot_arg)
    def queue(a):
        require(late_state['published'] and a[0]==names['__ZN12_GLOBAL__N_16workerEPvi'] and not a[1] and a[2],
                'Late hook did not queue its actual independent worker')
        late_state['queued']+=1;put(a[2],struct.pack('<Q',buffer+2048));returned(0)
    bind('_kernel_thread_start',queue)
    def deallocate_thread(a):
        require(a[0]==buffer+2048 and late_state['queued']==1,'Late hook lost its kernel thread reference')
        late_state['deallocated']+=1;returned()
    bind('_thread_deallocate',deallocate_thread)
    # The unmodified polled-corefile branch follows the late hook on this
    # kernel configuration. Its allocation API is a peer and returns null.
    bind('_thread_call_allocate_with_options',lambda a:returned(0))
    allowed=[]
    for obj in (ROOT/'build/ios16-gop-provider/DodgeGopProvider.o',ROOT/'build/ios16-graphics-late/DodgeGraphicsLate.o'):
        obj_raw=obj.read_bytes();obj_image=inspect_object(obj_raw)
        text=next(s for seg in obj_image['segments'] for s in seg['sections'] if s['name']=='__text')
        own=sorted((s for s in symbols(obj_raw) if s['section']==1 and s['kind']&14 and not s['kind']&0xe0 and not s['name'].startswith('ltmp')),key=lambda s:s['value'])
        for i,s in enumerate(own):
            length=(own[i+1]['value'] if i+1<len(own) else text['va']+text['size'])-s['value']
            allowed.append((names[s['name']],length))
    allowed.append((names['_IOKitBSDInit'],72))
    native_functions={name:(names[symbol_name],length) for name,symbol_name,length in (
        ('IOService.C2','__ZN9IOServiceC2EPK11OSMetaClass',32),('IORegistryEntry.C2','__ZN15IORegistryEntryC2EPK11OSMetaClass',32),
        ('OSObject.C2','__ZN8OSObjectC2EPK11OSMetaClass',40),('OSMetaClassBase.C2','__ZN15OSMetaClassBaseC2Ev',16),
        ('IOService.D2','__ZN9IOServiceD2Ev',4),('IORegistryEntry.D2','__ZN15IORegistryEntryD2Ev',4),
        ('OSObject.D2','__ZN8OSObjectD2Ev',4),('OSMetaClassBase.D2','__ZN15OSMetaClassBaseD2Ev',12))}
    allowed.extend(native_functions.values())
    original={'allocator':(int(fixture['blocks']['allocator']['address'],16)+slide,84),
              'get-meta-class':(table(vptr,7),12),'get-resources':(table(vptr,119),156),
              'D1':(table(vptr,0),4),'D0':(table(vptr,1),48)}
    allowed.extend(original.values())
    allowed.extend((a+slide,12) for a in (0xfffffff005626ab8,0xfffffff005627028,0xfffffff00562704c,
                                       0xfffffff005627034,0xfffffff005626aac,0xfffffff005626d64))
    def hook(engine,a,size,user):
        if a in handlers:
            name,action=handlers[a];events.append(name);action(args());return
        require(any(start<=a<start+n for start,n in allowed),'Unknown native provider implementation: '+','.join(reverse.get(a,[hex(a)])))
        for name,(start,n) in {**native_functions,**original}.items():
            if a==start:visits.append(name)
    def write(engine,kind,a,n,value,user):
        require(instance<=a and a+n<=instance+216 or stack<=a and a+n<=stack+65536 or buffer<=a and a+n<=buffer+4096 or
                any(start<=a and a+n<=start+length for start,length in data_ranges),
                'Provider code wrote an allocation canary or unowned memory')
    uc.hook_add(UC_HOOK_CODE,hook);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    def execute(a,*arguments):
        for i,v in enumerate(arguments):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),v)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
        uc.emu_start(a,halt,timeout=1000000,count=20000)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'Provider CPU path did not return')
        return uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff
    if case.startswith('late-hook-'):
        result=execute(names['_IOKitBSDInit'])
        require(result==0 and late_state['published'],'Actual isolated IOBSD hook did not preserve initialization success')
        execute(names['_dodge_graphics_late_status'],buffer)
        late_phase=struct.unpack('<I',uc.mem_read(buffer,4))[0]
        enabled=case=='late-hook-opt-in-queued'
        require(late_phase==(1 if enabled else 0) and late_state['queued']==late_state['deallocated']==int(enabled),
                'Actual late hook ignored the explicit opt-in or lost its queued worker')
        require(not constructed[0],'IOBSD caller constructed graphics synchronously')
    elif case=='unpublished-status':
        execute(names['_dodge_gop_provider_status'],buffer)
        status=bytes(uc.mem_read(buffer,48));require(struct.unpack_from('<I',status)[0]==0 and status[8:]==bytes(40),'Cold provider status invented a physical resource')
    elif case.startswith('factory-'):
        put(buffer,b'\xa5'*16)
        result=execute(names['_dodge_gop_provider_publish'],0 if case=='factory-null-platform' else platform,0 if case=='factory-null-out' else buffer)
        expected=0xe00002c2 if case in ('factory-null-out','factory-null-platform') else 0xe00002d8 if case in ('factory-modules-not-ready','factory-init-failure') else 0xe00002bd if case=='factory-memory-allocation-failure' else 0xe00002c7
        require(result==expected,'Source provider guard returned a different error: '+hex(result))
        require(bytes(uc.mem_read(buffer,8))==(b'\xa5'*8 if case=='factory-null-out' else bytes(8)),'Source factory changed output ownership')
        require(refs[platform]==1 and refs[symbol]==0 and not refs.get(meta) and not refs.get(other_meta),'Source factory leaked platform/symbol/metadata ownership')
        if case in ('factory-init-failure','factory-memory-allocation-failure'):
            require(constructed[0] and freed[0] and refs[instance]==0,'Factory did not unwind its real original provider')
        else:require(not constructed[0],'Refused factory allocated a provider')
        execute(names['_dodge_gop_provider_status'],buffer+128)
        require(struct.unpack('<I',uc.mem_read(buffer+128,4))[0]==0,'Unpublished factory failure was not retryable')
    elif case.startswith('original-resources-'):
        put(instance,struct.pack('<Q',vptr)+bytes(208));refs[instance]=1
        result=execute(original['get-resources'][0],instance)
        require(result==(0xe00002bc if case=='original-resources-missing-memory' else 0),'Original getResources memory-first behavior changed')
        require('allocator' not in visits,'Resource check unexpectedly allocated the class')
    else:
        execute(table(meta_vptr,13),meta)
        expected=bytearray(216);struct.pack_into('<Q',expected,0,vptr);struct.pack_into('<I',expected,8,1)
        require(bytes(uc.mem_read(instance,216))==expected,'Original typed allocation is not zero outside constructor fields')
        require(constructed[0] and visits[:5]==['allocator','IOService.C2','IORegistryEntry.C2','OSObject.C2','OSMetaClassBase.C2'],
                'Original allocator did not execute the complete native parent constructor chain')
        execute(table(vptr,7),instance)
        require(uc.reg_read(reg.UC_ARM64_REG_X0)==meta,'Actual original provider reports another class identity')
        execute(table(vptr,1 if case.endswith('d0') else 0),instance)
        require(bytes(uc.mem_read(instance,8))==b'\xff'*8,'Original provider did not run the complete native destructor chain')
        require(freed[0]==case.endswith('d0'),'Typed deleting destructor dispatch changed')
    require(bytes(uc.mem_read(storage,64))==b'\xa5'*64 and bytes(uc.mem_read(instance+216,64))==b'\xa5'*64,'Provider allocation canary changed')
    return {'case':case,'result':'PASS','original_allocator_executed':'allocator' in visits,
            'actual_native_parent_constructor_entries':[n for n in visits if n.endswith('.C2')],
            'original_provider_functions':[n for n in visits if n in original],
            'typed_delete_executed':freed[0],'object_canaries_preserved':True,'api_peer_calls':events,
            'actual_iobsd_hook_executed':case.startswith('late-hook-'),'independent_worker_queued':bool(late_state['queued'])}


def main():
    reports={n:json.loads((ROOT/'reports'/f'{n}.json').read_text()) for n in DEPENDENCIES}
    prelink=reports['ios16-display-prelink'];path=ROOT/prelink['candidate'];fixture=json.loads(FIXTURE.read_text())
    require(sha(path)==prelink['candidate_sha256'] and prelink['original_gop_provider_vtable_entries_read_back']==178,
            'Need current strict provider/display prelink')
    for report in reports.values():
        require('PASS' in report['result'],'Provider CPU dependency failed')
        for p,h in report.get('source_sha256',{}).items():require(sha(ROOT/p)==h,'Provider source changed: '+p)
        for n,h in report.get('dependency_report_sha256',{}).items():require(sha(ROOT/'reports'/f'{n}.json')==h,'Provider dependency changed: '+n)
    from build_gpu_graphics_prelink import ORIGINAL
    original=ORIGINAL.read_bytes();old_image=macho(original);raw=path.read_bytes();image=macho(raw);slide=int(fixture['slide'],0)
    blocks={}
    for name,block in fixture['blocks'].items():
        a=int(block['address'],16);n=block['bytes'];at=backed_offset(image['segments'],a+slide,n,len(raw))
        old_at=backed_offset(old_image['segments'],a,n,len(original));data=raw[at:at+n]
        require(data==original[old_at:old_at+n] and hashlib.sha256(data).hexdigest()==block['sha256'],'Original provider code changed: '+name)
        blocks[name]={**block,'linked_address':hex(a+slide)}
    results=[]
    for case in CASES:
        try:results.append(emulate(path,case))
        except ValueError as error:raise ValueError(case+': '+str(error)) from error
        print('PASS:',case,flush=True)
    controls=[]
    for name in ('unknown-native-allocator','nonzero-typed-allocation'):
        try:emulate(path,'original-allocation-and-d0',name)
        except ValueError as error:
            wanted='Unknown native provider implementation' if name=='unknown-native-allocator' else 'not zero outside constructor fields'
            require(wanted in str(error),'Provider CPU control failed for wrong reason: '+str(error))
            controls.append({'case':name,'result':'REJECTED','check':str(error)})
        else:raise ValueError('Provider CPU control accepted: '+name)
    protected=prelink['protected_default_artifact_sha256']
    require(all(sha(ROOT/p)==h for p,h in protected.items()),'Provider CPU execution changed a protected artifact')
    out=ROOT/'build/ios16-gop-provider';cases=out/'kernel-cpu-cases.json'
    cases.write_text(json.dumps({'cases':results,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/prepare_gop_provider.py',FIXTURE,
           ROOT/'drivers/DodgeDisplay/DodgeGopProvider.cpp',ROOT/'drivers/DodgeDisplay/DodgeGopProvider.h',
           ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.h',
           TREE/'.cache/xnu-work/pexpert/pexpert/pexpert.h']
    report={'result':'IOS16_LINKED_GOP_PROVIDER_GUARDS_AND_ORIGINAL_ALLOCATION_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'dependency_report_sha256':{n:sha(ROOT/'reports'/f'{n}.json') for n in DEPENDENCIES},
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':fixture['original_kernelcache_sha256'],
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'unicorn_version':'2.1.4',
            'case_count':len(results),'cases':results,'negative_controls':controls,'original_provider_blocks':blocks,
            'cpu_cases':str(cases.relative_to(ROOT)),'cpu_cases_sha256':sha(cases),'original_instance_bytes':216,
            'actual_original_allocator_and_native_parent_constructors_executed':True,'actual_source_factory_early_guards_and_unwind_executed':True,
            'actual_original_get_resources_fast_path_executed':True,'original_get_meta_class_identity_executed':True,
            'actual_iobsd_hook_and_opt_in_schedule_cpu_cases':4,'worker_executed_by_iobsd_caller':False,
            'allocation_metadata_reference_public_init_and_registry_are_peers':True,'original_instruction_bytes_unchanged':True,
            'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'actual_service_publication_executed':False,
            'original_loader_executed':False,'real_iokit_instance_constructed':False,'runtime_qualified':False,
            'default_kernel_selected':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Bounded CPU execution from the full current prelink: real original provider allocator/getMetaClass/getResources/D1/D0 '
                    'and complete native parent constructor/destructor chains, plus actual source factory early rejection and unwind. '
                    'Four cases also execute the actual isolated IOBSD hook and scheduler, preserving disabled defaults or queuing the exact worker. '
                    'Typed allocation/deallocation, metaclass registration/lookup, retain/release, generic public init, PE and registry operations are explicit peers. '
                    'No real loader, service publication, mapping, Apple bus/clock callbacks or physical hardware.'}
    (ROOT/'reports/ios16-gop-provider-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(results)} linked provider CPU paths and two rejected controls; original allocator/identity/native constructors executed, runtime APIs remain peers')


if __name__=='__main__':main()
