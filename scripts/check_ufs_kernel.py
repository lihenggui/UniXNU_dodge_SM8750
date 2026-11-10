#!/usr/bin/env python3
"""Run actual UFS constructors/parent lifetime and combined IOBSD scheduling."""
import json
from pathlib import Path
import struct

from native_driver_build import ROOT,NATIVE,require,sha,symbols,macho
from native_prelink import backed_offset

CASES=('ufs-block-ctor-dtor','ufs-driver-ctor-dtor','ufs-null-output','ufs-null-provider',
       'iobsd-default-disabled','iobsd-graphics-only','iobsd-storage-only','iobsd-storage-and-graphics')


def emulate(path,case,control=False):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw);names={s['name']:s['value'] for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14}
    reverse={}
    for name,a in names.items():reverse.setdefault(a,[]).append(name)
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
    def put(a,data=b'',size=0):
        p=a&~4095;last=(a+max(size,len(data))+4095)&~4095
        while p<last:
            if p in pages:p+=4096;continue
            end=p+4096
            while end<last and end not in pages:end+=4096
            uc.mem_map(p,end-p);pages.update(range(p,end,4096));p=end
        if data:uc.mem_write(a,data)
    for seg in image['segments']:
        if seg['size'] and seg['initprot']:put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
    storage,instance,platform,root,owned,out,stack,halt=0x200000,0x200040,0x210000,0x220000,0x230000,0x240000,0x300000,0x400000
    for a,n in ((storage,4096),(platform,4096),(root,4096),(owned,4096),(out,4096),(stack,65536),(halt,4096)):put(a,size=n)
    put(storage,b'\xa5'*(216+128));put(owned,struct.pack('<Q',names['__ZTV9IOService']+16))
    put(platform,struct.pack('<Q',names['__ZTV9IOService']+16))
    events=[];visits=[];handlers={};queue=[];dealloc=[];accounted=[];released=[0];terminated=[0];root_returned=[False]
    def arguments(n=8):return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(n)]
    def returned(value=0):uc.reg_write(reg.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def bind(name,action):
        require(name in names,'Missing native UFS CPU API: '+name);handlers[names[name]]=(name,action)
    def cstring(a):
        data=bytearray()
        for i in range(256):
            b=bytes(uc.mem_read(a+i,1))
            if b==b'\0':return data.decode()
            data+=b
        raise ValueError('Unbounded UFS CPU peer string')
    def accounting(a):accounted.append(a[0]);returned()
    bind('__ZNK11OSMetaClass19instanceConstructedEv',accounting)
    def resource(a):require(cstring(a[0])=='IOBSD' and not a[1],'Wrong IOBSD resource');events.append('IOBSD-published');returned()
    bind('__ZN9IOService15publishResourceEPKcP8OSObject',resource)
    def flag(a):
        require(events and events[0]=='IOBSD-published' and a[2]==4,'Scheduling preceded actual IOBSD publication')
        name=cstring(a[0]);require(name in ('native-ufs-root','dodge-graphics'),'Unknown startup flag')
        enabled=(name=='native-ufs-root' and case in ('iobsd-storage-only','iobsd-storage-and-graphics') or
                 name=='dodge-graphics' and case in ('iobsd-graphics-only','iobsd-storage-and-graphics'))
        put(a[1],struct.pack('<I',int(enabled)));returned(int(enabled))
    bind('_PE_parse_boot_argn',flag)
    def start_thread(a):
        require(not a[1] and a[2],'Worker argument/output contract changed')
        queue.append(a[0]);handle=out+1024+len(queue)*16;put(a[2],struct.pack('<Q',handle));returned(0)
    bind('_kernel_thread_start',start_thread)
    def deallocate(a):dealloc.append(a[0]);returned()
    bind('_thread_deallocate',deallocate)
    bind('_thread_call_allocate_with_options',lambda a:returned(0))
    bind('__ZN9IOService11getPlatformEv',lambda a:returned(platform))
    bind('__ZNK9IOService11getProviderEv',lambda a:returned(root if a[0]==platform else 0))
    bind('__ZNK9IOService10isInactiveEv',lambda a:returned(0))
    def ufs_start(a):
        require(a[0]==root and a[1] and not root_returned[0],'Root worker retried or changed its provider')
        events.append('ufs-start-peer');root_returned[0]=True;put(a[1],struct.pack('<Q',owned));returned(0)
    # Constructor/argument cases execute the real start function guards;
    # scheduling cases peer only the controller/loader entry to avoid MMIO.
    if case.startswith('iobsd-'):bind('_dodge_ufs_start',ufs_start)
    def release(a):require(a[0]==owned and not released[0],'Wrong owned driver release');released[0]+=1;events.append('owned-driver-released');returned()
    bind('__ZNK8OSObject7releaseEv',release)
    bind('_current_thread',lambda a:returned(out+2048))
    def terminate(a):require(a[0]==out+2048,'Wrong worker termination');terminated[0]+=1;returned()
    bind('_thread_terminate',terminate)
    allowed=[]
    native_functions={name:(names[symbol],n) for name,symbol,n in (
        ('IOService.C2','__ZN9IOServiceC2EPK11OSMetaClass',32),('IORegistryEntry.C2','__ZN15IORegistryEntryC2EPK11OSMetaClass',32),
        ('OSObject.C2','__ZN8OSObjectC2EPK11OSMetaClass',40),('OSMetaClassBase.C2','__ZN15OSMetaClassBaseC2Ev',16),
        ('IOService.D2','__ZN9IOServiceD2Ev',4),('IORegistryEntry.D2','__ZN15IORegistryEntryD2Ev',4),
        ('OSObject.D2','__ZN8OSObjectD2Ev',4),('OSMetaClassBase.D2','__ZN15OSMetaClassBaseD2Ev',12))}
    allowed.extend(native_functions.values())
    functions={}
    for mangled in ('14NativeUfsBlock','9NativeUfs'):
        for suffix in ('C1Ev','D1Ev'):
            name='__ZN'+mangled+suffix;a=names[name];end=min(v for v in names.values() if v>a);functions[name]=(a,end-a);allowed.append((a,end-a))
        name='__ZNK'+mangled+'12getMetaClassEv';functions[name]=(names[name],12);allowed.append((names[name],12))
    fixture=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/storage-abi.json').read_text());slide=int(fixture['slide'],0)
    original_functions={'original-block.C2':(int(fixture['protected_constructor'],16)+slide,32),'original-block.D2':(int(fixture['protected_destructor'],16)+slide,4)}
    allowed.extend(original_functions.values());allowed.extend((a+slide,12) for a in (0xfffffff0055eb4c0,0xfffffff0055eb4cc))
    # Public entry extents are taken from actual source-kernel symbol boundaries.
    for name in ('_dodge_ufs_start','_dodge_system_schedule','_dodge_system_late_status','_dodge_graphics_schedule'):
        a=names[name];end=min(v for v in names.values() if v>a);allowed.append((a,end-a))
    storage_worker=names['__ZN12_GLOBAL__N_113storageWorkerEPvi'];end=min(v for v in names.values() if v>storage_worker);allowed.append((storage_worker,end-storage_worker))
    allowed.append((names['_IOKitBSDInit'],72))
    def hook(engine,a,n,user):
        if a in handlers:
            name,action=handlers[a];action(arguments());return
        require(any(start<=a<start+length for start,length in allowed),'Unknown native UFS implementation: '+','.join(reverse.get(a,[hex(a)])))
        for name,(start,length) in {**native_functions,**original_functions,**functions}.items():
            if a==start:visits.append(name)
    uc.hook_add(UC_HOOK_CODE,hook)
    def execute(a,*args):
        for i,value in enumerate(args):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
        uc.emu_start(a,halt,timeout=1000000,count=20000);require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'UFS CPU path did not return')
        return uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff
    if case.startswith('ufs-') and 'ctor' in case:
        block='block' in case;size=216 if block else 152;mangled='14NativeUfsBlock' if block else '9NativeUfs'
        put(instance,(b'\x5a' if control else b'\0')*size)
        execute(names['__ZN'+mangled+'C1Ev'],instance)
        vptr=names['__ZTV'+mangled]+16;expected=bytearray(size);struct.pack_into('<Q',expected,0,vptr);struct.pack_into('<I',expected,8,1)
        require(bytes(uc.mem_read(instance,size))==expected,'UFS constructor object bytes are not canonical')
        meta=names['__ZN'+mangled+'10gMetaClassE'];require(accounted==[meta],'UFS source constructor accounted a different metaclass')
        execute(names['__ZNK'+mangled+'12getMetaClassEv'],instance);require(uc.reg_read(reg.UC_ARM64_REG_X0)==meta,'UFS source object class identity changed')
        execute(names['__ZN'+mangled+'D1Ev'],instance)
        struct.pack_into('<Q',expected,0,(1<<64)-1);require(bytes(uc.mem_read(instance,size))==expected,'UFS source/native destructor changed canonical object storage')
        for name in native_functions:require(visits.count(name)==1,'Native parent constructor/destructor path changed: '+name)
        require(('original-block.C2' in visits)==block and ('original-block.D2' in visits)==block,'Original storage protected parent dispatch changed')
        require(bytes(uc.mem_read(storage,64))==b'\xa5'*64 and bytes(uc.mem_read(instance+size,64))==b'\xa5'*64,'UFS constructor/destructor wrote an allocation canary')
    elif case=='ufs-null-output':require(execute(names['_dodge_ufs_start'],root,0)==0xe00002c2,'Native storage null-output guard changed')
    elif case=='ufs-null-provider':
        put(out,b'\xa5'*16);require(execute(names['_dodge_ufs_start'],0,out)==0xe00002c2 and bytes(uc.mem_read(out,8))==bytes(8),'Native storage null-provider/output guard changed')
    else:
        require(execute(names['_IOKitBSDInit'])==0 and events==['IOBSD-published'],'Actual combined IOBSD hook entered hardware synchronously')
        storage_requested='storage' in case;graphics_requested=case in ('iobsd-graphics-only','iobsd-storage-and-graphics')
        if storage_requested:
            require(queue==[storage_worker] and len(dealloc)==1,'Explicit root flag did not queue the actual storage worker')
            execute(storage_worker,0,0)
            require(root_returned[0] and released[0]==1 and terminated[0]==1 and events==['IOBSD-published','ufs-start-peer','owned-driver-released'],
                    'Actual root worker lost startup/release ordering')
            require(len(queue)==1+int(graphics_requested) and len(dealloc)==len(queue),'Actual graphics scheduler ignored its opt-in after root start')
        else:require(len(queue)==int(graphics_requested) and len(dealloc)==len(queue),'Combined hook changed default/graphics-only behavior')
    return {'case':case,'result':'PASS','actual_native_parent_entries':visits,'original_storage_parent_executed':'original-block.C2' in visits,
            'source_class_accounted':bool(accounted),'kernel_threads_queued':len(queue),'controller_start_is_peer':root_returned[0],
            'actual_combined_iobsd_executed':case.startswith('iobsd-'),'events':events}


def main():
    prelink_path=ROOT/'reports/ios16-storage-prelink.json';prelink=json.loads(prelink_path.read_text());path=ROOT/prelink['candidate']
    root_path=ROOT/'reports/ios16-ufs-root.json';root=json.loads(root_path.read_text())
    require('PASS' in prelink['result'] and sha(path)==prelink['candidate_sha256'] and prelink['root_source_report_sha256']==sha(root_path),
            'Need current combined UFS/display/original strict prelink')
    for report in (prelink,root):
        for p,h in report['source_sha256'].items():require(sha(ROOT/p)==h,'UFS CPU source dependency changed: '+p)
    results=[]
    for case in CASES:
        try:results.append(emulate(path,case))
        except ValueError as error:raise ValueError(case+': '+str(error)) from error
        print('PASS:',case,flush=True)
    from check_display_kernel_lifecycle import emulate as display_lifecycle
    display_cases=[{'name':'combined-root-default-display'},
                   {'name':'combined-root-late-display-thread','thread_success':True,'thread_after_detach':True},
                   {'name':'combined-root-original-user-client','client':'success'}]
    for case in display_cases:
        results.append(display_lifecycle(path,case));print('PASS:',case['name'],flush=True)
    try:emulate(path,'ufs-block-ctor-dtor',True)
    except ValueError as error:
        require(str(error)=='UFS constructor object bytes are not canonical','UFS nonzero-allocation control failed for wrong reason')
        negative={'case':'unzeroed-typed-allocation','result':'REJECTED','check':str(error)}
    else:raise ValueError('Unzeroed UFS allocation accepted')
    protected=prelink['protected_default_artifact_sha256'];require(all(sha(ROOT/p)==h for p,h in protected.items()),'UFS CPU execution changed protected artifact')
    out=ROOT/'build/cph2653-ufs-root/linked-cpu-cases.json';out.write_text(json.dumps({'cases':results,'negative_controls':[negative]},indent=2)+'\n')
    report={'result':'IOS16_COMBINED_UFS_NATIVE_LIFETIME_AND_IOBSD_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_display_kernel_lifecycle.py',ROOT/'profiles/os/ios-16.7.16-20H392/storage-abi.json')},
            'prelink_report_sha256':sha(prelink_path),'root_source_report_sha256':sha(root_path),'native_kernel_sha256':sha(NATIVE),
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'unicorn_version':'2.1.4','case_count':len(results),'cases':results,
            'full_original_display_lifecycle_on_combined_kernel_cases':3,
            'negative_controls':[negative],'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),
            'native_and_original_parent_ctor_dtor_instructions_executed':True,'actual_source_class_identity_and_full_bytes_checked':True,
            'actual_combined_iobsd_and_root_then_graphics_scheduling_executed':True,
            'metadata_accounting_allocation_registry_kernel_threads_and_controller_are_peers':True,
            'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'real_iokit_instance_constructed':False,
            'real_controller_or_dma_executed':False,'runtime_qualified':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual prelinked native UFS/block constructors, class identities, complete native/original parent C2/D2 and allocation canaries; '
                    'actual combined IOBSD/default flags, source storage worker, owned-driver release and graphics scheduling. '
                    'Metaclass accounting, allocation, registry, threads and controller startup are explicit peers; no original loader or physical storage.'}
    (ROOT/'reports/ios16-ufs-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 11 linked UFS/combined-boot/full original display CPU paths; unzeroed allocation rejected; no hardware execution')


if __name__=='__main__':main()
