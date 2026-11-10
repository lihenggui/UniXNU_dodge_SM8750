#!/usr/bin/env python3
"""Execute actual combined ARM64 input constructors and queue-only BSD hook."""
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,require,sha,symbols,macho
from native_prelink import backed_offset
from build_input_native import fresh,INIT


def emulate(path,case,control=False):
    import unicorn
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw);all_symbols=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14]
    names={s['name']:s['value'] for s in all_symbols};addresses={s['value'] for s in all_symbols}
    def worker_for(prefix):
        found=[s['value'] for s in all_symbols if s['name']=='__ZN12_GLOBAL__N_16workerEPvi' and
               names[prefix+'_schedule']<s['value']<names[prefix+'_late_status']]
        require(len(found)==1,'Ambiguous source worker identity: '+prefix);return found[0]
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
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
    storage,obj,out,stack,halt=0x200000,0x200040,0x210000,0x300000,0x400000
    for a,n in ((storage,8192),(out,4096),(stack,65536),(halt,4096)):put(a,size=n)
    size=json.loads((ROOT/'reports/ios16-input-native.json').read_text())['compiled_instance_bytes'];put(storage,b'\xa5'*(size+128));put(obj,bytes(size))
    if control:put(obj+32,b'\x5a'*16)
    events=[];visited=[];peers={};queues=[];deallocated=[];accounted=[]
    def args():return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(value=0):uc.reg_write(reg.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def bind(n,fn):require(n in names,'Missing CPU peer entry '+n);peers[names[n]]=fn
    def cstring(a):
        data=bytearray()
        for i in range(128):
            b=bytes(uc.mem_read(a+i,1))
            if not b[0]:return data.decode()
            data+=b
        raise ValueError('Unbounded CPU string')
    def account(a):accounted.append(a[0]);ret()
    bind('__ZNK11OSMetaClass19instanceConstructedEv',account)
    def zero(a):require(obj+208<=a[0]<=a[0]+a[1]<=obj+size,'Source initialization zeroes original HID storage');put(a[0],bytes(a[1]));events.append('derived-zero-peer');ret()
    bind('_bzero',zero)
    def published(a):require(cstring(a[0])=='IOBSD' and not a[1],'Wrong BSD resource');events.append('IOBSD-published');ret()
    bind('__ZN9IOService15publishResourceEPKcP8OSObject',published)
    mask=int(case.split('-')[-1]) if case.startswith('iobsd-') else 0
    def flag(a):
        require(events and events[0]=='IOBSD-published' and a[2]==4,'Queueing preceded IOBSD publication')
        key=cstring(a[0]);bits={'native-ufs-root':1,'dodge-graphics':2,'dodge-input':4};require(key in bits,'Unexpected boot flag')
        on=bool(mask&bits[key]);put(a[1],struct.pack('<I',on));ret(int(on))
    bind('_PE_parse_boot_argn',flag)
    def queue(a):require(not a[1] and a[2],'Worker queue ABI changed');queues.append(a[0]);put(a[2],struct.pack('<Q',out+16*len(queues)));ret(0)
    bind('_kernel_thread_start',queue)
    def deallocate(a):deallocated.append(a[0]);ret()
    bind('_thread_deallocate',deallocate)
    bind('_thread_call_allocate_with_options',lambda a:ret(0))
    allowed=[];functions={}
    def allow(name,n=None):
        a=names[name];end=min(v for v in addresses if v>a) if n is None else a+n
        allowed.append((a,end-a));functions[name]=(a,end-a)
    for name,n in (
        ('__ZN9IOServiceC2EPK11OSMetaClass',32),('__ZN15IORegistryEntryC2EPK11OSMetaClass',32),
        ('__ZN8OSObjectC2EPK11OSMetaClass',40),('__ZN15OSMetaClassBaseC2Ev',16),
        ('__ZN9IOServiceD2Ev',4),('__ZN15IORegistryEntryD2Ev',4),('__ZN8OSObjectD2Ev',4),('__ZN15OSMetaClassBaseD2Ev',12),
        ('__ZN11IOHIDDeviceC2EPK11OSMetaClass',32),('__ZN11IOHIDDeviceD2Ev',4)):
        allow(name,n)
    # Actual original imported native constructor/destructor branch stubs.
    allowed.extend([(0xfffffff00575c6ac-0x1000000,12),(0xfffffff00575c6b8-0x1000000,12)])
    for n in ('__ZN10DodgeInputC1Ev','__ZN10DodgeInputD1Ev','__ZNK10DodgeInput12getMetaClassEv','_dodge_input_start','_dodge_input_schedule',
              '_dodge_system_schedule','_dodge_graphics_schedule'):
        allow(n)
    allow('_IOKitBSDInit',80)
    def hook(engine,a,n,user):
        if a in peers:peers[a](args());return
        require(any(start<=a<start+length for start,length in allowed),'Unqualified input CPU implementation reached: '+hex(a))
        for name,(start,length) in functions.items():
            if a==start:visited.append(name)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def execute(a,*arguments):
        for i,v in enumerate(arguments):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),v)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
        uc.emu_start(a,halt,timeout=1000000,count=20000);require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'Input CPU path did not return')
        return uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff
    if case=='input-ctor-dtor':
        execute(names['__ZN10DodgeInputC1Ev'],obj)
        expected=bytearray(208);struct.pack_into('<Q',expected,0,names['__ZTV10DodgeInput']+16);struct.pack_into('<I',expected,8,1)
        require(bytes(uc.mem_read(obj,208))==expected,'Input constructor base storage is not canonical')
        meta=names['__ZN10DodgeInput10gMetaClassE'];require(accounted==[meta],'Input constructor accounted wrong class')
        execute(names['__ZNK10DodgeInput12getMetaClassEv'],obj);require(uc.reg_read(reg.UC_ARM64_REG_X0)==meta,'Input source metaclass differs')
        before=bytes(uc.mem_read(obj,size));execute(names['__ZN10DodgeInputD1Ev'],obj)
        expected=struct.pack('<Q',(1<<64)-1)+before[8:];require(bytes(uc.mem_read(obj,size))==expected,'Input destructor changed owned/base storage')
        for name in ('__ZN9IOServiceC2EPK11OSMetaClass','__ZN15IORegistryEntryC2EPK11OSMetaClass','__ZN8OSObjectC2EPK11OSMetaClass',
                     '__ZN15OSMetaClassBaseC2Ev','__ZN9IOServiceD2Ev','__ZN15IORegistryEntryD2Ev','__ZN8OSObjectD2Ev','__ZN15OSMetaClassBaseD2Ev',
                     '__ZN11IOHIDDeviceC2EPK11OSMetaClass','__ZN11IOHIDDeviceD2Ev'):
            require(visited.count(name)==1,'Input source/original/native protected chain changed: '+name)
        require(bytes(uc.mem_read(storage,64))==b'\xa5'*64 and bytes(uc.mem_read(obj+size,64))==b'\xa5'*64,'Input allocation canary changed')
    elif case=='null-out':require(execute(names['_dodge_input_start'],obj,0,0)==0xe00002c2,'Input null output guard changed')
    elif case=='null-provider':
        put(out,b'\xa5'*16);require(execute(names['_dodge_input_start'],0,0,out)==0xe00002c2 and bytes(uc.mem_read(out,8))==bytes(8),'Input null provider/output guard changed')
    else:
        require(execute(names['_IOKitBSDInit'])==0 and events==['IOBSD-published'],'Actual IOBSD hook executed hardware inline')
        wanted=[]
        if mask&1:wanted.append(names['__ZN12_GLOBAL__N_113storageWorkerEPvi'])
        elif mask&2:wanted.append(worker_for('_dodge_graphics'))
        if mask&4:wanted.append(worker_for('_dodge_input'))
        require(queues==wanted and deallocated==[out+16*(i+1) for i in range(len(wanted))],'Actual BSD worker selection/order changed')
    return {'case':case,'result':'PASS','source_original_native_chain_executed':case=='input-ctor-dtor','worker_entry_bodies_executed':False,
            'queues':[hex(q) for q in queues],'peers':'metaclass accounting, derived bzero, resource, boot flags, thread scheduling; no MMIO'}

def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json';source=fresh(source_path);prelink=fresh(prelink_path)
    require(prelink['input_source_report_sha256']==sha(source_path),'Input prelink source dependency stale')
    path=ROOT/prelink['candidate'];require(sha(path)==prelink['candidate_sha256'],'Input prelink bytes changed')
    names=['input-ctor-dtor','null-out','null-provider']+['iobsd-'+str(n) for n in range(8)]
    cases=[emulate(path,n) for n in names];controls=[]
    try:emulate(path,'input-ctor-dtor',True)
    except ValueError as error:
        require(str(error)=='Input constructor base storage is not canonical','Input negative failed for another reason: '+str(error));controls.append({'case':'dirty-base-allocation','result':'REJECTED','check':str(error)})
    else:raise ValueError('Dirty input base allocation accepted')
    out=ROOT/'build/cph2653-input-prelink/cpu-cases.json';out.write_text(json.dumps({'result':'PASS','cases':cases,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/build_input_native.py',ROOT/'scripts/build_input_prelink.py',ROOT/'scripts/native_driver_build.py']
    report={'result':'IOS16_PRELINKED_INPUT_CONSTRUCTOR_AND_IOBSD_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'prelink_report_sha256':sha(prelink_path),'source_report_sha256':sha(source_path),
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'case_count':len(cases),'cases':cases,'negative_controls':controls,
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'original_protected_constructor_destructor_and_native_chain_executed':True,
            'eight_actual_iobsd_flag_combinations':True,'actual_hid_start_parser_or_hardware_executed':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual new prelinked source C1/D1 + unchanged original HID protected C2/D2 and native parents with allocation canaries and all eight real queue-only BSD boot-flag combinations. '
                    'Metadata accounting, bzero, boot/resource/thread APIs are peers. Worker bodies are covered by sanitized source tests; no full original HID init/start/parser, report service or controller MMIO executes.'}
    (ROOT/'reports/ios16-input-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 11 actual input C1/D1/guard/BSD ARM64 cases and dirty-allocation rejection; no hardware or original HID parser execution')

if __name__=='__main__':main()
