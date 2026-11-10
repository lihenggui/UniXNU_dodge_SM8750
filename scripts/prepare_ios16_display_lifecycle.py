#!/usr/bin/env python3
"""Audit original iPhone display initialization and its empty startup queues."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT,NATIVE,build_objects,macho,require,sha,symbols
from native_prelink import exports

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-lifecycle.json'
HEADER=FIXTURE.parent/'graphics/OriginalLegacyLifecycleABI.h'


def derive():
    classes,raw,image,read=original_input();legacy=classes['classes']['IOMobileFramebufferLegacy'];parent=classes['classes']['IOMobileFramebufferService']
    table=struct.unpack('<338Q',read(int(legacy['vptr'],16),338*8));parent_vptr=int(parent['vptr'],16)
    require(table[21]==0xfffffff005c0c404 and table[86]==0xfffffff005c0c8cc and table[87]==0xfffffff005c0dff4,
        'Original Legacy init/start/stop entries differ')
    require(parent_vptr==0xfffffff006dedc80 and struct.unpack('<Q',read(parent_vptr+21*8,8))[0]==0xfffffff007744674,
        'Original Legacy init no longer calls the actual parent IOService init')
    def block(address,size):return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    require(struct.unpack('<10I',read(0xfffffff005c0d458,40))==
        (0xf9404fe9,0xd282620a,0xf909893f,0xaa0903e8,0x8b0a0108,0xf9098d28,0x14000001,0x14000001,0xf9404fe9,0xd282640a),
        'Original primary/unsubmitted startup queue writes differ')
    require(struct.unpack('<5I',read(0xfffffff005c0d76c,20))==(0xf9404fe0,0xf9400008,0xf9415108,0x52800001,0xd63f0100),
        'Original start no longer calls registerService(self,0) before returning')
    gate_target,=struct.unpack('<Q',read(0xfffffff006deaf68,8));loop_target,=struct.unpack('<Q',read(0xfffffff006deaee0,8))
    names=exports(raw,image)
    require(any('IOCommandGate11commandGate' in name for name in names.get(gate_target,[])) and
        any('IOWorkLoop8workLoopEv' in name for name in names.get(loop_target,[])),'Original init factory imports changed')
    label=b'iomfb_enable_edr_scaling\0'
    require(read(0xfffffff004f6598b,len(label))==label,'Original init boot argument changed')
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'display_bytes':5728,'init':block(table[21],528),'start':block(table[86],3852),'stop':block(table[87],1408),
        'parent_init':hex(0xfffffff007744674),'parent_table_word':hex(parent_vptr+21*8),
        'gate_factory_stub':block(0xfffffff005c26e90,12),'gate_factory_import':hex(0xfffffff006deaf68),'gate_factory_target':hex(gate_target),
        'workloop_factory_stub':block(0xfffffff005c26de8,12),'workloop_factory_import':hex(0xfffffff006deaee0),'workloop_factory_target':hex(loop_target),
        'gate_field':5040,'workloop_field':5048,'add_event_source_slot':20,'startup_queues':block(0xfffffff005c0d458,188),
        'current':4872,'primary_head':4880,'primary_tail':4888,'unsubmitted_head':4896,'unsubmitted_tail':4904,
        'notification_heads':4912,'notification_count':6,'notification_stride':16,'hardware_call':block(0xfffffff005c0d5c0,60),
        'register_service_call':block(0xfffffff005c0d76c,20),'register_service_slot':84,'registers_before_start_returns':True,
        'initialization_failure_ownership_qualified':False,'full_start_stop_lifecycle_qualified':False}


def emulate(contract,probe):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4');_,_,_,read=original_input()
    raw=probe.read_bytes();image=macho(raw);text,=[s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
    require(struct.unpack_from('<I',raw,text['command_offset']+60)[0]==0,'Native lifecycle probes contain external relocations')
    code=raw[text['fileoff']:text['fileoff']+text['size']];functions={s['name']:s['value']-text['va'] for s in symbols(raw) if s['name'].startswith('_iphone_') and s['kind']&14}
    require(set(functions)=={'_iphone_startup_empty','_iphone_lifecycle_add_event'},'Native lifecycle probe entries differ')
    native,display,gate,loop,vtable,props,stack,stop,add=0x100000,0x200000,0x210000,0x220000,0x230000,0x240000,0x300000,0x400000,0x410000
    init=int(contract['init']['address'],16);queue=int(contract['startup_queues']['address'],16);results=[]
    def prepared():
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def mapped(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:uc.mem_map(page,4096);pages.add(page)
        for address,size in ((native,len(code)),(display,5728),(gate,64),(loop,64),(vtable,256),(props,64),(stack,16384),(stop,4),(add,4),
                (init,528),(queue,188),(0xfffffff005c26000,4096),(0xfffffff006dea000,4096),(0xfffffff006ded000,4096),(0xfffffff004f65000,4096),
                (int(contract['parent_init'],16),4),(int(contract['gate_factory_target'],16),4),(int(contract['workloop_factory_target'],16),4),(0xfffffff005bf761c,4)):
            mapped(address,size)
        uc.mem_write(native,code)
        for address,size in ((init,528),(queue,188),(0xfffffff005c26000,4096),(0xfffffff006dea000,4096),(0xfffffff006ded000,4096),(0xfffffff004f65000,4096)):
            uc.mem_write(address,read(address,size))
        uc.mem_write(display,b'\xa5'*5728);uc.mem_write(loop,struct.pack('<Q',vtable));uc.mem_write(vtable+20*8,struct.pack('<Q',add))
        uc.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20);return uc
    for name,parent,gate_ok,loop_ok,add_status,boot in (
            ('init-success',1,True,True,0,None),('parent-init-refusal',0,True,True,0,None),
            ('gate-factory-refusal',1,False,True,0,None),('loop-factory-refusal',1,True,False,0,None),
            ('add-source-refusal',1,True,True,1,None),('bootarg-zero',1,True,True,0,0),('bootarg-nonzero',1,True,True,0,7)):
        uc=prepared();calls=[];writes=[]
        def returned(value):uc.reg_write(reg.UC_ARM64_REG_X0,value);uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
        def instruction(engine,address,size,user):
            values=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
            if address==int(contract['parent_init'],16):require(values[:2]==[display,props],'Original init parent arguments differ');calls.append('parent');returned(parent)
            elif address==0xfffffff005bf761c:
                require(values[0]==0xfffffff004f6598b and stack<=values[1]<=stack+16380 and values[2]==4,'Original init bootarg arguments differ')
                calls.append('bootarg')
                if boot is not None:engine.mem_write(values[1],struct.pack('<I',boot))
                returned(int(boot is not None))
            elif address==int(contract['gate_factory_target'],16):require(values[:2]==[display,0],'Original gate owner/default action differ');calls.append('gate');returned(gate if gate_ok else 0)
            elif address==int(contract['workloop_factory_target'],16):calls.append('loop');returned(loop if loop_ok else 0)
            elif address==add:require(values[:2]==[loop,gate],'Original addEventSource self/source differ');calls.append('add');returned(add_status)
            elif address==0xfffffff005c26cec:calls.append('log');returned(0)
        windows=[(display,5728),(loop,64),(vtable,256),(props,64),(stack,16384),(0xfffffff006dea000,4096),(0xfffffff006ded000,4096),(0xfffffff004f65000,4096)]
        def memory(engine,kind,address,size,value,user):
            require(any(p<=address and address+size<=p+n for p,n in windows),'Original init escaped exact object/stack/readonly windows')
            if kind==UC_MEM_WRITE:
                require(display<=address and address+size<=display+5728 or stack<=address and address+size<=stack+16384,'Original init wrote a factory/readonly fixture')
                if display<=address<display+5728:writes.append((address-display,size))
        uc.hook_add(UC_HOOK_CODE,instruction);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        uc.reg_write(reg.UC_ARM64_REG_X0,display);uc.reg_write(reg.UC_ARM64_REG_X1,props);uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
        uc.emu_start(init,stop,timeout=100000,count=512)
        expected=bool(parent and gate_ok and loop_ok and add_status==0)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop and uc.reg_read(reg.UC_ARM64_REG_X0)==int(expected),'Original init result differs: '+name)
        require(struct.unpack('<I',uc.mem_read(display+5652,4))[0]==0x3f800000 and struct.unpack('<I',uc.mem_read(display+5660,4))[0]==1 and
            uc.mem_read(display+5648,2)==bytes((int(boot!=0),0)),'Original init defaults differ')
        require(struct.unpack('<Q',uc.mem_read(display+5040,8))[0]==(gate if gate_ok else 0),'Original gate field differs')
        if gate_ok:require(struct.unpack('<Q',uc.mem_read(display+5048,8))[0]==(loop if loop_ok else 0),'Original loop field differs')
        results.append({'case':name,'result':'PASS','original_init_result':expected,'callee_peers':calls,'original_display_writes':writes})
    # Execute the original primary/unsubmitted/six-notification initialization
    # loop, then feed its object to the actual native read-only startup guard.
    for defect in range(-1,19):
        uc=prepared();uc.mem_write(display+4872,bytes(8));sp=stack+0x2000;fp=sp+0x130
        uc.reg_write(reg.UC_ARM64_REG_SP,sp);uc.reg_write(reg.UC_ARM64_REG_X29,fp);uc.mem_write(sp+0x98,struct.pack('<Q',display));uc.mem_write(sp+0x8c,bytes(4))
        uc.emu_start(queue,queue+188,timeout=100000,count=512)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==queue+188,'Original startup queue loop escaped')
        heads=[4880,4896,*range(4912,5008,16)]
        for head in heads:require(struct.unpack('<2Q',uc.mem_read(display+head,16))==(0,display+head),'Original startup head/tail differs')
        pointer=display
        if 0<=defect<16:
            head=heads[defect//2];uc.mem_write(display+head+(8 if defect&1 else 0),struct.pack('<Q',0x1234))
        elif defect==16:uc.mem_write(display+4872,struct.pack('<Q',0x1234))
        elif defect==17:pointer=0
        elif defect==18:pointer=0xffffffffffffffff-100
        before=bytes(uc.mem_read(display,5728))
        def memory(engine,kind,address,size,value,user):
            require(stack<=address and address+size<=stack+16384 or display<=address and address+size<=display+5728,'Native startup guard escaped exact display/stack')
            if kind==UC_MEM_WRITE:require(stack<=address<stack+16384,'Native startup guard modified display')
        uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        uc.reg_write(reg.UC_ARM64_REG_X0,pointer);uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
        uc.emu_start(native+functions['_iphone_startup_empty'],stop,timeout=100000,count=2048)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop and uc.reg_read(reg.UC_ARM64_REG_X0)==int(defect<0) and bytes(uc.mem_read(display,5728))==before,
            'Native guard disagrees with original startup queue shape/refusal')
        results.append({'case':'original-queue-to-native-startup-'+str(defect),'result':'PASS','accepted':defect<0})
    for status in (0,0xe00002c7):
        uc=prepared();calls=[]
        def instruction(engine,address,size,user):
            if address==add:
                require(engine.reg_read(reg.UC_ARM64_REG_X0)==loop and engine.reg_read(reg.UC_ARM64_REG_X1)==gate,'Native loop add-event arguments differ')
                calls.append(address);engine.reg_write(reg.UC_ARM64_REG_X0,status);engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
        uc.hook_add(UC_HOOK_CODE,instruction);uc.reg_write(reg.UC_ARM64_REG_X0,loop);uc.reg_write(reg.UC_ARM64_REG_X1,gate)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
        uc.emu_start(native+functions['_iphone_lifecycle_add_event'],stop,timeout=100000,count=256)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop and len(calls)==1 and uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff==status,'Native add-event slot/status differs')
        results.append({'case':'native-loop-add-'+hex(status),'result':'PASS','callee_peer':True})
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed lifecycle fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n');return
    lock=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_lifecycle']
    require(sha(FIXTURE)==lock['sha256'] and sha(HEADER)==lock['header_sha256'] and json.loads(FIXTURE.read_text())==contract,'Exact iPhone lifecycle contract/header changed')
    out=ROOT/'build/ios16-display-lifecycle';out.mkdir(parents=True,exist_ok=True);source=out/'lifecycle.cpp'
    source.write_text('#include "OriginalLegacyLifecycleABI.h"\n#include <IOKit/IOWorkLoop.h>\n'
        'extern "C" bool iphone_startup_empty(const void *p){return IPhone16Lifecycle::emptyStartupQueues(p);}\n'
        'extern "C" IOReturn iphone_lifecycle_add_event(IOWorkLoop *p,IOEventSource *s){return p->addEventSource(s);}\n')
    probe,=build_objects([source],out,[HEADER.parent]);cases=emulate(contract,probe)
    sources=[Path(__file__),HEADER,HEADER.parent/'OriginalLegacySwapABI.h']
    report={'result':'IPHONE16_ORIGINAL_DISPLAY_LIFECYCLE_CPU_PASS','builder_sha256':sha(Path(__file__)),'native_kernel_sha256':sha(NATIVE),
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),
        'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),'native_probe':str(probe.relative_to(ROOT)),'native_probe_sha256':sha(probe),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sources},'cases':cases,'case_count':len(cases),
        'original_init_and_queue_bytes_changed':False,'startup_guard_read_only':True,'registration_precedes_start_return':True,
        'original_factory_or_event_loop_implementation_executed':False,'original_full_start_stop_executed':False,
        'initialization_failure_ownership_qualified':False,'concrete_legacy_subclass_installed':False,'hardware_tested':False,
        'scope':'Unchanged full original Legacy init and queue initialization run on a bounded CPU fixture with explicit parent/factory/bootarg/log/add-event peers. '
                'The native startup guard consumes the original loop output and refuses occupied/malformed primary, unsubmitted or six notification queues. '
                'Actual native loop-add dispatch matches the original slot. Original start calls registerService before returning; concrete frontend setup must precede publication. '
                'Original IOKit allocation/refcounts, failure ownership, full start/stop, backend initialization and hardware remain unqualified.'}
    (ROOT/'reports/ios16-display-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(cases)} original init/queue and native lifecycle CPU cases; factory/event/refcount peers; no service published')


if __name__=='__main__':main()
