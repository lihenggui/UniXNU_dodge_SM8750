#!/usr/bin/env python3
"""Qualify typed event access against actual original iPhone ARM64 bodies."""
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,require,sha,symbols,macho
from prepare_hid_event_abi import CONTRACT,HEADER,CLASSES
from build_input_native import fresh
from check_hid_parser import context,SLIDE


def probes():
    out=ROOT/'build/ios16-hid-event-cpu';out.mkdir(parents=True,exist_ok=True);source=out/'HidEventCalls.cpp'
    source.write_text('#include "OriginalHidEventABI.h"\n'
        'extern "C" uint32_t dodge_event_type(IOHIDEvent *p){return p->getType();}\n'
        'extern "C" int32_t dodge_event_integer(IOHIDEvent *p,uint32_t f,IOOptionBits o){return p->getIntegerValue(f,o);}\n'
        'extern "C" IOFixed dodge_event_fixed(IOHIDEvent *p,uint32_t f,IOOptionBits o){return p->getFixedValue(f,o);}\n'
        'extern "C" void dodge_event_set_integer(IOHIDEvent *p,uint32_t f,int32_t v,IOOptionBits o){p->setIntegerValue(f,v,o);}\n'
        'extern "C" void dodge_event_dispatch(IOHIDEventDriver *p,IOHIDEvent *e,IOOptionBits o){p->dispatchEvent(e,o);}\n')
    obj,=build_objects([source],out,[HEADER.parent]);return obj


def emulate(candidate,obj,contract,control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    original,original_read,module,imports=context();raw=candidate.read_bytes();im=macho(raw)
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(address,value=b'',size=0):
        p=address&~4095;end=(address+max(size,len(value))+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            last=p+4096
            while last<end and last not in pages:last+=4096
            uc.mem_map(p,last-p);pages.update(range(p,last,4096));p=last
        if value:uc.mem_write(address,value)
    for seg in im['segments']:
        if seg['size'] and seg['initprot']:put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
    probe_raw=obj.read_bytes();probe_im=inspect_object(probe_raw);code=next(s for seg in probe_im['segments'] for s in seg['sections'] if s['name']=='__text')
    _,relocations=struct.unpack_from('<2I',probe_raw,code['command_offset']+56);require(not relocations,'Event dispatch probes unexpectedly need linker relocations')
    probe_base=0x800000;put(probe_base+code['va'],probe_raw[code['fileoff']:code['fileoff']+code['size']])
    names={s['name']:probe_base+s['value'] for s in symbols(probe_raw) if not s['kind']&0xe0 and s['kind']&14==14}
    event,payload,driver,expansion,table,stack,halt=0x100040,0x110040,0x120040,0x130040,0x140040,0x200000,0x300000
    facts=contract['compiler_public_layout'];size=facts['digitizer_data_bytes']
    objects={event:80,payload:size,driver:264,expansion:1024,table:37*8}
    for address,extent in objects.items():put(address-64,b'\xa5'*(extent+128));put(address,bytes(extent))
    put(stack,size=65536);put(halt,size=4096)
    event_vptr=CLASSES['IOHIDEvent']['vptr']+SLIDE;driver_vptr=CLASSES['IOHIDEventDriver']['vptr']+SLIDE
    put(event,struct.pack('<Q',event_vptr));put(event+16,struct.pack('<Q',payload))
    put(driver,struct.pack('<Q',driver_vptr));put(driver+256,struct.pack('<Q',expansion))
    if control:
        original_table=bytes(uc.mem_read(event_vptr,37*8));put(table,original_table)
        put(table+23*8,original_table[22*8:23*8]);put(event,struct.pack('<Q',table))
    visited=set();cases=[];forwarded=[];text=[(s['va']+SLIDE,s['va']+SLIDE+s['size']) for s in module['segments'] if s['initprot']&4]
    parent_dispatch=int(contract['classes']['IOHIDEventService']['methods'][198]['address'],16)+SLIDE
    def args():return [uc.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4)]
    def ret(value=0):uc.reg_write(arm.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(arm.UC_ARM64_REG_PC,uc.reg_read(arm.UC_ARM64_REG_LR))
    def hook(engine,address,length,user):
        if address==parent_dispatch:
            a=args();require(a[0]==driver and a[1]==event,'Original driver dispatch changed self/event dataflow')
            forwarded.append(a[:3]);ret();return
        if probe_base+code['va']<=address<probe_base+code['va']+code['size']:return
        require(address not in imports and any(a<=address<b for a,b in text),'Unqualified original event implementation/import reached: '+hex(address))
        if address not in visited:
            require(bytes(uc.mem_read(address,length))==original_read(address-SLIDE,length),'Original event executable instruction changed')
            visited.add(address)
    def memory(engine,access,address,length,value,user):
        if access!=unicorn.UC_MEM_WRITE:return
        allowed=stack<=address<=address+length<=stack+65536 or any(a<=address<=address+length<=a+n for a,n in objects.items())
        require(allowed,'Original event write escaped its fixture allocation')
    uc.hook_add(unicorn.UC_HOOK_CODE,hook);uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,memory)
    def execute(entry,arguments):
        uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
        for i,v in enumerate(arguments):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v&((1<<64)-1))
        uc.emu_start(entry,halt,timeout=5000000,count=1000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt,'Original event method did not return within bounds')
        return uc.reg_read(arm.UC_ARM64_REG_X0)
    def setup(x=12345,y=54321,identity=9,mask=0x42,touch=True,kind=11):
        data=bytearray(size);struct.pack_into('<3I',data,0,size,kind,0x20000 if touch else 0)
        struct.pack_into('<2i',data,facts['position'],x,y);struct.pack_into('<I',data,facts['index'],identity)
        struct.pack_into('<I',data,facts['mask'],mask);put(payload,bytes(data));return bytes(data)
    def record(name,**extra):cases.append({'case':name,'result':'PASS',**extra})
    original_data=setup()
    require(execute(names['_dodge_event_type'],(event,))==11,'Actual event type dispatch differs');record('type-virtual-dispatch')
    for field,expected,label in ((0xb0005,9,'index'),(0xb0007,0x42,'mask'),(0xb0009,1,'touch')):
        require(execute(names['_dodge_event_integer'],(event,field,0))&0xffffffff==expected,'Actual typed event integer slot/dataflow differs')
        require(bytes(uc.mem_read(payload,size))==original_data,'Original integer getter changed event data');record(label+'-virtual-dispatch')
    for identity in (0,1,9,255,0xffffffff):
        before=setup(identity=identity)
        require(execute(names['_dodge_event_integer'],(event,0xb0005,0x80000001))&0xffffffff==identity and bytes(uc.mem_read(payload,size))==before,'Original index width/options dataflow differs')
        record('index-'+str(identity),value=identity)
    for coordinate in (-2147483648,-65536,-1,0,1,32768,65536,2147483647):
        before=setup(x=coordinate,y=coordinate)
        for axis,field in (('x',0xb0000),('y',0xb0001)):
            require(execute(names['_dodge_event_fixed'],(event,field,0))&0xffffffff==coordinate&0xffffffff and bytes(uc.mem_read(payload,size))==before,
                    'Actual event fixed-value width/field dispatch differs: '+axis+' '+str(coordinate))
        record('fixed-xy-'+str(coordinate),value=coordinate)
    for mask in (0,2,0x800,0x842,0x80000000,0xffffffff):
        before=setup(mask=0x42);expected=bytearray(before);struct.pack_into('<I',expected,facts['mask'],mask)
        execute(names['_dodge_event_set_integer'],(event,0xb0007,mask,0))
        require(bytes(uc.mem_read(payload,size))==bytes(expected) and execute(names['_dodge_event_integer'],(event,0xb0007,0))&0xffffffff==mask,
                'Original mask setter altered fields outside exact eventMask or changed width')
        record('set-mask-'+hex(mask),mask=mask)
    for down in (False,True):
        setup(touch=down);require(execute(names['_dodge_event_integer'],(event,0xb0009,0))==int(down),'Original touch bit differs');record('touch-'+str(down))
    for pointer in (0,0xfffffff076543210):
        put(event+24,struct.pack('<Q',pointer));require(execute(int(contract['children_getter'],16)+SLIDE,(event,))==pointer,'Original children getter narrowed its pointer')
        record('children-'+hex(pointer),pointer=hex(pointer))
    put(event+24,bytes(8));before=setup(kind=3)
    require(execute(names['_dodge_event_integer'],(event,0xb0007,0))==0 and bytes(uc.mem_read(payload,size))==before,'Original wrong-type event access did not return empty')
    record('wrong-event-type-empty')
    for options in (0,1,0x80000001,0xffffffff):
        setup();put(expansion+0x1d8,struct.pack('<H',0))
        execute(names['_dodge_event_dispatch'],(driver,event,options))
        require(forwarded[-1]==[driver,event,options],'Actual event driver dispatch narrowed/changed its arguments')
        record('driver-dispatch-'+hex(options),options=options)
    for address,extent in objects.items():
        require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+extent,64))==b'\xa5'*64,'Original event allocation canary changed')
    return {'result':'PASS','cases':cases,'case_count':len(cases),'original_instructions_visited':len(visited),
            'original_driver_dispatch_with_empty_auxiliary_collection':True,'parent_service_dispatch_is_peer':True}


def main():
    interface_path=ROOT/'reports/ios16-hid-event-abi.json';interface=fresh(interface_path)
    require(interface['contract_sha256']==sha(CONTRACT) and interface['header_sha256']==sha(HEADER),'Event interface audit changed')
    contract=json.loads(CONTRACT.read_text());prelink_path=ROOT/'reports/ios16-input-prelink.json';prelink=fresh(prelink_path)
    candidate=ROOT/prelink['candidate'];require(sha(candidate)==prelink['candidate_sha256'],'Event CPU prelinked candidate changed')
    obj=probes();result=emulate(candidate,obj,contract);controls=[]
    try:emulate(candidate,obj,contract,True)
    except ValueError as error:
        require(str(error)=='Actual typed event integer slot/dataflow differs','Wrong event slot control failed for another reason: '+str(error))
        controls.append({'case':'integer-slot-replaced-with-event-getter','result':'REJECTED','check':str(error)})
    else:raise ValueError('Wrong original event dispatch slot was accepted')
    out=ROOT/'build/ios16-hid-event-cpu/cpu-cases.json';out.write_text(json.dumps({**result,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_hid_parser.py',HEADER,CONTRACT]
    report={**result,'result':'IOS16_TYPED_EVENT_ORIGINAL_GETTER_SETTER_AND_DRIVER_DISPATCH_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'interface_report_sha256':sha(interface_path),
            'prelink_report_sha256':sha(prelink_path),'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':sha(candidate),
            'negative_controls':controls,'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'original_instructions_unchanged':True,
            'hardware_tested':False,'ready_for_ios_boot':False,'edge_gesture_implementation_installed':False,
            'scope':'Actual iPhone original event getType/getEvent/getIntegerValue/getFixedValue/setIntegerValue/getChildren and default event-driver dispatch bodies, '
                    'called through actual bounded C++ ARM64 virtual probes with fixture canaries and compiler-derived public payload offsets. '
                    'Driver auxiliary collection is empty and final parent event-service dispatch is an explicit peer. '
                    'No event factory, full driver init/start/stop, matching, event consumer/UI, edge injection or hardware qualification.'}
    (ROOT/'reports/ios16-hid-event-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(result['case_count'])+' typed native/original iPhone event accessor and driver-dispatch cases; wrong virtual slot rejected')


if __name__=='__main__':main()
