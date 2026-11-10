#!/usr/bin/env python3
"""Audit and execute the exact iPhone refresh sender with an async-transport peer."""
import argparse
import hashlib
import json
import struct
import subprocess
import tomllib

from check_ios16_swap import original_input
from native_driver_build import ROOT, NATIVE, build_objects, inspect_object, macho, require, sha, symbols
from native_prelink import exports

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-refresh.json'
HEADER=FIXTURE.parent/'graphics/OriginalLegacyRefreshABI.h'


def derive():
    classes,raw,image,read=original_input()
    names={name:address for address,group in exports(raw,image).items() for name in group}
    def words(address,count):return struct.unpack('<%dI'%count,read(address,count*4))
    def branch(pc):
        word,=words(pc,1);require(word&0xfc000000==0x94000000,'Expected refresh BL')
        value=word&0x3ffffff
        return pc+4*(value-(1<<26) if value&(1<<25) else value)
    def stub(address):
        a,b,c=words(address,3)
        require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,
                'Expected original refresh import stub')
        immediate=((a>>5)&0x7ffff)*4+((a>>29)&3)
        if immediate&(1<<20):immediate-=1<<21
        got=(address&~4095)+(immediate<<12)+((b>>10)&4095)*8
        return struct.unpack('<Q',read(got,8))[0]
    sender,transport=0xfffffff005c1b838,0xfffffff005bfe258
    require(words(sender+12,4)==(0xf81f83a0,0xf81f03a1,0xf81e83a2,0xf81e03a3),
            'Refresh sender no longer accepts self and three 64-bit time arguments')
    # The sender splits each time into two zero-extended 32-bit values, then
    # traverses the type-5 list and passes a six-element vector to async result.
    require(words(0xfffffff005c1b948,1)==(0xf949c108,) and
            words(0xfffffff005c1b968,6)==(0xf85d83a8,0x91006100,0x52800001,0x910023e2,0x528000c3,0x52800024),
            'Original notification head/reference/vector/count/options changed')
    require(branch(0xfffffff005c1b980)==transport and branch(transport+52)==0xfffffff005c26e54 and
            stub(0xfffffff005c26e54)==names['__ZN12IOUserClient28sendAsyncResult64WithOptionsEPyiS0_jj'],
            'Refresh sender no longer uses the original async result transport')
    require(branch(0xfffffff005c1b8e8)==0xfffffff005c274cc and
            stub(0xfffffff005c274cc)==names['_memset'],'Refresh payload initialization differs')
    # Registration indexes six TAILQs, base + type*16; type 5's head is 4992.
    require(words(0xfffffff005c1b0d4,6)==(0xd282660a,0xaa0903e8,0x8b0a0108,0xb94017eb,0x8b0b1108,0xf9400508),
            'Original notification registration list indexing differs')
    require(words(0xfffffff005c1b9b0,3)==(0xf85d83a8,0xf9400108,0xf81d83a8),
            'Original sender list traversal differs')
    require(words(0xfffffff005c237a8,5)==(0xf9400008,0xf9406508,0x90ff9a21,0x91354821,0xd63f0100),
            'Original refresh property publisher changed')
    legacy=struct.unpack('<338Q',read(int(classes['classes']['IOMobileFramebufferLegacy']['vptr'],16),338*8))
    require(legacy[287]==0xfffffff005c234b4 and legacy[301]!=legacy[287] and
            read(0xfffffff004f67d52,len(b'IOMFBDisplayRefresh\0'))==b'IOMFBDisplayRefresh\0',
            'Exact iPhone refresh getter/property identity differs')
    require(legacy[239]==0xfffffff005c2475c and branch(legacy[239]+16)==0xfffffff005c17770 and
            branch(0xfffffff005c17778)==0xfffffff005c17784 and branch(0xfffffff005c1778c)==0xfffffff005c274b4 and
            stub(0xfffffff005c274b4)==names['_mach_continuous_time'],
            'Original fallback time is not mach_continuous_time')
    require(legacy[271]==0xfffffff005c24a58 and branch(legacy[271]+32)==0xfffffff005c25b54 and
            branch(0xfffffff005c25b70)==0xfffffff005c274e4 and stub(0xfffffff005c274e4)==names['_nanoseconds_to_absolutetime'],
            'Original interval conversion is not nanoseconds_to_absolutetime')
    def code(address,size):return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392',
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],'legacy_instance_bytes':5728,
        'sender':{**code(sender,404),'prototype':'void (self, timestamp, continuous, interval)'},
        'transport_wrapper':code(transport,68),'async_transport':'__ZN12IOUserClient28sendAsyncResult64WithOptionsEPyiS0_jj',
        'async_import_stub':hex(0xfffffff005c26e54),'memset_import_stub':hex(0xfffffff005c274cc),
        'failure_logger':hex(0xfffffff005c0bb30),'registration':code(0xfffffff005c1b01c,492),
        'notification_list_base':4912,'notification_type':5,'notification_head':4992,
        'node_next_offset':0,'node_async_reference_offset':24,'async_reference_words':8,
        'payload_words':6,'payload_word_bytes':8,'payload_times_split_into_32bit_halves':True,'async_options':1,
        'refresh_attributes_slot':287,'refresh_attributes':code(0xfffffff005c234b4,348),
        'refresh_property_publisher':code(0xfffffff005c23610,484),
        'wrong_reference_head':5592,'wrong_reference_attributes_slot':301,
        'original_notification_lifecycle_qualified':False,'hardware_vblank_qualified':False}


def emulate(contract,obj):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    _,_,_,read=original_input();data=obj.read_bytes();image=macho(data);table=symbols(data)
    text,=[s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
    code=bytearray(data[text['fileoff']:text['fileoff']+text['size']])
    base,original_base,display,stack,stop=0x100000,0x500000,0x200000,0x300000,0x400000
    original_start=0xfffffff005bf3000
    relocate=lambda address:original_base+address-original_start
    sender=relocate(int(contract['sender']['address'],16))
    transport=relocate(int(contract['transport_wrapper']['address'],16))
    send_peer=relocate(int(contract['async_import_stub'],16));zero_peer=relocate(int(contract['memset_import_stub'],16))
    log_peer=relocate(int(contract['failure_logger'],16))
    offset,count=struct.unpack_from('<2I',data,text['command_offset']+56)
    require(count==1,'Expected one exact refresh-sender relocation')
    at,bits=struct.unpack_from('<2I',data,offset)
    require(bits>>24&1 and bits>>25&3==2 and bits>>27&1 and bits>>28==2 and
            table[bits&0xffffff]['name']=='_native_iphone_refresh_notify','Unexpected native refresh relocation')
    instruction,=struct.unpack_from('<I',code,at)
    require(instruction==0x94000000,'Expected a plain refresh call without addend')
    struct.pack_into('<I',code,at,instruction|(((sender-base-at)//4)&0x3ffffff))
    functions={s['name']:base+s['value']-text['va'] for s in table if s['kind']&0xe and s['name'].startswith('_iphone_')}
    require(set(functions)=={'_iphone_refresh_clients','_iphone_refresh_notify'},'Missing native refresh probes')
    cases=[]
    descriptions=[('one-client-high-bits',1,(0x1122334455667788,0xaabbccddeeff0011,0x123456789abcdef0),None),
                  ('two-clients-low-halves',2,(0xffffffff,0x80000000,1),None),
                  ('three-clients-high-halves',3,(1<<63,1<<32,(1<<64)-1),None),
                  ('transport-failure-continues-list',3,(17,23,31),'transport-failure'),
                  ('null-display',1,(17,23,31),'null-display'),('empty-client-list',0,(17,23,31),None),
                  ('zero-timestamp',1,(0,23,31),None),('zero-continuous',1,(17,0,31),None),
                  ('zero-interval',1,(17,23,0),None),('wrong-reference-head-only',0,(17,23,31),'wrong-head')]
    for name,clients,times,defect in descriptions:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,length in ((base,4096),(original_base,0x40000),(display,8192),(stack,16384),(stop,4096),
                               (0x210000,4096),(0x220000,4096),(0x230000,4096)):
            machine.mem_map(address,length)
        machine.mem_write(base,bytes(code))
        for block,address in ((contract['sender'],sender),(contract['transport_wrapper'],transport)):
            machine.mem_write(address,read(int(block['address'],16),block['bytes']))
        content=bytearray([0xa5])*5728;nodes={}
        struct.pack_into('<Q',content,4992,0x210000 if clients else 0)
        struct.pack_into('<Q',content,5592,0x210000 if defect=='wrong-head' else 0)
        for index in range(clients):
            address=0x210000+index*0x10000;node=bytearray([0x96])*88
            struct.pack_into('<Q',node,0,address+0x10000 if index+1<clients else 0)
            for word in range(8):struct.pack_into('<Q',node,24+word*8,0x1020304050607080+index*16+word)
            nodes[address]=bytes(node);machine.mem_write(address,bytes(node))
        machine.mem_write(display,bytes(content))
        calls=[];logs=[];zeros=[];sender_entries=[]
        def hook(engine,address,size,user):
            allowed=base<=address<base+len(code) or sender<=address<sender+404 or transport<=address<transport+68 or address in (send_peer,zero_peer,log_peer)
            require(allowed,'Refresh probe escaped qualified instruction ranges')
            if address==sender:sender_entries.append(tuple(engine.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)))
            if address==zero_peer:
                destination,value,length=(engine.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2))
                require(stack<=destination and destination+length<=stack+16384 and value==0 and length==48,'Refresh memset arguments differ')
                engine.mem_write(destination,bytes(length));zeros.append(length);engine.reg_write(UC_ARM64_REG_X0,destination)
            elif address==send_peer:
                reference,status,payload,length,options=(engine.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4))
                require(stack<=payload and payload+48<=stack+16384 and status==0 and length==6 and options==1,'Async result arguments differ')
                calls.append({'reference':reference,'payload':struct.unpack('<6Q',bytes(engine.mem_read(payload,48)))})
                engine.reg_write(UC_ARM64_REG_X0,0xe00002bc if defect=='transport-failure' and len(calls)==2 else 0)
            elif address==log_peer:logs.append(address)
            else:return
            engine.reg_write(UC_ARM64_REG_PC,engine.reg_read(UC_ARM64_REG_LR))
        def access(engine,kind,address,size,value,user):
            in_stack=stack<=address and address+size<=stack+16384
            in_object=display<=address and address+size<=display+5728 or any(a<=address and address+size<=a+len(node) for a,node in nodes.items())
            require(in_stack or in_object,'Refresh probe escaped exact object/access windows')
            require(kind!=UC_MEM_WRITE or in_stack,'Refresh sender modified display or notification nodes')
        machine.hook_add(UC_HOOK_CODE,hook);machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        def execute(function,args):
            for register,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3),args):machine.reg_write(register,value)
            machine.reg_write(UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(UC_ARM64_REG_LR,stop)
            machine.emu_start(function,stop,timeout=100000,count=4096)
            require(machine.reg_read(UC_ARM64_REG_PC)==stop,'Refresh probe did not return')
            return machine.reg_read(UC_ARM64_REG_X0)
        this=0 if defect=='null-display' else display
        require(execute(functions['_iphone_refresh_clients'],(this,))==bool(this and clients),'Wrong native refresh client-head access')
        result=execute(functions['_iphone_refresh_notify'],(this,*times))
        expected=bool(this and clients and all(times))
        payload=tuple(part for time in times for part in (time&0xffffffff,time>>32))
        require(result==expected and calls==([{'reference':a+24,'payload':payload} for a in nodes] if expected else []) and
                sender_entries==([(display,*times)] if expected else []) and zeros==([48] if expected else []) and
                len(logs)==int(defect=='transport-failure'),'Original refresh sender call/payload/refusal differs: '+name)
        require(bytes(machine.mem_read(display,5728))==bytes(content) and
                all(bytes(machine.mem_read(a,len(node)))==node for a,node in nodes.items()),'Refresh sender changed objects')
        cases.append({'case':name,'original_sender_executed':expected,'async_transport_peer_calls':len(calls),'result':'PASS'})
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args()
    contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed refresh fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n')
        print('Derived original iPhone refresh sender/list/property facts for review');return
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_refresh']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'] and json.loads(FIXTURE.read_text())==contract,
            'Reviewed exact iPhone refresh interface changed')
    out=ROOT/'build/ios16-refresh-interface';out.mkdir(parents=True,exist_ok=True)
    source=out/'refresh.cpp';source.write_text('#include "OriginalLegacyRefreshABI.h"\n'
        'extern "C" bool iphone_refresh_clients(const void *p){return IPhone16Refresh::hasClients(p);}\n'
        'extern "C" bool iphone_refresh_notify(void *p,uint64_t a,uint64_t b,uint64_t c){return IPhone16Refresh::notifyIfListening(p,a,b,c);}\n')
    obj,=build_objects([source],out,[HEADER.parent]);cases=emulate(contract,obj)
    profile=tomllib.loads((FIXTURE.parent/'profile.toml').read_text());slide=int(profile['kernel']['prelink']['slide'],0)
    target=int(contract['sender']['address'],16)+slide
    assembly=out/'original-refresh-binding.S';assembly.write_text(f'.globl _native_iphone_refresh_notify\n.set _native_iphone_refresh_notify, {target:#x}\n')
    binding=out/'original-refresh-binding.o'
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',assembly,'-o',binding],check=True)
    inspect_object(binding.read_bytes())
    require({s['name']:s['value'] for s in symbols(binding.read_bytes()) if s['kind']==3}=={'_native_iphone_refresh_notify':target},
            'Original refresh absolute alias differs from exact profile slide')
    archive=out/'libIPhone16Refresh.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,binding],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,binding.name])==binding.read_bytes(),'Refresh archive readback failed')
    report={'result':'IOS16_ORIGINAL_REFRESH_SENDER_ARM64_CHECK_PASS','original_kernelcache_sha256':contract['original_kernelcache_sha256'],
        'native_kernel_sha256':sha(NATIVE),'builder_sha256':sha(ROOT/'scripts/prepare_ios16_refresh.py'),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'queue_header_sha256':sha(HEADER.parent/'OriginalLegacySwapABI.h'),'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'binding_address':hex(target),'slide':slide,
        'arm64_cases':cases,'original_sender_bytes_changed':False,'original_sender_body_executed':True,
        'original_async_transport_executed':False,'async_transport_peer':True,'original_notification_objects_constructed':False,
        'node_fixture_access_window_bytes':88,'notification_head_offset':4992,'refresh_attributes_slot':287,
        'timer_provider_installed':False,'hardware_vblank_generated':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Native guarded calls and unchanged complete original scalar refresh sender/transport wrapper execute over exact-size display and bounded node windows. '
                'Async delivery, memset and logger are explicit peers. No original notification lifecycle, kernel transport, timer or hardware executes.'}
    (ROOT/'reports/ios16-refresh-interface.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: exact iPhone refresh sender, six split time words and client list; ten ARM64 cases with async-transport peers')


if __name__=='__main__':main()
