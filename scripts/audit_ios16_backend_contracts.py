#!/usr/bin/env python3
"""Audit stock display subclass leaves without selecting Apple hardware code."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT,require,sha
from native_prelink import backed_offset,exports,macho,unserialize_xml

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-backend-discovery.json'
PURE=(211,212,242,243,292,293,321,322,329)

# Names intentionally describe slot numbers. The argument/return widths are
# visible in original callers; controller operation and status domains are not.
BACKEND_DECLARATIONS={
    211:'uint32_t backend211(uint32_t,void *,uint32_t)',
    212:'uint32_t backend212(uint32_t,uint32_t *,void *)',
    242:'uint32_t backend242(void *,void *)',
    292:'void backend292(void *,bool)',
    293:'uint32_t backend293(void *,void *)',
    321:'uint32_t backend321(uint32_t,void *,uint32_t *,uint32_t)',
    322:'void backend322(uint32_t)',
    329:'uint32_t backend329()',
}


def call_shapes(read,targets,fingerprint):
    evidence=(
        (211,0xfffffff005c254ac,(0xf9400fe0,0xb94017e1,0xf94007e2,0xb94007e3,0xf9400008,0xf9434d08,0xd63f0100,0xa9457bfd,0x910183ff,0xd65f03c0)),
        (212,0xfffffff005bfec48,(0xf9406d00,0xb85f43a1,0xf9400be3,0xf9400008,0xf9435108,0xd63f0100,0xb9000be0,0xb9400fe8,0xf9400fe9,0xf9000128,0xb9400be0,0xa9437bfd,0x910103ff)),
        (242,0xfffffff005bff5fc,(0xf9406d00,0xf94003e1,0xf9407502,0xf9400008,0xf943c908,0xd63f0100,0xa9417bfd)),
        (292,0xfffffff005c1b194,(0xf94007e0,0xf94013e1,0xf9400008,0xf9449108,0x52800029,0x12000122,0xd63f0100)),
        (292,0xfffffff005c1b4e4,(0xf9401be0,0xf85e03a1,0xf9400008,0xf9449108,0x52800009,0x12000122,0xd63f0100)),
        (293,0xfffffff005c1ba90,(0xf94007e0,0x3201f3e8,0xb90017e8,0xf9400fe1,0xf85f03a2,0xf9400008,0xf9449508,0xd63f0100,0xb90017e0,0xb94017e9,0x52800008,0x6b090108,0x1a9f17e8,0x370000c8)),
        (321,0xfffffff005c10230,(0xf94013e0,0xf9498408,0xb9431501,0xf9400008,0xf9450508,0xd2800003,0xaa0303e2,0x52800004,0xd63f0100)),
        (322,0xfffffff005c1bdd4,(0xf9401be0,0xb85d43a1,0xf9400008,0xf9450908,0xd63f0100)),
        (329,0xfffffff005c10e38,(0xf9400fe0,0xf9400008,0xf9452508,0xd63f0100,0x360005e0)),
    )
    sizes={211:16,212:16,242:12,292:16,293:36,321:0x454,322:4,329:12}
    result={str(slot):{'declaration':declaration,'original_target':fingerprint(targets[slot],sizes[slot]),
                      'caller_blocks':[],'operation_semantics_qualified':False}
            for slot,declaration in BACKEND_DECLARATIONS.items()}
    for slot,address,words in evidence:
        require(read(address,len(words)*4)==struct.pack('<%dI'%len(words),*words),
                'Original backend caller register/result shape changed: '+str(slot))
        result[str(slot)]['caller_blocks'].append(fingerprint(address,len(words)*4))
    require(struct.unpack('<I',read(0xfffffff005bfec34,4))[0]==0x910033e2,
            'Original slot 212 count output is no longer a local uint32 pointer')
    result['212']['count_local_address']=fingerprint(0xfffffff005bfec34,4)
    result['321'].update(records_are_optional=True,record_stride_bytes=216,count_word_bytes=4,
                         capacity_word_bytes=4,original_full_report_semantics_qualified=False)
    result['329'].update(raw_byte_zero_extended_to_uint32=True,caller_consumes_bit_zero=True,
                         state_meaning_qualified=False)
    return result


def derive():
    classes,raw,image,read=original_input()
    names={name:address for address,group in exports(raw,image).items() for name in group}
    legacy=classes['classes']['IOMobileFramebufferLegacy']
    require(struct.unpack('<Q',read(0xfffffff006dfb4a0,8))[0]==int(legacy['metadata'],16),'Stock display parent is not exact Legacy')
    info=next(s for s in image['segments'] if s['name']=='__PRELINK_INFO')
    entries=unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary']
    entry=next(e for e in entries if e['CFBundleIdentifier']=='com.apple.driver.AppleMobileDispH10P')
    module=macho(raw,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(raw)))
    text=next(s for s in module['segments'] if s['name']=='__TEXT_EXEC')
    def fingerprint(address,size):return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    records={}
    for name,label,metadata,parent,vptr,metavptr,alloc,ctor,ctor_size in (
        ('UnifiedPipeline',0xfffffff004f974cb,0xfffffff007a9a338,int(legacy['metadata'],16),0xfffffff006e06980,0xfffffff006e07518,0xfffffff005cce498,0xfffffff005cce4cc,100),
        ('AppleCLCD',0xfffffff004f978cc,0xfffffff007a9a360,0xfffffff007a9a338,0xfffffff006e075b0,0xfffffff006e08148,0xfffffff005cce72c,0xfffffff005cce760,112)):
        require(read(label,len(name)+1)==name.encode()+b'\0' and read(vptr-16,16)==bytes(16) and
                read(vptr+368*8,24)==bytes(24),'Stock display class label/observed table prefix differs')
        table=struct.unpack('<368Q',read(vptr,368*8))
        require(all(pointer and pointer!=names['___cxa_pure_virtual'] for pointer in table),
                'Stock display prefix has a null/pure entry')
        require(struct.unpack('<Q',read(metavptr+13*8,8))[0]==alloc and
                struct.unpack('<I',read(alloc+16,4))[0]==0x5283db01,'Stock display alloc slot no longer requests 7896 bytes in w1')
        records[name]={'metadata':hex(metadata),'parent_metadata':hex(parent),'instance_bytes':7896,'vptr':hex(vptr),
            'observed_nonzero_virtual_prefix_entries':368,'full_vtable_boundary_qualified':False,
            'vtable_prefix_sha256':hashlib.sha256(read(vptr,368*8)).hexdigest(),
            'metaclass_vptr':hex(metavptr),'allocation':fingerprint(alloc,32),'constructor':fingerprint(ctor,ctor_size),
            'legacy_backend_targets':{str(slot):hex(table[slot]) for slot in PURE}}
    require(records['AppleCLCD']['legacy_backend_targets']==records['UnifiedPipeline']['legacy_backend_targets'],
            'Stock child overrides a backend leaf previously inherited from UnifiedPipeline')
    targets={int(slot):int(address,16) for slot,address in records['UnifiedPipeline']['legacy_backend_targets'].items()}
    unsupported=struct.pack('<3I',0x528058e0,0x72bc0000,0xd65f03c0)
    require(read(targets[242],12)==unsupported==read(targets[243],12),'Stock unsupported return leaves differ')
    require(read(targets[322],4)==struct.pack('<I',0xd65f03c0),'Stock notification leaf is no longer RET only')
    boolean=struct.unpack('<3I',read(targets[329],12))
    require(boolean==(0x52837e28,0x38686800,0xd65f03c0),'Stock backend status is not the observed byte load at +7153')
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'component':entry['CFBundleIdentifier'],'component_version':entry['CFBundleVersion'],
        'component_text':fingerprint(text['va'],text['filesize']),'metadata_setup':fingerprint(0xfffffff005cde6a0,100),
        'legacy_instance_bytes':5728,'legacy_virtual_entries':338,'classes':records,
        'unsupported_leaves':{str(slot):{**fingerprint(targets[slot],12),'return_value':'0xe00002c7'} for slot in (242,243)},
        'noop_leaf':{'slot':322,**fingerprint(targets[322],4)},
        'status_byte_leaf':{'slot':329,'field_in_stock_subclass':7153,**fingerprint(targets[329],12)},
        'controller_forwarders':{'field_in_stock_subclass':7208,'controller_virtual_slots':{'211':12,'212':92,'292':11,'293':13}},
        'completion_report_leaf':{'slot':321,'address':hex(targets[321]),'body_executed':False},
        'qualified_raw_call_shapes':call_shapes(read,targets,fingerprint),
        'unclassified_argument_slots':[243],
        'fully_classified_backend_override_prototypes':False,'controller_method_semantics_qualified':False,
        'stock_subclass_selected_for_oneplus':False,'hardware_code_reusable_on_oneplus':False}


def emulate(contract):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as registers
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    _,_,_,read=original_input();base,obj,stop,stack=0x100000,0x200000,0x300000,0x400000
    argument_registers=[getattr(registers,'UC_ARM64_REG_X'+str(index)) for index in range(8)]
    descriptions=[('unsupported-'+str(slot)+'-'+str(nonnull),contract['unsupported_leaves'][str(slot)],
                   obj if nonnull else 0,0xe00002c7,None) for slot in (242,243) for nonnull in (False,True)]
    descriptions += [('noop-'+str(nonnull),contract['noop_leaf'],obj if nonnull else 0,obj if nonnull else 0,None) for nonnull in (False,True)]
    descriptions += [('status-byte-'+str(value),contract['status_byte_leaf'],obj,value,value) for value in (0,1)]
    cases=[]
    for name,leaf,this,expected,state in descriptions:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,length in ((base,4096),(obj,8192),(stop,4096),(stack,16384)):machine.mem_map(address,length)
        machine.mem_write(base,read(int(leaf['address'],16),leaf['bytes']));content=bytearray([0xa5])*7896
        if state is not None:content[7153]=state
        machine.mem_write(obj,bytes(content));arguments=[this,*[0x1122334455667700+index for index in range(1,8)]]
        for register,value in zip(argument_registers,arguments):machine.reg_write(register,value)
        machine.reg_write(registers.UC_ARM64_REG_LR,stop);machine.reg_write(registers.UC_ARM64_REG_SP,stack+0x3f00)
        accesses=[]
        def access(engine,kind,address,size,value,user):
            require(kind!=UC_MEM_WRITE and state is not None and address==obj+7153 and size==1,
                    'Stock scalar leaf performed an unqualified memory access')
            accesses.append((address,size))
        machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        machine.emu_start(base,stop,timeout=100000,count=32)
        require(machine.reg_read(registers.UC_ARM64_REG_PC)==stop and machine.reg_read(registers.UC_ARM64_REG_X0)==expected and
                [machine.reg_read(register) for register in argument_registers[1:]]==arguments[1:] and
                bytes(machine.mem_read(obj,7896))==bytes(content) and len(accesses)==int(state is not None),
                'Original scalar backend leaf did not match its limited contract: '+name)
        cases.append({'case':name,'result':'PASS','return_x0':hex(expected),'object_writes':0,'hardware_accesses':0})
    return cases


def emulate_native_dispatch(contract,native_code,functions,read):
    """Native typed calls -> unchanged stock bodies -> explicit controller peers.

    Only stock-sized synthetic objects have +7208/+7153. This does not add
    those fields to the much smaller Legacy instance used by the frontend.
    """
    import unicorn
    from unicorn import Uc,UcError,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    code,stop,obj,table,controller,ctable,node,output,stack,peer=(
        0x100000,0x110000,0x200000,0x210000,0x220000,0x230000,0x240000,0x250000,0x300000,0x400000)
    registers=[getattr(reg,'UC_ARM64_REG_X'+str(i)) for i in range(8)]
    # The 321 prelude and logging are peers. Its original argument validation,
    # empty-ring path and return code execute; no controller report is claimed.
    report_peers=(0xfffffff005ccf6d8,0xfffffff005ce108c)
    cases=[]

    def run(slot,label,arguments,expected=None,state=0,node_word=1,status=0xe1234567,wrong=False):
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def map_region(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:machine.mem_map(page,4096);pages.add(page)
        windows=((obj,7896),(table,338*8),(controller,16),(ctable,93*8),(node,128),(output,256),(stack,16384))
        for address,size in ((code,len(native_code)),(stop,4),(peer,4),*((a,n) for a,n in windows)):
            map_region(address,size)
        shape=contract['qualified_raw_call_shapes'][str(slot)];target=shape['original_target']
        target_address=int(target['address'],16);body=read(target_address,target['bytes'])
        require(hashlib.sha256(body).hexdigest()==target['sha256'],'Original backend dispatch body changed')
        map_region(target_address,len(body));machine.mem_write(target_address,body)
        for address in report_peers:map_region(address,4)
        probe=bytearray(native_code)
        if wrong:
            positions=[at for at in range(0,len(probe),4) if
                       struct.unpack_from('<I',probe,at)[0]&0xffc00000==0xf9400000 and
                       (struct.unpack_from('<I',probe,at)[0]>>10&4095)==slot]
            require(len(positions)==1,'Cannot identify own typed backend slot load')
            at,=positions;word,=struct.unpack_from('<I',probe,at)
            struct.pack_into('<I',probe,at,(word&~(4095<<10))|((slot+1)<<10))
        machine.mem_write(code,bytes(probe));machine.mem_write(table+slot*8,struct.pack('<Q',target_address))
        content=bytearray(7896);struct.pack_into('<Q',content,0,table)
        struct.pack_into('<Q',content,7208,controller);content[7153]=state
        machine.mem_write(obj,bytes(content));machine.mem_write(controller,struct.pack('<Q',ctable))
        controller_slot=contract['controller_forwarders']['controller_virtual_slots'].get(str(slot))
        if controller_slot is not None:machine.mem_write(ctable+controller_slot*8,struct.pack('<Q',peer))
        machine.mem_write(node,bytes([0x5a])*128);machine.mem_write(node+120,struct.pack('<I',node_word))
        machine.mem_write(output,bytes([0xcc])*256)
        for r,value in zip(registers,[obj,*arguments,*([0]*7)][:8]):machine.reg_write(r,value)
        machine.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(reg.UC_ARM64_REG_LR,stop)
        machine.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        observations=[];visited=[];helpers=[];writes=[]
        def memory(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in windows),
                    'Original backend escaped exact synthetic object/stack/output windows')
            if kind==UC_MEM_WRITE:
                require(stack<=address and address+size<=stack+16384 or
                        slot==321 and address==output+224 and size==4,
                        'Original backend unexpectedly wrote an object or opaque buffer')
                writes.append((address,size))
        def instruction(engine,address,size,user):
            visited.append(address)
            if address==peer:
                observations.append([engine.reg_read(r) for r in registers[:5]])
                if slot==212:engine.mem_write(output+224,struct.pack('<I',0xfedcba98))
                engine.reg_write(reg.UC_ARM64_REG_X0,status)
                engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
            elif address in report_peers:
                require(slot==321,'Unexpected report helper from another stock leaf')
                helpers.append(hex(address));engine.reg_write(reg.UC_ARM64_REG_X0,0)
                engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
        machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory);machine.hook_add(UC_HOOK_CODE,instruction)
        error=None
        try:machine.emu_start(code+functions['_iphone_backend'+str(slot)],stop,timeout=100000,count=1024)
        except UcError as caught:error=str(caught)
        if wrong:
            require(error is not None and not observations and target_address not in visited,
                    'Sparse wrong backend slot unexpectedly reached an original method')
        else:
            require(error is None and machine.reg_read(reg.UC_ARM64_REG_PC)==stop and target_address in visited,
                    'Typed native backend call did not reach/return from unchanged original body: '+str(error))
            if expected is not None:require(machine.reg_read(reg.UC_ARM64_REG_X0)==expected,'Original backend raw return value changed')
            forwarding=controller_slot is not None and (slot!=293 or arguments[0] and node_word)
            require(len(observations)==int(bool(forwarding)),'Original controller dispatch count changed')
            if forwarding:
                count={211:3,212:3,292:2,293:2}[slot]
                require(observations[0][:count+1]==[controller,*arguments[:count]],
                        'Typed native -> original forwarder truncated/reordered scalar or pointer arguments')
            if slot==321:
                require(helpers.count(hex(report_peers[0]))==1,'Original report prelude was not reached once')
                require(helpers.count(hex(report_peers[1]))==int(expected==0xe00002c2),'Original report validation/log path changed')
        require(bytes(machine.mem_read(obj,7896))==bytes(content),'Original backend modified its synthetic stock display')
        actual=bytes(machine.mem_read(output,256));reference=bytearray([0xcc])*256
        if not wrong and slot==212:struct.pack_into('<I',reference,224,0xfedcba98)
        if not wrong and slot==321 and arguments[1] and arguments[2] and arguments[3]:struct.pack_into('<I',reference,224,0)
        require(actual==bytes(reference),'Original backend/explicit controller peer overwrote count or buffer guards')
        cases.append({'case':'backend'+str(slot)+'-'+label,'result':'REJECTED' if wrong else 'PASS',
                      'slot':slot,'unchanged_original_body_executed':not wrong,'controller_peer_calls':len(observations),
                      'report_helper_peers':helpers,'instructions':len(visited),
                      'stock_instance_bytes':7896,'original_hardware_accesses':0})

    pointer=0x123456789abcdef0;second=0xfedcba9876543210
    for slot,args in ((211,[0xfedcba98,pointer,0x87654321]),(212,[0x89abcdef,output+224,pointer]),
                      (242,[pointer,second]),(292,[node,False]),(292,[node,True]),
                      (293,[node,pointer]),(322,[0xfedcba98])):
        expected=0xe00002c7 if slot==242 else None if slot in (292,322) else 0xe1234567
        run(slot,'arguments-'+str(len(cases)),args,expected)
    for slot,args in ((211,[0,None,0]),(212,[0,output+224,0])):
        run(slot,'zero-arguments',[0 if x is None else x for x in args],0,status=0)
    for argument,word,label in ((0,1,'null-node'),(node,0,'zero-node-word')):
        run(293,label,[argument,pointer],5,node_word=word)
    for state in (0,1,2,255):run(329,'raw-byte-'+str(state),[],state,state=state)
    for args,expected,label in (([0x89abcdef,0,0,0],0,'no-output-empty-ring'),
                                ([0x89abcdef,output,output+224,1],0,'bounded-output-empty-ring'),
                                ([0x89abcdef,output,0,1],0xe00002c2,'missing-count'),
                                ([0x89abcdef,output,output+224,0],0xe00002c2,'zero-capacity')):
        run(321,label,args,expected)
    for slot in BACKEND_DECLARATIONS:run(slot,'sparse-wrong-slot',[],wrong=True)
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed backend discovery fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n')
        print('Derived stock display class/leaf evidence; override prototypes remain incomplete');return
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_backend_discovery']
    require(sha(FIXTURE)==pin['sha256'] and json.loads(FIXTURE.read_text())==contract,'Reviewed stock display backend evidence changed')
    cases=emulate(contract)
    report={'result':'IOS16_STOCK_BACKEND_CLASS_AND_LIMITED_LEAF_AUDIT_PASS',
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'builder_sha256':sha(ROOT/'scripts/audit_ios16_backend_contracts.py'),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'component':contract['component'],
        'classes':contract['classes'],'legacy_backend_slots':list(PURE),'arm64_leaf_cases':cases,
        'original_scalar_leaf_bytes_changed':False,'stock_subclass_constructors_executed':False,'original_device_objects_constructed':False,
        'controller_forwarders_executed':False,'completion_report_body_executed':False,'hardware_access_methods_executed':False,
        'stock_subclass_selected':False,'full_backend_override_prototypes_qualified':False,'hardware_tested':False,
        'scope':'Original Legacy -> UnifiedPipeline -> AppleCLCD metadata/size and a nonzero virtual prefix; nine inherited backend targets identified. '
                'Eight CPU cases execute unchanged unsupported/noop/raw-byte leaves with synthetic memory only. '
                'This neither classifies all override arguments nor ports the controller, request lifecycle, timing semantics or Apple hardware code.'}
    (ROOT/'reports/ios16-backend-discovery.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: exact stock display subclass metadata and 8 limited scalar leaf CPU cases; full backend override contracts remain open')


if __name__=='__main__':main()
