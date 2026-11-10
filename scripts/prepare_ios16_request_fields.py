#!/usr/bin/env python3
"""Compare a read-only native snapshot with actual original iPhone field builders."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT,NATIVE,build_objects,macho,require,sha,symbols

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-request-fields.json'
HEADER=FIXTURE.parent/'graphics/OriginalLegacyRequestFieldsABI.h'


def derive():
    classes,_,_,read=original_input()
    def words(address,count):return struct.unpack('<%dI'%count,read(address,count*4))
    require(words(0xfffffff005c14c10,3)==(0xb9410529,0xf940014a,0xb9031949),
            'Original primary mask copy differs')
    require(words(0xfffffff005c1607c,5)==(0xb941090a,0xf9400be9,0xb9431d28,0x2a0a0108,0xb9031d28),
            'Original secondary mask OR differs')
    require(words(0xfffffff005c14ccc,6)==(0xb9545808,0xf940012a,0xb9033148,0xb9545c08,0xf940012a,0xb9033548),
            'Original request dimensions no longer copy the qualified display words')
    blocks=[]
    for name,address,size in (('primary',0xfffffff005c14c04,24),('common',0xfffffff005c14c94,80),
        ('rectangles-scalars',0xfffffff005c15190,136),('transform-bits',0xfffffff005c1534c,40),('secondary',0xfffffff005c16068,48)):
        blocks.append({'name':name,'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()})
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'request_bytes':2424,'layer_count':4,'primary_mask':792,'secondary_mask':796,'background_raw':800,
        'options':[804,812],'dimensions':[816,820],'source_rectangles':{'base':17,'stride':16,'words':4},
        'destination_rectangles':{'base':81,'stride':16,'words':4},'raw_layer_word':{'base':532,'stride':4},
        'raw_float_bits':{'base':564,'stride':4},'raw_transform_bits':{'base':580,'stride':4,'builder_mask':7},
        'user_packet_access_window_bytes':312,'builder_blocks':blocks,'color_alpha_transform_semantics_qualified':False,
        'producer_sync_qualified':False,'full_swap_validation_qualified':False}


def emulate(contract,obj):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_SP,UC_ARM64_REG_X29,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_CPACR_EL1
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    _,_,_,read=original_input();data=obj.read_bytes();image=macho(data)
    text,=[s for segment in image['segments'] for s in segment['sections'] if s['name']=='__text']
    require(struct.unpack_from('<I',data,text['command_offset']+60)[0]==0,'Snapshot probe must have no external text relocations')
    code=data[text['fileoff']:text['fileoff']+text['size']]
    function,=[s for s in symbols(data) if s['name']=='_iphone_request_snapshot' and s['kind']&14]
    base,original,display,request,packet,context,output,stack,stop=0x100000,0x500000,0x200000,0x210000,0x220000,0x230000,0x240000,0x300000,0x400000
    extents={display:5728,request:2424,packet:312,context:64,output:72,stack:16384}
    cases=[]
    valid=[('layer-'+str(layer),layer,0x10010001+layer,0xaabbccdd,0x80001234,0x7fff5678) for layer in range(4)]
    valid+=[('zero-fields',0,0,0,0,0),('opaque-bit-patterns',3,0xffffffff,0x80000000,0xffffffff,0xffffffff)]
    def machine():
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,length in ((base,4096),(original,0x5000),(stop,4096),*((a,(n+4095)&~4095) for a,n in extents.items())):uc.mem_map(address,length)
        uc.mem_write(base,code)
        for index,block in enumerate(contract['builder_blocks']):uc.mem_write(original+index*4096,read(int(block['address'],16),block['bytes']))
        # Only the CPU fixture enables SIMD for the original unaligned Q/S
        # stores. The native snapshot retains -mgeneral-regs-only and no FP.
        uc.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
        return uc
    def native(uc,this,layer,out):
        uc.reg_write(UC_ARM64_REG_X0,this);uc.reg_write(UC_ARM64_REG_X1,layer);uc.reg_write(UC_ARM64_REG_X2,out)
        uc.reg_write(UC_ARM64_REG_SP,stack+0x3e00);uc.reg_write(UC_ARM64_REG_LR,stop)
        uc.emu_start(base+function['value']-text['va'],stop,timeout=100000,count=1024)
        require(uc.reg_read(UC_ARM64_REG_PC)==stop,'Snapshot probe did not return');return uc.reg_read(UC_ARM64_REG_X0)
    for name,layer,primary,secondary,width,height in valid:
        uc=machine();disp=bytearray([0xa6])*5728;req=bytearray([0xb7])*2424;pay=bytearray((i*37+11)&255 for i in range(312))
        for at,value in ((5208,width),(5212,height)):struct.pack_into('<I',disp,at,value)
        for at,value in ((0x104,primary),(0x108,secondary),(0x10c,0xff102030),(0x110,0x11223344),(0x134,0x55667788)):struct.pack_into('<I',pay,at,value)
        struct.pack_into('<I',req,796,0x10000000)
        uc.mem_write(display,bytes(disp));uc.mem_write(request,bytes(req));uc.mem_write(packet,bytes(pay));uc.mem_write(output,b'\xd8'*72)
        args=bytearray(64);struct.pack_into('<Q',args,0,request);struct.pack_into('<Q',args,56,packet);uc.mem_write(context,bytes(args))
        phase=['builder']
        def access(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in extents.items()),'Request field test escaped exact access windows')
            allowed=stack<=address and address+size<=stack+16384 or (request<=address and address+size<=request+2424 if phase[0]=='builder' else output<=address and address+size<=output+72)
            require(kind!=UC_MEM_WRITE or allowed,'Builder/snapshot changed an unauthorized object')
        uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        for index,block in enumerate(contract['builder_blocks']):
            sp=stack+0x3000;fp=sp+0x180
            uc.reg_write(UC_ARM64_REG_SP,sp);uc.reg_write(UC_ARM64_REG_X29,fp);uc.reg_write(UC_ARM64_REG_LR,stop)
            uc.mem_write(sp+0x88,struct.pack('<Q',context));uc.mem_write(sp+0xb0,struct.pack('<Q',display));uc.mem_write(fp-0x68,struct.pack('<I',layer))
            start=original+index*4096
            if block['name']=='secondary':
                uc.reg_write(UC_ARM64_REG_X0,display);uc.reg_write(UC_ARM64_REG_X1,request);uc.reg_write(UC_ARM64_REG_X2,packet)
                uc.emu_start(start,stop,timeout=100000,count=128);require(uc.reg_read(UC_ARM64_REG_PC)==stop,'Original secondary mask function escaped')
            else:
                uc.emu_start(start,start+block['bytes'],timeout=100000,count=128)
                require(uc.reg_read(UC_ARM64_REG_PC)==start+block['bytes'],'Original field block escaped')
        built=bytes(uc.mem_read(request,2424));phase[0]='snapshot'
        expected=[primary,0x10000000|secondary,0xff102030,0x11223344,0x55667788,width,height]
        expected+=list(struct.unpack_from('<4I',pay,0x64+layer*16))+list(struct.unpack_from('<4I',pay,0xc4+layer*16))
        expected+=[struct.unpack_from('<I',pay,0xa4+layer*4)[0],struct.unpack_from('<I',pay,0xb4+layer*4)[0],struct.unpack_from('<I',pay,0x114+layer*4)[0]&7]
        require(native(uc,request,layer,output)==1 and struct.unpack('<18I',bytes(uc.mem_read(output,72)))==tuple(expected),
                'Native snapshot differs from unchanged original builders: '+name)
        require(bytes(uc.mem_read(request,2424))==built and bytes(uc.mem_read(display,5728))==bytes(disp) and
                bytes(uc.mem_read(packet,312))==bytes(pay),'Read-only snapshot changed its inputs')
        cases.append({'case':name,'result':'PASS','unchanged_original_builder_blocks_executed':5})
    for name,this,layer,out in (('null-request',0,0,output),('null-output',request,0,0),('layer-four',request,4,output),
        ('layer-max',request,0xffffffff,output),('output-alias-request',request,0,request+16),
        ('output-overlaps-request-start',request,0,request-8),('request-address-wrap',(1<<64)-1024,0,output),
        ('output-address-wrap',request,0,(1<<64)-8)):
        uc=machine();req=b'\xb7'*2424;out_before=b'\xd8'*72;uc.mem_write(request,req);uc.mem_write(output,out_before)
        def access(engine,kind,address,size,value,user):
            require(kind!=UC_MEM_WRITE or stack<=address and address+size<=stack+16384,'Refused snapshot wrote an object')
        uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        require(native(uc,this,layer,out)==0 and bytes(uc.mem_read(request,2424))==req and bytes(uc.mem_read(output,72))==out_before,
                'Invalid snapshot arguments were not refused without writes: '+name)
        cases.append({'case':name,'result':'REFUSED_WITHOUT_WRITES'})
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed request-field fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n')
        print('Derived exact iPhone read-only request fields for review');return
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_request_fields']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'] and json.loads(FIXTURE.read_text())==contract,
            'Reviewed original request fields changed')
    out=ROOT/'build/ios16-request-fields';out.mkdir(parents=True,exist_ok=True);source=out/'request-fields.cpp'
    source.write_text('#include "OriginalLegacyRequestFieldsABI.h"\nextern "C" bool iphone_request_snapshot('
        'const IOMFBSwapIORequest *p,unsigned i,IPhone16RequestFields *o){return IPhone16Swap::snapshotFields(p,i,o);}\n')
    obj,=build_objects([source],out,[HEADER.parent]);cases=emulate(contract,obj)
    report={'result':'IOS16_REQUEST_FIELDS_NATIVE_AND_ORIGINAL_BLOCKS_PASS','native_kernel_sha256':sha(NATIVE),
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'builder_sha256':sha(ROOT/'scripts/prepare_ios16_request_fields.py'),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'queue_header_sha256':sha(HEADER.parent/'OriginalLegacySwapABI.h'),'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),
        'arm64_cases':cases,'native_snapshot_bytes':72,'original_builder_blocks':5,'original_instructions_changed':False,
        'original_neon_runs_only_in_cpu_fixture':True,'snapshot_fp_types_used':False,'snapshot_validation_semantics_complete':False,
        'original_objects_constructed':False,'producer_fences_executed':False,'full_original_swap_builder_executed':False,
        'frontend_invoked':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Native read-only packed-field snapshot matches five unchanged original scalar/NEON builder blocks on synthetic bounded memory. '
                'Output overlap/wrap and invalid arguments are refused before writes. Raw scalar fields retain unclassified semantics; '
                'this is not full layer/color/alpha/transform validation, producer completion, a queue frontend or display execution.'}
    (ROOT/'reports/ios16-request-fields.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: native read-only iPhone request snapshot vs five unchanged builders; 6 layouts and 8 guarded refusals; not a swap validator')


if __name__=='__main__':main()
