#!/usr/bin/env python3
"""Derive and compile exact original iPhone IOSurface getter bindings; no backing-memory cast."""
import argparse
import hashlib
import json
import struct
import subprocess
import tomllib

from check_ios16_swap import original_input
from native_driver_build import ROOT, build_objects, inspect_object, macho, require, sha, symbols
from native_prelink import backed_offset, exports, unserialize_xml

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/surface-abi.json'
HEADER=FIXTURE.parent/'graphics/OriginalIOSurfaceABI.h'


def derive():
    classes,raw,image,read=original_input()
    info,=[s for s in image['segments'] if s['name']=='__PRELINK_INFO']
    entry,=[e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary']
            if e['CFBundleIdentifier']=='com.apple.iokit.IOSurface']
    module=macho(raw,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(raw)))
    text,=[s for s in module['segments'] if s['name']=='__TEXT_EXEC']
    def words(a,n):return struct.unpack('<%dI'%(n//4),read(a,n))
    def adrp(pc,word):
        require(word & 0x9f000000==0x90000000,'Expected original property-key ADRP')
        v=((word>>5)&0x7ffff)*4+((word>>29)&3)
        return (pc & ~4095)+((v-(1<<21) if v & (1<<20) else v)<<12)
    def key(pc,expected):
        a,b=words(pc,8)
        require(a & 0x9f00001f==0x90000001 and b & 0xffc003ff==0x91000021,'Expected property key in x1')
        address=adrp(pc,a)+((b>>10)&4095)
        require(read(address,len(expected)+1)==expected.encode()+b'\0','Wrong original property key: '+expected)
        return hex(address)
    roles=[('width',0xfffffff005a4e7f4,144,0xfffffff005a4ac10,0xfffffff005a4ac40,'IOSurfaceWidth'),
           ('height',0xfffffff005a4e7fc,148,0xfffffff005a4ac58,0xfffffff005a4ac88,'IOSurfaceHeight'),
           ('stride',0xfffffff005a4e80c,152,0xfffffff005a4af30,0xfffffff005a4af64,'IOSurfaceBytesPerRow'),
           ('offset',0xfffffff005a4e804,160,0xfffffff005a4b290,0xfffffff005a4b2c0,'IOSurfaceOffset'),
           ('format',0xfffffff005a4e7e4,164,0xfffffff005a4a9b0,0xfffffff005a4a9d8,'IOSurfacePixelFormat'),
           ('allocation',0xfffffff005a4e834,172,0xfffffff005a4b2cc,0xfffffff005a4b3b4,'IOSurfaceAllocSize')]
    getters={}
    for name,address,field,pc,store,label in roles:
        require(words(address,8)==(0xb9400000|((field//4)<<10),0xd65f03c0),'Wrong original 32-bit surface getter: '+name)
        require(words(store,4)[0]==0xb9000000|((field//4)<<10)|(19<<5),'Wrong original property destination: '+name)
        # Original dictionary lookup obtains its char-key virtual method,
        # then the same field is read by the getter. Retain complete path
        # digests so changes between the key and store are rejected too.
        require(words(pc-8,8)==(0xf9400288,0xf9409d08) and
                words(pc+8,8)==(0xaa1403e0,0xd63f0100),'Property does not use the actual dictionary-char lookup')
        getters[name]={'address':hex(address),'field':field,'result_bits':32,
            'sha256':hashlib.sha256(read(address,8)).hexdigest(),
            'property':label,'property_string':key(pc,label),'property_key_load':hex(pc),'property_store':hex(store),
            'property_flow_sha256':hashlib.sha256(read(pc-8,store+4-(pc-8))).hexdigest()}
    layout_roles=[('bytes_per_element',0xfffffff005a4e814,156,16,0xfffffff005a4aa24,0xfffffff005a4ac04,'IOSurfaceBytesPerElement'),
        ('element_width',0xfffffff005a4e81c,158,8,0xfffffff005a4acd0,0xfffffff005a4ad00,'IOSurfaceElementWidth'),
        ('element_height',0xfffffff005a4e824,159,8,0xfffffff005a4ad0c,0xfffffff005a4ad3c,'IOSurfaceElementHeight'),
        ('tile_format',0xfffffff005a50528,528,32,0xfffffff005a4a8bc,0xfffffff005a4a8e4,'IOSurfaceBufferTileFormat'),
        ('tile_mode',0xfffffff005a54ad4,512,8,0xfffffff005a4a924,0xfffffff005a4a950,'IOSurfaceBufferTileMode')]
    for name,address,field,bits,pc,store,label in layout_roles:
        load={8:0x39400000,16:0x79400000,32:0xb9400000}[bits]|((field//(bits//8))<<10)
        write={8:0x39000000,16:0x79000000,32:0xb9000000}[bits]|((field//(bits//8))<<10)|(19<<5)
        require(words(address,8)==(load,0xd65f03c0) and words(store,4)==(write,),
                'Original surface layout property/getter width differs: '+name)
        require(words(pc-8,8)==(0xf9400288,0xf9409d08) and words(pc+8,8)==(0xaa1403e0,0xd63f0100),
                'Original layout property dictionary dispatch differs: '+name)
        getters[name]={'address':hex(address),'field':field,'result_bits':bits,
            'sha256':hashlib.sha256(read(address,8)).hexdigest(),'property':label,'property_string':key(pc,label),
            'property_key_load':hex(pc),'property_store':hex(store),
            'property_flow_sha256':hashlib.sha256(read(pc-8,store+4-(pc-8))).hexdigest()}
    # Plane count is the actual OSArray count, not the adjacent 16-bit
    # bytes-per-element word. IOSurface zeroes it for nonplanar storage.
    require(words(0xfffffff005a4e82c,8)==(0xb940b000,0xd65f03c0) and
            words(0xfffffff005a478bc,20)==(0xaa0003f9,0xf9400008,0xf9404908,0xd63f0100,0xb900b260),
            'Original plane-array count path differs')
    plane_key=key(0xfffffff005a47894,'IOSurfacePlaneInfo')
    getters['planes']={'address':hex(0xfffffff005a4e82c),'field':176,'result_bits':32,
        'sha256':hashlib.sha256(read(0xfffffff005a4e82c,8)).hexdigest(),'property':'IOSurfacePlaneInfo count',
        'property_string':plane_key,'property_flow_sha256':hashlib.sha256(read(0xfffffff005a47894,60)).hexdigest()}
    require(words(0xfffffff005a4e844,8)==(0xf9401800,0xd65f03c0),'Original region pointer getter differs')
    getters['region']={'address':hex(0xfffffff005a4e844),'field':48,'result_bits':64,
        'sha256':hashlib.sha256(read(0xfffffff005a4e844,8)).hexdigest(),'result':'borrowed IOSurfaceMemoryRegion pointer'}
    # Resolve original public metadata and virtual identities to establish
    # the typed property flow and the region ancestry before naming it.
    names={n:a for a,group in exports(raw,image).items() for n in group}
    def slot(table,index):return struct.unpack('<Q',read(names[table]+16+index*8,8))[0]
    require(slot('__ZTV12OSDictionary',39)==names['__ZNK12OSDictionary9getObjectEPKc'] and
            slot('__ZTV8OSNumber',21)==names['__ZNK8OSNumber18unsigned32BitValueEv'] and
            slot('__ZTV8OSNumber',22)==names['__ZNK8OSNumber18unsigned64BitValueEv'] and
            slot('__ZTV7OSArray',18)==names['__ZNK7OSArray8getCountEv'],'Original property virtual prototypes differ')
    require(words(0xfffffff005a54e88,4)==(0x52809203,) and
            key(0xfffffff005a54e68,'IOSurface') and
            words(0xfffffff005a57fac,4)==(0x52800503,) and
            key(0xfffffff005a57f9c,'IOSurfaceMemoryRegion') and
            words(0xfffffff005a57780,4)==(0x52800c03,) and
            key(0xfffffff005a57770,'IOSurfaceDeviceMemoryRegion'), 'Original surface/region metadata identities differ')
    a,b=words(0xfffffff005a57fa4,8)
    c,d=words(0xfffffff005a57778,8)
    require(a & 0x9f00001f==0x90000002 and b & 0xffc003ff==0xf9400042 and
            c & 0x9f00001f==0x90000002 and d & 0xffc003ff==0x91000042 and
            struct.unpack('<Q',read(adrp(0xfffffff005a57fa4,a)+((b>>10)&4095)*8,8))[0]==names['__ZN8OSObject10gMetaClassE'] and
            adrp(0xfffffff005a57778,c)+((d>>10)&4095)==0xfffffff007a1e668, 'Region metadata ancestry differs')
    return {'schema_version':2,'product':'iPhone10,3','build':'20H392',
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'family_version':entry['CFBundleVersion'],'family_text_address':hex(text['va']),'family_text_bytes':text['filesize'],
        'family_text_sha256':hashlib.sha256(read(text['va'],text['filesize'])).hexdigest(),
        'surface_instance_bytes':1168,'memory_region_instance_bytes':40,'device_memory_region_instance_bytes':96,
        'memory_region_ancestry':['IOSurfaceDeviceMemoryRegion','IOSurfaceMemoryRegion','OSObject','OSMetaClassBase'],
        'getters':getters,'region_is_memory_descriptor':False,'backing_descriptor_provider_complete':False}


def emulate(contract,obj):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC
    _,_,_,read=original_input()
    raw=obj.read_bytes();im=macho(raw);syms=symbols(raw)
    text,=[s for g in im['segments'] for s in g['sections'] if s['name']=='__text']
    code=bytearray(raw[text['fileoff']:text['fileoff']+text['size']])
    base,original,instance,stack,stop=0x100000,0x110000,0x200000,0x300000,0x400000
    addresses={name:original+index*4096 for index,name in enumerate(contract['getters'])}
    ro,rc=struct.unpack_from('<2I',raw,text['command_offset']+56)
    require(rc==len(contract['getters']),'Expected one actual original getter relocation per native probe')
    for index in range(rc):
        offset,bits=struct.unpack_from('<2I',raw,ro+index*8)
        require(bits>>24 & 1 and bits>>25 & 3==2 and bits>>27 & 1 and bits>>28==2,'Unexpected native call relocation')
        name=syms[bits & 0xffffff]['name'];prefix='_native_iphone_surface_'
        require(name.startswith(prefix) and name[len(prefix):] in addresses,'Unexpected original getter import')
        target=addresses[name[len(prefix):]]
        instruction,=struct.unpack_from('<I',code,offset)
        require(instruction in (0x14000000,0x94000000),'Probe branch has an unexpected addend')
        struct.pack_into('<I',code,offset,instruction|(((target-base-offset)//4)&0x3ffffff))
    functions={s['name']:s['value']-text['va'] for s in syms if s['kind'] & 0xe and s['name'].startswith('_iphone_read_')}
    require(len(functions)==len(contract['getters']),'Expected one compiled typed probe per getter')
    results=[]
    for name,getter in contract['getters'].items():
        bits=getter['result_bits']
        for value in ((0,0xabcdef0187654321) if name=='region' else (0,(1<<(bits-1))|0x57,(1<<bits)-1)):
            machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
            for a,n in ((base,65536),(original,65536),(instance,4096),(stack,16384),(stop,4096)):machine.mem_map(a,n)
            machine.mem_write(base,bytes(code))
            machine.mem_write(addresses[name],read(int(getter['address'],16),8))
            content=bytearray([0xa5])*1168
            struct.pack_into({8:'<B',16:'<H',32:'<I',64:'<Q'}[bits],content,getter['field'],value)
            machine.mem_write(instance,bytes(content));machine.reg_write(UC_ARM64_REG_X0,instance)
            machine.reg_write(UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(UC_ARM64_REG_LR,stop)
            def access(engine,kind,address,size,written,user):
                require(instance<=address and address+size<=instance+1168 or stack<=address and address+size<=stack+16384,
                        'Original surface getter escaped the fixture object/stack')
            machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
            machine.emu_start(base+functions['_iphone_read_'+name],stop,timeout=100000,count=128)
            require(machine.reg_read(UC_ARM64_REG_PC)==stop and machine.reg_read(UC_ARM64_REG_X0)==value and
                    bytes(machine.mem_read(instance,1168))==bytes(content),'Typed original getter return or object preservation differs: '+name)
            results.append({'getter':name,'value':hex(value),'result':'PASS'})
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true')
    args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed IOSurface fixture already exists')
        FIXTURE.write_text(json.dumps(contract,indent=2)+'\n');print('Derived exact iPhone IOSurface getter contract for review');return
    lock=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_surface_interface']
    require(sha(FIXTURE)==lock['sha256'] and sha(HEADER)==lock['header_sha256'] and
            json.loads(FIXTURE.read_text())==contract,'Reviewed IOSurface getter interface differs')
    out=ROOT/'build/ios16-surface-interface';out.mkdir(parents=True,exist_ok=True)
    profile=tomllib.loads((FIXTURE.parent/'profile.toml').read_text());slide=int(profile['kernel']['prelink']['slide'],0)
    assembly=out/'original-surface-bindings.S'
    bindings={'_native_iphone_surface_'+name:int(item['address'],16)+slide for name,item in contract['getters'].items()}
    assembly.write_text(''.join(f'.globl {name}\n.set {name}, {address:#x}\n' for name,address in sorted(bindings.items())))
    binding=out/'original-surface-bindings.o'
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',assembly,'-o',binding],check=True)
    inspect_object(binding.read_bytes())
    require({s['name']:s['value'] for s in symbols(binding.read_bytes()) if s['kind']==3}==bindings,'Compiled absolute original bindings differ')
    source=out/'surface.cpp'
    source.write_text('#include "OriginalIOSurfaceABI.h"\n'+''.join(
        f'extern "C" uint64_t iphone_read_{name}(const OSObject *p) {{return '+
        (f'reinterpret_cast<uint64_t>(native_iphone_surface_{name}(p));' if name=='region' else f'native_iphone_surface_{name}(p);')+'}\n'
        for name in contract['getters']))
    obj,=build_objects([source],out,[HEADER.parent]);cases=emulate(contract,obj)
    archive=out/'libIPhone16SurfaceBindings.a'
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,binding],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,binding.name])==binding.read_bytes(),
            'Original bindings archive member changed')
    report={'result':'IOS16_SURFACE_BINDINGS_NATIVE_AND_ORIGINAL_ARM64_CHECK_PASS',
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),
        'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
        'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),'native_target':'arm64-apple-ios16.0',
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'slide':slide,
        'bindings':{name:hex(address) for name,address in bindings.items()},'cases':cases,
        'original_method_bytes_changed':False,'own_probe_branch_relocations_applied_to_fixture_addresses':True,
        'region_is_memory_descriptor':False,'backing_descriptor_provider_complete':False,
        'original_surface_constructed':False,'hardware_tested':False,
        'scope':'Thirteen exact original getters, property-to-field provenance, ordinary ARM64 typed calls and unsigned return-width checks. '
                'The borrowed IOSurfaceMemoryRegion must not be passed to the GPU as an IOMemoryDescriptor.'}
    (ROOT/'reports/ios16-surface-interface.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(contract["getters"])} exact original IOSurface bindings / {len(cases)} real ARM64 getter calls; region remains distinct from memory descriptor')


if __name__=='__main__':main()
