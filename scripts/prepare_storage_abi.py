#!/usr/bin/env python3
"""Derive the original iPhone storage ABI against real, pinned public headers."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT,NATIVE,build_objects,inspect_object,pinned_sources,require,sha,symbols
from native_prelink import exports,macho,backed_offset,unserialize_xml

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/storage-abi.json'
HEADER=FIXTURE.parent/'storage/OriginalStorageABI.h'


def stage_headers(out):
    sources=pinned_sources(('iostorage_headers_reference','iphoneos_sdk_reference'))
    source=sources['iostorage_headers_reference'];sdk=sources['iphoneos_sdk_reference']/'iPhoneOS16.5.sdk'
    include=out/'include';headers=include/'IOKit/storage';headers.mkdir(parents=True,exist_ok=True)
    for path in source.glob('*.h'):shutil.copyfile(path,headers/path.name)
    target=sdk/'usr/include/TargetConditionals.h';require(target.is_file(),'Need the pinned real iPhone SDK target header')
    shutil.copyfile(target,include/'TargetConditionals.h')
    return source,include,target


def reference_methods(obj):
    raw=obj.read_bytes();image=inspect_object(raw);table=symbols(raw)
    symbol=next(s for s in table if s['name']=='__ZTV20IOBlockStorageDevice')
    section=next(s for seg in image['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    reloc,count=struct.unpack_from('<2I',raw,section['command_offset']+56);slots={}
    for i in range(count):
        at,bits=struct.unpack_from('<2I',raw,reloc+i*8);a=section['va']+at
        if a<symbol['value']+16:continue
        require(bits>>24==14,'Storage vtable reference relocation changed')
        slots[a]=table[bits&0xffffff]['name']
    methods=[];at=symbol['value']+16
    while at in slots:methods.append(slots[at]);at+=8
    require(len(methods)==190 and methods.count('___cxa_pure_virtual')==14,'Public iPhone storage vtable shape changed')
    return methods


def derive(methods):
    classes,raw,image,read=original_input();native_public=exports(raw,image)
    original_names={n:a for a,ns in native_public.items() for n in ns}
    info=next(s for s in image['segments'] if s['name']=='__PRELINK_INFO')
    entry=next(e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary'] if e['CFBundleIdentifier']=='com.apple.iokit.IOStorageFamily')
    module=macho(raw,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(raw)))
    def inside(a,executable=False):return any(s['va']<=a<s['va']+s['size'] and (not executable or s['initprot']&4) for s in module['segments'])
    def words(a,n):return struct.unpack('<'+str(n)+'I',read(a,n*4))
    def adrp(pc,w):
        require(w&0x9f000000==0x90000000,'Storage ADRP changed')
        v=((w>>5)&0x7ffff)*4+((w>>29)&3);return (pc&~4095)+((v-(1<<21) if v&(1<<20) else v)<<12)
    def branch(pc,call=True):
        w,=words(pc,1);require(w&0xfc000000==(0x94000000 if call else 0x14000000),'Storage direct branch changed')
        v=w&0x3ffffff;return pc+4*(v-(1<<26) if v&(1<<25) else v)
    def stub(pc):
        a,b,c=words(pc,3);require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Storage native import stub changed')
        return struct.unpack('<Q',read(adrp(pc,a)+((b>>10)&4095)*8,8))[0]
    setup=0xfffffff0055da09c;w=words(setup,15)
    require(w[:2]==(0xa9bf7bfd,0x910003fd) and w[8]==0x52801203,'Original storage metadata instance size changed')
    meta=adrp(setup+8,w[2])+((w[3]>>10)&4095)
    label=adrp(setup+16,w[4])+((w[5]>>10)&4095)
    require(read(label,21)==b'IOBlockStorageDevice\0','Original storage metaclass name changed')
    parent,=struct.unpack('<Q',read(adrp(setup+24,w[6])+((w[7]>>10)&4095)*8,8))
    require(parent==original_names['__ZN9IOService10gMetaClassE'] and stub(branch(setup+36))==original_names['__ZN11OSMetaClassC2EPKcPKS_j'],
            'Original storage class has a different real parent/metadata constructor')
    constructor=0xfffffff0055d9d98;c=words(constructor,8)
    require(c[:2]==(0xa9bf7bfd,0x910003fd) and c[5:]==(0xf9000008,0xa8c17bfd,0xd65f03c0) and
            stub(branch(constructor+8))==original_names['__ZN9IOServiceC2EPK11OSMetaClass'],'Storage protected C2 does not use native IOService')
    vptr=adrp(constructor+12,c[3])+((c[4]>>10)&4095);table=struct.unpack('<190Q',read(vptr,190*8))
    require(read(vptr+190*8,8)==bytes(8),'Original storage vtable terminator changed')
    require(inside(vptr) and inside(meta) and inside(constructor,True),'Storage identities escaped their original module')
    destructor=table[0]-4
    require(words(table[0],1)==words(table[1],1)==(0xd4200020,) and stub(branch(destructor,False))==original_names['__ZN9IOServiceD2Ev'],
            'Storage abstract destructors/protected D2 changed')
    a,b,c=words(table[7],3)
    require(a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and
            adrp(table[7],a)+((b>>10)&4095)==meta,'Storage getMetaClass does not identify the actual original object')
    rows=[]
    for slot,(name,address) in enumerate(zip(methods,table)):
        if name in original_names:
            require(original_names[name]==address,'Original storage/native vtable mismatch at '+str(slot)+': '+name);kind='native'
        else:
            require('IOBlockStorageDevice' in name and inside(address,True),'Unclassified original storage method: '+name);kind='original'
        rows.append({'slot':slot,'name':name,'address':hex(address),'kind':kind})
    slide=-0x1000000
    blocks={name:{'address':hex(a),'bytes':n,'sha256':hashlib.sha256(read(a,n)).hexdigest()} for name,a,n in
            (('metadata_constructor',setup,60),('protected_constructor',constructor,32),('protected_destructor',destructor,4))}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
            'module':'com.apple.iokit.IOStorageFamily','version':entry['CFBundleVersion'],'instance_bytes':144,'native_parent_instance_bytes':136,
            'vptr':hex(vptr),'metaclass':hex(meta),'protected_constructor':hex(constructor),'protected_destructor':hex(destructor),
            'slide':hex(slide),'vtable_entries':190,'pure_virtual_slots':[i for i,n in enumerate(methods) if n=='___cxa_pure_virtual'],
            'vtable_sha256':hashlib.sha256(read(vptr,190*8)).hexdigest(),'blocks':blocks,'methods':rows,
            'public_source_code_linked_or_executed':False,'metaclass_registered':False,'runtime_qualified':False,'hardware_tested':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
    out=ROOT/'build/ios16-storage-abi';source,include,target=stage_headers(out)
    probe=out/'StorageHeaderProbe.cpp';probe.write_text('#include <IOKit/storage/IOBlockStorageDevice.h>\n'
        'static_assert(sizeof(IOBlockStorageDevice)==144,"iPhone storage base size");\n'
        'static_assert(TARGET_OS_IOS && !TARGET_OS_OSX && !TARGET_OS_SIMULATOR,"real device iPhone target");\n'
        'extern "C" unsigned dodge_storage_header_size(){return sizeof(IOBlockStorageDevice);}\n')
    objects=build_objects([source/'IOBlockStorageDevice.cpp',probe],out,[include],
                          ['-Wno-deprecated-declarations','-Wno-macro-redefined','-include',str(target)])
    methods=reference_methods(objects[0]);fixture=derive(methods)
    if args.write:
        require(not FIXTURE.exists(),'Refuse to replace reviewed storage ABI inputs');FIXTURE.write_text(json.dumps(fixture,indent=2)+'\n')
    require(json.loads(FIXTURE.read_text())==fixture,'Original iPhone storage ABI changed')
    sources=[Path(__file__),ROOT/'scripts/native_driver_build.py',FIXTURE,HEADER,target,source/'IOBlockStorageDevice.cpp',source/'APPLE_LICENSE',*sorted(source.glob('*.h'))]
    lock=json.loads((ROOT/'upstream.lock.json').read_text());reference=lock['iostorage_headers_reference'];pin=lock['iphone_storage_abi']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'],'Reviewed storage contract/header changed')
    report={'result':'IOS16_ORIGINAL_STORAGE_CLASS_AND_PUBLIC_HEADER_ABI_STATIC_PASS','builder_sha256':sha(Path(__file__)),
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':fixture['original_kernelcache_sha256'],
            'public_reference':reference,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sources},
            'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'instance_bytes':144,'vtable_entries':190,'pure_virtual_slots':14,
            'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
            'native_method_bindings':sum(r['kind']=='native' for r in fixture['methods']),
            'original_method_bindings':sum(r['kind']=='original' for r in fixture['methods']),
            'public_headers':str(include.relative_to(ROOT)),'target_header':str(target.relative_to(ROOT)),'target_header_sha256':sha(target),
            'reference_objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in objects],
            'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
            'uses_real_pinned_iphone_sdk_conditionals':True,'exact_protected_constructor_and_destructor_derived':True,
            'public_reference_implementation_linked_or_executed':False,'metaclass_registered':False,'root_publication_built':False,
            'storage_reads_qualified':False,'runtime_qualified':False,'default_kernel_selected':False,'hardware_tested':False,
            'scope':'Actual iOS16 kernel compilation of pinned Apple public storage headers and reference implementation for annotation only. '
                    'All 190 original iPhone slots, actual 144-byte metadata, native IOService parent and protected C2/D2 are derived independently. '
                    'Reference implementation is not linked or executed; this is static ABI evidence, not block I/O or root publication.'}
    (ROOT/'reports/ios16-storage-abi.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: original iPhone storage class, 144 bytes / 190 slots / 14 pure virtual entries; public headers compile for native iOS16, no runtime execution')


if __name__=='__main__':main()
