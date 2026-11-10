#!/usr/bin/env python3
"""Derive original graphics module/metaclass identities from the pinned iPhone."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tomllib

from check_ios16_swap import original_input
from check_ios16_graphics import derive as derive_accelerator
from native_driver_build import ROOT,require,sha,macho
from native_prelink import backed_offset,exports,unserialize_xml

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/graphics-modules.json'
HEADER=FIXTURE.parent/'graphics/OriginalGraphicsModulesABI.h'


def derive():
    classes,raw,image,read=original_input()
    info,=[s for s in image['segments'] if s['name']=='__PRELINK_INFO']
    entries={e['CFBundleIdentifier']:e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary']}
    names={n:a for a,group in exports(raw,image).items() for n in group}
    def words(pc,count):return struct.unpack('<'+str(count)+'I',read(pc,count*4))
    def adrp(pc,w):
        require(w&0x9f000000==0x90000000,'Original graphics metadata ADRP differs')
        immediate=((w>>5)&0x7ffff)*4+((w>>29)&3)
        return (pc&~4095)+((immediate-(1<<21) if immediate&(1<<20) else immediate)<<12)
    pc=0xfffffff005a54e60;a,b,c,d=words(pc,4)
    require(a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and
            c&0x9f00001f==0x90000001 and d&0xffc003ff==0x91000021 and
            words(0xfffffff005a54e88,1)==(0x52809203,),'Original IOSurface metadata this/name/size path differs')
    surface=adrp(pc,a)+((b>>10)&4095);label=adrp(pc+8,c)+((d>>10)&4095)
    require(read(label,10)==b'IOSurface\0','Wrong original IOSurface metadata name')
    call=0xfffffff005a54e90;w,=words(call,1);require(w&0xfc000000==0x94000000,'Expected original metadata constructor call')
    immediate=w&0x3ffffff;stub=call+4*(immediate-(1<<26) if immediate&(1<<25) else immediate)
    a,b,c=words(stub,3)
    require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Original metadata import stub differs')
    target,=struct.unpack('<Q',read(adrp(stub,a)+((b>>10)&4095)*8,8))
    ctor='__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t'
    require(target==names[ctor],'IOSurface does not call the actual zoned OSMetaClass constructor')
    accelerator,_=derive_accelerator()
    require(accelerator==json.loads((FIXTURE.parent/'graphics-abi.json').read_text()),'Original accelerator fixture changed')
    require(accelerator['original_sha256']==classes['original_kernelcache_sha256'],'Accelerator identity uses a different iPhone input')
    slide=int(tomllib.loads((FIXTURE.parent/'profile.toml').read_text())['kernel']['prelink']['slide'],0)
    identities=[('IOSurface','surface',surface,1168),('IOGPUFamily','accelerator',int(accelerator['metaclass'],16),136),
                ('IOMobileGraphicsFamily','legacy',int(classes['classes']['IOMobileFramebufferLegacy']['metadata'],16),5728)]
    modules=[]
    for family,alias,meta,size in identities:
        bundle='com.apple.iokit.'+family;entry=entries[bundle]
        module=macho(raw,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(raw)))
        require(module['kind']==11,'Original graphics input is not a kext')
        def inside(address,executable=False):
            return any(s['va']<=address<s['va']+s['size'] and (not executable or s['initprot']&4) for s in module['segments'])
        require(inside(meta),'Original graphics metaclass belongs to another component')
        kmod=entry['_PrelinkKmodInfo'];body=read(kmod,196)
        require(body[16:80].split(b'\0')[0].decode()==bundle,'Original kmod bundle name differs')
        start,stop=struct.unpack_from('<2Q',body,180)
        require(inside(start,True) and inside(stop,True),'Original module entrypoint is outside executable storage')
        sections={}
        for section in (s for seg in module['segments'] for s in seg['sections'] if s['name'] in ('__mod_init_func','__mod_term_func')):
            data=read(section['va'],section['size']);require(len(data)%8==0,'Original constructor table is not pointer aligned')
            pointers=struct.unpack('<'+str(len(data)//8)+'Q',data)
            require(all(inside(v,True) for v in pointers),'Original constructor/finalizer is outside its module')
            sections[section['name']]={'address':hex(section['va']),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                'entries':[{'address':hex(v),'prefix_sha256':hashlib.sha256(read(v,16)).hexdigest()} for v in pointers]}
        require(set(sections)=={'__mod_init_func','__mod_term_func'},'Original module lacks constructor/finalizer tables')
        modules.append({'bundle':bundle,'version':entry['CFBundleVersion'],'class_name':{'surface':'IOSurface','accelerator':'IOAcceleratorES','legacy':'IOMobileFramebufferLegacy'}[alias],
            'instance_bytes':size,'metaclass':hex(meta),'linked_metaclass':hex(meta+slide),'alias':'_dodge_original_graphics_'+alias+'_meta',
            'request_matching':alias=='surface','kmod_info':hex(kmod),'kmod_info_sha256':hashlib.sha256(body).hexdigest(),
            'start':hex(start),'stop':hex(stop),'start_prefix_sha256':hashlib.sha256(read(start,48)).hexdigest(),
            'stop_prefix_sha256':hashlib.sha256(read(stop,48)).hexdigest(),'sections':sections})
    waitpc=0xfffffff005c0ce40;a,b,c=words(waitpc,3)
    require(a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and c==0xd2800001 and
        words(waitpc+20,1)==(0xf9402be1,),'Original software-root matching/wait arguments differ')
    label=adrp(waitpc,a)+((b>>10)&4095);require(read(label,18)==b'IOCoreSurfaceRoot\0','Original Legacy waits for a different software root')
    personality=entries['com.apple.iokit.IOSurface']['IOKitPersonalities']['FirstPersonality']
    require(personality['IOClass']=='IOSurfaceRoot' and personality['IOProviderClass']=='IOResources' and personality['IOResourceMatch']=='IOBSD',
        'Original IOSurface software-root personality changed')
    root={'name':'IOCoreSurfaceRoot','class':'IOSurfaceRoot','provider':'IOResources','resource':'IOBSD',
        'original_wait_flow':{'address':hex(waitpc),'bytes':48,'sha256':hashlib.sha256(read(waitpc,48)).hexdigest()},'original_wait_has_timeout':False}
    provider_meta,=struct.unpack('<Q',read(0xfffffff006deafc8,8))
    provider_object,=struct.unpack('<Q',read(provider_meta,8))
    setup=0xfffffff0055f83e8;a,b,c,d=words(setup,4)
    require(a&0x9f00001f==0x90000000 and b&0xffc003ff==0x91000000 and
        c&0x9f00001f==0x90000001 and d&0xffc003ff==0x91000021 and
        adrp(setup,a)+((b>>10)&4095)==provider_object and words(setup+24,1)==(0x52801b03,),
        'Original Legacy provider cast does not use the actual device metadata constructor')
    label=adrp(setup+8,c)+((d>>10)&4095)
    require(read(label,17)==b'AppleARMIODevice\0','Original Legacy provider cast expects a different class')
    provider={'class':'AppleARMIODevice','instance_bytes':216,'metaclass':hex(provider_object),'metaclass_pointer':hex(provider_meta),
        'metadata_constructor':{'address':hex(setup),'bytes':52,'sha256':hashlib.sha256(read(setup,52)).hexdigest()},'original_cast_flow':{
        'address':hex(0xfffffff005c0cde8),'bytes':48,'sha256':hashlib.sha256(read(0xfffffff005c0cde8,48)).hexdigest()}}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'slide':hex(slide),'iosurface_metadata_flow':{'address':hex(pc),'bytes':52,'sha256':hashlib.sha256(read(pc,52)).hexdigest(),'constructor_import':ctor},
        'modules':modules,'surface_root_dependency':root,'provider_requirement':provider,'runtime_initialization_executed':False}


def header(fixture):
    lines=['// SPDX-License-Identifier: BSD-2-Clause-Patent','// Exact pinned iPhone10,3 / 20H392 identities. Address aliases contain no code.','#pragma once',
        'struct DodgeOriginalGraphicsModule {const char *bundle,*className;const void *expected;unsigned instanceBytes;bool requestMatching;};']
    for m in fixture['modules']:lines.append('extern "C" const unsigned char '+m['alias'][1:]+'[];')
    lines+=['constexpr unsigned DodgeOriginalGraphicsModuleCount=3;','static const DodgeOriginalGraphicsModule DodgeOriginalGraphicsModules[]={']
    for m in fixture['modules']:lines.append('    {"'+m['bundle']+'","'+m['class_name']+'",'+m['alias'][1:]+','+str(m['instance_bytes'])+','+str(m['request_matching']).lower()+'},')
    root=fixture['surface_root_dependency']
    return '\n'.join([*lines,'};','constexpr char DodgeOriginalGraphicsSurfaceRoot[]="'+root['name']+'";',
        'constexpr char DodgeOriginalGraphicsSurfaceRootClass[]="'+root['class']+'";',
        'constexpr char DodgeOriginalGraphicsProviderClass[]="'+fixture['provider_requirement']['class']+'";',''])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args();actual=derive()
    if args.write:
        require(not FIXTURE.exists() and not HEADER.exists(),'Refuse to replace a reviewed graphics lifecycle fixture')
        FIXTURE.write_text(json.dumps(actual,indent=2)+'\n');HEADER.write_text(header(actual))
    require(json.loads(FIXTURE.read_text())==actual and HEADER.read_text()==header(actual),'Original module lifecycle fixture/header changed')
    print('PASS: three exact original module identities, metaclass sizes, start/stop and 53 constructor entries derived')


if __name__=='__main__':main()
