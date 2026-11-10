#!/usr/bin/env python3
"""Pin lifecycle observer hooks that acquire references without borrowed retains."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, macho, require, symbols
from native_prelink import backed_offset
from prepare_initial_data import sha

PROFILE=ROOT/'profiles/os/ios-16.7.16-20H392'
FIXTURE=PROFILE/'surface-backing-owner.json'
HEADER=PROFILE/'graphics/OriginalIOSurfaceBackingABI.h'
SLIDE=-0x1000000
HOOKS=(('init',0xfffffff005a4732c,0x318),('replace',0xfffffff005a548a8,0x90),
       ('clear',0xfffffff005a54938,0xec),('free',0xfffffff005a4c1d8,0xb4))


def derive():
    classes,raw,image,read=original_input()
    blocks={}
    for name,address,size in (*HOOKS,('init_without_parent',0xfffffff005a47324,8),('factory_before_publish',0xfffffff005a5a0a4,0x130),
        ('root_factory_init',0xfffffff005a5a100,0xd4),('root_publish',0xfffffff005a5a1d4,0x10c),
        ('surface_release_to_free',0xfffffff005a4c2ec,0x48),
        ('descriptor_owned_swap',0xfffffff005a4e5c0,0x64),
        ('initial_descriptor_builder',0xfffffff005a4bbb0,0x628)):
        blocks[name]={'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    first={name:struct.unpack('<I',read(address,4))[0] for name,address,_ in HOOKS}
    require(first=={'init':0xd10183ff,'replace':0xa9bd57f6,'clear':0xa9be4ff4,'free':0xd100c3ff},
        'Displaced original instructions must be the reviewed non-PC-relative stack operations')
    # All direct entry references in both executable regions. Final free is a
    # virtual call; the original slot and custom reference-zero path are pinned.
    references={name:[] for name,_,_ in HOOKS};targets={a:n for n,a,_ in HOOKS}
    for segment in image['segments']:
        if segment['name'] not in ('__TEXT_EXEC','__PLK_TEXT_EXEC'):continue
        body=raw[segment['fileoff']:segment['fileoff']+segment['filesize']]
        for index,(word,) in enumerate(struct.iter_unpack('<I',body)):
            if word&0x7c000000!=0x14000000:continue
            pc=segment['va']+index*4;value=word&0x3ffffff
            target=pc+4*(value-(1<<26) if value&(1<<25) else value)
            if target in targets:references[targets[target]].append(hex(pc))
    require(references=={'init':['0xfffffff005a47328','0xfffffff005a5a15c'],'replace':[],'clear':[],'free':[]},
        'Reviewed init-before-publication and indirect mutator entry references changed')
    require(struct.unpack('<Q',read(0xfffffff006d86040+15*8,8))[0]==dict((n,a) for n,a,_ in HOOKS)['free'],
        'Original IOSurface final free dispatch changed')
    require(struct.unpack('<I',read(0xfffffff005a5a15c,4))[0]==0x97ffb474 and
        struct.unpack('<I',read(0xfffffff005a5a0cc,4))[0]==0x94000042,
        'Original factory must finish init before publishing the surface')
    hooks={n:{'entry':hex(a),'bytes':size,'displaced_word':hex(first[n]),
        'resume_alias':'_native_iphone_surface_'+n+'_resume','wrapper':'_dodge_iphone_surface_'+n,
        'trampoline':'_dodge_original_surface_'+n} for n,a,size in HOOKS}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392',
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],'hooks':hooks,'blocks':blocks,
        'direct_entry_references':references,'surface_final_free_slot':15,'registry_max_surfaces':4096,
        'copy_acquires_reference_from_observer':True,'copy_retains_borrowed_getter':False,
        'init_capture_is_before_root_publication':True,'replacement_capture_uses_original_caller_input_reference':True,
        'observer_retains_surface':False,'observer_prepares_descriptor':False,
        'backing_immutable_until_GPU_completion':False,'producer_grant_implemented':False}


def checked():
    contract=derive();pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_surface_backing']
    require(pin['path']==str(FIXTURE.relative_to(ROOT)) and sha(FIXTURE)==pin['sha256'] and
        pin['header']==str(HEADER.relative_to(ROOT)) and sha(HEADER)==pin['header_sha256'] and
        json.loads(FIXTURE.read_text())==contract,'Reviewed surface backing ownership contract changed')
    return contract,pin


def branch(pc,target):
    distance=target-pc
    require(not distance&3 and -(1<<27)<=distance<(1<<27),'Surface lifecycle branch outside ARM64 B range')
    return 0x14000000|((distance//4)&0x3ffffff)


def hook_readbacks(data,contract):
    table={s['name']:s for s in symbols(data) if not s['kind']&0xe0};image=macho(data);rows={}
    for name,hook in contract['hooks'].items():
        entry=int(hook['entry'],16)+SLIDE;wrapper=table[hook['wrapper']]['value'];trampoline=table[hook['trampoline']]['value']
        resume=table[hook['resume_alias']]
        require(resume['kind']==3 and resume['value']==entry+4,'Surface lifecycle resume alias changed')
        def read(a,n):
            at=backed_offset(image['segments'],a,n,len(data));return data[at:at+n]
        actual=struct.unpack('<I',read(entry,4))[0];expected=branch(entry,wrapper)
        require(actual==expected,'Original surface lifecycle entry hook changed: '+name)
        words=struct.unpack('<2I',read(trampoline,8))
        require(words==(int(hook['displaced_word'],16),branch(trampoline+4,entry+4)),
            'Surface lifecycle trampoline does not replay exactly one instruction and resume at +4: '+name)
        restored=struct.pack('<I',int(hook['displaced_word'],16))+read(entry+4,hook['bytes']-4)
        require(hashlib.sha256(restored).hexdigest()==contract['blocks'][name]['sha256'],
            'Original surface lifecycle body changed beyond its single reviewed hook: '+name)
        rows[name]={'entry':hex(entry),'wrapper':hex(wrapper),'trampoline':hex(trampoline),'resume':hex(entry+4),
                    'patched_word':hex(actual),'displaced_word':hook['displaced_word'],'remaining_original_body_preserved':True}
    return rows


def apply_hooks(data,contract):
    result=bytearray(data);image=macho(data);table={s['name']:s for s in symbols(data) if not s['kind']&0xe0}
    for name,hook in contract['hooks'].items():
        entry=int(hook['entry'],16)+SLIDE;at=backed_offset(image['segments'],entry,4,len(data))
        require(struct.unpack_from('<I',result,at)[0]==int(hook['displaced_word'],16),'Refuse to overwrite an unknown original entry: '+name)
        struct.pack_into('<I',result,at,branch(entry,table[hook['wrapper']]['value']))
    hook_readbacks(result,contract)
    return bytes(result)


def restore_hooks(data,contract):
    hook_readbacks(data,contract);result=bytearray(data);image=macho(data)
    for hook in contract['hooks'].values():
        at=backed_offset(image['segments'],int(hook['entry'],16)+SLIDE,4,len(data))
        struct.pack_into('<I',result,at,int(hook['displaced_word'],16))
    return bytes(result)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--record-fixture',action='store_true');a=p.parse_args()
    if a.record_fixture:
        require(not FIXTURE.exists(),'Surface backing fixture already exists');FIXTURE.write_text(json.dumps(derive(),indent=2)+'\n')
    else:checked();print('PASS: pinned init-before-publish / replace / clear / final-free ownership hooks')


if __name__=='__main__':main()
