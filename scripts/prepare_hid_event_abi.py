#!/usr/bin/env python3
"""Derive bounded iPhone event/driver interfaces from the pinned original."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from native_driver_build import ROOT,build_objects,compile_command,inspect_object,pinned_sources,require,sha,symbols
from check_ios16_swap import original_input
from native_prelink import exports
from check_gpu_link import assemble

OUT=ROOT/'build/ios16-hid-event-abi'
CONTRACT=ROOT/'profiles/os/ios-16.7.16-20H392/hid-event-interface.json'
HEADER=CONTRACT.parent/'input/OriginalHidEventABI.h'
CLASSES={
    'IOHIDEvent':{'bytes':80,'slots':37,'public_slots':35,'vptr':0xfffffff006cc1018,'meta':0xfffffff007a12c58,
                  'meta_constructor':0xfffffff0057483fc,'constructor':0xfffffff005748434,'destructor':0xfffffff005748474},
    'IOHIDEventService':{'bytes':200,'slots':218,'public_slots':217,'vptr':0xfffffff006cbfb20,'meta':0xfffffff007a129d0,
                         'meta_constructor':0xfffffff0057384f8,'constructor':0xfffffff005738530,'destructor':0xfffffff005738570},
    'IOHIDEventDriver':{'bytes':264,'slots':219,'public_slots':218,'vptr':0xfffffff006cc0770,'meta':0xfffffff007a12c30,
                        'meta_constructor':0xfffffff00573dfd0,'constructor':0xfffffff00573e008,'destructor':0xfffffff00573e048}}
EVENT_SLOTS={18:'virtual uint32_t getType();',23:'virtual int32_t getIntegerValue(uint32_t,IOOptionBits=0);',
             24:'virtual void setIntegerValue(uint32_t,int32_t,IOOptionBits=0);',25:'virtual IOFixed getFixedValue(uint32_t,IOOptionBits=0);'}


def header():
    result='''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded iPhone10,3 / 20H392 declarations. Unqualified slots preserve
// original pointers only; the compiler forbids calls to their placeholders.
#pragma once
#include <IOKit/IOService.h>
class OSArray;
class IOHIDEvent : public OSObject {
    OSDeclareAbstractStructors(IOHIDEvent)
    unsigned char originalPrivate[80-sizeof(OSObject)];
public:
    void free() override;
    OSArray *getChildren();
'''
    for slot in range(15,37):
        result+='    '+EVENT_SLOTS.get(slot,f'virtual void dodgeEventOpaque{slot}() __attribute__((unavailable("Opaque original event slot: source calls are forbidden")));')+'\n'
    result+='''};
static_assert(sizeof(IOHIDEvent)==80,"Original iPhone event instance");
class IOHIDEventDriver : public IOService {
    OSDeclareDefaultStructors(IOHIDEventDriver)
    unsigned char originalPrivate[264-sizeof(IOService)];
public:
    IOReturn Dispatch(IORPC) override;
    void free() override;
    bool init(OSDictionary *properties=nullptr) override;
    IOReturn setProperties(OSObject *) override;
    bool didTerminate(IOService *,IOOptionBits,bool *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    void close(IOService *,IOOptionBits=0) override;
    bool handleOpen(IOService *,IOOptionBits,void *) override;
    void handleClose(IOService *,IOOptionBits) override;
    bool handleIsOpen(const IOService *) const override;
    bool matchPropertyTable(OSDictionary *,SInt32 *) override;
    IOReturn message(UInt32,IOService *,void *) override;
    IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) override;
'''
    for slot in range(168,219):
        result+='    '+('virtual void dispatchEvent(IOHIDEvent *,IOOptionBits=0);' if slot==198 else
                        f'virtual void dodgeEventDriverOpaque{slot}() __attribute__((unavailable("Opaque original event driver slot: source calls are forbidden")));')+'\n'
    result+='};\nstatic_assert(sizeof(IOHIDEventDriver)==264,"Original iPhone event driver instance");\n'
    return result


def methods(path,name,count=None):
    raw=path.read_bytes();im=inspect_object(raw);table=symbols(raw)
    vtable,=[s['value'] for s in table if s['name']=='__ZTV'+str(len(name))+name]
    section=next(s for seg in im['segments'] for s in seg['sections'] if s['va']<=vtable<s['va']+s['size'])
    start,n=struct.unpack_from('<2I',raw,section['command_offset']+56);refs={}
    for i in range(n):
        at,bits=struct.unpack_from('<2I',raw,start+8*i)
        if bits>>24==14:refs[section['va']+at]=table[bits&0xffffff]['name']
    result=[];pc=vtable+16
    while pc in refs:result.append(refs[pc]);pc+=8
    if count is not None:require(len(result)==count,'Event source table extent differs: '+name+' '+str(len(result)))
    return result


def stage():
    refs=pinned_sources(('iohid_headers_reference','iphoneos_sdk_reference'));OUT.mkdir(parents=True,exist_ok=True)
    include=OUT/'include';old=ROOT/'build/ios16-hid-abi/include'
    hid_report=json.loads((ROOT/'reports/ios16-hid-abi.json').read_text())
    require(sha(ROOT/hid_report['generated_iig_header'])==hid_report['generated_iig_header_sha256'],'Real IIG HID device header changed')
    shutil.copytree(old,include,dirs_exist_ok=True)
    public=refs['iohid_headers_reference']/'IOHIDFamily'
    (include/'IOKit/hidevent').mkdir(parents=True,exist_ok=True)
    for path in public.glob('*.h'):shutil.copyfile(path,include/'IOKit/hidevent'/path.name)
    base=json.loads((ROOT/'build/ios16-hid-abi/iig-command.json').read_text());commands={}
    host=json.loads((ROOT/'reports/host-tools.json').read_text())
    require(sha(Path(base[0]))==host['iig_executable_sha256'],'Actual pinned IIG executable changed')
    for name in ('IOHIDInterface','IOHIDEventService'):
        command=[arg.replace(str(old),str(include)) for arg in base]
        command[command.index('--def')+1]=str(refs['iohid_headers_reference']/'HIDDriverKit'/f'{name}.iig')
        command[command.index('--header')+1]=str(include/'HIDDriverKit'/f'{name}.h')
        command[command.index('--impl')+1]=str(OUT/f'{name}.iig.cpp')
        with (OUT/(name+'-iig.log')).open('w') as log:
            process=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
        require(not process.returncode,'Actual IIG event dependency generation failed: '+name)
        commands[name]=command
    (OUT/'iig-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    probe=OUT/'HidEventHeaderReference.cpp'
    probe.write_text('#include <stddef.h>\n#include <IOKit/hid/IOHIDEvent.h>\n#include <IOKit/hid/IOHIDEventData.h>\n#include <IOKit/hid/IOHIDEventDriver.h>\n'
                     'OSDefineMetaClassAndAbstractStructors(IOHIDEvent,OSObject)\n'
                     'OSDefineMetaClassAndAbstractStructors(IOHIDEventService,IOService)\n'
                     'OSDefineMetaClassAndStructors(IOHIDEventDriver,IOHIDEventService)\n'
                     'extern "C" const unsigned dodge_hid_event_layout[]={sizeof(IOHIDEvent),sizeof(IOHIDEventService),sizeof(IOHIDEventDriver),'
                     'sizeof(IOHIDDigitizerEventData),offsetof(IOHIDDigitizerEventData,position),offsetof(IOHIDDigitizerEventData,transducerIndex),'
                     'offsetof(IOHIDDigitizerEventData,eventMask),offsetof(IOHIDDigitizerEventData,options),kIOHIDDigitizerEventFromEdgeTip,kIOHIDDigitizerEventTouch};\n')
    target=refs['iphoneos_sdk_reference']/'iPhoneOS16.5.sdk/usr/include/TargetConditionals.h'
    obj,=build_objects([probe],OUT,[include],['-include',str(target),'-Wno-macro-redefined','-Wno-deprecated-declarations'])
    raw=obj.read_bytes();im=inspect_object(raw);s,=[s for s in symbols(raw) if not s['kind']&0xe0 and s['name']=='_dodge_hid_event_layout']
    section=next(t for seg in im['segments'] for t in seg['sections'] if t['va']<=s['value']<t['va']+t['size'])
    labels=('event_bytes','service_bytes','driver_bytes','digitizer_data_bytes','position','index','mask','options','from_edge_tip','touch_changed')
    facts=dict(zip(labels,struct.unpack_from('<10I',raw,section['fileoff']+s['value']-section['va'])))
    require(facts['event_bytes']==80 and facts['service_bytes']==200 and facts['driver_bytes']==264 and facts['from_edge_tip']==0x800 and facts['touch_changed']==2,
            'Real public event layouts/constants changed')
    return refs,obj,facts,target


def derive(public,facts,mutation=None):
    identity,raw,im,read_original=original_input();ex=exports(raw,im);names={n:a for a,ns in ex.items() for n in ns}
    def read(address,size):
        data=bytearray(read_original(address,size))
        if mutation and address<=mutation[0]<address+size:data[mutation[0]-address]^=mutation[1]
        return bytes(data)
    def pair(pc,a,b,reg):
        require(a&0x9f00001f==(0x90000000|reg) and b&0xffc003ff==(0x91000000|(reg<<5)|reg),'Original event address pair changed')
        d=((a>>5)&0x7ffff)*4+((a>>29)&3);d=d-(1<<21) if d&(1<<20) else d
        return (pc&~4095)+(d<<12)+((b>>10)&4095)
    def branch(pc,word,call):
        require(word&0xfc000000==(0x94000000 if call else 0x14000000),'Original event parent branch changed')
        delta=word&0x3ffffff;return pc+4*(delta-(1<<26) if delta&(1<<25) else delta)
    def imported(stub):
        a,b,c=struct.unpack('<3I',read(stub,12))
        require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Original event parent import stub changed')
        delta=((a>>5)&0x7ffff)*4+((a>>29)&3);delta=delta-(1<<21) if delta&(1<<20) else delta
        got=(stub&~4095)+(delta<<12)+((b>>10)&4095)*8
        return struct.unpack('<Q',read(got,8))[0]
    results={}
    for name,spec in CLASSES.items():
        table=struct.unpack('<'+str(spec['slots'])+'Q',read(spec['vptr'],spec['slots']*8))
        require(all(table) and read(spec['vptr']-16,16)==bytes(16) and read(spec['vptr']+len(table)*8,16)==bytes(16),'Original event table boundary changed: '+name)
        code=struct.unpack('<13I',read(spec['meta_constructor'],52));label=pair(spec['meta_constructor']+8,code[2],code[3],1)
        require(read(label,len(name)+1)==name.encode()+b'\0' and code[6]==0x52800003|(spec['bytes']<<5),'Original event metadata name/instance size changed: '+name)
        require(imported(branch(spec['meta_constructor']+28,code[7],True))==names['__ZN11OSMetaClassC2EPKcPKS_j'],'Original event metadata allocator changed')
        meta_code=struct.unpack('<3I',read(table[7],12));require(meta_code[2]==0xd65f03c0 and pair(table[7],meta_code[0],meta_code[1],0)==spec['meta'],'Original event identity getter changed')
        ctor=struct.unpack('<8I',read(spec['constructor'],32))
        require(ctor[:2]==(0xa9bf7bfd,0x910003fd) and ctor[5:]==(0xf9000008,0xa8c17bfd,0xd65f03c0) and
                pair(spec['constructor']+12,ctor[3],ctor[4],8)==spec['vptr'],'Original event protected constructor changed')
        parent_ctor=branch(spec['constructor']+8,ctor[2],True)
        parent_dtor=branch(spec['destructor'],struct.unpack('<I',read(spec['destructor'],4))[0],False)
        if name=='IOHIDEventDriver':
            require(pair(spec['meta_constructor']+16,code[4],code[5],2)==CLASSES['IOHIDEventService']['meta'] and
                    parent_ctor==CLASSES['IOHIDEventService']['constructor'] and parent_dtor==CLASSES['IOHIDEventService']['destructor'],
                    'Original event driver direct parent chain changed')
        else:
            base_name='OSObject' if name=='IOHIDEvent' else 'IOService';mangled=str(len(base_name))+base_name
            require(imported(parent_ctor)==names['__ZN'+mangled+'C2EPK11OSMetaClass'] and imported(parent_dtor)==names['__ZN'+mangled+'D2Ev'],
                    'Original event native protected parent chain changed')
        base_name='OSObject' if name=='IOHIDEvent' else 'IOService';base_count=15 if name=='IOHIDEvent' else 168
        base=struct.unpack('<'+str(base_count)+'Q',read(names['__ZTV'+str(len(base_name))+base_name]+16,base_count*8))
        overrides=[i for i,a in enumerate(base) if a!=table[i]]
        expected={'IOHIDEvent':[0,1,7,14],'IOHIDEventService':[0,1,7,12,14,21,44,86,87,89,91,92,93,101,132,140],
                  'IOHIDEventDriver':[0,1,7,12,14,21,44,77,86,87,89,91,92,93,101,132,140]}[name]
        require(overrides==expected,'Original event native override set changed')
        reference=methods(public,name,spec['public_slots'])
        for i,a in enumerate(base):
            if i not in overrides:require(reference[i] in names and names[reference[i]]==table[i],'Original event native inherited slot changed')
        results[name]={**{k:hex(v) if k in ('vptr','meta','meta_constructor','constructor','destructor') else v for k,v in spec.items()},
                       'native_overrides':overrides,'methods':[{'slot':i,'address':hex(a),'native_inherited_exact':i<base_count and i not in overrides,
                                                              'public_reference':reference[i] if i<len(reference) else None} for i,a in enumerate(table)],
                       'vtable_sha256':hashlib.sha256(read(spec['vptr'],spec['slots']*8)).hexdigest(),
                       'constructor_sha256':hashlib.sha256(read(spec['constructor'],32)).hexdigest()}
    children=0xfffffff00574eb0c;require(read(children,8)==struct.pack('<2I',0xf9400c00,0xd65f03c0),'Original event children leaf changed')
    require(read(0xfffffff00574a208,12)==struct.pack('<3I',0xf9400808,0xb9400500,0xd65f03c0),'Original event type/data pointer getter changed')
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':identity['original_kernelcache_sha256'],
            'classes':results,'compiler_public_layout':facts,'typed_event_slots':sorted(EVENT_SLOTS),'typed_driver_slot':198,
            'children_getter':hex(children),'children_getter_sha256':hashlib.sha256(read(children,8)).hexdigest(),
            'driver_dispatch_address':'0xfffffff005747ff8','driver_dispatch_bytes':296,
            'driver_dispatch_sha256':hashlib.sha256(read(0xfffffff005747ff8,296)).hexdigest(),
            'all_private_prototypes_qualified':False,'source_private_fields_access_required':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
    refs,public,facts,target=stage();contract=derive(public,facts)
    if args.write:
        require(not HEADER.exists() and not CONTRACT.exists(),'Refuse to replace an already reviewed event interface')
        HEADER.write_text(header());CONTRACT.write_text(json.dumps(contract,indent=2)+'\n')
    require(HEADER.read_text()==header() and json.loads(CONTRACT.read_text())==contract,'Reviewed iPhone event interface changed')
    if not args.write:
        pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_hid_event_interface']
        require(sha(HEADER)==pin['header_sha256'] and sha(CONTRACT)==pin['sha256'],'Reviewed event interface pin changed')
    out=OUT/'bounded';out.mkdir(exist_ok=True);probe=out/'DodgeHidEventInterfaceProbe.cpp'
    probe.write_text('#include "OriginalHidEventABI.h"\nOSDefineMetaClassAndAbstractStructors(IOHIDEvent,OSObject)\n'
                     'class DodgeHidEventInterfaceProbe : public IOHIDEventDriver {\nOSDeclareDefaultStructors(DodgeHidEventInterfaceProbe)\npublic:\n'
                     'void dispatchEvent(IOHIDEvent *,IOOptionBits) override {}\n};\nOSDefineMetaClassAndStructors(DodgeHidEventInterfaceProbe,IOHIDEventDriver)\n')
    obj,=build_objects([probe],out,[HEADER.parent]);table=methods(obj,'DodgeHidEventInterfaceProbe',219)
    require([i for i,n in enumerate(table) if '27DodgeHidEventInterfaceProbe' in n]==[0,1,7,198],'Bounded event driver override slots changed')
    methods(obj,'IOHIDEvent',37)
    slide=-0x1000000;aliases={}
    driver=contract['classes']['IOHIDEventDriver']
    for slot,(declaration,row) in enumerate(zip(table,driver['methods'])):
        if slot in (0,1,7,198) or row['native_inherited_exact']:continue
        aliases[declaration]=int(row['address'],16)+slide
    aliases.update({'__ZN16IOHIDEventDriverC2EPK11OSMetaClass':int(driver['constructor'],16)+slide,
                    '__ZN16IOHIDEventDriverD2Ev':int(driver['destructor'],16)+slide,
                    '__ZN16IOHIDEventDriver10gMetaClassE':int(driver['meta'],16)+slide,
                    '__ZTV16IOHIDEventDriver':int(driver['vptr'],16)-16+slide,
                    '__ZN16IOHIDEventDriver13dispatchEventEP10IOHIDEventj':int(contract['driver_dispatch_address'],16)+slide,
                    '__ZN10IOHIDEvent11getChildrenEv':int(contract['children_getter'],16)+slide,
                    '_dodge_original_hid_event_vtable':int(contract['classes']['IOHIDEvent']['vptr'],16)+slide})
    binding=assemble(OUT,'original-hid-event-bindings',''.join(f'.globl {n}\n.set {n},{a:#x}\n' for n,a in sorted(aliases.items())))
    require(all(not s['size'] for seg in inspect_object(binding.read_bytes())['segments'] for s in seg['sections']),'Original event bindings introduced implementation bytes')
    actual={s['name']:s for s in symbols(binding.read_bytes()) if not s['kind']&0xe0 and s['kind']&1}
    require(set(actual)==set(aliases) and all(actual[n]['kind']==3 and actual[n]['value']==a for n,a in aliases.items()),'Original event binding addresses changed')
    archive=OUT/'libIPhoneHidEventBindings.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',str(archive),str(binding)],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',str(archive),binding.name])==binding.read_bytes(),'Original event binding archive member changed')
    controls=[]
    invalid=out/'OpaqueCall.cpp';invalid.write_text('#include "OriginalHidEventABI.h"\nvoid forbidden(IOHIDEvent *e,IOHIDEventDriver *d){e->dodgeEventOpaque35();d->dodgeEventDriverOpaque218();}\n')
    recipe=compile_command(invalid,out/'invalid.o',[HEADER.parent]);process=subprocess.run(recipe['arguments'],cwd=recipe['directory'],capture_output=True,text=True)
    require(process.returncode and process.stderr.count('source calls are forbidden')>=2,'Original event opaque source calls were not rejected by the real compiler')
    controls.append({'case':'opaque-event-and-driver-source-calls','result':'REJECTED'})
    for name,where in (('event-class-size',CLASSES['IOHIDEvent']['meta_constructor']+24),('driver-native-pointer',CLASSES['IOHIDEventDriver']['vptr']+2*8)):
        try:derive(public,facts,(where,1))
        except ValueError as error:controls.append({'case':name,'result':'REJECTED','check':str(error)})
        else:raise ValueError('Mutated event interface was accepted')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_gpu_link.py',ROOT/'scripts/check_ios16_swap.py',HEADER,CONTRACT,target,
           *sorted((refs['iohid_headers_reference']/'IOHIDFamily').glob('*.h')),
           *[refs['iohid_headers_reference']/'HIDDriverKit'/(n+'.iig') for n in ('IOHIDInterface','IOHIDEventService')]]
    report={'result':'IOS16_BOUNDED_ORIGINAL_IPHONE_HID_EVENT_AND_DRIVER_ABI_PREPARATION_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
            'contract':str(CONTRACT.relative_to(ROOT)),'contract_sha256':sha(CONTRACT),'public_reference_object':str(public.relative_to(ROOT)),
            'public_reference_object_sha256':sha(public),'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'original_binding_count':len(aliases),
            'original_bindings':{n:hex(a) for n,a in sorted(aliases.items())},'bindings_contain_no_implementation_bytes':True,
            'original_event_bytes':80,'original_event_slots':37,'original_driver_bytes':264,'original_driver_slots':219,
            'public_event_slots':35,'public_driver_slots':218,'typed_event_slots':sorted(EVENT_SLOTS),'typed_driver_slot':198,
            'negative_controls':controls,'compiler_public_layout':facts,'full_private_prototypes_qualified':False,
            'source_implementation_linked':False,'event_driver_vtable_modified':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Original class identities, metadata sizes, protected constructors, vtable extents and inherited native slots; real public/iPhone-SDK/IIG annotation. '
                    'Bounded 80-byte/37-slot event and 264-byte/219-slot driver declarations permit only used extra operations; other source calls remain unavailable. '
                    'Getter/setter/dispatch body CPU qualification and source edge implementation remain separate, not claimed by this shape audit.'}
    (ROOT/'reports/ios16-hid-event-abi.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: bounded iPhone event 80/37 and driver 264/219; public 35/218 mismatch preserved, no private-field or vtable mutation')


if __name__=='__main__':main()
