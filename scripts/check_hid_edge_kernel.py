#!/usr/bin/env python3
"""Run the concrete source edge driver with real original event accessor bodies."""
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,require,sha,symbols,macho
from build_input_native import fresh
from check_hid_parser import context,SLIDE
from prepare_hid_event_abi import CONTRACT,HEADER

CASES=('left-sequence','right','top','bottom','exact-inner-boundary','ten-contacts','duplicate-id','invalid-coordinate',
       'invalid-id','too-many','changing-count','unknown-child','wrong-type','standalone-finger','empty-hand',
       'not-ready','null-event','inactive','init-success','init-failure','init-repeat','init-duplicate-object','free-never-initialized','start-success','start-parent-failure',
       'start-no-loop','start-bad-geometry','start-before-init','start-null','stop-disables-dispatch','constructor-destructor',
       'prepare-success','prepare-load-failure','prepare-parent-missing','prepare-parent-wrong','prepare-parent-size',
       'prepare-pre-failure','prepare-post-failure','prepare-class-missing','prepare-repeat')


def layout():
    out=ROOT/'build/ios16-hid-edge-abi';out.mkdir(parents=True,exist_ok=True)
    original=ROOT/'drivers/DodgeInput/DodgeHidEventDriver.cpp';source=out/original.name
    needle='    OSDeclareDefaultStructors(DodgeHidEventDriver)\n';text=original.read_text();require(text.count(needle)==1,'Source edge class annotation anchor changed')
    labels=('instance_bytes','edges','loop','providerPin','initAttempted','startAttempted','ready','edge_x','edge_y',
            'video_bytes','video_width','video_height','video_rotate','digitizer_type','video_width_bytes','video_height_bytes')
    values=('sizeof(DodgeHidEventDriver)',*[f'offsetof(DodgeHidEventDriver,{n})' for n in labels[1:7]],
            'offsetof(DodgeHidEdgePolicy,x)','offsetof(DodgeHidEdgePolicy,y)','sizeof(PE_Video)',
            'offsetof(PE_Video,v_width)','offsetof(PE_Video,v_height)','offsetof(PE_Video,v_rotate)',
            'offsetof(IOHIDDigitizerEventData,transducerType)','sizeof(((PE_Video *)0)->v_width)','sizeof(((PE_Video *)0)->v_height)')
    source.write_text(text.replace(needle,needle+'public: // layout annotation only\n')+
                      '\n#include <IOKit/hid/IOHIDEventData.h>\nextern "C" const unsigned dodge_hid_edge_layout[]={'+','.join(values)+'};\n')
    obj,=build_objects([source],out,[HEADER.parent,original.parent,ROOT/'build/ios16-hid-event-abi/include'],['-Wno-invalid-offsetof','-Wno-macro-redefined'])
    def machine_code(path):
        data=path.read_bytes();s=next(s for seg in inspect_object(data)['segments'] for s in seg['sections'] if s['name']=='__text')
        return data[s['fileoff']:s['fileoff']+s['size']]
    require(machine_code(obj)==machine_code(ROOT/'build/ios16-hid-edge-source/DodgeHidEventDriver.o'),'Source edge access annotation changed real code')
    data=obj.read_bytes();im=inspect_object(data);symbol,=[s for s in symbols(data) if not s['kind']&0xe0 and s['name']=='_dodge_hid_edge_layout']
    section=next(s for seg in im['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    at=section['fileoff']+symbol['value']-section['va'];return dict(zip(labels,struct.unpack_from('<'+str(len(labels))+'I',data,at))),obj


def emulate(candidate,case,facts,control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=candidate.read_bytes();im=macho(raw);symbols_all=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14]
    names={s['name']:s['value'] for s in symbols_all};addresses={s['value'] for s in symbols_all}
    original,original_read,module,imports=context();contract=json.loads(CONTRACT.read_text());payload_facts=contract['compiler_public_layout']
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(address,data=b'',size=0):
        p=address&~4095;end=(address+max(size,len(data))+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            stop=p+4096
            while stop<end and stop not in pages:stop+=4096
            uc.mem_map(p,stop-p);pages.update(range(p,stop,4096));p=stop
        if data:uc.mem_write(address,data)
    for seg in im['segments']:
        if seg['size'] and seg['initprot']:put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
    obj,loop,provider,expansion,array,stack,halt=0x100040,0x110040,0x120040,0x130040,0x140040,0x200000,0x300000
    extents={obj:facts['instance_bytes'],loop:128,provider:144,expansion:1024,array:128};refs={obj:1,loop:1,provider:1}
    root=0x500040;events=[root,*[0x510040+i*0x2000 for i in range(10)]];payloads={event:event+0x1000 for event in events}
    for event in events:extents[event]=80;extents[payloads[event]]=payload_facts['digitizer_data_bytes'];refs[event]=1
    for address,size in extents.items():put(address-64,b'\xa5'*(size+128));put(address,bytes(size))
    put(stack,size=65536);put(halt,size=65536)
    for address,type_name in ((obj,'19DodgeHidEventDriver'),(loop,'10IOWorkLoop'),(provider,'9IOService'),(array,'7OSArray')):
        put(address,struct.pack('<Q',names['__ZTV'+type_name]+16))
    original_vptr=int(contract['classes']['IOHIDEvent']['vptr'],16)+SLIDE
    for event in events:
        put(event,struct.pack('<Q',original_vptr));put(event+16,struct.pack('<Q',payloads[event]))
    put(obj+256,struct.pack('<Q',expansion))
    def field(name,value,width=1):put(obj+facts[name],int(value).to_bytes(width,'little'))
    def get(name,width=1):return int.from_bytes(bytes(uc.mem_read(obj+facts[name],width)),'little')
    field('loop',loop,8);field('initAttempted',1);field('ready',1)
    put(obj+facts['edges']+facts['edge_x'],struct.pack('<2I',48*65536//1440,48*65536//3168))
    gate=0;continuations={};next_callback=0;peers={};visited=set();original_visited=set();trace=[];forwarded=[]
    children=events[1:2];count_reads=0;parent_inits=0;parent_starts=0;native_frees=0
    load_calls=0;meta_constructors=0;loader_open=False;symbol_name=''
    def args():return [uc.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(value=0):uc.reg_write(arm.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(arm.UC_ARM64_REG_PC,uc.reg_read(arm.UC_ARM64_REG_LR))
    def bind(name,fn):require(name in names,'Missing source edge peer: '+name);peers[names[name]]=fn
    def invoke(entry,arguments,done):
        nonlocal next_callback
        next_callback+=1;return_pc=halt+16*next_callback;context=uc.context_save()
        def finish():
            value=uc.reg_read(arm.UC_ARM64_REG_X0);uc.context_restore(context);done(value)
        continuations[return_pc]=finish;uc.reg_write(arm.UC_ARM64_REG_SP,uc.reg_read(arm.UC_ARM64_REG_SP)-4096)
        uc.reg_write(arm.UC_ARM64_REG_LR,return_pc)
        for i,v in enumerate(arguments):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
        uc.reg_write(arm.UC_ARM64_REG_PC,entry)
    def retain(a):require(a[0] in refs,'Source edge retains unknown object');refs[a[0]]+=1;ret()
    def release(a):require(a[0] in refs and refs[a[0]]>0,'Source edge releases unowned object');refs[a[0]]-=1;ret()
    bind('__ZNK8OSObject6retainEv',retain);bind('__ZNK8OSObject7releaseEv',release)
    def run_action(a):
        nonlocal gate
        require(a[0]==loop and a[2]==obj,'Source edge workloop/target changed');gate+=1
        def done(rc):
            nonlocal gate
            gate-=1;ret(rc)
        invoke(a[1],(a[2],*a[3:7]),done)
    bind('__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_',run_action)
    bind('__ZNK10IOWorkLoop6inGateEv',lambda a:ret(int(a[0]==loop and gate>0)))
    bind('__ZNK9IOService10isInactiveEv',lambda a:ret(int(case=='inactive')))
    def count(a):
        nonlocal count_reads
        require(a[0]==array,'Source edge reads unknown child array');count_reads+=1
        ret(11 if case=='too-many' else len(children)+(1 if case=='changing-count' and count_reads>=2 else 0))
    bind('__ZNK7OSArray8getCountEv',count)
    def child(a):require(a[0]==array and a[1]<len(children),'Source edge child lookup escaped its bounded array');ret(children[a[1]])
    bind('__ZNK7OSArray9getObjectEj',child)
    def cast(a):ret(array if a[0]==array else provider if a[0]==provider else 0)
    bind('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass',cast)
    bind('__ZNK15OSMetaClassBase8metaCastEPKc',lambda a:ret(provider if a[0]==provider else 0))
    bind('__ZNK9IOService11getWorkLoopEv',lambda a:ret(0 if case=='start-no-loop' else loop))
    def video(a):
        require(stack<=a[0] and a[0]+facts['video_bytes']<=stack+65536,'Source edge video output escaped stack')
        put(a[0],bytes(facts['video_bytes']))
        put(a[0]+facts['video_width'],(96 if case=='start-bad-geometry' else 1440).to_bytes(facts['video_width_bytes'],'little'))
        put(a[0]+facts['video_height'],(3168).to_bytes(facts['video_height_bytes'],'little'));ret()
    bind('_PE_current_console',video)
    def parent_init(a):
        nonlocal parent_inits
        require(a[0]==obj and get('initAttempted') and refs[obj]==2,'Source event instance was not pinned before original init')
        parent_inits+=1;ret(int(case!='init-failure'))
    def parent_start(a):
        nonlocal parent_starts
        require(a[:2]==[obj,provider] and get('startAttempted') and get('ready') and refs[provider]==2 and refs[loop]==2,
                'Source event provider/workloop/configuration was not pinned before original start')
        parent_starts+=1;ret(int(case!='start-parent-failure'))
    def parent_stop(a):require(a[:2]==[obj,provider] and not get('ready'),'Source event stop did not first disable reports');trace.append('parent-stop-peer');ret()
    base=int(contract['classes']['IOHIDEventDriver']['vptr'],16)+SLIDE
    for slot,fn in ((21,parent_init),(86,parent_start),(87,parent_stop)):
        peers[struct.unpack('<Q',bytes(uc.mem_read(base+slot*8,8)))[0]]=fn
    def native_free(a):
        nonlocal native_frees
        require(a[0] in (obj,0x150040) and bytes(uc.mem_read(a[0]+facts['initAttempted'],1))==b'\0','Attempted original event init fell through to unsafe free');native_frees+=1;ret()
    bind('__ZN8OSObject4freeEv',native_free)
    parent_dispatch=int(contract['classes']['IOHIDEventService']['methods'][198]['address'],16)+SLIDE
    def forward(a):
        require(gate and a[0]==obj and a[1]==root and a[2]==0x80000001,'Source/original event forwarding arguments or gate changed')
        forwarded.append([int.from_bytes(bytes(uc.mem_read(payloads[e]+payload_facts['mask'],4)),'little') for e in [root,*children]])
        ret()
    peers[parent_dispatch]=forward
    def zero(a):
        require(stack<=a[0]<=a[0]+a[1]<=stack+65536 or obj+264<=a[0]<=a[0]+a[1]<=obj+facts['instance_bytes'],'Source edge bzero escaped its owned fields')
        put(a[0],bytes(a[1]));ret()
    bind('_bzero',zero)
    def copy(a):
        require(0<a[2]<=facts['instance_bytes'] and obj+264<=a[0]<=a[0]+a[2]<=obj+facts['instance_bytes'],'Source edge memcpy escaped its owned fields')
        require(stack<=a[1]<=a[1]+a[2]<=stack+65536 or any(s['va']<=a[1]<=a[1]+a[2]<=s['va']+s['size'] and not s['initprot']&2 for s in im['segments']),
                'Source edge memcpy source escaped stack/readonly image')
        put(a[0],bytes(uc.mem_read(a[1],a[2])));ret(a[0])
    bind('_memcpy',copy)
    if case.startswith('prepare-'):
        symbol,wrong_meta,handle=0x180040,0x170040,0x190040
        parent_meta=names['__ZN16IOHIDEventDriver10gMetaClassE'];own_meta=names['__ZN19DodgeHidEventDriver10gMetaClassE']
        for address,size in ((symbol,128),(wrong_meta,128)):
            extents[address]=size;put(address-64,b'\xa5'*(size+128));put(address,bytes(size));refs[address]=0
        put(symbol,struct.pack('<Q',names['__ZTV8OSSymbol']+16));refs[parent_meta]=0;refs[own_meta]=0
        symbol_release=struct.unpack('<Q',bytes(uc.mem_read(names['__ZTV8OSSymbol']+16+5*8,8)))[0];peers[symbol_release]=release
        def cstring(address):
            data=bytearray()
            for i in range(256):
                value=bytes(uc.mem_read(address+i,1))
                if not value[0]:return data.decode()
                data+=value
            raise ValueError('Source edge loader string escaped bound')
        def load(a):
            nonlocal load_calls
            require(cstring(a[0])=='com.apple.iokit.IOHIDFamily' and a[1:6]==[0,1,0,0,0],'Source edge kext load arguments changed')
            load_calls+=1;ret(0xe00002bc if case=='prepare-load-failure' else 0)
        bind('__ZN6OSKext22loadKextWithIdentifierEPKcbbhhP7OSArray',load)
        def string(a):
            nonlocal symbol_name
            symbol_name=cstring(a[0]);require(symbol_name in ('IOHIDEventDriver','DodgeHidEventDriver'),'Source edge looked up unrelated metadata')
            require(refs[symbol]==0,'Source edge leaked prior lookup symbol');refs[symbol]=1;ret(symbol)
        bind('__ZN8OSSymbol17withCStringNoCopyEPKc',string)
        def copy_meta(a):
            require(a[0]==symbol and refs[symbol]==1,'Source edge metadata lookup did not own its symbol')
            if symbol_name=='IOHIDEventDriver':
                value=0 if case=='prepare-parent-missing' else wrong_meta if case=='prepare-parent-wrong' else parent_meta
            else:value=0 if case=='prepare-class-missing' else own_meta
            if value:refs[value]+=1
            ret(value)
        bind('__ZN11OSMetaClass21copyMetaClassWithNameEPK8OSSymbol',copy_meta)
        bind('__ZNK11OSMetaClass12getClassSizeEv',lambda a:ret(265 if a[0]==parent_meta and case=='prepare-parent-size' else 264 if a[0]==parent_meta else facts['instance_bytes']))
        def release_meta(a):require(a[0] in refs and refs[a[0]]>0,'Source edge releases unowned metaclass');refs[a[0]]-=1;ret()
        bind('__ZNK11OSMetaClass16releaseMetaClassEv',release_meta)
        def pre_load(a):
            nonlocal loader_open
            require(cstring(a[0])=='__kernel__' and not loader_open,'Source edge registered outside the Kernel loader namespace')
            if case=='prepare-pre-failure':ret(0);return
            loader_open=True;ret(handle)
        bind('__ZN11OSMetaClass10preModLoadEPKc',pre_load)
        def meta_ctor(a):
            nonlocal meta_constructors
            require(loader_open and a[:4]==[own_meta,a[1],parent_meta,facts['instance_bytes']] and cstring(a[1])=='DodgeHidEventDriver',
                    'Source edge metaclass initializer changed parent/size or lacked loader context')
            meta_constructors+=1;ret(a[0])
        bind('__ZN11OSMetaClassC2EPKcPKS_j',meta_ctor)
        def post_load(a):
            nonlocal loader_open
            require(loader_open and a[0]==handle and meta_constructors==1,'Source edge postModLoad did not pair with its initializer')
            loader_open=False;ret(0xe00002bc if case=='prepare-post-failure' else 0)
        bind('__ZN11OSMetaClass11postModLoadEPv',post_load)
    accounted=[];bind('__ZNK11OSMetaClass19instanceConstructedEv',lambda a:(accounted.append(a[0]),ret()))
    source_data=(ROOT/'build/ios16-hid-edge-source/DodgeHidEventDriver.o').read_bytes();oi=inspect_object(source_data)
    sections=[s for seg in oi['segments'] for s in seg['sections']];allowed=[]
    for s in symbols(source_data):
        if s['kind']&0xe0 or s['kind']&14!=14 or not s['section'] or sections[s['section']-1]['name']!='__text' or s['name'].startswith('ltmp'):continue
        matches=[v['value'] for v in symbols_all if v['name']==s['name']];require(len(matches)==1,'Ambiguous source edge implementation: '+s['name'])
        a=matches[0];allowed.append((a,min(v for v in addresses if v>a)))
    native_allowed=[]
    for name,n in (('__ZN9IOServiceC2EPK11OSMetaClass',32),('__ZN15IORegistryEntryC2EPK11OSMetaClass',32),
                   ('__ZN8OSObjectC2EPK11OSMetaClass',40),('__ZN15OSMetaClassBaseC2Ev',16),
                   ('__ZN9IOServiceD2Ev',4),('__ZN15IORegistryEntryD2Ev',4),('__ZN8OSObjectD2Ev',4),('__ZN15OSMetaClassBaseD2Ev',12)):
        native_allowed.append((names[name],names[name]+n))
    original_text=[(s['va']+SLIDE,s['va']+SLIDE+s['size']) for s in module['segments'] if s['initprot']&4]
    def hook(engine,address,length,user):
        if address in continuations:continuations.pop(address)();return
        if address in peers:peers[address](args());return
        if any(a<=address<b for a,b in allowed+native_allowed):visited.add(address);return
        require(any(a<=address<b for a,b in original_text),'Unqualified edge CPU implementation: '+hex(address)+' '+str([n for n,a in names.items() if a==address]))
        if address not in original_visited:
            require(bytes(uc.mem_read(address,length))==original_read(address-SLIDE,length),'Source edge changed original event instructions');original_visited.add(address)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    def execute(entry,arguments):
        uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
        for i,v in enumerate(arguments):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),v)
        uc.emu_start(entry,halt,timeout=5000000,count=1000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt and not continuations,'Source edge CPU path did not return within bounds')
        return uc.reg_read(arm.UC_ARM64_REG_X0)&0xffffffff
    def payload(event,identity=0,x=32768,y=32768,mask=2,down=True,kind=11,finger=True):
        data=bytearray(payload_facts['digitizer_data_bytes']);struct.pack_into('<3I',data,0,len(data),kind,(0x20000 if down else 0))
        struct.pack_into('<2i',data,payload_facts['position'],x,y);struct.pack_into('<I',data,payload_facts['index'],identity)
        struct.pack_into('<I',data,facts['digitizer_type'],2 if finger else 3);struct.pack_into('<I',data,payload_facts['mask'],mask)
        put(payloads[event],bytes(data));return bytes(data)
    if case=='unsafe-original-free':
        put(obj+256,bytes(8));faults=[]
        def invalid(engine,access,address,size,value,user):faults.append(address);return False
        uc.hook_add(unicorn.UC_HOOK_MEM_INVALID,invalid)
        original_free=struct.unpack('<Q',bytes(uc.mem_read(base+14*8,8)))[0]
        try:execute(original_free,(obj,))
        except unicorn.UcError:
            require(faults==[0x18],'Original event free control faulted outside its known null expansion read')
            return {'case':'original-event-driver-null-expansion-free','result':'REJECTED','fault_address':'0x18',
                    'scope':'Deliberately invalid fixture, not a real kernel allocation failure; actual original free reads null expansion before native cleanup.'}
        raise ValueError('Unsafe original event free unexpectedly returned')
    if control=='lost-init-pin':
        start=names['__ZN19DodgeHidEventDriver4initEP12OSDictionary'];end=min(a for a in addresses if a>start)
        code=bytes(uc.mem_read(start,end-start));words=struct.unpack('<'+str(len(code)//4)+'I',code)
        sites=[i+2 for i,w in enumerate(words[:-2]) if w==0xf9401108 and words[i+2]==0xd63f0100]
        require(len(sites)==1,'Source edge init retention call shape changed');put(start+sites[0]*4,struct.pack('<I',0xd503201f))
    if case.startswith('prepare-'):
        rc=execute(names['_dodge_hid_edge_prepare'],())
        good=case in ('prepare-success','prepare-repeat');expected=0 if good else 0xe00002bc if case in ('prepare-load-failure','prepare-post-failure') else 0xe00002bd if case=='prepare-pre-failure' else 0xe00002d8 if case=='prepare-class-missing' else 0xe00002c7
        require(rc==expected and not loader_open and refs[symbol]==0,'Source edge loader error/state differs: '+case+' '+hex(rc))
        require(meta_constructors==int(case in ('prepare-success','prepare-repeat','prepare-post-failure','prepare-class-missing')),'Source edge initialized metadata before validating original parent')
        expected_pin=int(case not in ('prepare-load-failure','prepare-parent-missing','prepare-parent-wrong','prepare-parent-size'))
        require(refs[parent_meta]==expected_pin and refs[own_meta]==0 and refs[wrong_meta]==0,'Source edge parent metadata pin/unwind differs')
        if case=='prepare-repeat':
            require(execute(names['_dodge_hid_edge_prepare'],())==0 and load_calls==meta_constructors==1,'Source edge duplicated metadata registration')
        if case in ('prepare-pre-failure','prepare-post-failure','prepare-class-missing'):
            before=(load_calls,meta_constructors);require(execute(names['_dodge_hid_edge_prepare'],())==expected and before==(load_calls,meta_constructors),'Source edge retried partial metadata registration')
    elif case=='constructor-destructor':
        put(obj,bytes(facts['instance_bytes']));execute(names['__ZN19DodgeHidEventDriverC1Ev'],(obj,))
        expected=bytearray(264);struct.pack_into('<Q',expected,0,names['__ZTV19DodgeHidEventDriver']+16);struct.pack_into('<I',expected,8,1)
        require(bytes(uc.mem_read(obj,264))==bytes(expected) and accounted==[names['__ZN19DodgeHidEventDriver10gMetaClassE']],
                'Source edge C1/original event-driver/service/native chain differs')
        before=bytes(uc.mem_read(obj,facts['instance_bytes']));execute(names['__ZN19DodgeHidEventDriverD1Ev'],(obj,))
        require(bytes(uc.mem_read(obj,facts['instance_bytes']))==struct.pack('<Q',(1<<64)-1)+before[8:],'Source edge D1/original/native chain changed fields')
    elif case.startswith('init-'):
        field('initAttempted',0);field('ready',0)
        rc=execute(names['__ZN19DodgeHidEventDriver4initEP12OSDictionary'],(obj,0))
        require(rc==int(case!='init-failure') and refs[obj]==2 and parent_inits==1 and get('initAttempted') and
                execute(names['_dodge_hid_edge_instance_pinned'],())==1,'Source edge original-init retention/return differs')
        if case=='init-repeat':require(execute(names['__ZN19DodgeHidEventDriver4initEP12OSDictionary'],(obj,0))==0 and parent_inits==1 and refs[obj]==2,'Source edge repeated original init')
        execute(names['__ZN19DodgeHidEventDriver4freeEv'],(obj,));require(not native_frees,'Source edge tried to free partially initialized original state')
        if case=='init-duplicate-object':
            duplicate=0x150040;extents[duplicate]=facts['instance_bytes'];refs[duplicate]=1
            put(duplicate-64,b'\xa5'*(facts['instance_bytes']+128));put(duplicate,bytes(facts['instance_bytes']))
            put(duplicate,struct.pack('<Q',names['__ZTV19DodgeHidEventDriver']+16))
            require(execute(names['__ZN19DodgeHidEventDriver4initEP12OSDictionary'],(duplicate,0))==0 and parent_inits==1 and refs[duplicate]==1,
                    'Duplicate source event allocation entered original init or gained a leaked pin')
            execute(names['__ZN19DodgeHidEventDriver4freeEv'],(duplicate,));require(native_frees==1,'Duplicate untouched source event did not use native free')
    elif case=='free-never-initialized':
        field('initAttempted',0);execute(names['__ZN19DodgeHidEventDriver4freeEv'],(obj,))
        require(native_frees==1 and not parent_inits,'Untouched source event allocation did not use native free')
    elif case.startswith('start-'):
        for name in ('ready','loop','providerPin'):field(name,0,8 if name in ('loop','providerPin') else 1)
        if case=='start-before-init':field('initAttempted',0)
        rc=execute(names['__ZN19DodgeHidEventDriver5startEP9IOService'],(obj,0 if case=='start-null' else provider))
        ok=case=='start-success';require(rc==int(ok) and bool(get('ready'))==ok,'Source edge startup return/state differs')
        expected_parent=int(case in ('start-success','start-parent-failure'));require(parent_starts==expected_parent,'Source edge entered original start before valid geometry/resources')
        if case not in ('start-before-init','start-null'):
            require(refs[provider]==2 and refs[loop]==(1 if case=='start-no-loop' else 2),'Source edge start did not retain attempted provider/workloop')
            require(execute(names['__ZN19DodgeHidEventDriver5startEP9IOService'],(obj,provider))==0 and parent_starts==expected_parent,'Source edge repeated original start')
    else:
        if case=='not-ready':field('ready',0)
        if case=='stop-disables-dispatch':execute(names['__ZN19DodgeHidEventDriver4stopEP9IOService'],(obj,provider));require(trace==['parent-stop-peer'],'Source edge stop skipped original parent')
        root_before=payload(root,finger=False,mask=0x80000004)
        child_before=payload(children[0],identity=9,x=0)
        put(root+24,struct.pack('<Q',array))
        expected_edge=True
        if case=='right':child_before=payload(children[0],identity=9,x=65536)
        if case=='top':child_before=payload(children[0],identity=9,y=0)
        if case=='bottom':child_before=payload(children[0],identity=9,y=65536)
        if case=='exact-inner-boundary':child_before=payload(children[0],identity=9,x=48*65536//1440);expected_edge=False
        if case=='invalid-coordinate':child_before=payload(children[0],identity=9,x=-1);expected_edge=False
        if case=='invalid-id':child_before=payload(children[0],identity=256,x=0);expected_edge=False
        if case in ('ten-contacts','duplicate-id'):
            children=events[1:] if case=='ten-contacts' else events[1:3]
            for i,event in enumerate(children):payload(event,identity=i if case=='ten-contacts' else 0,x=0 if not i else 32768)
            expected_edge=case=='ten-contacts'
        if case in ('too-many','changing-count'):expected_edge=False
        if case=='unknown-child':put(children[0],struct.pack('<Q',names['__ZTV9IOService']+16));expected_edge=False
        if case=='wrong-type':root_before=payload(root,kind=3,finger=False,mask=0x80000004);expected_edge=False
        if case in ('standalone-finger','empty-hand'):
            put(root+24,bytes(8));children=[];root_before=payload(root,x=0,mask=2,finger=case=='standalone-finger');expected_edge=case=='standalone-finger'
        if control is True:
            at=names['__ZN19DodgeHidEventDriver13dispatchEventEP10IOHIDEventj'];put(at,struct.pack('<I',0xd65f03c0))
        dispatch=names['__ZN19DodgeHidEventDriver13dispatchEventEP10IOHIDEventj']
        execute(dispatch,(obj,0 if case=='null-event' else root,0x80000001))
        guarded=case in ('not-ready','null-event','inactive','stop-disables-dispatch')
        require(len(forwarded)==int(not guarded),'Source edge omitted or repeated original forwarding')
        if not guarded:
            require(bool(forwarded[-1][0]&0x800)==expected_edge,'Source edge parent event mask differs from contact origin')
            if case=='left-sequence':
                for x,mask,down,wanted in ((32768,4,True,0x804),(32768,2,False,0x802),(32768,2,True,2)):
                    payload(root,finger=False,mask=4);payload(children[0],identity=9,x=x,mask=mask,down=down)
                    execute(dispatch,(obj,root,0x80000001));require(forwarded[-1][1]==wanted,'Source edge lost edge origin before lift or kept it on identity reuse')
            if case not in ('left-sequence','ten-contacts','duplicate-id','standalone-finger','empty-hand'):
                after=bytes(uc.mem_read(payloads[children[0]],len(child_before)));expected=bytearray(child_before)
                if expected_edge:struct.pack_into('<I',expected,payload_facts['mask'],2|0x800)
                require(after==bytes(expected),'Source edge modified child fields outside exact mask')
        require(refs[obj]==refs[loop]==refs[provider]==1 and all(refs[e]==1 for e in events),'Source edge dispatch changed its held reference counts')
    require(not gate,'Source edge left workloop gate held')
    for address,size in extents.items():
        require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+size,64))==b'\xa5'*64,'Source edge fixture canary changed')
    return {'case':case,'result':'PASS','source_instructions_visited':len(visited),'original_instructions_visited':len(original_visited),
            'forwarded_masks':forwarded,'parent_init_peers':parent_inits,'parent_start_peers':parent_starts,
            'kext_load_calls':load_calls,'source_metadata_constructors':meta_constructors,
            'permanent_init_reference':refs[obj]-1,'permanent_provider_reference':refs[provider]-1}


def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json'
    source=fresh(source_path);prelink=fresh(prelink_path);candidate=ROOT/prelink['candidate']
    require(prelink['input_source_report_sha256']==sha(source_path) and sha(candidate)==prelink['candidate_sha256'],'Source edge prelink/input stale')
    facts,obj=layout();require(facts['instance_bytes']==source['edge_concrete_instance_bytes'],'Source edge compiled size differs')
    cases=[]
    for name in CASES:
        try:cases.append(emulate(candidate,name,facts))
        except Exception as error:raise ValueError('Source edge case '+name+': '+str(error)) from error
    controls=[]
    try:emulate(candidate,'left-sequence',facts,True)
    except ValueError as error:
        require(str(error)=='Source edge omitted or repeated original forwarding','Missing source dispatch control failed for another reason: '+str(error))
        controls.append({'case':'source-edge-dispatch-removed','result':'REJECTED','check':str(error)})
    else:raise ValueError('Missing edge source dispatch was accepted')
    try:emulate(candidate,'init-failure',facts,'lost-init-pin')
    except ValueError as error:
        require(str(error)=='Source event instance was not pinned before original init','Lost edge init pin control failed for another reason: '+str(error))
        controls.append({'case':'source-original-init-pin-removed','result':'REJECTED','check':str(error)})
    else:raise ValueError('Missing source event initialization pin was accepted')
    controls.append(emulate(candidate,'unsafe-original-free',facts))
    out=ROOT/'build/cph2653-input-prelink/edge-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeInput/DodgeHidEventDriver.cpp',ROOT/'drivers/DodgeInput/DodgeHidEdgePolicy.h',HEADER,CONTRACT]
    report={'result':'IOS16_PRELINKED_SOURCE_EDGE_DRIVER_AND_ORIGINAL_EVENT_ACCESSOR_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':sha(candidate),'case_count':len(cases),'cases':cases,'negative_controls':controls,
            'compiler_derived_layout':facts,'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'source_annotation_text_identical_to_production':True,
            'actual_original_event_getters_setter_and_default_driver_dispatch_executed':True,
            'unsafe_original_event_free_null_expansion_confirmed':True,
            'original_parent_init_start_stop_and_final_event_service_dispatch_are_peers':True,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual concrete source class init/start/stop/dispatch, transactional bounded edge annotation, original event getters/setter/default driver dispatch and source/original/native C1/D1 chain. '
                    'IOKit gate/array/registry/refcount/video/accounting and original parent init/start/stop/final event-service dispatch are peers. '
                    'No complete original driver lifecycle, matching/client ordering, physical touch, kernel runtime or UI qualification.'}
    (ROOT/'reports/ios16-hid-edge-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(cases))+' actual source edge/original event ARM64 paths, init/provider pins and missing-dispatch control')


if __name__=='__main__':main()
