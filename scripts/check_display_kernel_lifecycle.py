#!/usr/bin/env python3
"""Execute concrete-source and complete original Legacy functions from the linked candidate."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT,NATIVE,require,sha,symbols,macho
from native_prelink import backed_offset

DEPENDENCIES=('ios16-display-service','ios16-graphics-lifecycle','ios16-display-kernel','ios16-display-prelink')
INSTANCE_BYTES=5768


def emulate(path,case):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw)
    names={s['name']:s['value'] for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14}
    reverse={}
    for name,address in names.items():reverse.setdefault(address,[]).append(name)
    def find(part):
        found={v for n,v in names.items() if part in n};require(len(found)==1,'Ambiguous linked lifecycle entry: '+part);return found.pop()
    def read(address,size):return raw[backed_offset(image['segments'],address,size,len(raw)):][:size]
    def row(vptr,slot):return struct.unpack('<Q',read(vptr+slot*8,8))[0]
    profile=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/graphics-modules.json').read_text());slide=int(profile['slide'],0)
    original=lambda value:value+slide
    own_vptr=names['__ZTV22DodgeIPhoneFramebuffer']+16
    lifecycle=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/display-lifecycle.json').read_text())
    for key in ('init','start','stop'):
        block=lifecycle[key];data=read(original(int(block['address'],16)),block['bytes'])
        require(hashlib.sha256(data).hexdigest()==block['sha256'],'Linked original lifecycle instructions differ: '+key)
    original_start=original(int(lifecycle['start']['address'],16));original_stop=original(int(lifecycle['stop']['address'],16))
    start_return=original_start+lifecycle['start']['bytes']-4
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
    def put(address,data=b'',size=0):
        end=address+max(size,len(data));first=address&~4095;last=(end+4095)&~4095
        page=first
        while page<last:
            if page in pages:page+=4096;continue
            run=page+4096
            while run<last and run not in pages:run+=4096
            uc.mem_map(page,run-page);pages.update(range(page,run,4096));page=run
        if data:uc.mem_write(address,data)
    executable=[];mapped=[]
    for segment in image['segments']:
        if not segment['size'] or not segment['initprot']:continue
        require(segment['size']<256*1024*1024,'Unexpected candidate segment size')
        put(segment['va'],raw[segment['fileoff']:segment['fileoff']+segment['filesize']],segment['size'])
        mapped.append((segment['va'],segment['size']))
        if segment['initprot']&4:executable.append((segment['va'],segment['size']))
    display,provider,stack,halt,peer,heap_start=0x200000,0x210000,0x300000,0x400000,0x410000,0x1000000
    for a,n in ((display,8192),(provider,4096),(stack,65536),(halt,4096),(peer,4096)):put(a,size=n)
    put(display,bytes(INSTANCE_BYTES)+b'\xa5'*128);uc.mem_write(display,struct.pack('<Q',own_vptr))
    refs={display:1,provider:1};objects={};events=[];heap_cursor=heap_start;attached=set();properties={};returns=[]
    state={'gate':0,'loop':0,'core':0,'completion':0,'core_ready':False,'core_stopped':False,'core_inputs':False,
        'parent_returns':0,'parent_stops':0,'published':0,'registry':False,'depth':0,'thread':0,'thread_arg':0,
        'attributes':0,'attribute_names':0,'add_calls':0,'timer_calls':0,'core_busy':False,'hardware_calls':0,'gate_refs_at_stop':0,
        'parent_entered':False,'base_free':0,'post_hardware':0,'thread_completed':False,'core_loop':False,'thread_callbacks':0,
        'client_entries':0,'client_allocations':0,'client':0,'client_result':None}
    aliases={}
    def bind(address,name,action):
        if address in aliases:require(aliases[address][0]==name,'Lifecycle peers collide at '+hex(address))
        aliases[address]=(name,action)
    def arguments(n=8):return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(n)]
    def returned(value=0):
        uc.reg_write(reg.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def string(address,limit=256):
        if not address:return ''
        out=bytearray()
        for i in range(limit):
            b=bytes(uc.mem_read(address+i,1))
            if b==b'\0':return out.decode()
            out+=b
        raise ValueError('Unterminated lifecycle peer string')
    def retain(address):
        require(address in refs and refs[address]>0,'Retain of unknown/freed lifecycle peer: '+hex(address));refs[address]+=1
    def release(address):
        require(address in refs and refs[address]>0,'Release of unknown/freed lifecycle peer: '+hex(address));refs[address]-=1
        if address in objects and refs[address]==0:
            require(not objects[address].get('client_attached'),'Freed an attached user-client peer')
            require(address not in attached,'Freed an attached original event source');objects[address]['freed']=True
            if address==state['loop']:
                for source in list(attached):
                    objects[source]['enabled']=False;attached.remove(source);release(source)
    next_peer=peer
    def synthetic(name,action):
        nonlocal next_peer
        address=next_peer;next_peer+=4;require(next_peer<peer+0xf00,'Too many lifecycle peers');bind(address,name,action);return address
    retain_peer=synthetic('OSObject retain',lambda a:(retain(a[0]),returned()))
    release_peer=synthetic('OSObject release',lambda a:(release(a[0]),returned()))
    def allocate(kind,slots=None,external=False):
        nonlocal heap_cursor
        address=heap_cursor;heap_cursor+=4096;put(address,size=4096)
        refs[address]=2 if external else 1;objects[address]={'kind':kind,'enabled':kind!='interrupt','freed':False}
        table=address+512;uc.mem_write(address,struct.pack('<Q',table))
        for slot,target in {4:retain_peer,5:release_peer,**(slots or {})}.items():uc.mem_write(table+slot*8,struct.pack('<Q',target))
        return address
    def native(name,action):
        require(name in names,'Linked native lifecycle dependency missing: '+name);bind(names[name],name,action)
    # Actual concrete class retains/releases use the actual linked native
    # addresses. Synthetic IOKit objects have explicitly named peer tables.
    bind(row(own_vptr,4),'OSObject retain',lambda a:(retain(a[0]),returned()))
    bind(row(own_vptr,5),'OSObject release',lambda a:(release(a[0]),returned()))
    def bridge_return(action,owner,args,value=None):
        returns.append((uc.reg_read(reg.UC_ARM64_REG_LR),state['depth'],value));state['depth']+=1
        uc.reg_write(reg.UC_ARM64_REG_X0,owner)
        for i,arg in enumerate(args,1):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),arg)
        uc.reg_write(reg.UC_ARM64_REG_LR,peer+0xf00);uc.reg_write(reg.UC_ARM64_REG_PC,action)
    def run_action(a):
        require(a[0]==state['loop'],'Source lifecycle entered a different loop')
        if case.get('publication_refused') and a[1]==find('__ZN22DodgeIPhoneFramebuffer7publishE'):
            events.append('publication-action-refused');returned(0xe00002d8);return
        bridge_return(a[1],a[2],a[3:7])
    action_peer=synthetic('IOWorkLoop runAction',run_action)
    def add_source(a):
        state['add_calls']+=1;require(a[0]==state['loop'] and a[1] in objects,'Original source add lost its loop/source')
        fail=case.get('add_failure')==state['add_calls']
        if not fail:require(a[1] not in attached,'Original event source attached twice');attached.add(a[1]);retain(a[1])
        events.append('add-'+objects[a[1]]['kind']+('-refused' if fail else ''));returned(0xe00002bc if fail else 0)
    def remove_source(a):
        require(a[0]==state['loop'] and a[1] in objects,'Original source removal lost loop/source')
        if a[1] in attached:attached.remove(a[1]);release(a[1]);returned()
        else:returned(0xe00002c2)
    def disable_all(a):
        require(a[0]==state['loop'],'Original stop disabled a different loop')
        for address in attached:objects[address]['enabled']=False
        events.append('disable-original-sources');returned()
    add_peer=synthetic('IOWorkLoop addEventSource',add_source)
    remove_peer=synthetic('IOWorkLoop removeEventSource',remove_source)
    disable_peer=synthetic('IOWorkLoop disableAllEventSources',disable_all)
    enable_peer=synthetic('IOEventSource enable',lambda a:(objects[a[0]].__setitem__('enabled',True),returned()))
    loop_getter_peer=synthetic('IOEventSource getWorkLoop',lambda a:returned(state['loop'] if a[0] in attached else 0))
    # Provider property calls in default startup do not request a mapper. A
    # mapper branch is tested separately once a mapper peer has been selected.
    property_peer=synthetic('provider getProperty(char*)',lambda a:(events.append('provider-property:'+string(a[1])),returned()))
    provider_table=provider+512;uc.mem_write(provider,struct.pack('<Q',provider_table))
    for slot,target in ((4,retain_peer),(5,release_peer),(35,property_peer)):uc.mem_write(provider_table+slot*8,struct.pack('<Q',target))
    dictionary=0;root=allocate('IOSurfaceRoot')
    native_gate=names['__ZTV13IOCommandGate']+16;getter=names['__ZNK13IOEventSource11getWorkLoopEv']
    getter_slots=[i for i in range(40) if row(native_gate,i)==getter]
    require(len(getter_slots)==1,'Native command gate work-loop getter slot changed')
    def gate_factory(a):
        require(a[:2]==[display,0],'Original gate factory changed owner/action')
        if case.get('gate_failure'):returned();return
        state['gate']=allocate('command-gate',{22:enable_peer,getter_slots[0]:loop_getter_peer});returned(state['gate'])
    def loop_factory(a):
        if case.get('loop_failure'):returned();return
        state['loop']=allocate('work-loop',{20:add_peer,21:remove_peer,23:disable_peer,32:action_peer});returned(state['loop'])
    native('__ZN9IOService4initEP12OSDictionary',lambda a:(events.append('native-init-peer'),returned(int(not case.get('base_init_failure')))))
    # Original init import stubs stay intact and reach actual native names.
    native('__ZN13IOCommandGate11commandGateEP8OSObjectPFiS1_PvS2_S2_S2_E',gate_factory)
    native('__ZN10IOWorkLoop8workLoopEv',loop_factory)
    def bootarg(a):
        key=string(a[0]);require(a[2] in (4,8),'Original boot argument width changed')
        state['attributes']+=int(key.startswith('iomfb_'))
        if key==case.get('bootarg'):
            uc.mem_write(a[1],int(case.get('boot_value',1)).to_bytes(a[2],'little'));returned(1)
        else:returned()
    bind(original(0xfffffff005bf761c),'original boot-argument transport',bootarg)
    for name in ('_IOLog','_IOLogv'):
        if name in names:native(name,lambda a:returned())
    bind(original(0xfffffff005c0bb30),'original debug-log transport',lambda a:returned())
    if '_PE_i_can_has_debugger' in names:native('_PE_i_can_has_debugger',lambda a:returned())
    def meta_cast(a):
        require(a[0]==provider,'Original startup cast a different provider')
        require(a[1]==original(int(profile['provider_requirement']['metaclass'],16)),'Original provider cast uses wrong metadata')
        returned(provider)
    native('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass',meta_cast)
    def matching(a):
        nonlocal dictionary
        require(string(a[0])=='IOCoreSurfaceRoot' and not a[1],'Original software-root lookup differs')
        dictionary=0 if case.get('matching_failure') else allocate('matching-dictionary');returned(dictionary)
    def wait(a):
        require(a[:2]==[dictionary,0],'Original root wait arguments differ')
        if dictionary:release(dictionary)
        events.append('original-root-wait-peer');returned(root if dictionary and not case.get('root_failure') else 0)
    native('__ZN9IOService12nameMatchingEPKcP12OSDictionary',matching)
    native('__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec',wait)
    def thread_start(a):
        require(a[1]==display,'Original thread owner changed');state['thread']=a[0];state['thread_arg']=a[1]
        if case.get('thread_success'):
            handle=allocate('thread-handle');uc.mem_write(a[2],struct.pack('<Q',handle));returned()
        else:returned(5)
    native('_kernel_thread_start',thread_start)
    if '_thread_deallocate' in names:native('_thread_deallocate',lambda a:(release(a[0]),returned()))
    function_lookup=struct.unpack('<Q',read(original(0xfffffff006deafc0),8))[0]
    def lookup(a):
        require(a[0]==provider and refs[provider]>0,'Original background thread used a released provider')
        require(string(a[1])=='function-clpc_enabled','Original background thread queried a different platform function')
        state['thread_callbacks']+=1;events.append('original-platform-function-peer');returned()
    bind(function_lookup,'original AppleARMPlatform function lookup (char*)',lookup)
    def interrupt_factory(a):
        require(a[0]==display and a[2:4]==[0,0],'Original interrupt is not a software event source')
        if case.get('interrupt_failure'):returned();return
        returned(allocate('interrupt',{22:enable_peer}))
    native('__ZN22IOInterruptEventSource20interruptEventSourceEP8OSObjectPFvS1_PS_iEP9IOServicei',interrupt_factory)
    def timer_factory(a):
        state['timer_calls']+=1;require(a[0]==display,'Original timer lost owner')
        returned(0 if case.get('timer_failure')==state['timer_calls'] else allocate('timer',{22:enable_peer}))
    native('__ZN18IOTimerEventSource16timerEventSourceEP8OSObjectPFvS1_PS_E',timer_factory)
    def lock_alloc(a):returned(0 if case.get('lock_failure') else allocate('lock'))
    def recursive_alloc(a):returned(0 if case.get('recursive_failure') else allocate('recursive-lock'))
    native('_IOLockAlloc',lock_alloc);native('_IORecursiveLockAlloc',recursive_alloc)
    for name in ('_IOLockFree','_IORecursiveLockFree'):native(name,lambda a:(release(a[0]),returned()))
    native('__ZN12OSSerializer9forTargetEPvPFbS0_S0_P11OSSerializeES0_',lambda a:returned(0 if case.get('serializer_failure') else allocate('serializer')))
    set_property=row(own_vptr,25)
    def set_property_action(a):
        require(a[0]==display and a[2] in refs,'Original serializer property changed arguments')
        key=string(a[1]);properties[key]=a[2];retain(a[2]);returned(1)
    bind(set_property,'IORegistryEntry setProperty(char*,OSObject*)',set_property_action)
    get_name=row(own_vptr,61);label=heap_start-4096;put(label,b'DodgeIPhoneFramebuffer\0')
    bind(get_name,'IORegistryEntry getName',lambda a:returned(label))
    def zero(a):uc.mem_write(a[0],bytes(a[1]));returned(a[0])
    def copy(a):uc.mem_write(a[0],bytes(uc.mem_read(a[1],a[2])));returned(a[0])
    def memset(a):uc.mem_write(a[0],bytes([a[1]&255])*a[2]);returned(a[0])
    for name in ('_bzero','___bzero'):
        if name in names:
            address=names[name]
            if address not in aliases:bind(address,'bzero',zero)
    for name in ('_memcpy','_memmove'):
        if name in names:
            address=names[name]
            if address not in aliases:bind(address,'memory copy',copy)
    native('_memset',memset)
    # Actual compiled coordinator boundary is a peer, not a success claim for
    # GOP mapping, producer fences or event-loop primitives on a real kernel.
    def core_create(a):
        require(a[:2]==[display,provider] and state['gate'] and state['loop'],'Source coordinator created before original init')
        state['completion']=a[2]
        if case.get('core_failure'):returned();return
        state['core']=allocate('coordinator');state['core_inputs']=True;state['core_loop']=True
        for address in (display,provider,state['gate'],state['loop']):retain(address)
        returned(state['core'])
    def core_start(a):
        state['hardware_calls']+=1;require(a[:2]==[state['core'],1],'Source backend did not select coherent Adreno producer')
        heads=[4880,4896,*range(4912,5008,16)]
        require(all(struct.unpack('<2Q',uc.mem_read(display+h,16))==(0,display+h) for h in heads) and bytes(uc.mem_read(display+4872,8))==bytes(8),
            'Actual original start did not establish eight empty startup queues')
        if case.get('hardware_failure'):returned(0xe00002d8);return
        uc.mem_write(display+5208,struct.pack('<2I',1440,3168));state['core_ready']=True;returned()
    def core_ready(a):
        require(a[0]==state['core'],'Readiness lost its actual coordinator');returned(int(state['core_ready'] and not state['core_stopped']))
    def core_stop(a):
        require(a[0]==state['core'],'Stop lost its actual coordinator');state['core_ready']=False
        if state['core_busy']:returned(0xe00002d5);return
        if state['core_stopped']:returned();return
        state['core_stopped']=True
        bridge_return(state['completion'],display,[provider],0)
        # Input releases happen at the synthetic return trampoline, after
        # the actual compiled stopped callback and original stop return.
        returns[-1]=(*returns[-1][:3],'core-stop')
    def core_status(a):
        require(a[0]==state['core'],'Detach status lost coordinator')
        uc.mem_write(a[1],bytes([int(state['core_ready']),int(not state['core_ready']),int(state['core_stopped']),0])+bytes(4));returned(1)
    def core_release(a):
        require(a[0]==state['core'] and state['core_stopped'] and not state['core_inputs'],'Freed a live coordinator')
        require(state['core_loop'],'Consumed coordinator owner twice');state['core_loop']=False
        release(state['core']);release(state['loop']);returned()
    def core_admit(a):
        require(a[0]==state['core'],'Client admission used another coordinator')
        if not state['core_ready'] or state['core_stopped'] or case.get('client')=='admission-denied':returned(0xe00002d8);return
        bridge_return(a[1],display,[a[2]])
    for part,action in (('dodge_display_service_create',core_create),('dodge_display_service_start',core_start),
                        ('dodge_display_service_ready',core_ready),('dodge_display_service_stop',core_stop),
                        ('dodge_display_service_workloop',lambda a:returned(state['loop'])),('dodge_display_service_status',core_status),
                        ('dodge_display_service_release',core_release),('dodge_display_service_admit',core_admit)):
        bind(find(part),part,action)
    client_meta=0;client_meta_peer=0
    if case.get('client'):
        # The original metadata has not been constructed by this CPU fixture.
        # Supply only its vptr as an explicit allocation peer. No allocator,
        # original client class instance/layout or metadata registration is
        # represented by the synthetic object below.
        client_meta=struct.unpack('<Q',read(original(0xfffffff006dec448),8))[0]
        require(read(client_meta,8)==bytes(8),'Client metadata was unexpectedly initialized')
        task,security,client_type=0xfedcba9876543210,0x8877665544332211,0xdeadbeef
        def client_init(a):
            require(a[:4]==[state['client'],task,client_type,0],'Original client-init slot 186 changed its task/type/null call shape')
            success=case['client']!='init-failed';objects[a[0]]['client_initialized']=success;events.append('client-init-peer');returned(int(success))
        def client_attach(a):
            require(a[:2]==[state['client'],display] and objects[a[0]].get('client_initialized'),'Original client attached before its init')
            success=case['client']!='attach-failed'
            if success:objects[a[0]]['client_attached']=True;retain(display);retain(a[0])
            events.append('client-attach-peer');returned(int(success))
        def client_start(a):
            require(a[:2]==[state['client'],display] and objects[a[0]].get('client_attached'),'Original client started before attach')
            events.append('client-start-peer');returned(int(case['client']!='start-failed'))
        def client_detach(a):
            require(a[:2]==[state['client'],display] and objects[a[0]].get('client_attached'),'Original client detached a missing attachment')
            objects[a[0]]['client_attached']=False;release(display);release(a[0]);events.append('client-detach-peer');returned()
        init_peer=synthetic('client init slot 186',client_init);attach_peer=synthetic('client attach',client_attach)
        start_peer=synthetic('client start',client_start);detach_peer=synthetic('client detach',client_detach)
        def client_allocate(a):
            require(a[0]==client_meta,'Original newUserClient used the wrong metaclass')
            state['client_allocations']+=1;events.append('client-allocation-peer')
            if case['client']=='allocation-failed':returned();return
            state['client']=allocate('user-client',{186:init_peer,108:attach_peer,86:start_peer,109:detach_peer});returned(state['client'])
        allocation_peer=synthetic('original client metaclass allocation',client_allocate)
        client_meta_peer=allocate('client-allocation-table',{13:allocation_peer})
        uc.mem_write(client_meta,struct.pack('<Q',client_meta_peer+512))
    def publish(a):
        require(a[0]==display and state['parent_returns']==1 and state['core_ready'],'Source published before actual original start returned/was ready')
        state['published']+=1;events.append('native-publication');returned()
    native('__ZN9IOService15registerServiceEj',publish)
    def parent_stop(a):
        require(a[:2]==[display,provider],'Original parent stop lost provider')
        state['parent_stops']+=1;events.append('native-ioservice-stop-peer');returned()
    native('__ZN9IOService4stopEPS_',parent_stop)
    def detach(a):
        require(a[:2]==[display,provider] and state['registry'],'Source detached wrong/missing registry attachment')
        require(state['parent_stops']==int(state['parent_entered']),'Registry detached before original parent cleanup')
        state['registry']=False;release(provider);release(display);events.append('native-detach-peer');returned()
    native('__ZN9IOService6detachEPS_',detach)
    def base_free(a):
        require(a[0]==display and not state['registry'],'Base free before detach')
        for address in properties.values():release(address)
        properties.clear();state['base_free']+=1;returned()
    native('__ZN9IOService4freeEv',base_free)
    # Only this original family, the compiled concrete class, and the actual
    # IOService::start leaf may run. Any missing primitive is an explicit
    # failure, never an implicit return-success stub.
    # The merged prelink executable segment contains multiple families; bound
    # execution to the original mobile-graphics component from its raw header.
    from build_gpu_graphics_prelink import original_context,ORIGINAL,CONFIG,PROFILE
    import tomllib
    config=json.loads(CONFIG.read_text());target=tomllib.loads(PROFILE.read_text());original_data=ORIGINAL.read_bytes()
    context=original_context(original_data,target['kernel']['prelink']['roots']+config['additional_roots'],config)
    allowed=[(s['va']+slide,s['filesize']) for s in context['modules']['com.apple.iokit.IOMobileGraphicsFamily']['segments'] if s['initprot']&4 and s['filesize']]
    source_starts={a for n,a in names.items() if n.startswith('__ZN22DodgeIPhoneFramebuffer') and any(s['va']<=a<s['va']+s['size'] for s in image['segments'] if s['initprot']&4)}
    executable_symbols=sorted({s['value'] for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14==14 and
        any(a<=s['value']<a+n for a,n in executable)})
    for a in source_starts:
        end=min(v for v in executable_symbols if v>a);allowed.append((a,end-a))
    allowed.append((names['__ZN9IOService5startEPS_'],8))
    executed=set();instruction_count=0;recent=deque(maxlen=16)
    def instruction(engine,address,size,user):
        nonlocal instruction_count
        instruction_count+=1
        recent.append(address)
        if address==peer+0xf00:
            item=returns.pop();lr,depth,value=item[:3];state['depth']=depth
            if len(item)==4 and item[3]=='core-stop' and state['core_inputs']:
                for obj in (state['gate'],provider,display):release(obj)
                state['core_inputs']=False
            if value is not None:engine.reg_write(reg.UC_ARM64_REG_X0,value)
            engine.reg_write(reg.UC_ARM64_REG_PC,lr);return
        if address in aliases:
            name,action=aliases[address];executed.add('peer:'+name);action(arguments());return
        if address==start_return:state['parent_returns']+=1;events.append('original-start-return')
        if address==original_start:state['parent_entered']=True
        if address==original(0xfffffff005c0e840):
            require(state['depth']>0,'Original newUserClient escaped the admitted gate');state['client_entries']+=1
        if address==original(0xfffffff005c18a10):state['post_hardware']+=1
        if address==original(0xfffffff005c035fc):state['attribute_names']+=1
        if address==original_stop:
            require(state['depth']>0,'Compiled callback entered actual original stop outside retained work-loop gate')
            state['gate_refs_at_stop']=refs[state['gate']];events.append('original-stop-entry')
        require(any(a<=address< a+n for a,n in allowed),'Unreviewed lifecycle instruction '+hex(address)+' '+str(reverse.get(address,[])))
        executed.add(hex(address))
    writable=[(display,INSTANCE_BYTES),(provider,4096),(stack,65536),(heap_start-4096,4096)]
    for segment in image['segments']:
        if segment['initprot']&2:writable.append((segment['va'],segment['size']))
    def memory(engine,kind,address,size,value,user):
        # Kernel tables are real input. The CPU may mutate the original family
        # globals, its synthetic objects/stack and heap, never instruction bytes.
        if kind==UC_MEM_WRITE:
            require(any(a<=address and address+size<=a+n for a,n in writable) or heap_start<=address and address+size<=heap_cursor,
                'Linked lifecycle wrote outside bounded data/object/stack memory: '+hex(address))
    uc.hook_add(UC_HOOK_CODE,instruction);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
    uc.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
    def call(address,*args):
        for i,value in enumerate(args):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+0xff00);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
        try:uc.emu_start(address,halt,timeout=10000000,count=500000)
        except Exception as error:
            pc=uc.reg_read(reg.UC_ARM64_REG_PC)
            raise ValueError(f'Linked lifecycle {case["name"]} failed at {pc:#x} {reverse.get(pc)}; recent events {events[-12:]}; '
                f'PCs {[hex(v) for v in recent]}; args {arguments()}: {error}') from error
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt and uc.reg_read(reg.UC_ARM64_REG_SP)==stack+0xff00,'Linked lifecycle failed to return with intact SP')
        require(not returns and not state['depth'],'Linked lifecycle left a callback/gate frame');return uc.reg_read(reg.UC_ARM64_REG_X0)
    if case.get('unreviewed_native_call'):
        require('_IOMalloc' in names and names['_IOMalloc'] not in aliases,'Missing control for an unreviewed native allocator')
        call(names['_IOMalloc'],64)
    def complete_thread():
        require(state['thread'] and not state['thread_completed'],'Original thread was missing or completed twice')
        held=refs[display]
        call(state['thread'],state['thread_arg'],0)
        require(refs[display]==held-1 and state['thread_callbacks']==1,'Original thread did not release its display after provider lookup')
        state['thread_completed']=True
    def check_client():
        out=heap_start-4096+512;uc.mem_write(out,struct.pack('<Q',0xa5a5a5a5a5a5a5a5))
        before=refs[display];kind=case['client'];pointer=0 if kind=='null-output' else out
        value=call(row(own_vptr,141),display,task,security,client_type,pointer)&0xffffffff
        expected=0 if kind=='success' else 0xe00002c2 if kind=='null-output' else 0xe00002d8 if kind in ('admission-denied','after-stop') else 0xe00002c9
        require(value==expected,'Original/new source user-client status differs: '+kind);state['client_result']=value
        result=struct.unpack('<Q',uc.mem_read(out,8))[0]
        if kind=='success':
            require(result==state['client'] and refs[result]==2 and refs[display]==before+1,'Original client ownership was not transferred to caller/attachment')
            # Caller close is an explicit peer; actual clientClose, original
            # client implementations and asynchronous notification teardown
            # are outside this method-call/ownership check.
            call(detach_peer,result,display);release(result)
        elif kind!='null-output':require(result==0,'Failed client admission left a non-null output')
        require(refs[display]==before,'Original newUserClient leaked its display attachment')
        require(state['client_entries']==int(kind not in ('null-output','admission-denied','after-stop')),'Unadmitted client reached original parent')
        require(state['client_allocations']==state['client_entries'],'Original newUserClient allocation was skipped/repeated')
    initialized=bool(call(row(own_vptr,21),display,0));result=0;remaining_disabled=0
    if initialized:
        retain(display);retain(provider);state['registry']=True
        result=call(row(own_vptr,86),display,provider)
        require(result==int(not case.get('failure')),'Actual original + concrete source start returned wrong result')
        if result:
            require(state['published']==1 and state['hardware_calls']==1 and state['parent_stops']==0 and state['post_hardware']==1,
                'Success path missed real post-hardware/publication or stopped too early')
            require(struct.unpack('<2I',uc.mem_read(display+5208,8))==(1440,3168),'Original post-hardware initialization changed GOP dimensions')
            require(state['attribute_names']==176,'Actual original start did not visit all default boot attributes')
        else:require(state['published']==0,'Failed original startup published its concrete service')
        if case.get('client') and case['client']!='after-stop':check_client()
        if case.get('thread_success') and not case.get('thread_after_detach'):complete_thread()
        if case.get('busy_drain'):
            require(result,'Busy drain case needs a published display');state['core_busy']=True
            before={a:refs[a] for a in (display,provider,state['gate'],state['loop'])}
            call(row(own_vptr,87),display,provider)
            for _ in range(2):call(row(own_vptr,109),display,provider)
            require(state['parent_stops']==0 and state['registry'] and not state['core_stopped'],
                'Busy drain stopped the original parent or unlinked its provider')
            require(all(refs[a]==count+int(a==provider) for a,count in before.items()),
                'Busy drain lost inputs or duplicated its pending provider reference')
            state['core_busy']=False;events.append('drain-retry')
        call(row(own_vptr,87),display,provider)
        if state['registry']:call(row(own_vptr,109),display,provider)
        require(state['parent_stops']==int(state['parent_entered']) and not state['registry'],'Actual original/source stop-detach did not complete once')
        if state['parent_entered']:require(all(not objects[a]['enabled'] for a in attached),'Original stop left enabled sources on the retained loop')
        remaining_disabled=len(attached)
        if case.get('client')=='after-stop':check_client()
        if case.get('thread_success') and case.get('thread_after_detach'):
            if case.get('lost_provider_pin'):
                pin=struct.unpack('<Q',uc.mem_read(display+5760,8))[0]
                require(pin==provider,'Provider lifetime pin is missing before corruption control')
                uc.mem_write(display+5760,bytes(8));release(pin)
            release(provider)
            require(refs[provider]>0,'Provider died before the retained original background thread completed')
            complete_thread()
    else:require(case.get('init_failure') and not state['parent_entered'],'Unexpected original initialization failure')
    if client_meta_peer:release(client_meta_peer);uc.mem_write(client_meta,bytes(8))
    call(row(own_vptr,14),display)
    require(state['base_free']==1 and refs[display]==refs[root]==1 and refs[provider]==int(not case.get('thread_after_detach')),
        'Linked lifecycle leaked owner/provider/root references')
    require(not attached and not state['core_inputs'] and not state['core_loop'],'Final source free left loop inputs or event sources')
    require(all(count==0 for address,count in refs.items() if address not in (display,provider,root)),
        'Linked lifecycle leaked a synthetic factory object: '+str([(objects.get(a),n) for a,n in refs.items() if a not in (display,provider,root) and n]))
    for field in (5024,5032,5040,5048,5088,5104,5488,5520,5632,5704):
        require(bytes(uc.mem_read(display+field,8))==bytes(8),'Full original lifecycle left resource field '+str(field))
    require(bytes(uc.mem_read(display+INSTANCE_BYTES,128))==b'\xa5'*128,'Full linked lifecycle exceeded concrete object size')
    return {'case':case['name'],'result':'PASS','native_start_result':bool(result),'events':events,'instructions':instruction_count,
        'original_parent_start_returns':state['parent_returns'],'native_parent_stop_calls':state['parent_stops'],'published':state['published'],
        'peer_boundaries':sorted(e[5:] for e in executed if e.startswith('peer:')),'original_sources_remaining_disabled_before_free':remaining_disabled,
        'base_free_calls':state['base_free'],'original_post_hardware_calls':state['post_hardware'],'original_attribute_names_visited':state['attribute_names'],
        'gate_references_at_original_stop':state['gate_refs_at_stop'],'original_thread_dispatcher_executed':state['thread_completed'],
        'provider_alive_after_detach_and_external_release':bool(case.get('thread_after_detach')),
        'original_new_user_client_method_executed':bool(state['client_entries']),'original_client_method_result':state['client_result'],
        'client_allocator_metadata_init_attach_start_close_are_peers':bool(case.get('client')),
        'real_iokit_and_core_and_thread_execution':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--kernel',type=Path,default=ROOT/'build/cph2653-display-prelink/kernel.macho')
    parser.add_argument('--output',type=Path,default=ROOT/'build/ios16-display-kernel-lifecycle/cpu-cases.json');args=parser.parse_args()
    reports={n:json.loads((ROOT/'reports'/f'{n}.json').read_text()) for n in DEPENDENCIES}
    prelink=reports['ios16-display-prelink'];service=reports['ios16-display-service']
    require(sha(args.kernel)==prelink['candidate_sha256'] and prelink['strict_emission'] and not prelink['allow_missing'],
        'Need the currently validated strict full display prelink')
    require(service['concrete_instance_bytes']==INSTANCE_BYTES,'Concrete allocation size changed')
    require(prelink['display_kernel_report_sha256']==sha(ROOT/'reports/ios16-display-kernel.json') and
        prelink['graphics_lifecycle_report_sha256']==sha(ROOT/'reports/ios16-graphics-lifecycle.json') and
        reports['ios16-graphics-lifecycle']['service_report_sha256']==sha(ROOT/'reports/ios16-display-service.json'),
        'Full lifecycle dependencies are stale')
    for report in reports.values():
        require('PASS' in report['result'],'Lifecycle dependency did not pass')
        for name,digest in report.get('dependency_report_sha256',{}).items():
            require(sha(ROOT/'reports'/f'{name}.json')==digest,'Lifecycle dependency changed: '+name)
        for name,digest in report.get('source_sha256',{}).items():
            require(sha(ROOT/name)==digest,'Lifecycle source dependency changed: '+name)
    protected=prelink['protected_default_artifact_sha256']
    require(all(sha(ROOT/p)==h for p,h in protected.items()),'Protected/default artifacts changed before CPU execution')
    from build_gpu_graphics_prelink import ORIGINAL
    raw=args.kernel.read_bytes();image=macho(raw);old=ORIGINAL.read_bytes();old_image=macho(old)
    require(hashlib.sha256(old).hexdigest()==prelink['original_kernelcache_sha256'],'Original kernelcache changed')
    slide=int(json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/graphics-modules.json').read_text())['slide'],0)
    lifecycle=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/display-lifecycle.json').read_text())
    functions={name:(int(lifecycle[name]['address'],16),lifecycle[name]['bytes']) for name in ('init','start','stop')}
    functions.update({'free':(0xfffffff005c0c614,48),'thread-start-helper':(0xfffffff005c0c814,160),
        'thread-dispatcher':(0xfffffff005c24cd0,48),'thread-body':(0xfffffff005c24d00,236),
        'post-hardware-285':(0xfffffff005c18a10,740),'default-attributes':(0xfffffff005c0de44,432),
        'get-work-loop':(0xfffffff005c122bc,24),'cleanup-275':(0xfffffff005c17e5c,16),
        'new-user-client':(0xfffffff005c0e840,344)})
    checked={}
    for name,(address,size) in functions.items():
        at=backed_offset(image['segments'],address+slide,size,len(raw));before=backed_offset(old_image['segments'],address,size,len(old))
        require(raw[at:at+size]==old[before:before+size],'Original lifecycle function instructions changed: '+name)
        checked[name]={'address':hex(address+slide),'bytes':size,'sha256':hashlib.sha256(raw[at:at+size]).hexdigest()}
    cases=[{'name':'default-software-gop'},{'name':'optional-serializer-allocation-failed','serializer_failure':True},
        {'name':'original-background-thread-before-stop','thread_success':True},
        {'name':'original-background-thread-after-detach','thread_success':True,'thread_after_detach':True},
        {'name':'full-original-stop-after-busy-drain','busy_drain':True},
        {'name':'late-thread-after-busy-drain','busy_drain':True,'thread_success':True,'thread_after_detach':True},
        {'name':'optional-benchmark-timer','bootarg':'iomfb_benchmark_fps','boot_value':60},
        {'name':'optional-benchmark-timer-allocation-failed','bootarg':'iomfb_benchmark_fps','boot_value':60,'timer_failure':2,'failure':True},
        {'name':'optional-benchmark-timer-add-failed','bootarg':'iomfb_benchmark_fps','boot_value':60,'add_failure':4,'failure':True},
        {'name':'coordinator-allocation-failed','core_failure':True,'failure':True},
        {'name':'original-software-root-missing','root_failure':True,'failure':True},
        {'name':'original-matching-allocation-failed','matching_failure':True,'failure':True},
        {'name':'original-interrupt-allocation-failed','interrupt_failure':True,'failure':True},
        {'name':'original-interrupt-add-failed','add_failure':2,'failure':True},
        {'name':'original-timer-allocation-failed','timer_failure':1,'failure':True},
        {'name':'original-timer-add-failed','add_failure':3,'failure':True},
        {'name':'native-gop-hook-refused','hardware_failure':True,'failure':True},
        {'name':'original-lock-allocation-failed','lock_failure':True,'failure':True},
        {'name':'original-recursive-lock-allocation-failed','recursive_failure':True,'failure':True},
        {'name':'native-publication-action-refused','publication_refused':True,'failure':True},
        {'name':'original-gate-allocation-failed','gate_failure':True,'init_failure':True},
        {'name':'original-workloop-allocation-failed','loop_failure':True,'init_failure':True},
        {'name':'original-init-add-gate-failed','add_failure':1,'init_failure':True},
        {'name':'native-base-init-refused','base_init_failure':True,'init_failure':True}]
    cases += [{'name':('source-client-' if kind in ('admission-denied','null-output','after-stop') else 'original-client-')+kind,'client':kind}
        for kind in ('success','allocation-failed','init-failed','attach-failed','start-failed','admission-denied','null-output','after-stop')]
    results=[]
    for case in cases:
        try:results.append(emulate(args.kernel,case))
        except ValueError as error:raise ValueError(case['name']+': '+str(error)) from error
        print('PASS:',case['name'],flush=True)
    bad={'name':'lost-provider-lifetime-pin','thread_success':True,'thread_after_detach':True,'lost_provider_pin':True}
    try:emulate(args.kernel,bad)
    except ValueError as error:
        require(str(error)=='Provider died before the retained original background thread completed','Lost-pin control failed for a different reason')
        controls=[{'case':bad['name'],'result':'REJECTED','check':str(error)}]
    else:raise ValueError('Lost provider lifetime pin was accepted')
    try:emulate(args.kernel,{'name':'unreviewed-native-allocator','unreviewed_native_call':True})
    except ValueError as error:
        require('Unreviewed lifecycle instruction' in str(error) and '_IOMalloc' in str(error),'Unreviewed-native control failed for a different reason')
        controls.append({'case':'unreviewed-native-allocator','result':'REJECTED','check':'Unreviewed native _IOMalloc entry rejected before executing its body'})
    else:raise ValueError('Unreviewed native implementation was accepted')
    require(sha(args.kernel)==prelink['candidate_sha256'] and all(sha(ROOT/p)==h for p,h in protected.items()),
        'CPU execution altered the candidate or existing/default artifacts')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'result':'PASS','cases':results,'case_count':len(results),'negative_controls':controls},indent=2)+'\n')
    inputs=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/build_gpu_graphics_prelink.py',
        ROOT/'sources/UniXNU/kits/XnuPrelink/native_prelink.py',ROOT/'requirements-gpu.lock',
        ROOT/'drivers/DodgeDisplay/DodgeIPhoneFramebuffer.cpp',ROOT/'profiles/os/ios-16.7.16-20H392/display-lifecycle.json',
        ROOT/'profiles/os/ios-16.7.16-20H392/graphics-modules.json']
    report={'result':'IOS16_LINKED_CONCRETE_AND_FULL_ORIGINAL_DISPLAY_LIFECYCLE_CPU_PASS','builder_sha256':sha(Path(__file__)),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in inputs},
        'dependency_report_sha256':{n:sha(ROOT/'reports'/f'{n}.json') for n in DEPENDENCIES},
        'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':prelink['original_kernelcache_sha256'],
        'candidate':str(args.kernel.resolve().relative_to(ROOT)),'candidate_sha256':sha(args.kernel),
        'cpu_cases':str(args.output.resolve().relative_to(ROOT)),'cpu_cases_sha256':sha(args.output),
        'unicorn_version':'2.1.4','concrete_instance_bytes':INSTANCE_BYTES,'original_functions':checked,
        'case_count':len(results),'cases':results,'negative_controls':controls,
        'original_full_init_start_stop_free_instructions_executed':True,'actual_concrete_class_instructions_executed':True,
        'actual_native_ioservice_start_leaf_executed':True,'original_thread_dispatcher_cases':sum(c['original_thread_dispatcher_executed'] for c in results),
        'provider_after_detach_and_external_release_cases':sum(c['provider_alive_after_detach_and_external_release'] for c in results),
        'original_new_user_client_method_body_cases':sum(c['original_new_user_client_method_executed'] for c in results),
        'source_client_admission_refusal_cases':3,'client_allocator_metadata_init_attach_start_close_are_peers':True,
        'original_client_implementation_lifecycle_qualified':False,
        'provider_lifetime_pin_until_source_free':True,'original_surface_5056_path_executed':False,
        'iokit_core_platform_function_matching_and_scheduler_are_peers':True,'unknown_native_implementation_call_rejected':True,
        'original_instruction_bytes_unchanged':True,'native_instruction_bytes_unchanged':True,
        'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,
        'real_iokit_instance_constructed':False,'original_loader_executed':False,'real_kernel_scheduler_executed':False,
        'runtime_qualified':False,'default_kernel_selected':False,'hardware_tested':False,'ready_for_ios_boot':False,
        'scope':'Actual full prelinked candidate instructions execute original Legacy init/start/post-hardware/default attributes/stop/free '
            'and concrete source class methods, with explicit primitive IOKit, coordinator API, root lookup, platform-function and scheduler peers. '
            'Software GOP uses no original surface at +5056. Success/failure/busy/optional-timer paths check reference accounting, '
            'disabled original sources, once-only cleanup, publication ordering, object canary and late background dispatcher. '
            'Five cases also run the complete original newUserClient method and three check source admission refusal; '
            'client metadata vptr/allocation, slot 186 init, attach/start/detach and caller close are explicit peers, not original client lifecycle execution. '
            'No real IOKit allocator, original module initialization, Core/GPU/MMIO, matching race, power or runtime qualification.'}
    (ROOT/'reports/ios16-display-kernel-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(results)} concrete source + full original Legacy init/start/stop/free CPU paths; '
        'lost-provider-pin control rejected; explicit IOKit/core/thread peers')


if __name__=='__main__':main()
