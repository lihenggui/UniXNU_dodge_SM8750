"""CPU checks for concrete source glue; original start/core/IOKit are explicit peers."""
import json
import struct
import subprocess

from native_driver_build import ROOT,macho,require,symbols
from native_prelink import backed_offset


def emulate(path,read,slide,native,native_image,native_aliases,table_alias):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw)
    names={s['name']:s['value'] for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14}
    def find(part):
        matches=[value for name,value in names.items() if part in name]
        require(len(matches)==1,'Ambiguous concrete source symbol: '+part);return matches[0]
    cls='__ZN22DodgeIPhoneFramebuffer'
    slots={s:find(cls+(('9opaque243Ev') if s==243 else '10backend'+str(s))) for s in (211,212,242,243,292,293,321,322,329)}
    out=path.parent;asm=out/'parent-start-peer.S';obj=asm.with_suffix('.o')
    asm.write_text('''// Explicit parent-start control-flow peer, not original instructions.
.text
.globl _parent_start_peer
_parent_start_peer:
stp x19,x30,[sp,#-16]!
mov x19,x0
ldr x8,[x0]
ldr x8,[x8,#2192]
blr x8
cbz w0,1f
mov x0,x19
mov w1,#0x42
ldr x8,[x19]
ldr x8,[x8,#672]
blr x8
mov w0,#1
b 2f
1: mov w0,#0
2: ldp x19,x30,[sp],#16
.globl _parent_peer_return
_parent_peer_return:
ret
''')
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',asm,'-o',obj],check=True)
    peer_raw=obj.read_bytes();peer_image=macho(peer_raw)
    peer_text=next(s for seg in peer_image['segments'] for s in seg['sections'] if s['name']=='__text')
    peer_bytes=peer_raw[peer_text['fileoff']:peer_text['fileoff']+peer_text['size']]
    peer_return=next(s['value']-peer_text['va'] for s in symbols(peer_raw) if s['name']=='_parent_peer_return')
    display,provider,core,loop,table,stack,stop,peercode,peerbase,callback_return=0x200000,0x210000,0x220000,0x230000,0x240000,0x300000,0x400000,0x500000,0x600000,0x610000
    cases=[]
    def machine():
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def put(address,data=b'',size=0):
            count=max(len(data),size)
            for page in range(address&~4095,(address+count+4095)&~4095,4096):
                if page not in pages:uc.mem_map(page,4096);pages.add(page)
            if data:uc.mem_write(address,data)
        for seg in image['segments']:
            if seg['size'] and seg['size']<1024*1024:
                put(seg['va'],raw[seg['fileoff']:seg['fileoff']+seg['filesize']],seg['size'])
        for a,n in ((display,8192),(provider,4096),(core,4096),(loop,4096),(table,4096),(stack,16384),(stop,4096),(peerbase,8192),(callback_return,4096)):
            put(a,size=n)
        put(peercode,peer_bytes)
        def call(address,*arguments):
            for i,value in enumerate(arguments):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
            uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
            uc.emu_start(address,stop,timeout=1000000,count=200000)
            require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop,'Concrete ARM64 source failed to return')
            require(uc.reg_read(reg.UC_ARM64_REG_SP)==stack+0x3f00,'Concrete source corrupted SP')
            return uc.reg_read(reg.UC_ARM64_REG_X0)
        return uc,put,call
    # All nine local backend entries execute. Only 243 is compared to stock:
    # its unconditional error leaf needs no argument-prototype assumption.
    stock=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/display-backend-discovery.json').read_text())['unsupported_leaves']['243']
    original_leaf=read(int(stock['address'],16),stock['bytes'])
    require(original_leaf==struct.pack('<3I',0x528058e0,0x72bc0000,0xd65f03c0),'Original raw Unsupported leaf differs')
    own243=raw[backed_offset(image['segments'],slots[243],12,len(raw)):][:12]
    require(own243==original_leaf,'Source raw slot 243 is not instruction-identical to stock')
    for slot,address in slots.items():
        for seed in (0,0x123456789abcdef0,0xfedcba9876543210):
            uc,put,call=machine();before=[]
            for i in range(30):
                value=(seed+i*0x102030405060708)&((1<<64)-1);before.append(value);uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
            uc.mem_write(display,b'\xa5'*8192);uc.mem_write(core,b'\xcc'*4096)
            result=call(address)
            after=[uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(30)]
            expected=0 if slot==329 else before[0] if slot in (292,322) else 0xe00002c7
            require(result==expected and after[1:]==before[1:],'Backend source leaf changed raw register effects: '+str(slot))
            require(bytes(uc.mem_read(display,8192))==b'\xa5'*8192 and bytes(uc.mem_read(core,4096))==b'\xcc'*4096,'Backend leaf modified memory')
            if slot==243:
                put(peercode+0x800,original_leaf)
                for i,value in enumerate(before):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
                call(peercode+0x800)
                require([uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(30)]==after,'Raw source/stock 243 register equivalence failed')
            cases.append({'case':f'backend-{slot}-registers-{seed:x}','result':'PASS','original_leaf_compared':slot==243})
    # Execute the compiled concrete start/register/stop hooks. A tiny assembly
    # parent peer calls the actual derived hardware and registration slots.
    # Core lifecycle, IOService publication and work-loop scheduling are peers.
    inherited=json.loads((ROOT/'reports/ios16-display-subclass.json').read_text())['original_bindings']
    original_vtable=next(iter(table_alias.values()))
    original_rows=struct.unpack('<340Q',read(original_vtable-slide,340*8))
    legacy_table=struct.pack('<340Q',*(value+slide if value else 0 for value in original_rows))
    base_table=native_aliases['__ZTV9IOService']
    native_table_bytes=native[backed_offset(native_image['segments'],base_table,170*8,len(native)):][:170*8]
    native_table=struct.unpack('<170Q',native_table_bytes)
    uc,put,call=machine();source_start=native_table[86+2]
    at=backed_offset(native_image['segments'],source_start,8,len(native));source_start_bytes=native[at:at+8]
    require(source_start_bytes==struct.pack('<2I',0x52800020,0xd65f03c0),'Pinned source IOService::start is no longer unconditional success')
    put(source_start,source_start_bytes);require(call(source_start,display,provider)==1,'Actual native parent-start leaf did not return true')
    cases.append({'case':'actual-native-ioservice-start-unconditional-success','result':'PASS','original_native_bytes_executed':True})
    start=find(cls+'5startEP9IOService');stop_entry=find(cls+'4stopEP9IOService')
    service_create=find('__Z28dodge_display_service_create')
    service_start=find('__Z27dodge_display_service_start')
    service_ready=find('__Z27dodge_display_service_ready')
    service_stop=find('__Z26dodge_display_service_stop')
    borrowed_loop=find('dodge_display_service_workloop')
    parent_start=original_rows[86+2]+slide;parent_stop=original_rows[87+2]+slide
    get_loop=int(inherited['__ZNK25IOMobileFramebufferLegacy11getWorkLoopEv'],16)
    for mode in ('success','core-allocation-refused','hardware-refused','parent-refused','parent-no-register','core-not-ready','publication-not-ready','publication-runAction-refused','start-stop-deferred','stop-during-publication','core-drained-before-parent-return'):
        uc,put,call=machine();put(original_vtable,legacy_table);put(base_table,native_table_bytes)
        uc.mem_write(display,bytes(5768)+b'\xa5'*128)
        uc.mem_write(display,struct.pack('<Q',find('__ZTV22DodgeIPhoneFramebuffer')+16))
        uc.mem_write(display+5048,struct.pack('<Q',loop))
        uc.mem_write(loop,struct.pack('<Q',table))
        uc.mem_write(provider,struct.pack('<Q',table))
        loop_retain,loop_release,run_action=peerbase,peerbase+4,peerbase+8
        uc.mem_write(table+4*8,struct.pack('<Q',loop_retain));uc.mem_write(table+5*8,struct.pack('<Q',loop_release));uc.mem_write(table+32*8,struct.pack('<Q',run_action))
        events=[];state={'completion':0,'ready':0,'published':0,'parent_stops':0,'loop_refs':1,'provider_refs':1,'returns':[],'deferred':mode=='start-stop-deferred','completed':False}
        def returned(value):
            uc.reg_write(reg.UC_ARM64_REG_X0,value);uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
        def hook(engine,address,size,user):
            args=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(7)]
            if address==service_create:
                require(args[:2]==[display,provider],'Concrete service creation owner/provider mismatch');state['completion']=args[2];events.append('core-create')
                returned(0 if mode=='core-allocation-refused' else core)
            elif address==service_start:
                require(args[:2]==[core,1],'Concrete start must select coherent Adreno producer');events.append('core-start')
                if mode=='core-drained-before-parent-return':
                    state['completed']=True;state['returns'].append(engine.reg_read(reg.UC_ARM64_REG_LR))
                    engine.reg_write(reg.UC_ARM64_REG_X0,display);engine.reg_write(reg.UC_ARM64_REG_X1,provider)
                    engine.reg_write(reg.UC_ARM64_REG_LR,callback_return);engine.reg_write(reg.UC_ARM64_REG_PC,state['completion'])
                else:returned(1 if mode=='hardware-refused' else 0)
            elif address==service_ready:
                require(args[0]==core,'Concrete readiness used wrong controller');state['ready']+=1
                returned(0 if mode in ('core-not-ready','start-stop-deferred','core-drained-before-parent-return') or mode=='publication-not-ready' and state['ready']>=2 else 1)
            elif address==service_stop:
                require(args[0]==core,'Concrete stop used wrong controller');events.append('core-stop')
                if state['deferred']:returned(1)
                elif state['completed']:returned(0)
                else:
                    state['completed']=True;state['returns'].append(engine.reg_read(reg.UC_ARM64_REG_LR))
                    engine.reg_write(reg.UC_ARM64_REG_X0,display);engine.reg_write(reg.UC_ARM64_REG_X1,provider)
                    engine.reg_write(reg.UC_ARM64_REG_LR,callback_return);engine.reg_write(reg.UC_ARM64_REG_PC,state['completion'])
            elif address==callback_return:
                engine.reg_write(reg.UC_ARM64_REG_X0,0);engine.reg_write(reg.UC_ARM64_REG_PC,state['returns'].pop())
            elif address==parent_start:
                events.append('parent-start')
                if mode=='parent-refused':returned(0)
                elif mode=='parent-no-register':returned(1)
                else:engine.reg_write(reg.UC_ARM64_REG_PC,peercode)
            elif address==peercode+peer_return:events.append('parent-return')
            elif address==parent_stop:
                require(args[:2]==[display,provider],'Original parent stop lost its retained provider');state['parent_stops']+=1;events.append('parent-stop');returned(0)
            elif address==get_loop:returned(loop)
            elif address==borrowed_loop:require(args[0]==core,'Partial-stop cleanup lost its retained core');returned(loop)
            elif address in (loop_retain,loop_release):
                require(args[0] in (loop,provider),'Concrete glue retained/released an unknown peer')
                key='loop_refs' if args[0]==loop else 'provider_refs'
                state[key]+=1 if address==loop_retain else -1;returned(0)
            elif address==run_action:
                if mode=='publication-runAction-refused':returned(1)
                else:
                    engine.reg_write(reg.UC_ARM64_REG_PC,args[1]);engine.reg_write(reg.UC_ARM64_REG_X0,args[2]);engine.reg_write(reg.UC_ARM64_REG_X1,args[3])
                    for i in range(2,5):engine.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),0)
            elif address==native_table[84+2]:
                require(args[:2]==[display,0x42] and 'parent-return' in events,'Concrete source published before parent start returned')
                state['published']+=1;events.append('publish')
                if mode=='stop-during-publication':
                    state['completed']=True;state['returns'].append(engine.reg_read(reg.UC_ARM64_REG_LR))
                    engine.reg_write(reg.UC_ARM64_REG_X0,display);engine.reg_write(reg.UC_ARM64_REG_X1,provider)
                    engine.reg_write(reg.UC_ARM64_REG_LR,callback_return);engine.reg_write(reg.UC_ARM64_REG_PC,state['completion'])
                else:returned(0)
        peers={service_create,service_start,service_ready,service_stop,parent_start,parent_stop,get_loop,borrowed_loop,loop_retain,loop_release,run_action,callback_return,native_table[86],peercode+peer_return}
        for address in peers:put(address,size=4)
        uc.hook_add(UC_HOOK_CODE,hook)
        result=call(start,display,provider)
        require(bool(result)==(mode=='success') and state['published']==int(mode in ('success','stop-during-publication')),'Concrete start/publication result differs: '+mode)
        if mode=='stop-during-publication':require(state['parent_stops']==1,'Registration callback stop was lost or repeated')
        if mode=='success':
            call(stop_entry,display,provider);require(state['parent_stops']==1,'Successful concrete stop did not call original parent exactly once')
            call(stop_entry,display,provider);require(state['parent_stops']==1,'Repeated concrete stop called parent twice')
        if mode=='start-stop-deferred':
            require(state['parent_stops']==0,'Busy drain tore down original work-loop resources')
            state['deferred']=False;call(stop_entry,display,provider);require(state['parent_stops']==1,'Deferred stop lost original parent cleanup')
        if mode not in ('core-allocation-refused','success','stop-during-publication','start-stop-deferred'):
            require(state['parent_stops']==1,'Failed parent start leaked its partial original resources: '+mode)
        require(state['loop_refs']==1 and state['provider_refs']==2 and not state['returns'],
            'Concrete glue lost its provider lifetime pin or leaked a loop/callback reference')
        require(bytes(uc.mem_read(display+5768,128))==b'\xa5'*128,'Concrete class exceeded its actual allocation boundary')
        cases.append({'case':'native-concrete-start-'+mode,'result':'PASS','events':events,'parent_and_core_are_peers':True})
    # Actual compiled newUserClient override and qualified parent dispatch.
    # The coordinator admission peer is separate from the real coordinator's
    # sanitizer cases, which exercise its ready/operation/stop serialization.
    client_entry=find(cls+'13newUserClient');admit=find('dodge_display_service_admit')
    parent_client=original_rows[141+2]+slide
    for mode in ('ready','not-ready','parent-not-started','null-output','no-controller','parent-client-error'):
        uc,put,call=machine();put(original_vtable,legacy_table)
        uc.mem_write(display,bytes(5768)+b'\xa5'*128)
        uc.mem_write(display+5728,struct.pack('<Q',0 if mode=='no-controller' else core))
        uc.mem_write(display+5741,bytes([int(mode!='parent-not-started')]))
        outptr=provider+0x100;uc.mem_write(outptr,struct.pack('<Q',0xdead));events=[]
        for address in (admit,parent_client):put(address,size=4)
        def client_hook(engine,address,size,user):
            args=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(5)]
            def returned(value):
                engine.reg_write(reg.UC_ARM64_REG_X0,value);engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
            if address==admit:
                require(args[0]==(0 if mode=='no-controller' else core),'Client admission lost its controller');events.append('admit')
                if mode in ('not-ready','no-controller'):returned(0xe00002c2 if mode=='no-controller' else 0xe00002d8)
                else:
                    engine.reg_write(reg.UC_ARM64_REG_PC,args[1]);engine.reg_write(reg.UC_ARM64_REG_X0,display);engine.reg_write(reg.UC_ARM64_REG_X1,args[2])
            elif address==parent_client:
                require(args==[display,0xabc,0xdef,0x123,outptr],'Original client argument widths/order changed');events.append('parent-client')
                if mode=='parent-client-error':returned(0xe00002c7)
                else:engine.mem_write(outptr,struct.pack('<Q',0xc1c1));returned(0)
        uc.hook_add(UC_HOOK_CODE,client_hook)
        result=call(client_entry,display,0xabc,0xdef,0x123,0 if mode=='null-output' else outptr)
        expected=0 if mode=='ready' else 0xe00002c2 if mode in ('null-output','no-controller') else 0xe00002c7 if mode=='parent-client-error' else 0xe00002d8
        require(result==expected,'Compiled original-client admission returned the wrong status: '+mode)
        value,=struct.unpack('<Q',uc.mem_read(outptr,8))
        require(value==(0xdead if mode=='null-output' else 0xc1c1 if mode=='ready' else 0),'Client admission did not preserve the owned-output contract')
        require(('parent-client' in events)==(mode in ('ready','parent-client-error')),'Unready/stopped client reached original parent')
        require(bytes(uc.mem_read(display+5768,128))==b'\xa5'*128,'Client admission exceeded concrete allocation')
        cases.append({'case':'native-client-admission-'+mode,'result':'PASS','events':events,'coordinator_admission_and_original_client_are_peers':True})
    # Actual compiled detach, stopped callback and base-vtable call. The
    # attachment stays present until original parent stop has returned, even
    # if parent stop reenters detach or the first drain attempt is busy.
    detach=find(cls+'6detachEP9IOService');completion=find(cls+'7stoppedEP9IOService')
    borrowed_loop=find('dodge_display_service_workloop');status_entry=find('dodge_display_service_status')
    base_detach=native_table[109+2]
    for mode in ('no-controller','already-stopped','immediate-drain','busy-drain','parent-stop-reentrant-detach','loop-action-refused','null-provider'):
        uc,put,call=machine();put(original_vtable,legacy_table);put(base_table,native_table_bytes)
        uc.mem_write(display,bytes(5768)+b'\xa5'*128)
        uc.mem_write(display+5728,struct.pack('<Q',0 if mode=='no-controller' else core))
        uc.mem_write(display+5741,bytes([int(mode not in ('already-stopped','no-controller','null-provider'))]))
        uc.mem_write(display+5745,bytes([int(mode not in ('already-stopped','no-controller','null-provider'))]))
        uc.mem_write(display+5048,struct.pack('<Q',loop))
        uc.mem_write(loop,struct.pack('<Q',table));uc.mem_write(provider,struct.pack('<Q',table))
        retain,release,run_action=peerbase,peerbase+4,peerbase+8
        uc.mem_write(table+4*8,struct.pack('<Q',retain));uc.mem_write(table+5*8,struct.pack('<Q',release));uc.mem_write(table+32*8,struct.pack('<Q',run_action))
        events=[];state={'refs':{loop:1,provider:1},'stopped':mode=='already-stopped','attached':True,'parent_stops':0,
            'parent_in_progress':False,'returns':[],'refuse':mode=='loop-action-refused','busy':mode=='busy-drain'}
        def detach_hook(engine,address,size,user):
            args=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(7)]
            def returned(value=0):
                engine.reg_write(reg.UC_ARM64_REG_X0,value);engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
            if address==borrowed_loop:
                require(args[0]==core,'Detach borrowed another controller work loop');events.append('borrow-loop');returned(loop)
            elif address==retain:state['refs'][args[0]]+=1;returned()
            elif address==release:state['refs'][args[0]]-=1;require(state['refs'][args[0]]>=1,'Detach overreleased a retained peer');returned()
            elif address==run_action:
                require(args[0]==loop,'Detach did not enter its retained work loop')
                if state['refuse']:returned(0xe00002d8)
                else:
                    engine.reg_write(reg.UC_ARM64_REG_PC,args[1])
                    for i,value in enumerate(args[2:7]):engine.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),value)
            elif address==status_entry:
                require(args[0]==core,'Detach queried wrong core');events.append('status')
                engine.mem_write(args[1],bytes([0,1,int(state['stopped']),0])+bytes(4));returned(1)
            elif address==service_stop:
                require(args[0]==core,'Detach stopped wrong core');events.append('stop')
                if state['busy']:returned(0xe00002d5)
                elif state['stopped']:returned()
                else:
                    state['stopped']=True;state['returns'].append(engine.reg_read(reg.UC_ARM64_REG_LR))
                    engine.reg_write(reg.UC_ARM64_REG_X0,display);engine.reg_write(reg.UC_ARM64_REG_X1,provider)
                    engine.reg_write(reg.UC_ARM64_REG_LR,callback_return);engine.reg_write(reg.UC_ARM64_REG_PC,completion)
            elif address==callback_return:engine.reg_write(reg.UC_ARM64_REG_X0,0);engine.reg_write(reg.UC_ARM64_REG_PC,state['returns'].pop())
            elif address==parent_stop:
                require(args[:2]==[display,provider] and state['attached'],'Original stop lost the real attachment')
                state['parent_stops']+=1;events.append('parent-stop')
                if mode=='parent-stop-reentrant-detach':
                    state['parent_in_progress']=True;state['returns'].append(engine.reg_read(reg.UC_ARM64_REG_LR))
                    engine.reg_write(reg.UC_ARM64_REG_LR,callback_return+4);engine.reg_write(reg.UC_ARM64_REG_PC,detach)
                else:engine.mem_write(display+5048,bytes(8));returned()
            elif address==callback_return+4:
                require(state['attached'],'Reentrant detach unlinked during original parent stop')
                state['parent_in_progress']=False;events.append('parent-return');engine.mem_write(display+5048,bytes(8))
                engine.reg_write(reg.UC_ARM64_REG_X0,0);engine.reg_write(reg.UC_ARM64_REG_PC,state['returns'].pop())
            elif address==base_detach:
                require(args[:2]==[display,provider] and state['attached'] and not state['parent_in_progress'],'Base detach repeated or ran before parent returned')
                state['attached']=False;events.append('base-detach');returned()
        for address in (borrowed_loop,status_entry,service_stop,retain,release,run_action,parent_stop,base_detach,callback_return,callback_return+4):put(address,size=4)
        uc.hook_add(UC_HOOK_CODE,detach_hook)
        call(detach,display,0 if mode=='null-provider' else provider)
        if mode=='busy-drain':
            require(state['attached'] and state['parent_stops']==0 and state['refs'][provider]==2,'Busy drain lost its retained attachment')
            call(detach,display,provider);require(state['refs'][provider]==2,'Repeated pending detach retained provider twice')
            state['stopped']=True;state['busy']=False;call(completion,display,provider)
            call(completion,display,provider);require(state['parent_stops']==1,'Completion repeated original stop')
        if mode=='loop-action-refused':
            require(state['attached'] and not events[1:] and state['refs'][provider]==1,'Refused gate consumed an attachment')
            state['refuse']=False;call(detach,display,provider)
        require(state['refs']=={loop:1,provider:1} and not state['returns'],'Concrete detach leaked loop/provider references')
        require(state['attached']==(mode=='null-provider') and state['parent_stops']==int(mode not in ('no-controller','already-stopped','null-provider')),
            'Concrete deferred detach did not complete once: '+mode)
        require(bytes(uc.mem_read(display+5752,8))==bytes(8) and bytes(uc.mem_read(display+5768,128))==b'\xa5'*128,'Detach left pending state or exceeded allocation')
        cases.append({'case':'native-deferred-detach-'+mode,'result':'PASS','events':events,'core_workloop_and_original_stop_are_peers':True})
    uc,put,call=machine()
    require(call(find('dodge_iphone_framebuffer_allocate'))==0,'Concrete allocator bypassed deferred metadata initialization')
    cases.append({'case':'allocation-before-metadata-initialization-refused','result':'PASS'})
    for mode in ('symbol-allocation-refused','parent-missing','parent-identity-mismatch','own-class-missing','own-class-identity-mismatch'):
        uc,put,call=machine();events=[]
        own=mode.startswith('own-class-')
        if own:uc.mem_write(find('__ZL11initialized'),b'\x01')
        symbol_factory=native_aliases['__ZN8OSSymbol17withCStringNoCopyEPKc']
        metadata_lookup=native_aliases['__ZN11OSMetaClass20getMetaClassWithNameEPK8OSSymbol']
        release=peerbase;initializer=find('__GLOBAL__sub_I_DodgeIPhoneFramebuffer.cpp')
        uc.mem_write(provider,struct.pack('<Q',table));uc.mem_write(table+5*8,struct.pack('<Q',release))
        for address in (symbol_factory,metadata_lookup,release):put(address,size=4)
        def guard_hook(engine,address,size,user):
            def returned(value):
                engine.reg_write(reg.UC_ARM64_REG_X0,value);engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
            if address==initializer:raise ValueError('Concrete metadata initializer ran before its exact original parent was registered')
            if address==symbol_factory:
                pointer=engine.reg_read(reg.UC_ARM64_REG_X0)
                expected=b'DodgeIPhoneFramebuffer\0' if own else b'IOMobileFramebufferLegacy\0'
                require(bytes(engine.mem_read(pointer,len(expected)))==expected,'Metadata guard checked the wrong parent/owned class')
                events.append('symbol');returned(0 if mode=='symbol-allocation-refused' else provider)
            elif address==metadata_lookup:
                require(engine.reg_read(reg.UC_ARM64_REG_X0)==provider,'Metadata guard lost its retained symbol')
                events.append('lookup');returned(provider if mode.endswith('identity-mismatch') else 0)
            elif address==release:events.append('release');returned(0)
        uc.hook_add(UC_HOOK_CODE,guard_hook)
        if not own:require(call(find('dodge_iphone_framebuffer_initialize'))==0,'Metadata guard accepted a missing/wrong parent')
        require(call(find('dodge_iphone_framebuffer_allocate'))==0,'Metadata refusal enabled instance allocation')
        require(events==(['symbol'] if mode=='symbol-allocation-refused' else ['symbol','lookup','release']),'Metadata guard leaked or bypassed lookup')
        cases.append({'case':'native-metadata-guard-'+mode,'result':'PASS','lookup_and_symbol_are_peers':True})
    from ios16_parent_stop_emulation import emulate as emulate_parent_stop
    original_stop=emulate_parent_stop(read)
    cases+=original_stop['cases']
    return {'cases':cases,'case_count':len(cases),'native_backend_leaf_cases':27,'native_start_glue_cases':11,
            'native_client_admission_cases':6,'native_deferred_detach_cases':7,
            'actual_native_parent_start_leaf_cases':1,'original_partial_stop_body':original_stop,
            'native_metadata_guard_cases':5,'concrete_instance_bytes':5768,
            'original_slot243_instruction_bytes_changed':False,'slot243_original_argument_prototype_assumed':False,
            'original_start_stop_executed':False,'parent_start_peer':'Assembly control-flow peer calls actual native slots 274 and 84',
            'core_and_workloop_and_publication_are_peers':True,'iokit_objects_are_synthetic':True}
