#!/usr/bin/env python3
"""Run unchanged iPhone completion code over bounded memory and explicit peers."""
import hashlib
import struct

from check_ios16_swap import original_input
from native_driver_build import macho,require,symbols


def emulate_body(contract,obj):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    _,_,_,read=original_input();bounded=contract['bounded_retirement_cpu']
    data=obj.read_bytes();image=macho(data);names=symbols(data)
    text,=[section for segment in image['segments'] for section in segment['sections'] if section['name']=='__text']
    code=bytearray(data[text['fileoff']:text['fileoff']+text['size']])
    base,display,request,gate,table,rtable,gtable,stack,stop,peer=(
        0xfffffff005000000,0x200000,0x210000,0x220000,0x230000,0x240000,0x250000,0x300000,0x400000,0x500000)
    wrapper=int(contract['wrapper']['address'],16);body=int(contract['body']['address'],16)
    relocation,count=struct.unpack_from('<2I',data,text['command_offset']+56)
    require(count==1,'Full completion probe must have one original call relocation')
    at,bits=struct.unpack_from('<2I',data,relocation)
    require(names[bits&0xffffff]['name']=='_native_iphone_complete_current' and struct.unpack_from('<I',code,at)[0]==0x94000000,
            'Full completion probe has an unexpected call/addend')
    displacement=(wrapper-base-at)//4
    require(-(1<<25)<=displacement<(1<<25),'Full completion fixture call is outside the native BL range')
    struct.pack_into('<I',code,at,0x94000000|(displacement&0x3ffffff))
    function,=[name for name in names if name['name']=='_iphone_dispatch_completion' and name['kind']&0xe]
    entry=base+function['value']-text['va']
    registers=[getattr(reg,'UC_ARM64_REG_X'+str(i)) for i in range(8)]
    peers={0xfffffff005c15f2c:'trace-begin',0xfffffff005c16c6c:'trace-end',
           0xfffffff005c1a534:'surface-selector',0xfffffff005c272bc:'surface-word-a',0xfffffff005c27304:'surface-word-b',
           0xfffffff005c1a5d4:'surface-commit',0xfffffff005c16d10:'trace-combine',0xfffffff005c2749c:'debug-trace',
           0xfffffff005c11c04:'state-notify',0xfffffff005c1ac74:'pending-action',
           peer:'backend-report',peer+16:'timestamp',peer+32:'request-release',peer+48:'gate-wakeup'}
    debug=int(bounded['debug_flag_address'],16);guard=int(bounded['stack_guard_address'],16)
    configurations=(
        ('normal',{}),('no-surface-code-path',{'layers':0}),('cancelled-code-path',{'cancelled':True}),
        ('options-five',{'options':5}),('options-fifteen',{'options':15}),
        ('background-word',{'background':True}),('mode-two',{'mode':2,'mode_word':7}),
        ('mode-one',{'mode':1,'mode_word':9}),('state-change',{'state_change':True}),
        ('trace-four-surfaces-bounded-to-three',{'debug':9,'layers':15}),
        ('backend-unsupported-return-ignored',{'backend_status':0xe00002c7}),
        ('pending-action',{'pending_action':True}),('raw-wrapper-no-current',{'current':False,'raw':True}),
        ('guard-mismatched-current',{'wrong':True}),('guard-null-display',{'null_display':True}),
        ('guard-null-expected',{'null_expected':True}),
    )
    cases=[]
    for label,options in configurations:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def map_region(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:machine.mem_map(page,4096);pages.add(page)
        windows=((display,5728),(request,2424),(gate,16),(table,338*8),(rtable,16*8),(gtable,34*8),(stack,16384))
        readonly=[]
        def original(blob):
            address=int(blob['address'],16);content=read(address,blob['bytes'])
            require(hashlib.sha256(content).hexdigest()==blob['sha256'],'Original completion/helper bytes changed')
            map_region(address,len(content));machine.mem_write(address,content)
        for address,size in ((base,len(code)),(stop,4),*windows):map_region(address,size)
        machine.mem_write(base,bytes(code))
        for blob in (contract['wrapper'],contract['body'],*bounded['helpers'].values()):original(blob)
        for name in ('trace_template','debug_flag_import','stack_guard_import'):
            original(bounded[name]);readonly.append((int(bounded[name]['address'],16),bounded[name]['bytes']))
        for address,size in ((debug,4),(guard,8)):
            map_region(address,size);readonly.append((address,size))
        machine.mem_write(debug,struct.pack('<I',options.get('debug',0)))
        machine.mem_write(guard,struct.pack('<Q',0x23456789abcdef01))
        for address in peers:
            map_region(address,4);machine.mem_write(address,struct.pack('<I',0xd65f03c0))
        content=bytearray(5728);current=request if options.get('current',True) else 0
        struct.pack_into('<Q',content,0,table);struct.pack_into('<Q',content,4872,current)
        struct.pack_into('<Q',content,5040,gate);struct.pack_into('<I',content,172,41)
        struct.pack_into('<3I',content,5220,0x11111111,0x22222222,0x33333333)
        struct.pack_into('<I',content,5260,0xaabbccdd);struct.pack_into('<I',content,5452,0x33)
        struct.pack_into('<2I',content,5460,10,20)
        if options.get('pending_action'):struct.pack_into('<I',content,5244,1)
        packet=bytearray(2424);struct.pack_into('<Q',packet,0,rtable)
        struct.pack_into('<I',packet,788,0xfedcba98)
        struct.pack_into('<I',packet,792,0x80000001 if options.get('background') else 1)
        struct.pack_into('<I',packet,800,0x1234abcd)
        struct.pack_into('<I',packet,812,options.get('options',0))
        struct.pack_into('<2I',packet,836,options.get('mode',0),options.get('mode_word',0))
        packet[1354]=int(options.get('cancelled',False));packet[1360]=int(options.get('state_change',False))
        machine.mem_write(display,bytes(content));machine.mem_write(request,bytes(packet));machine.mem_write(gate,struct.pack('<Q',gtable))
        virtuals={321:peer,239:peer+16,327:int(bounded['helpers']['statistics']['address'],16),
                  337:int(bounded['helpers']['after_completion']['address'],16)}
        for slot,target in virtuals.items():machine.mem_write(table+slot*8,struct.pack('<Q',target))
        machine.mem_write(rtable+5*8,struct.pack('<Q',peer+32));machine.mem_write(gtable+33*8,struct.pack('<Q',peer+48))
        expected=0 if options.get('null_expected') else request+16 if options.get('wrong') else request
        machine.reg_write(reg.UC_ARM64_REG_X0,0 if options.get('null_display') else display)
        machine.reg_write(reg.UC_ARM64_REG_X1,expected)
        machine.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(reg.UC_ARM64_REG_LR,stop)
        machine.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        calls=[];visited=[];events=[];writes=[]
        def memory(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in (*windows,*readonly)),
                    'Full original completion escaped exact object/table/stack/read-only windows: '+hex(address))
            if kind==UC_MEM_WRITE:
                require(any(a<=address and address+size<=a+n for a,n in ((display,5728),(request,2424),(stack,16384))),
                        'Full original completion wrote a vtable, gate or read-only fixture')
                writes.append((address,size))
        def instruction(engine,address,size,user):
            visited.append(address)
            if address==virtuals[337]:
                events.append('after-completion')
                require(engine.mem_read(display+4872,8)==bytes(8),'Original post-completion hook ran before Current clear')
            if address not in peers:return
            name=peers[address];args=[engine.reg_read(r) for r in registers[:6]];calls.append((name,args))
            result=0
            if name=='surface-selector':
                require(args[0]==display and args[1]<4,'Original surface loop arguments changed')
                result=(0x600000+4096*args[1]) if options.get('layers',1)&(1<<args[1]) else 0
            elif name in ('surface-word-a','surface-word-b'):
                require(args[0] in (0x600000,0x601000,0x602000,0x603000),'Original scalar query lost surface identity')
                result=17 if name=='surface-word-a' else 4
            elif name=='backend-report':
                require(args[:5]==[display,0xfedcba98,0,0,0],'Original report call argument shape changed')
                result=options.get('backend_status',0)
            elif name=='timestamp':require(args[0]==display,'Original timestamp receiver changed');result=0x0123456789abcdef
            elif name=='surface-commit':require(args[0]==display,'Original commit receiver changed')
            elif name=='request-release':
                require(args[0]==request and engine.mem_read(display+4872,8)==struct.pack('<Q',request),
                        'Original release receiver or release-before-clear order changed')
                events.append('release-peer')
            elif name=='gate-wakeup':
                require(args[:3]==[gate,display+4880,0] and engine.mem_read(display+4872,8)==bytes(8) and
                        engine.mem_read(display+5260,4)==struct.pack('<I',0xaabbccdd),
                        'Original clear-before-wakeup/state-clear-after-wakeup order changed')
                events.append('wakeup-peer')
            elif name=='trace-combine':result=0xaabbccdd
            elif name=='state-notify':require(args[:2]==[display,1],'Original state-bit callback shape changed')
            elif name=='pending-action':require(args[:2]==[display,0],'Original pending action callback shape changed')
            engine.reg_write(reg.UC_ARM64_REG_X0,result);engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
        machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory);machine.hook_add(UC_HOOK_CODE,instruction)
        machine.emu_start(wrapper if options.get('raw') else entry,stop,timeout=200000,count=10000)
        admitted=not any(options.get(k) for k in ('wrong','null_expected','null_display'))
        require(machine.reg_read(reg.UC_ARM64_REG_PC)==stop and (options.get('raw') or machine.reg_read(reg.UC_ARM64_REG_X0)==admitted),
                'Original completion/native guard did not return as expected: '+label)
        retired=bool(admitted and current)
        expected_display=bytearray(content);expected_request=bytearray(packet)
        if retired:
            struct.pack_into('<Q',expected_display,4872,0);struct.pack_into('<I',expected_display,172,42)
            struct.pack_into('<I',expected_display,5260,0);struct.pack_into('<I',expected_request,844,4)
            if options.get('options',0) in (0,15):struct.pack_into('<2I',expected_display,5220,0xfedcba98,0xfedcba98)
            if options.get('background'):struct.pack_into('<I',expected_display,5228,0x1234abcd)
            if not options.get('cancelled'):
                index=int(options.get('mode')==2);struct.pack_into('<I',expected_display,5448,index)
                struct.pack_into('<I',expected_display,5452,options.get('mode_word') or 0x33)
                struct.pack_into('<I',expected_display,5460+index*4,(10,20)[index]+1)
                if options.get('options',0)==0:
                    expected_display[5415]=1;expected_display[5421]=int(options.get('state_change',False))
        require(bytes(machine.mem_read(display,5728))==bytes(expected_display) and bytes(machine.mem_read(request,2424))==bytes(expected_request),
                'Original completion/helper wrote unexpected display/request state: '+label)
        require((body in visited)==admitted and events==(['release-peer','wakeup-peer','after-completion'] if retired else ['after-completion'] if admitted else []),
                'Original completion body or release/current/wakeup/post-hook order changed: '+label)
        call_names=[name for name,args in calls]
        surfaces=min(options.get('layers',1).bit_count(),3) if retired else 0
        selectors=(3 if options.get('layers',1)==15 else 4) if retired else 0
        for name,count in (('trace-begin',int(admitted)),('trace-end',int(admitted)),('backend-report',int(retired)),
                           ('surface-commit',int(retired)),('timestamp',int(retired)),('debug-trace',4 if retired and options.get('debug') else 0),
                           ('surface-selector',selectors),('surface-word-a',surfaces),('surface-word-b',surfaces),
                           ('state-notify',int(retired and options.get('state_change',False))),('pending-action',int(admitted and options.get('pending_action',False)))):
            require(call_names.count(name)==count,'Original full completion peer count changed: '+name+' / '+label)
        cases.append({'case':label,'result':'PASS','native_guard_admitted':admitted,'raw_wrapper_entry':bool(options.get('raw')),
                      'unchanged_full_body_executed':admitted,'original_tail_executed':retired,'release_clear_wakeup_order':events,
                      'original_notification_helper_executed':int(bounded['helpers']['request_notification']['address'],16) in visited,
                      'helper_or_lifetime_peers':call_names,'instructions':len(visited),'memory_writes':len(writes)})
    return cases
