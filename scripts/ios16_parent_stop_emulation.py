"""Execute unchanged Legacy stop for partial no-surface GOP startup resources."""
import hashlib
import json
import struct

from native_driver_build import ROOT,require


def emulate(read):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    contract=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/display-lifecycle.json').read_text())
    entry=int(contract['stop']['address'],16);body=read(entry,1408)
    require(hashlib.sha256(body).hexdigest()==contract['stop']['sha256'],'Original parent stop changed')
    vptr=0xfffffff006def8e0;parent=0xfffffff006dedc70
    stock=struct.unpack('<338Q',read(vptr,338*8))
    display,provider,table,objects_base,stack,stop,peer=0x200000,0x210000,0x220000,0x240000,0x300000,0x400000,0x410000
    fields={'mapper':5024,'root':5032,'gate':5040,'loop':5048,'interrupt':5088,'timer':5104,'pool':5488,'lock':5520,'recursive':5632,'optional-timer':5704}
    configs=[('init-only',()),('root-retained',('root',)),('interrupt-unattached',('root','interrupt')),
        ('interrupt-attached',('root','interrupt','attach-interrupt')),('timer-unattached',('root','interrupt','attach-interrupt','timer')),
        ('timer-attached',('root','interrupt','attach-interrupt','timer','attach-timer')),
        ('optional-timer-attached',('root','interrupt','attach-interrupt','timer','attach-timer','optional-timer','attach-optional-timer')),
        ('mapper-command-pool',('root','mapper','pool')),('lock-only',('lock',)),('lock-and-recursive',('lock','recursive')),
        ('all-start-resources',('root','mapper','pool','interrupt','attach-interrupt','timer','attach-timer','optional-timer','attach-optional-timer','lock','recursive'))]
    cases=[]
    for label,options in configs:
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set();events=[];writes=[]
        def put(address,data=b'',size=0):
            for page in range(address&~4095,(address+max(len(data),size)+4095)&~4095,4096):
                if page not in pages:uc.mem_map(page,4096);pages.add(page)
            if data:uc.mem_write(address,data)
        for a,n in ((display,8192),(provider,4096),(table,4096),(objects_base,65536),(stack,16384),(stop,4),(peer,4096)):
            put(a,size=n)
        readonly=[]
        for a,n in ((entry,1408),(0xfffffff005c0e574,100),(stock[275],16),(stock[111],24),(parent,340*8),
            (0xfffffff004f65000,4096)):
            put(a,read(a,n));readonly.append((a,n))
        content=bytearray(5728);struct.pack_into('<Q',content,0,table)
        addresses={name:objects_base+index*4096 for index,name in enumerate(fields)}
        refs={};attached=set();freed=set()
        for name,field in fields.items():
            if name not in ('gate','loop') and name not in options:continue
            address=addresses[name];struct.pack_into('<Q',content,field,address)
            # Gate and loop keep the coordinator's reference. Other software
            # objects have an outside registry reference only for root/mapper.
            refs[address]=2 if name in ('gate','loop','root','mapper') else 1
            if name=='gate' or 'attach-'+name in options:attached.add(address);refs[address]+=1
            uc.mem_write(address,struct.pack('<Q',address+128))
            for index,target in ((5,peer+4),(17,peer+20),(21,peer+8),(23,peer+12)):
                uc.mem_write(address+128+index*8,struct.pack('<Q',target))
        # Loop is not an event source and receives no attachment reference.
        require(addresses['loop'] not in attached,'Bad original stop peer setup')
        uc.mem_write(display,bytes(content)+b'\xa5'*128)
        uc.mem_write(table+111*8,struct.pack('<Q',stock[111]));uc.mem_write(table+275*8,struct.pack('<Q',stock[275]))
        # Only the original qualified parent's IOService::stop pointer is a
        # peer. Legacy's complete body, getter, gating helper and cleanup leaf
        # execute unchanged; original bytes are never patched.
        uc.mem_write(parent+0x2c8,struct.pack('<Q',peer+16))
        pool_commands=[]
        if 'pool' in options:
            for i in range(2):
                a=objects_base+0xc000+i*0x100;pool_commands.append(a);refs[a]=1
                uc.mem_write(a,struct.pack('<Q',a+32));uc.mem_write(a+32+5*8,struct.pack('<Q',peer+4))
        logger=0xfffffff005c0bb30;free_lock=0xfffffff005c26cc8;free_recursive=0xfffffff005c26d1c
        for a in (logger,free_lock,free_recursive):put(a,size=4)
        counts={'parent_stop':0,'disable':0,'remove':0}
        def returned(value=0):
            uc.reg_write(reg.UC_ARM64_REG_X0,value);uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
        def hook(engine,address,size,user):
            x0=engine.reg_read(reg.UC_ARM64_REG_X0);x1=engine.reg_read(reg.UC_ARM64_REG_X1)
            if address==logger:events.append('log');returned()
            elif address==peer+4:
                require(x0 in refs and refs[x0]>0,'Original stop released an absent/freed object');refs[x0]-=1
                if not refs[x0]:freed.add(x0)
                events.append('release-'+hex(x0));returned()
            elif address==peer+8:
                require(x0==addresses['loop'] and x1 in refs,'Original stop removed from the wrong loop')
                counts['remove']+=1;events.append('remove-'+hex(x1))
                if x1 in attached:attached.remove(x1);refs[x1]-=1;returned()
                else:returned(0xe00002c2)
            elif address==peer+12:
                require(x0==addresses['loop'],'Original stop disabled wrong loop');counts['disable']+=1;events.append('disable-all');returned()
            elif address==peer+16:
                require(x0==display and x1==provider,'Original qualified IOService stop lost provider')
                require(counts['disable']==1 and not struct.unpack('<Q',engine.mem_read(display+5048,8))[0],
                    'Original stop called parent before disabling/releasing original loop')
                counts['parent_stop']+=1;events.append('ioservice-stop');returned()
            elif address==peer+20:
                require(x0==addresses['pool'] and x1==0,'Original command pool drain arguments differ')
                returned(pool_commands.pop(0) if pool_commands else 0)
            elif address in (free_lock,free_recursive):
                name='lock' if address==free_lock else 'recursive'
                require(x0==addresses[name] and name in options and x0 not in freed,'Original lock free repeated or used wrong object')
                freed.add(x0);refs[x0]=0;events.append('free-'+name);returned()
        windows=[(display,5728),(table,338*8),(objects_base,65536),(stack,16384),*readonly]
        def access(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in windows),'Original stop escaped bounded display/objects/stack/readonly input')
            if kind==UC_MEM_WRITE:
                require(display<=address and address+size<=display+5728 or stack<=address and address+size<=stack+16384,'Original stop wrote a callee peer or readonly original')
                if display<=address<display+5728:writes.append({'offset':address-display,'bytes':size})
        uc.hook_add(UC_HOOK_CODE,hook);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        uc.reg_write(reg.UC_ARM64_REG_X0,display);uc.reg_write(reg.UC_ARM64_REG_X1,provider)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
        uc.emu_start(entry,stop,timeout=1000000,count=10000)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop and uc.reg_read(reg.UC_ARM64_REG_SP)==stack+0x3f00,'Full original partial-stop body did not return')
        require(counts['parent_stop']==counts['disable']==1,'Full original stop skipped or repeated native cleanup')
        for name,field in fields.items():require(bytes(uc.mem_read(display+field,8))==bytes(8),'Original stop left a nonzero resource field: '+name)
        for name,address in addresses.items():
            if address not in refs:continue
            expected=1 if name in ('gate','loop','root','mapper') or address in attached else 0
            require(refs[address]==expected,'Original partial-stop resource reference differs: '+name)
        require(not pool_commands and bytes(uc.mem_read(display+5728,128))==b'\xa5'*128,'Original partial stop left pool commands or exceeded base size')
        cases.append({'case':'unchanged-full-original-partial-stop-'+label,'result':'PASS','original_stop_bytes':1408,
            'object_field_writes':writes,'original_event_sources_remaining_disabled':len(attached),'callee_events':events})
    return {'case_count':len(cases),'cases':cases,'original_stop_instruction_bytes_changed':False,'entire_original_stop_body_executed':True,
        'original_getter_gate_and_cleanup_leaf_executed':True,'scope_no_original_surface_5056':True,
        'osobject_workloop_lock_and_ioservice_stop_are_peers':True,'real_iokit_ownership_or_runtime_qualified':False}
