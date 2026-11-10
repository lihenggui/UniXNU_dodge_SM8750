#!/usr/bin/env python3
"""Bounded derived-object C2/D2 CPU probe with original and source-kernel parents."""
import hashlib
import struct

from native_driver_build import NATIVE,macho,require,symbols
from native_prelink import backed_offset,exports


def emulate(path,contract,classes,read):
    import unicorn
    from unicorn import Uc,UcError,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    raw=path.read_bytes();image=macho(raw);names={s['name']:s['value'] for s in symbols(raw) if s['kind']&14 and not s['kind']&0xe0}
    # Run both the original kernel's IOService C2/D2 and the actual source
    # kernel's complete IOService/IORegistryEntry/OSObject/OSMetaClassBase paths.
    # Only import-pointer data changes between modes; no code is patched.
    functions={
        'Legacy.C2':(int(contract['protected_constructor'],16),76),
        'Service.C2':(0xfffffff005c0186c,76),'Framebuffer.C2':(0xfffffff005c01674,76),
        'Legacy.D2':(int(contract['protected_destructor'],16),44),
        'Service.D2':(0xfffffff005c018b8,52),'Framebuffer.D2':(0xfffffff005c016c0,44),
    }
    imports=[]
    for stub in (0xfffffff005c27184,0xfffffff005c27190):
        a,b,c=struct.unpack('<3I',read(stub,12))
        require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Original IOService lifetime stub changed')
        displacement=((a>>5)&0x7ffff)*4+((a>>29)&3)
        if displacement&(1<<20):displacement-=1<<21
        pointer=(stub&~4095)+(displacement<<12)+((b>>10)&4095)*8
        target,=struct.unpack('<Q',read(pointer,8));imports.append((stub,pointer,target))
    constructor_parent,destructor_parent=[record[2] for record in imports]
    # These targets are the original kernel imports and names, rather than a
    # guessed branch to the new source kernel's allocation implementation.
    from check_ios16_swap import original_input
    _,original,original_image,_=original_input();original_exports=exports(original,original_image)
    require('__ZN9IOServiceC2EPK11OSMetaClass' in original_exports[constructor_parent] and
            '__ZN9IOServiceD2Ev' in original_exports[destructor_parent],'Original lifetime import no longer targets IOService C2/D2')
    fingerprint=lambda address,size:{'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    native=NATIVE.read_bytes();native_image=macho(native)
    native_names={name:address for address,group in exports(native,native_image).items() for name in group}
    def native_read(address,size):
        at=backed_offset(native_image['segments'],address,size,len(native));return native[at:at+size]
    native_functions={name:(native_names[symbol],size) for name,symbol,size in (
        ('IOService.C2','__ZN9IOServiceC2EPK11OSMetaClass',32),('IORegistryEntry.C2','__ZN15IORegistryEntryC2EPK11OSMetaClass',32),
        ('OSObject.C2','__ZN8OSObjectC2EPK11OSMetaClass',40),('OSMetaClassBase.C2','__ZN15OSMetaClassBaseC2Ev',16),
        ('IOService.D2','__ZN9IOServiceD2Ev',4),('IORegistryEntry.D2','__ZN15IORegistryEntryD2Ev',4),
        ('OSObject.D2','__ZN8OSObjectD2Ev',4),('OSMetaClassBase.D2','__ZN15OSMetaClassBaseD2Ev',12))}
    evidence={'functions':{name:fingerprint(*value) for name,value in functions.items()},
              'imports':[{'stub':fingerprint(stub,12),'pointer':fingerprint(pointer,8),'target':hex(target)} for stub,pointer,target in imports],
              'original_parent_functions':{'IOService.C2':fingerprint(constructor_parent,24),'IOService.D2':fingerprint(destructor_parent,12)},
              'source_parent_functions':{name:{'address':hex(address),'bytes':size,'sha256':hashlib.sha256(native_read(address,size)).hexdigest()}
                                         for name,(address,size) in native_functions.items()},
              'constructor_path':['Legacy.C2','Service.C2','Framebuffer.C2','IOService.C2'],
              'destructor_path':['Legacy.D2','Service.D2','IOService.D2'],
              'service_d2_calls_ioservice_d2_directly':True,'parent_ctor_dtor_instruction_bodies_executed':True,
              'source_parent_import_rebinding_is_fixture_data_only':True,'instruction_bytes_changed':False,
              'parent_lifetime_uses_peers':False}
    storage,instance,stack,stop=0x200000,0x200040,0x300000,0x400000
    cases=[];snapshots={}
    for mode,label,metadata in [(mode,label,metadata) for mode in ('original-parent','source-parent')
                               for label,metadata in (('opaque-metadata-64-bit',0x123456789abcdef0),('null-metadata-transport-only',0),
                                                      ('opaque-metadata-high-bits',0xfedcba9876543210))]:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def mapped(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:machine.mem_map(page,4096);pages.add(page)
        for segment in image['segments']:
            if not segment['size']:continue
            mapped(segment['va'],segment['size'])
            if segment['filesize']:machine.mem_write(segment['va'],raw[segment['fileoff']:segment['fileoff']+segment['filesize']])
        for address,size in (*functions.values(),(storage,5736+128),(stack,16384),(stop,4),(constructor_parent,24),(destructor_parent,12)):
            mapped(address,size)
        for address,size in functions.values():machine.mem_write(address,read(address,size))
        for address,size in ((constructor_parent,24),(destructor_parent,12)):machine.mem_write(address,read(address,size))
        if mode=='source-parent':
            for address,size in native_functions.values():mapped(address,size);machine.mem_write(address,native_read(address,size))
        readonly=[(names['__ZTV25IPhoneLegacySubclassProbe'],(338+3)*8)]
        got,=[section for segment in image['segments'] for section in segment['sections'] if section['name']=='__got']
        require(got['size']==8 and struct.unpack_from('<Q',raw,got['fileoff'])[0]==int(contract['legacy_metadata'],16),
                'Native parent metadata GOT entry differs')
        readonly.append((got['va'],got['size']))
        for stub,pointer,target in imports:
            mapped(stub,12);machine.mem_write(stub,read(stub,12));mapped(pointer,8);machine.mem_write(pointer,read(pointer,8));readonly.append((pointer,8))
            if mode=='source-parent':
                replacement=native_functions['IOService.C2' if target==constructor_parent else 'IOService.D2'][0]
                machine.mem_write(pointer,struct.pack('<Q',replacement))
        content=bytes([0xa5])*(5736+128);machine.mem_write(storage,content)
        phase=['construct'];visits=[];calls=[];vptr_writes=[];source_visits=[]
        def instruction(engine,address,size,user):
            for name,(start,length) in functions.items():
                if address==start:visits.append(name)
            for name,(start,length) in native_functions.items():
                if address==start:source_visits.append(name)
            parent_ctor=native_functions['IOService.C2'][0] if mode=='source-parent' else constructor_parent
            parent_dtor=native_functions['IOService.D2'][0] if mode=='source-parent' else destructor_parent
            if address in (parent_ctor,parent_dtor):
                expected=parent_ctor if phase[0]=='construct' else parent_dtor
                require(address==expected and engine.reg_read(reg.UC_ARM64_REG_X0)==instance,'Original parent lifetime receiver/path changed')
                if address==parent_ctor:
                    require(engine.reg_read(reg.UC_ARM64_REG_X1)==metadata,'Original protected C2 truncated or changed metadata')
                calls.append('IOService.C2' if address==parent_ctor else 'IOService.D2')
        def memory(engine,kind,address,size,value,user):
            require(storage<=address and address+size<=storage+len(content) or stack<=address and address+size<=stack+16384 or
                    any(a<=address and address+size<=a+n for a,n in readonly),
                    'Derived lifetime escaped exact object/canary/stack/table/import windows: '+hex(address))
            if kind==UC_MEM_WRITE:
                require(instance<=address and address+size<=instance+5736 or stack<=address and address+size<=stack+16384,
                        'Derived lifetime wrote an object canary or import pointer')
                if address==instance:
                    require(size==8,'Unexpected partial vptr write');vptr_writes.append(value&0xffffffffffffffff)
        machine.hook_add(UC_HOOK_CODE,instruction);machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        def execute(address,*arguments):
            for index,value in enumerate(arguments):machine.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(index)),value)
            machine.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(reg.UC_ARM64_REG_LR,stop)
            machine.emu_start(address,stop,timeout=100000,count=512)
            require(machine.reg_read(reg.UC_ARM64_REG_PC)==stop,'Derived lifetime did not return')
        execute(names['_iphone_legacy_probe_construct'],instance,metadata)
        fixture_vptr=names['__ZTV25IPhoneLegacySubclassProbe']+16
        if mode=='source-parent':
            parent_vptrs=[native_names[name]+16 for name in ('__ZTV15OSMetaClassBase','__ZTV8OSObject','__ZTV15IORegistryEntry','__ZTV9IOService')]
            require(source_visits==['IOService.C2','IORegistryEntry.C2','OSObject.C2','OSMetaClassBase.C2'],'Source parent constructor path changed')
        else:parent_vptrs=[next(address for address,group in original_exports.items() if '__ZTV9IOService' in group)+16]
        expected_vptrs=parent_vptrs+[int(classes['classes'][name]['vptr'],16) for name in ('IOMobileFramebuffer','IOMobileFramebufferService','IOMobileFramebufferLegacy')]+[fixture_vptr]
        require(visits==['Legacy.C2','Service.C2','Framebuffer.C2'] and calls==['IOService.C2'] and vptr_writes==expected_vptrs,
                'Native/original protected constructor path or vptr installation order differs')
        expected=bytearray(content);struct.pack_into('<Q',expected,64,fixture_vptr);struct.pack_into('<Q',expected,64+5728,0x1122334455667788)
        struct.pack_into('<I',expected,64+8,1)
        require(bytes(machine.mem_read(storage,len(content)))==bytes(expected),'Derived constructor touched private storage, marker or canaries unexpectedly')
        snapshot=bytes(machine.mem_read(storage,len(content)))
        if mode=='original-parent':snapshots[label]=snapshot
        else:require(snapshots[label]==snapshot,'Mixed source/original constructor differs from original-parent object bytes')
        execute(names['_iphone_legacy_probe_marker'],instance)
        require(machine.reg_read(reg.UC_ARM64_REG_X0)==0x1122334455667788,'Native subclass marker is not at the actual 5728-byte base extent')
        execute(names['_iphone_legacy_probe_parent_metadata'])
        require(machine.reg_read(reg.UC_ARM64_REG_X0)==int(contract['legacy_metadata'],16),'Native parent metaclass binding differs from exact original metadata')
        phase[0]='destruct';visits.clear();source_visits.clear();execute(names['_iphone_legacy_probe_destruct'],instance)
        struct.pack_into('<Q',expected,64,0xffffffffffffffff)
        if mode=='source-parent':require(source_visits==['IOService.D2','IORegistryEntry.D2','OSObject.D2','OSMetaClassBase.D2'],'Source parent protected destructor path changed')
        require(visits==['Legacy.D2','Service.D2'] and calls==['IOService.C2','IOService.D2'] and
                vptr_writes==[*expected_vptrs,0xffffffffffffffff] and bytes(machine.mem_read(storage,len(content)))==bytes(expected),
                'Derived source destructor did not call actual protected D2, or changed fixture storage')
        cases.append({'case':mode+'-'+label,'result':'PASS','protected_original_c2_bodies_executed':3,'protected_original_d2_bodies_executed':2,
                      'vptr_installation_order':[hex(value) for value in vptr_writes],'marker_offset':5728,'object_canaries_preserved':True,
                      'parent_entries':calls,'parent_uses_software_peers':False,'source_parent_used':mode=='source-parent',
                      'retain_count_initialized_to_one':True,'destructor_vptr_poison_preserved':True,'full_object_bytes_match_original_parent':True,
                      'original_parent_metaclass_address_checked':True,
                      'real_iokit_instance_constructed':False})
    # The original abstract D1 really traps and is not a valid substitute for
    # the protected D2 selected by the real native derived destructor.
    abstract=int.from_bytes(read(int(contract['legacy_vptr'],16),8),'little')
    machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    machine.mem_map(abstract&~4095,4096);machine.mem_write(abstract,read(abstract,20))
    machine.mem_map(stack,16384);machine.mem_map(stop,4096)
    machine.reg_write(reg.UC_ARM64_REG_X0,instance);machine.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(reg.UC_ARM64_REG_LR,stop)
    error=None
    try:machine.emu_start(abstract,stop,timeout=100000,count=64)
    except UcError as caught:error=str(caught)
    require(error is not None and machine.reg_read(reg.UC_ARM64_REG_PC)==abstract+16,'Original abstract complete destructor did not trap at its reviewed BRK')
    cases.append({'case':'original-abstract-d1-is-not-protected-d2','result':'REJECTED','original_brk_executed':True,'error':error})
    return cases,evidence
