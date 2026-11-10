#!/usr/bin/env python3
"""Execute unchanged original iPhone swap setters to derive default packet fields."""
import argparse
import hashlib
import json
import struct

from ios16_display_cache import DisplayCache
from native_driver_build import ROOT,require,sha
from check_ios16_swap import original_input

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-userland.json'


def derive(cache):
    names=cache.local_symbols()
    require(names['_kern_SwapBegin']==0x1af223708 and names['_kern_SwapSetLayer']==0x1af2238a4,'Original swap setter symbols differ')
    def code(name,address,size):return {'name':name,'address':hex(address),'bytes':size,'sha256':hashlib.sha256(cache.read(address,size)).hexdigest()}
    require(struct.unpack('<3I',cache.read(0x1af22376c,12))==(0x91006260,0x52808d81,0x9425cfb8),
        'Original SwapBegin packet base/zeroed extent differ')
    require(struct.unpack('<4I',cache.read(0x1af223e2c,16))==(0x8b180928,0x52800029,0xb900a509,0xb900b51f),
        'Original default layer scalar writes differ')
    classes,_,_,read=original_input();vptr=int(classes['classes']['IOMobileFramebufferLegacy']['vptr'],16)
    require(names['_kern_GetDisplaySize']==0x1af2248a0 and struct.unpack('<Q',read(vptr+246*8,8))[0]==0xfffffff005c247ac,
        'Original userspace/kernel display size entries changed')
    require(struct.unpack('<Q4I',read(0xfffffff006decc18,24))==(0xfffffff005bffb94,0,0,2,0) and
        struct.unpack('<Q4I',read(0xfffffff006decc18-4*24,24))[3]==1 and
        struct.unpack('<Q4I',read(0xfffffff006decc18-3*24,24))[2]==1132,
        'Original scalar selector 8 and neighboring SwapBegin/SwapEnd dispatch contracts differ')
    def kernel(address,size):return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','cache_uuid':cache.report['cache_files'][0]['uuid'],
        'framework_path':cache.report['framework']['path'],'framework_address':hex(cache.address),
        'swap_begin':code('_kern_SwapBegin',names['_kern_SwapBegin'],200),
        'set_layer':code('_kern_SwapSetLayer',names['_kern_SwapSetLayer'],1456),
        'get_display_size':code('_kern_GetDisplaySize',names['_kern_GetDisplaySize'],180),
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'size_dispatch_row':kernel(0xfffffff006decc18,24),'size_action':kernel(0xfffffff005bffb94,116),
        'size_wrapper':kernel(0xfffffff005bfe0a0,68),'size_getter':kernel(0xfffffff005c247ac,112),
        'size_selector':8,'size_scalar_outputs':2,'size_display_word_offsets':[5208,5212],'size_cache_offset':1192,
        'rectangle_helper':code('original-rectangle-normalization',0x1af224a1c,144),
        'connection_access_window_bytes':2832,'packet_offset':24,'packet_bytes':1132,'packet_id':80,
        'packet_surfaces':84,'packet_source_rectangles':100,'packet_destination_rectangles':196,
        'packet_requested_mask':260,'packet_initial_ready_mask':264,'packet_layer_word':164,
        'packet_raw_float_bits':180,'packet_transform_word':276,'default_layer_word':1,'default_raw_float_bits':0,
        'default_transform_word':0,'geometry_words_are_integers':True,
        'scalar_fields_fully_named':False,'iosurface_implementation_executed':False,'full_display_userspace_executed':False}


def emulate(cache,contract,inspect_packet=None):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    text,=[s for s in cache.image['segments'] if s['name']=='__TEXT']
    code=cache.read(text['va'],text['size'])
    connection,surface,output,stack,stop,globals_=0x200000,0x210000,0x220000,0x300000,0x400000,0x230000
    kernel_service,kernel_display,kernel_arguments,kernel_vtable=0x250000,0x260000,0x270000,0x280000
    _,_,_,read=original_input()
    guard_import=0x1dac9a0d8
    begin,layer=int(contract['swap_begin']['address'],16),int(contract['set_layer']['address'],16)
    get_size=int(contract['get_display_size']['address'],16)
    peer_entries={0x1afb974c8:'scalar-io',0x1afb97654:'zero-packet',0x1afb975d0:'surface-id',0x1afb977e0:'logger',
        0x1af22d730:'size-lock',0x1af22d73c:'size-unlock'}
    cases=[]
    def prepare(width=1440,height=3168,io_status=0,size_status=0):
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        def map_at(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:uc.mem_map(page,4096);pages.add(page)
        extents={connection:2832,surface:64,output:32,stack:16384,globals_:16,guard_import:8,
            kernel_service:224,kernel_display:5728,kernel_arguments:80,kernel_vtable:338*8}
        kernel_blocks=[contract[k] for k in ('size_action','size_wrapper','size_getter')]
        for address,size in (*extents.items(),(text['va'],text['size']),(stop,4096),*((address,4) for address in peer_entries),
                *((int(block['address'],16),block['bytes']) for block in kernel_blocks)):map_at(address,size)
        for block in kernel_blocks:
            address=int(block['address'],16);body=read(address,block['bytes']);require(hashlib.sha256(body).hexdigest()==block['sha256'],'Original kernel size function changed')
            uc.mem_write(address,body)
        uc.mem_write(text['va'],code);uc.mem_write(connection,b'\xa6'*2832)
        uc.mem_write(connection+0xb08,struct.pack('<Q',0));uc.mem_write(connection+0x6a0,struct.pack('<Q',get_size))
        uc.mem_write(connection+1192,bytes(16));uc.mem_write(kernel_service+216,struct.pack('<Q',kernel_display))
        uc.mem_write(kernel_display,struct.pack('<Q',kernel_vtable));uc.mem_write(kernel_display+5208,struct.pack('<2I',width,height))
        uc.mem_write(kernel_vtable+246*8,struct.pack('<Q',int(contract['size_getter']['address'],16)))
        uc.mem_write(connection+0x4c0,bytes(16));uc.mem_write(connection+0x14,struct.pack('<I',0x33445566))
        uc.mem_write(guard_import,struct.pack('<Q',globals_));uc.mem_write(globals_,struct.pack('<Q',0x123456789abcdef0))
        uc.mem_write(output,b'\xcc'*32);uc.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
        state={'surface_ids':0,'zeroed':0,'io':0,'geometry':0,'logs':0,'size_io':0,'size_locks':0,'size_unlocks':0,'kernel_size_actions':0}
        locked=[False]
        def hook(engine,address,size,user):
            if address==get_size:state['geometry']+=1
            if address==int(contract['size_action']['address'],16):
                require(locked[0],'Original kernel size action escaped user size lock');state['kernel_size_actions']+=1
            kind=peer_entries.get(address)
            if not kind:return
            values=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
            if kind=='scalar-io':
                require(values[0]==0x33445566 and values[1] in (4,8) and values[2:4]==[0,0] and
                    stack<=values[4]<stack+16384 and stack<=values[5]<stack+16384,
                    'Original SwapBegin scalar selector/output signature differs')
                if values[1]==4:
                    if io_status==0:engine.mem_write(values[4],struct.pack('<Q',0x10203040))
                    state['io']+=1;engine.reg_write(reg.UC_ARM64_REG_X0,io_status)
                else:
                    require(locked[0] and struct.unpack('<I',engine.mem_read(values[5],4))[0]==2,'Original size scalar output count differs')
                    state['size_io']+=1
                    if size_status:engine.reg_write(reg.UC_ARM64_REG_X0,size_status)
                    else:
                        # Explicit IOKit marshalling peer. It forwards to the
                        # unchanged kernel action/wrapper/getter, preserving
                        # the original user call's LR and scalar output area.
                        engine.mem_write(kernel_arguments+72,struct.pack('<Q',values[4]))
                        for index,value in enumerate((kernel_service,0,kernel_arguments)):engine.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(index)),value)
                        engine.reg_write(reg.UC_ARM64_REG_PC,int(contract['size_action']['address'],16));return
            elif kind=='zero-packet':
                require(values[:2]==[connection+24,1132],'SwapBegin no longer zeroes the complete original packet')
                engine.mem_write(values[0],bytes(values[1]));state['zeroed']+=1
            elif kind=='surface-id':
                require(values[0]==surface,'Unexpected surface passed to original setter');engine.reg_write(reg.UC_ARM64_REG_X0,0x42424242);state['surface_ids']+=1
            elif kind=='size-lock':
                require(values[0]==connection+0x618 and not locked[0],'Original display size lock differs');locked[0]=True;state['size_locks']+=1
            elif kind=='size-unlock':
                require(values[0]==connection+0x618 and locked[0],'Original display size unlock differs');locked[0]=False;state['size_unlocks']+=1
            else:state['logs']+=1
            engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
        def memory(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in extents.items()) or
                kind!=UC_MEM_WRITE and text['va']<=address and address+size<=text['va']+text['size'],
                'Original swap setter escaped exact fixture memory: '+hex(address))
            require(kind!=UC_MEM_WRITE or connection<=address and address+size<=connection+2832 or
                output<=address and address+size<=output+32 or stack<=address and address+size<=stack+16384,
                'Original setter wrote outside its packet/output/stack')
        uc.hook_add(UC_HOOK_CODE,hook);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        def run(address,args,rectangles=None):
            for index,value in enumerate(args):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(index)),value)
            if rectangles:
                for index,value in enumerate(rectangles):uc.reg_write(getattr(reg,'UC_ARM64_REG_D'+str(index)),struct.unpack('<Q',struct.pack('<d',value))[0])
            uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
            uc.emu_start(address,stop,timeout=300000,count=12000)
            require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop,'Original userspace setter did not return')
            require(not locked[0],'Original display size call retained its lock')
            return uc.reg_read(reg.UC_ARM64_REG_X0)
        return uc,state,run
    for width,height in ((17,4),(1440,3168)):
        for index in range(4):
            uc,state,run=prepare(width,height)
            require(run(begin,[connection,output])==0 and state['zeroed']==1 and struct.unpack('<I',uc.mem_read(output,4))[0]==0x10203040,
                'Original SwapBegin did not return its request ID')
            require(run(layer,[connection,index,surface,0],[0,0,width,height,0,0,width,height])==0,'Original default full-frame setter refused')
            packet=bytes(uc.mem_read(connection+24,1132))
            words=lambda offset,count=1:struct.unpack_from('<%dI'%count,packet,offset)
            require(words(80)==(0x10203040,) and words(84+index*4)==(0x42424242,) and words(260,2)==(1<<index,0) and
                words(100+index*16,4)==words(196+index*16,4)==(0,0,width,height) and words(164+index*4)==(1,) and
                words(180+index*4)==(0,) and words(276+index*4)==(0,),
                'Default original layer packet does not match inferred integer geometry/scalar state')
            cases.append({'case':f'default-layer-{index}-{width}x{height}','result':'PASS','packet_requested':1<<index,
                'packet_initial_ready':0,'default_layer_word':1,'default_raw_float_bits':0,'transform_word':0,
                'original_display_size_calls':state['geometry'],'original_kernel_size_actions':state['kernel_size_actions']})
            if inspect_packet:inspect_packet(packet,width,height,index,True)
    for index in range(4):
        uc,state,run=prepare();require(run(begin,[connection,output])==0,'Original begin failed')
        require(run(layer,[connection,index,0,0],[0,0,1440,3168,0,0,1440,3168])==0,'Original null layer refused')
        packet=bytes(uc.mem_read(connection+24,1132));require(struct.unpack_from('<2I',packet,260)==(1<<index,1<<index) and
            not state['surface_ids'] and packet[100+index*16:116+index*16]==bytes(16) and packet[196+index*16:212+index*16]==bytes(16),
            'Null surface must set both initial mask bits and clear its geometry')
        cases.append({'case':'disabled-layer-'+str(index),'result':'PASS','initial_ready_bit_set_for_null_surface':True})
        if inspect_packet:inspect_packet(packet,1440,3168,index,False)
    for index in (4,31,0xffffffff):
        uc,state,run=prepare();require(run(begin,[connection,output])==0,'Original begin failed');before=bytes(uc.mem_read(connection,2832))
        require(run(layer,[connection,index,surface,0],[0,0,1440,3168,0,0,1440,3168])==0xe00002c2 and
            bytes(uc.mem_read(connection,2832))==before and not state['surface_ids'],'Original setter accepted invalid layer or changed packet')
        cases.append({'case':'invalid-layer-'+str(index),'result':'REFUSED_WITHOUT_PACKET_WRITES'})
    uc,state,run=prepare();before=bytes(uc.mem_read(connection,2832));
    # The no-token output is optional and still returns success.
    require(run(begin,[connection,0])==0 and state['zeroed']==1,'Original optional SwapBegin ID output differs')
    cases.append({'case':'begin-null-token-output','result':'PASS'})
    uc,state,run=prepare(io_status=0xe00002c7);before=bytes(uc.mem_read(connection,2832))
    require(run(begin,[connection,output])==0xe00002bc and state['zeroed']==0 and bytes(uc.mem_read(connection,2832))==before,
        'Failed original scalar call zeroed the packet or reported success')
    cases.append({'case':'begin-transport-failure','result':'REFUSED_WITHOUT_PACKET_WRITES'})
    for width,height in ((17,4),(1440,3168),(0xffffffff,0x80000000)):
        uc,state,run=prepare(width,height)
        require(run(get_size,[connection,output])==0 and struct.unpack('<2d',uc.mem_read(output,16))==(float(width),float(height)) and
            state['size_io']==state['kernel_size_actions']==state['size_locks']==state['size_unlocks']==1,
            'Original kernel u32 -> scalar u64 -> user CGSize dataflow differs')
        cases.append({'case':f'original-size-chain-{width}x{height}','result':'PASS','unchanged_kernel_functions':3,'geometry_callback_peer':False})
    uc,state,run=prepare(17,4);require(run(get_size,[connection,output])==0,'Original size getter failed')
    uc.mem_write(kernel_display+5208,struct.pack('<2I',1440,3168))
    require(run(get_size,[connection,output])==0 and struct.unpack('<2d',uc.mem_read(output,16))==(17.0,4.0) and state['size_io']==1 and
        state['size_locks']==state['size_unlocks']==2,'Original display size cache was not retained under its lock')
    cases.append({'case':'original-size-cache-hit','result':'PASS','kernel_queries':1})
    uc,state,run=prepare(0,4)
    require(run(get_size,[connection,output])==0 and run(get_size,[connection,output])==0 and state['size_io']==2 and
        struct.unpack('<2d',uc.mem_read(output,16))==(0.0,4.0),'Original zero-width size incorrectly became a cache hit')
    cases.append({'case':'original-zero-width-size-requeries','result':'PASS'})
    uc,state,run=prepare(size_status=0xe00002c7)
    require(run(get_size,[connection,output])==0xe00002c7 and not state['kernel_size_actions'] and
        struct.unpack('<2d',uc.mem_read(output,16))==(0.0,0.0),'Original size transport failure did not preserve its empty cache/error')
    cases.append({'case':'original-size-transport-failure','result':'PASS'})
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args()
    with DisplayCache() as cache:
        contract=derive(cache)
        if args.record_fixture:
            require(not FIXTURE.exists(),'Reviewed display userland fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n');return
        pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_userland']
        require(sha(FIXTURE)==pin['sha256'] and json.loads(FIXTURE.read_text())==contract,'Original display userland contract changed')
        cases=emulate(cache,contract)
    report={'result':'IOS16_ORIGINAL_DISPLAY_SWAP_SETTERS_ARM64_PASS','contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),
        'builder_sha256':sha(ROOT/'scripts/prepare_ios16_display_userland.py'),'cache_reader_sha256':sha(ROOT/'scripts/ios16_display_cache.py'),
        'cache_report_sha256':sha(ROOT/'reports/ios16-display-cache.json'),'arm64_cases':cases,'unchanged_original_functions':['_kern_SwapBegin','_kern_SwapSetLayer','_kern_GetDisplaySize'],
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'original_size_kernel_functions_executed':3,
        'original_kernel_size_scalar_to_double_dataflow_checked':True,
        'original_instruction_bytes_changed':False,'fp_simd_runs_only_in_userspace_cpu_fixture':True,
        'io_transport_marshalling_surface_id_and_mutex_are_peers':True,'display_size_callback_is_peer':False,'original_iosurface_executed':False,
        'full_userspace_or_dyld_executed':False,'request_color_effect_semantics_complete':False,'hardware_tested':False,
        'scope':'Original iPhone framework symbols and unchanged swap-begin/layer-setter instructions produce bounded packet fixtures. '
                'Default one-layer integer geometry, flags and scalar bit patterns are observed without guessing alpha semantics. '
                'The original display-size callback executes unchanged, through an IOKit marshalling peer into three unchanged original kernel functions '
                'and back to user CGSize/cache conversion. Surface ID, mutex and transport are peers; no original service, IOSurface or notification lifecycle executes.'}
    (ROOT/'reports/ios16-display-userland.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(cases))+' original iPhone swap-begin/layer-setter CPU cases; normal layer scalar defaults are 1/0, not an assumed alpha float')


if __name__=='__main__':main()
