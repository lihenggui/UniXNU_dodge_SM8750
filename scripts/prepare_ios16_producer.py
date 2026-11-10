#!/usr/bin/env python3
"""Check actual iPhone producer registration/callback bookkeeping and native guards."""
import argparse
import hashlib
import json
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT,NATIVE,build_objects,macho,require,sha,symbols

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-producer.json'
HEADER=FIXTURE.parent/'graphics/OriginalLegacyProducerABI.h'
ORIGINAL_START=0xfffffff005bf3000


def derive():
    classes,_,_,read=original_input()
    def words(address,count):return struct.unpack('<%dI'%count,read(address,count*4))
    def block(name,address,size):return {'name':name,'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    require(words(0xfffffff005cd5918,4)==(0xb9431a89,0xb9431e8a,0x6b0a013f,0x54000721),
            'Stock submitter no longer compares full requested/ready words')
    require(words(0xfffffff005c0c190,7)==(0xb85f03a9,0x52800028,0x1ac9210a,0xf85e83a9,0xb9431d28,0x2a0a0108,0xb9031d28),
            'Original asynchronous completion no longer ORs the ready bit')
    require(words(0xfffffff005c0c224,4)==(0xf94013e0,0xf9400008,0xf9445108,0xd63f0100) and
            words(0xfffffff005c16ff8,4)==(0xf94007e0,0xf9400008,0xf9445108,0xd63f0100),
            'Original enqueue/callback no longer invokes no-argument submit slot 276')
    require(words(0xfffffff005c17300,5)==(0x9ac9210a,0xf85f03a9,0xb9431d28,0xaa0a0108,0xb9031d28),
            'Immediate producer completion bit writer differs')
    require(struct.unpack('<Q',read(0xfffffff006deb1d8,8))[0]==0xfffffff005a51a94 and
            words(0xfffffff005c2719c,3)==(0x90008e30,0xf940ee10,0xd61f0200),
            'Original IOSurface completion import binding differs')
    # Exact full functions and a stock admission block are pinned separately;
    # original external callees stay explicit software peers in CPU fixtures.
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392',
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'request_bytes':2424,'requested_layers':792,'ready_layers':796,'registered_byte':1349,
        'cancelled_byte':1354,'new_surfaces':2184,'effective_surfaces':2216,'surface_count':4,
        'queue_submit_slot':276,'queue_submit_prototype':'void (self)',
        'validation_slot':282,'validation_prototype':'bool (self, request)',
        'registration':block('original-registration',0xfffffff005c17020,0x388),
        'callback_update':block('original-gated-ready-update',0xfffffff005c0bfb0,0x454),
        'callback_action':block('original-callback-action',0xfffffff005c0bde0,0x1d0),
        'enqueue_action':block('original-enqueue-action',0xfffffff005c16d94,0x28c),
        'stock_ready_compare':block('stock-ready-admission',0xfffffff005cd5918,16),
        'surface_completion_import':{'stub':'0xfffffff005c2719c','target':'0xfffffff005a51a94'},
        'secondary_mask_is_persistent_disable_mask':False,
        'original_iosurface_fence_implementation_executed':False,'producer_hardware_visibility_qualified':False}


def emulate(contract,obj):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    _,_,_,read=original_input();data=obj.read_bytes();native_image=macho(data)
    text,=[s for seg in native_image['segments'] for s in seg['sections'] if s['name']=='__text']
    require(struct.unpack_from('<I',data,text['command_offset']+60)[0]==0,'Producer native guard has external text relocations')
    native=data[text['fileoff']:text['fileoff']+text['size']]
    functions={s['name']:s['value']-text['va'] for s in symbols(data) if s['kind']&14 and s['name'].startswith('_iphone_')}
    require(set(functions)=={'_iphone_producers_ready','_iphone_effective_surface'},'Producer native probes differ')
    base,orig,display,request,second,surface,stack,stop,vtable,peers,globals_=0x100000,0x500000,0x200000,0x210000,0x220000,0x230000,0x300000,0x400000,0x240000,0x250000,0x260000
    relocate=lambda address:orig+address-ORIGINAL_START
    callback=relocate(int(contract['callback_update']['address'],16));registration=relocate(int(contract['registration']['address'],16))
    debug_import=relocate(0xfffffff006deb458)
    # The same original ADRP keeps its displacement when code and its import
    # slot are relocated by one common delta; only fixture slot contents differ.
    extents={display:5728,request:2424,second:2424,surface:64,stack:16384,vtable:338*8,globals_:64}
    cases=[]
    def prepare(requested=1,ready=0,registered=0,cancelled=0,layer=0,nonnull=True):
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        pages=set()
        def map_at(address,size):
            for page in range(address&~4095,(address+size+4095)&~4095,4096):
                if page not in pages:uc.mem_map(page,4096);pages.add(page)
        admission=relocate(int(contract['stock_ready_compare']['address'],16))
        for address,size in ((base,len(native)),(orig,0x40000),(stop,4096),(peers,4096),(debug_import,8),(admission,4096),*extents.items()):map_at(address,size)
        uc.mem_write(base,native)
        for key in ('callback_update','registration'):
            block=contract[key];uc.mem_write(relocate(int(block['address'],16)),read(int(block['address'],16),block['bytes']))
        uc.mem_write(admission,read(int(contract['stock_ready_compare']['address'],16),16))
        uc.mem_write(debug_import,struct.pack('<Q',globals_))
        disp=bytearray(5728);req=bytearray(2424);other=bytearray(2424)
        struct.pack_into('<Q',disp,0,vtable);struct.pack_into('<Q',disp,4880,request)
        struct.pack_into('<I',req,788,0x11223344);struct.pack_into('<2I',req,792,requested,ready)
        req[1349]=registered;req[1354]=cancelled
        if nonnull:
            struct.pack_into('<Q',req,2184+layer*8,surface);struct.pack_into('<Q',req,2216+layer*8,surface)
        struct.pack_into('<Q',req,0,vtable)
        uc.mem_write(display,bytes(disp));uc.mem_write(request,bytes(req));uc.mem_write(second,bytes(other));uc.mem_write(surface,bytes(64))
        for slot,offset in ((4,0),(5,4),(239,8),(276,12)):
            uc.mem_write(vtable+slot*8,struct.pack('<Q',peers+offset));uc.mem_write(peers+offset,struct.pack('<I',0xd65f03c0))
        state={'submits':0,'retains':0,'releases':0,'registered':[],'phase':'native','writes':[],'surface_ready':True}
        peer_calls={relocate(0xfffffff005c272bc):'surface-id',relocate(0xfffffff005c273ac):'surface-time',
            relocate(0xfffffff005c1763c):'trace',relocate(0xfffffff005c173a8):'trace',relocate(0xfffffff005c13050):'mode',
            relocate(0xfffffff005c2719c):'surface-registration',relocate(0xfffffff005c26cec):'logger'}
        def code(engine,address,size,user):
            kind=peer_calls.get(address)
            if address==peers:state['retains']+=1;kind='return'
            elif address==peers+4:state['releases']+=1;kind='return'
            elif address==peers+8:engine.reg_write(reg.UC_ARM64_REG_X0,17);kind='return'
            elif address==peers+12:state['submits']+=1;kind='return'
            if kind:
                if kind=='surface-id':engine.reg_write(reg.UC_ARM64_REG_X0,42)
                elif kind=='surface-time':engine.reg_write(reg.UC_ARM64_REG_X0,123456)
                elif kind=='mode':engine.reg_write(reg.UC_ARM64_REG_X0,0)
                elif kind=='surface-registration':
                    values=[engine.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
                    require(values[0]==surface and request+2152<=values[1]<request+2184 and values[2:8]==
                        [1,0,relocate(0xfffffff005c17458),display,request,0],'Original IOSurface registration argument widths/order differ: '+repr(values))
                    state['registered'].append(values[1]);engine.reg_write(reg.UC_ARM64_REG_X0,int(state['surface_ready']))
                    if not state['surface_ready']:engine.mem_write(values[1],struct.pack('<Q',0xdecafbad))
                engine.reg_write(reg.UC_ARM64_REG_PC,engine.reg_read(reg.UC_ARM64_REG_LR))
        def memory(engine,kind,address,size,value,user):
            # Imports, exact synthetic objects and stack are the only data.
            allowed=any(a<=address and address+size<=a+n for a,n in extents.items()) or debug_import<=address and address+size<=debug_import+8
            require(allowed,'Producer execution escaped fixture data windows: '+hex(address))
            if kind==UC_MEM_WRITE:
                require(stack<=address and address+size<=stack+16384 or state['phase']!='native' and request<=address and address+size<=request+2424,
                    'Read-only native producer guard wrote a request or display')
                if request<=address<request+2424:state['writes'].append((address-request,size))
        uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        def run(address,*args):
            for index,value in enumerate(args):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(index)),value)
            uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
            uc.emu_start(address,stop,timeout=200000,count=12000)
            require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop,'Producer ARM64 function failed to return')
            return uc.reg_read(reg.UC_ARM64_REG_X0)
        return uc,state,run
    # Execute the entire unchanged registration function. The IOSurface API
    # is an explicit peer, not an implementation of real fences or memory.
    for layer in range(4):
        for immediate in (False,True):
            uc,state,run=prepare(1<<layer,0,0,0,layer);state['phase']='registration';state['surface_ready']=immediate
            run(registration,display,request)
            requested,ready=struct.unpack('<2I',uc.mem_read(request+792,8))
            require(requested==1<<layer and ready==(1<<layer if immediate else 0) and
                len(state['registered'])==1 and state['retains']==1 and state['releases']==int(immediate),
                'Original registration failed to preserve pending-vs-ready state/ref ownership')
            state['phase']='native';require(run(base+functions['_iphone_producers_ready'],request)==int(immediate),'Native ready guard ignored original registration result')
            if not immediate:
                state['phase']='callback';status=run(callback,display,0x11223344,layer)
                require(status==0 and state['submits']==1 and struct.unpack('<I',uc.mem_read(request+796,4))[0]==1<<layer,
                    'Original asynchronous callback failed to set the correct ready bit and invoke slot 276')
                state['phase']='native';require(run(base+functions['_iphone_producers_ready'],request)==1,'Native guard missed actual callback ready state')
            cases.append({'case':f'layer-{layer}-'+('immediate' if immediate else 'deferred-callback'),'result':'PASS',
                'original_registration_executed':True,'original_gated_update_executed':not immediate,'surface_completion_api':'software peer'})
    for name,requested,ready,registered,cancelled,nonnull,expected in (
        ('pending-producer',1,0,1,0,True,0),('unregistered-surface',1,1,0,0,True,0),
        ('cancelled',1,1,1,1,True,0),('unknown-request-bit',0x10,0x10,1,0,True,0),
        ('extra-ready-bit',1,3,1,0,True,0),('two-producers-one-pending',3,1,1,0,True,0),
        ('surface-without-request-bit',0,0,1,0,True,0),
        ('background-pending',0x80000001,1,1,0,True,0),('background-and-layer-ready',0x80000001,0x80000001,1,0,True,1),
        ('no-new-surfaces',0xf,0xf,0,0,False,1)):
        uc,state,run=prepare(requested,ready,registered,cancelled,nonnull=nonnull);before=bytes(uc.mem_read(request,2424))
        require(run(base+functions['_iphone_producers_ready'],request)==expected and bytes(uc.mem_read(request,2424))==before,
                'Read-only producer guard mismatch: '+name)
        admission=relocate(int(contract['stock_ready_compare']['address'],16));uc.reg_write(reg.UC_ARM64_REG_X20,request)
        uc.emu_start(admission,admission+16,timeout=100000,count=4)
        require(uc.reg_read(reg.UC_ARM64_REG_PC)==(admission+16 if requested==ready else relocate(0xfffffff005cd5a08)),
                'Original stock producer admission comparison differs')
        cases.append({'case':name,'result':'PASS','ready':bool(expected),'original_stock_compare_executed':True,'request_writes':0})
    for pointer in (0,(1<<64)-1024):
        uc,state,run=prepare();require(run(base+functions['_iphone_producers_ready'],pointer)==0,'Invalid producer pointer was not refused')
        cases.append({'case':'null-request' if pointer==0 else 'request-address-wrap','result':'REFUSED_WITHOUT_WRITES'})
    for layer in range(6):
        uc,state,run=prepare(layer=layer%4)
        require(run(base+functions['_iphone_effective_surface'],request,layer)==(surface if layer<4 else 0),'Wrong effective surface slot')
    # An invalid callback layer/ID must not set readiness or kick a frontend.
    for name,request_id,layer,status in (('wrong-layer',0x11223344,4,0xe00002c2),('unknown-request-id',9,0,0xe00002bc)):
        uc,state,run=prepare(1,0,1);state['phase']='callback';before=bytes(uc.mem_read(request,2424))
        require(run(callback,display,request_id,layer)==status and state['submits']==0 and bytes(uc.mem_read(request,2424))==before,
                'Invalid original callback changed producer readiness')
        cases.append({'case':name,'result':'REFUSED_WITHOUT_WRITES'})
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed producer fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n');return
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_producer']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'] and json.loads(FIXTURE.read_text())==contract,'Exact producer contract/header changed')
    out=ROOT/'build/ios16-producer';out.mkdir(parents=True,exist_ok=True);source=out/'producer.cpp'
    source.write_text('#include "OriginalLegacyProducerABI.h"\nextern "C" bool iphone_producers_ready(const IOMFBSwapIORequest *p){return IPhone16Swap::producersReady(p);}\n'
        'extern "C" void *iphone_effective_surface(const IOMFBSwapIORequest *p,unsigned n){return IPhone16Swap::effectiveSurface(p,n);}\n')
    obj,=build_objects([source],out,[HEADER.parent]);cases=emulate(contract,obj)
    report={'result':'IOS16_PRODUCER_REGISTRATION_CALLBACK_AND_NATIVE_GUARD_PASS','native_kernel_sha256':sha(NATIVE),
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'builder_sha256':sha(ROOT/'scripts/prepare_ios16_producer.py'),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'queue_header_sha256':sha(HEADER.parent/'OriginalLegacySwapABI.h'),'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),
        'arm64_cases':cases,'original_instruction_bytes_changed':False,'original_functions_executed':['producer-registration','gated-ready-update'],
        'iosurface_completion_api_is_peer':True,'original_iosurface_fence_implementation_executed':False,'producer_cache_visibility_qualified':False,
        'full_frontend_installed':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Read-only native admission matches actual original immediate/deferred completion bookkeeping and full ready-word comparison. '
                'Unchanged registration and gated update run on bounded synthetic memory with explicit IOSurface/lifetime/trace peers. '
                'No real IOSurface producer, fence, DMA visibility or hardware is executed.'}
    (ROOT/'reports/ios16-producer.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: original iPhone producer registration/deferred update and '+str(len(cases))+' native guard/callback cases')


if __name__=='__main__':main()
