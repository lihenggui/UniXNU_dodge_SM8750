#!/usr/bin/env python3
"""Audit exact iPhone swap fields and compare native queue access with original ARM64 blocks."""
import argparse
import copy
import hashlib
import json
import struct

from check_ios16_display import derive as derive_classes, validate_fixture, FIXTURE as CLASSES
from native_driver_build import ROOT, build_objects, macho, require, sha, symbols
from native_prelink import backed_offset, exports

FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/display-swap.json'
HEADER = ROOT / 'profiles/os/ios-16.7.16-20H392/graphics/OriginalLegacySwapABI.h'


def original_input():
    classes = derive_classes()
    validate_fixture(classes, json.loads(CLASSES.read_text()))
    raw = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    image = macho(raw)
    def read(address, size):
        at = backed_offset(image['segments'], address, size, len(raw))
        return raw[at:at+size]
    return classes, raw, image, read


def derive():
    classes, raw, image, read = original_input()
    def words(address, size):
        return struct.unpack('<%dI' % (size//4), read(address, size))
    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Expected original ADRP')
        value = ((word >> 5) & 0x7ffff)*4 + ((word >> 29) & 3)
        return (pc & ~4095) + ((value-(1<<21) if value & (1<<20) else value)<<12)
    def branch(pc):
        word, = words(pc, 4)
        require(word & 0xfc000000 == 0x94000000, 'Expected original BL')
        value = word & 0x3ffffff
        return pc + 4*(value-(1<<26) if value & (1<<25) else value)
    def stub(pc):
        a,b,c = words(pc,12)
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200,
                'Expected original import stub')
        return struct.unpack('<Q',read(adrp(pc,a)+((b>>10)&4095)*8,8))[0]
    # Full unoptimized request metaclass constructor, including its actual
    # class name, size argument, native OSMetaClass call, and this/vptr path.
    setup = 0xfffffff005c04a44
    w = words(setup,88)
    require(w[:3] == (0xd100c3ff,0xa9027bfd,0x910083fd) and
            w[5:10] == (0x91004108,0xf9000be8,0xf81f83a0,0xf85f83a0,0xf90007e0) and
            w[16:] == (0xf94007e0,0xf9400be8,0xf9000008,0xa9427bfd,0x9100c3ff,0xd65f03c0),
            'Request metaclass this/vptr flow differs')
    require(w[10] & 0x9f00001f == 0x90000001 and w[11] & 0xffc003ff == 0x91000021 and
            w[14] & 0xffe0001f == 0x52800003, 'Request metaclass arguments differ')
    label = adrp(setup+40,w[10])+((w[11]>>10)&4095)
    expected_name = b'IOMFBSwapIORequest\0'
    require(read(label,len(expected_name)) == expected_name, 'Wrong original swap class')
    names = {n:a for a,group in exports(raw,image).items() for n in group}
    require(stub(branch(setup+60)) == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'Wrong original metadata constructor')
    size = (w[14]>>5)&65535
    require(size == 2424, 'Original request size changed')
    legacy = struct.unpack('<338Q',read(int(classes['classes']['IOMobileFramebufferLegacy']['vptr'],16),338*8))
    require(legacy[281] == 0xfffffff005c1ace4 and branch(legacy[281]+28) == 0xfffffff005c1012c and
            words(legacy[281]+20,8) == (0x52800028,0x12000101), 'Original normal completion must pass true')
    # The complete head-to-current and TAILQ unlink blocks below are also
    # executed byte-for-byte on the CPU model. The parent's stack slot holds
    # this. Both conditional paths end immediately before completion work.
    select = 0xfffffff005c0fec8
    require(words(select,12) == (0xf85e03a9,0xf9498928,0xf9098528), 'Original current/head transfer differs')
    unlink = 0xfffffff005c0ffcc
    require(words(unlink,100) == (
        0xf85e03a8,0xf9498508,0xf944b508,0xf1000108,0x1a9f17e8,0x37000128,0x14000001,
        0xf85e03a9,0xf9498528,0xf944b908,0xf9498529,0xf944b529,0xf904b928,0x14000006,
        0xf85e03a9,0xf9498528,0xf944b908,0xf9098d28,0x14000001,
        0xf85e03a9,0xf9498528,0xf944b508,0xf9498529,0xf944b929,0xf9000128),
        'Original request link/head/tail removal differs')
    # Both queue validation and surface retirement index the same four
    # IOSurface pointers in the actual request, not IOMFBDisplayedData.
    require(words(0xfffffff005c19a40,16) == (0xb85ec3a8,0x71001108,0x1a9f27e8,0x370001a8) and
            words(0xfffffff005c19a98,16) == (0xf85f03a8,0x91222108,0xb85ec3a9,0xf8697908),
            'Original bounded request surface array differs')
    require(words(0xfffffff005c165a8,28) == (0xf94067e0,0xf85303a1,0xf9400008,0xf9446908,
            0xd63f0100,0x52800028,0x0a080008), 'Original request validation call differs')
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392',
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'legacy_instance_bytes':5728,'request_class':'IOMFBSwapIORequest','request_instance_bytes':size,
        'request_metadata_setup':hex(setup),'request_metadata_setup_sha256':hashlib.sha256(read(setup,88)).hexdigest(),
        'queue':{'current':4872,'head':4880,'tail':4888,'request_next':2408,'request_previous_link':2416},
        'request_surfaces':{'offset':2184,'count':4,'element_bytes':8},
        'native_private_dispatch':{'complete_current':281,'validate_request':282},
        'original_queue_blocks':[{'address':hex(a),'bytes':n,'sha256':hashlib.sha256(read(a,n)).hexdigest()}
                                 for a,n in ((select,12),(unlink,100))],
        'retirement_and_surface_array_body':{'address':hex(0xfffffff005c19a14),'bytes':0x278,
            'sha256':hashlib.sha256(read(0xfffffff005c19a14,0x278)).hexdigest()},
        'request_payload_geometry_qualified':False,'producer_sync_qualified':False,'provider_complete':False}


def emulate(contract, obj):
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X29, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC
    _,_,_,read = original_input()
    data=obj.read_bytes(); image=macho(data)
    text, = [s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
    require(struct.unpack_from('<I',data,text['command_offset']+60)[0] == 0,'Native queue code has unresolved text relocations')
    code=data[text['fileoff']:text['fileoff']+text['size']]
    functions={s['name']:s['value']-text['va'] for s in symbols(data) if s['kind'] & 0xe and s['name'].startswith('_iphone_')}
    require(set(functions)=={'_iphone_activate','_iphone_can_activate','_iphone_pending','_iphone_surface'},'Expected actual native queue entry points')
    base, original, stop, display, first, second, third, stack = 0x100000,0x110000,0x120000,0x200000,0x210000,0x220000,0x230000,0x300000
    objects={display:5728,first:2424,second:2424,third:2424}
    results=[]
    def prepare(count, defect=None):
        blobs={a:bytearray([0xa5])*n for a,n in objects.items()}
        def put(a,off,value):struct.pack_into('<Q',blobs[a],off,value)
        put(display,4872,0); put(display,4880,first if count else 0)
        chain=[first,second,third][:count]
        put(display,4888,chain[-1]+2408 if chain else display+4880)
        for index,a in enumerate(chain):
            put(a,2408,chain[index+1] if index+1<count else 0)
            put(a,2416,chain[index-1]+2408 if index else display+4880)
        for index in range(4):put(first,2184+index*8,0x1020304050607080+index)
        if defect=='busy':put(display,4872,third)
        elif defect=='wrong-head':put(display,4880,second)
        elif defect=='previous-link':put(first,2416,display+4872)
        elif defect=='tail':put(display,4888,first+2416)
        elif defect=='next-link':put(second,2416,display+4880)
        elif defect=='next-is-self':put(first,2408,first)
        elif defect=='tail-at-removed':put(display,4888,first+2408)
        return blobs
    def execute(blobs, name, arg0=display, arg1=first, original_blocks=False):
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,length in ((base,65536),(original,65536),(stop,4096),(stack,16384),
                               *((a,(n+4095)&~4095) for a,n in objects.items())):machine.mem_map(address,length)
        machine.mem_write(base,code)
        for a,b in blobs.items():machine.mem_write(a,bytes(b))
        frame=stack+0x3e00
        machine.mem_write(frame-32,struct.pack('<Q',display))
        machine.reg_write(UC_ARM64_REG_X29,frame);machine.reg_write(UC_ARM64_REG_SP,stack+0x3c00)
        machine.reg_write(UC_ARM64_REG_LR,stop);machine.reg_write(UC_ARM64_REG_X0,arg0);machine.reg_write(UC_ARM64_REG_X1,arg1)
        def memory(engine,access,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in objects.items()) or
                    stack<=address and address+size<=stack+16384,'Queue access escaped exact fixture extent')
        machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        try:
            if original_blocks:
                for index,block in enumerate(contract['original_queue_blocks']):
                    size=block['bytes']; body=read(int(block['address'],16),size)
                    address=original+index*4096
                    machine.mem_write(address,body)
                    machine.emu_start(address,address+size,timeout=100000,count=128)
                    require(machine.reg_read(UC_ARM64_REG_PC)==address+size,'Original queue block escaped its boundary')
            else:
                machine.emu_start(base+functions[name],stop,timeout=100000,count=512)
                require(machine.reg_read(UC_ARM64_REG_PC)==stop,'Native queue helper did not return')
        except UcError as error:raise ValueError('Queue CPU-model execution failed: '+str(error)) from error
        return machine.reg_read(UC_ARM64_REG_X0),{a:bytes(machine.mem_read(a,n)) for a,n in objects.items()}
    for count in (1,2,3):
        blobs=prepare(count)
        eligible,unmodified=execute(blobs,'_iphone_can_activate')
        require(eligible==1 and unmodified=={a:bytes(b) for a,b in blobs.items()},'Eligibility check must not write queue objects')
        result,native=execute(blobs,'_iphone_activate')
        _,expected=execute(blobs,'_iphone_activate',original_blocks=True)
        require(result==1 and native==expected,'Native queue transfer differs from actual original TAILQ blocks')
        # Execute head access too, checking it follows the real queue after
        # one transfer, without modifying a byte or touching request refs.
        head,unchanged=execute(native,'_iphone_pending')
        require(head==(second if count>1 else 0) and unchanged==native,'Wrong pending request after transfer')
        results.append({'case':str(count)+'-queued','result':'PASS','matches_original_queue_blocks':True})
    refusals=[(0,None),(1,'busy'),(1,'wrong-head'),(1,'previous-link'),(1,'tail'),
              (2,'next-link'),(2,'next-is-self'),(2,'tail-at-removed'),(1,'null-display'),(1,'null-request')]
    for count,defect in refusals:
        blobs=prepare(count,defect)
        eligible,unmodified=execute(blobs,'_iphone_can_activate',arg0=0 if defect=='null-display' else display,
                                    arg1=0 if defect=='null-request' else first)
        require(eligible==0 and unmodified=={a:bytes(b) for a,b in blobs.items()},'Invalid eligibility check changed memory')
        result,after=execute(blobs,'_iphone_activate',arg0=0 if defect=='null-display' else display,
                             arg1=0 if defect=='null-request' else first)
        require(result==0 and after=={a:bytes(b) for a,b in blobs.items()},'Invalid queue changed memory: '+str(defect))
        results.append({'case':defect or 'empty','result':'REFUSED_WITHOUT_WRITES'})
    blobs=prepare(1)
    for index in (0,1,2,3,4,0xffffffff):
        value,after=execute(blobs,'_iphone_surface',arg0=first,arg1=index)
        require(value==(0x1020304050607080+index if index<4 else 0) and
                after=={a:bytes(b) for a,b in blobs.items()},'Request surface array returned wrong pointer or wrote memory')
    value,_=execute(blobs,'_iphone_surface',arg0=0,arg1=0)
    require(value==0,'Null request surface access was not refused')
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record-fixture',action='store_true')
    args=parser.parse_args()
    contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed swap input already exists')
        FIXTURE.write_text(json.dumps(contract,indent=2)+'\n')
        print('Derived exact iPhone request/queue contract for review');return
    spec=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_swap']
    require(sha(FIXTURE)==spec['sha256'] and sha(HEADER)==spec['header_sha256'],'Reviewed swap contract/access header changed')
    require(json.loads(FIXTURE.read_text())==contract,'Derived original iPhone swap contract changed')
    wrong=copy.deepcopy(contract);wrong['request_surfaces']['offset']=2624
    require(wrong['request_surfaces']['offset']+32>contract['request_instance_bytes'],'Wrong-OS negative fixture no longer escapes original size')
    out=ROOT/'build/ios16-display-swap';out.mkdir(parents=True,exist_ok=True)
    source=out/'queue.cpp'
    source.write_text('#include "OriginalLegacySwapABI.h"\n'
        'extern "C" bool iphone_activate(void *p,IOMFBSwapIORequest *r){return IPhone16Swap::activatePending(p,r);}\n'
        'extern "C" bool iphone_can_activate(const void *p,const IOMFBSwapIORequest *r){return IPhone16Swap::canActivatePending(p,r);}\n'
        'extern "C" IOMFBSwapIORequest *iphone_pending(void *p){return IPhone16Swap::pending(p);}\n'
        'extern "C" void *iphone_surface(IOMFBSwapIORequest *r,unsigned i){return IPhone16Swap::surface(r,i);}\n')
    obj,=build_objects([source],out,[HEADER.parent])
    cases=emulate(contract,obj)
    report={'result':'IOS16_DISPLAY_SWAP_NATIVE_AND_ORIGINAL_ARM64_CHECK_PASS',
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),
        'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'native_object':str(obj.relative_to(ROOT)),'native_object_sha256':sha(obj),
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],
        'request_instance_bytes':2424,'surface_array_offset':2184,'queue':contract['queue'],
        'native_target':'arm64-apple-ios16.0','cases':cases,'surface_index_cases':7,'read_only_eligibility_cases':13,
        'wrong_os_surface_array_out_of_bounds':True,'original_queue_blocks_changed':False,
        'full_original_method_executed':False,'retains_releases_fences_or_vblank_emulated':False,
        'original_objects_constructed':False,'provider_complete':False,'hardware_tested':False,
        'scope':'Owned native queue access matches unchanged original head/unlink blocks over synthetic exact-size objects. '
                'Invalid queues are refused without writes. No swap is completed and no display is published.'}
    (ROOT/'reports/ios16-display-swap.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: exact iPhone swap/queue native code matches original ARM64 blocks; three queue shapes, ten refusals, seven surface cases')


if __name__=='__main__':main()
