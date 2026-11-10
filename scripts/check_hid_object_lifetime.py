#!/usr/bin/env python3
"""Execute unchanged original HID init/free, including its partial-init hazard."""
import hashlib
import json
from pathlib import Path
import struct
from check_ios16_swap import original_input
from native_driver_build import ROOT,require,sha
from native_prelink import backed_offset,macho,unserialize_xml


def emulate(case,unsafe=False):
    import unicorn
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    _,raw,image,read=original_input();info=next(s for s in image['segments'] if s['name']=='__PRELINK_INFO')
    entry=next(e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary'] if e['CFBundleIdentifier']=='com.apple.iokit.IOHIDFamily')
    module=macho(raw,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(raw)))
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(a,data=b'',size=0):
        p=a&~4095;last=(a+max(size,len(data))+4095)&~4095
        while p<last:
            if p in pages:p+=4096;continue
            end=p+4096
            while end<last and end not in pages:end+=4096
            uc.mem_map(p,end-p);pages.update(range(p,end,4096));p=end
        if data:uc.mem_write(a,data)
    for s in module['segments']:
        if s['size'] and s['initprot']:put(s['va'],read(s['va'],s['filesize']) if s['filesize'] else b'',s['size'])
    store,obj,expansion,objects,table,dictionary,stack,halt=0x200000,0x200040,0x210040,0x220000,0x230000,0x240000,0x300000,0x400000
    for a,n in ((store,4096),(expansion&~4095,8192),(objects,8192),(table,4096),(dictionary,4096),(stack,65536),(halt,4096)):put(a,size=n)
    put(store,b'\xa5'*(208+128));put(obj,bytes(208));put(expansion-64,b'\xa5'*(4096+128));put(expansion,bytes(4096))
    setobj=objects;release_cb,count_cb,parent_init,parent_free=halt+0x100,halt+0x200,halt+0x300,halt+0x400
    peer_table=[0]*207;peer_table[5]=release_cb;peer_table[18]=count_cb;put(table,struct.pack('<207Q',*peer_table));put(setobj,struct.pack('<Q',table))
    native_table=struct.unpack('<Q',read(0xfffffff006cbaef8,8))[0];put(native_table,size=4096)
    put(native_table+16+21*8,struct.pack('<Q',parent_init));put(native_table+16+14*8,struct.pack('<Q',parent_free))
    events=[];releases=[];expected_releases=[setobj];allocated=False;freed=False;faults=[]
    def args():return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(v=0):uc.reg_write(reg.UC_ARM64_REG_X0,v);uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def alloc(a):
        nonlocal allocated
        require(a[0]==0xfffffff006cc5358,'Original HID allocator type-view changed');events.append('typed-expansion-allocation-peer')
        allocated=case!='init-expansion-failure';ret(expansion if allocated else 0)
    def newset(a):require(a[0]==2,'Original HID set capacity changed');events.append('set-allocation-peer');ret(0 if case=='init-set-failure' else setobj)
    def init(a):require(a[:2]==[obj,dictionary],'Original parent init self/properties changed');events.append('parent-init-peer');ret(int(case!='init-parent-failure'))
    def free_parent(a):require(a[0]==obj and freed,'Original parent free preceded expansion free');events.append('parent-free-peer');ret()
    def release(a):require(a[0] in expected_releases and a[0] not in releases,'Original HID free released an unexpected or duplicate object');releases.append(a[0]);events.append('release-peer');ret()
    def count(a):require(a[0]==setobj,'Original HID count query changed');events.append('set-count-peer');ret(int(case=='free-nonempty-set'))
    def iterate(a):
        require(a[0]==setobj and struct.unpack('<Q',bytes(uc.mem_read(a[1]+16,8)))[0]==0xfffffff005726e8c and
                struct.unpack('<Q',bytes(uc.mem_read(a[1]+32,8)))[0]==obj,'Original HID collection block/captured self changed')
        events.append('collection-iteration-peer-no-items');ret()
    def free_thread(a):require(a[0]==objects+0x1f00,'Original HID thread-call pointer changed');events.append('thread-call-free-peer');ret(1)
    def free_expansion(a):
        nonlocal freed
        require(a[:2]==[0xfffffff006cc5398,expansion] and allocated and not freed,'Original typed expansion free changed')
        require(bytes(uc.mem_read(obj+200,8))==bytes(8),'Original HID expansion pointer not cleared before freeing')
        freed=True;events.append('typed-expansion-free-peer');ret()
    peers={0xfffffff00575c1fc:alloc,0xfffffff00575c550:newset,parent_init:init,parent_free:free_parent,release_cb:release,count_cb:count,
           0xfffffff00575c364:iterate,0xfffffff00575c898:free_thread,0xfffffff00575c1a8:free_expansion}
    def hook(engine,a,n,user):
        if a in peers:peers[a](args());return
        require(0xfffffff005726c34<=a<0xfffffff005726ca0 or 0xfffffff005726ca0<=a<0xfffffff005726e8c,'Unqualified original HID lifetime implementation reached')
    def fault(engine,access,a,size,value,user):faults.append(a);return False
    uc.hook_add(unicorn.UC_HOOK_CODE,hook);uc.hook_add(unicorn.UC_HOOK_MEM_INVALID,fault)
    uc.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20)
    def execute(a,*values):
        for i,v in enumerate(values):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),v)
        uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
        uc.emu_start(a,halt,timeout=1000000,count=2000);require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'Original HID lifetime function did not return')
        return uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff
    ok=execute(0xfffffff005726c34,obj,dictionary)
    require(bool(ok)==(case not in ('init-expansion-failure','init-set-failure','init-parent-failure')),'Original HID init result changed')
    require(struct.unpack('<Q',bytes(uc.mem_read(obj+200,8)))[0]==(expansion if allocated else 0),'Original HID private allocation pointer changed')
    if case=='init-expansion-failure':
        require(events==['typed-expansion-allocation-peer'],'Original HID allocated peers after expansion failure')
        if unsafe:
            try:execute(0xfffffff005726ca0,obj)
            except unicorn.UcError as error:require(error.errno==unicorn.UC_ERR_READ_UNMAPPED and faults==[0x20],'Unexpected partial-init free fault')
            else:raise ValueError('Original free unexpectedly accepted a null expansion')
        return {'case':case,'result':'PASS','original_init_full_body':True,'original_free_full_body':False,'unsafe_free_fault_at_0x20_confirmed':unsafe,'events':events}
    if case=='init-set-failure':expected_releases=[]
    else:require(bytes(uc.mem_read(expansion,8))==struct.pack('<Q',setobj),'Original HID set pointer changed')
    if case=='free-owned-fields':
        for i,offset in enumerate((32,40,48,88,152,160,136,72,64),1):
            address=objects+i*0x100;put(address,struct.pack('<Q',table));put(expansion+offset,struct.pack('<Q',address));expected_releases.append(address)
        address=objects+0x1000;put(address,struct.pack('<Q',table));put(obj+136,struct.pack('<Q',address));expected_releases.append(address)
    if case=='free-thread-call':put(expansion+96,struct.pack('<Q',objects+0x1f00))
    execute(0xfffffff005726ca0,obj)
    require(sorted(releases)==sorted(expected_releases) and freed and events[-1]=='parent-free-peer','Original HID lifetime release ordering/count changed')
    require(bytes(uc.mem_read(obj,208))==bytes(208) and bytes(uc.mem_read(expansion,4096))==bytes(4096),'Original HID free left populated fixture storage')
    require(bytes(uc.mem_read(store,64))==b'\xa5'*64 and bytes(uc.mem_read(obj+208,64))==b'\xa5'*64 and
            bytes(uc.mem_read(expansion-64,64))==b'\xa5'*64 and bytes(uc.mem_read(expansion+4096,64))==b'\xa5'*64,'Original HID lifetime allocation canary changed')
    return {'case':case,'result':'PASS','original_init_full_body':True,'original_free_full_body':True,'events':events,'released_peer_objects':len(releases),
            'expansion_fixture_bytes_not_a_claim_of_original_allocation_size':4096}


def main():
    names=('init-expansion-failure','init-set-failure','init-parent-failure','init-success','free-owned-fields','free-nonempty-set','free-thread-call')
    cases=[emulate(n) for n in names];unsafe=emulate('init-expansion-failure',True)
    _,raw,image,read=original_input();out=ROOT/'build/ios16-hid-source-interface/object-lifetime-cases.json'
    out.write_text(json.dumps({'result':'PASS','cases':cases,'unsafe_partial_free_control':unsafe},indent=2)+'\n')
    report={'result':'IOS16_ORIGINAL_HID_INIT_FREE_AND_PARTIAL_INITIALIZATION_HAZARD_AUDIT_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),ROOT/'scripts/check_ios16_swap.py',ROOT/'scripts/native_driver_build.py')},
            'original_kernelcache_sha256':hashlib.sha256(raw).hexdigest(),'case_count':len(cases),'cases':cases,
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'unsafe_partial_free_control':unsafe,
            'original_function_blocks':{n:{'address':hex(a),'bytes':length,'sha256':hashlib.sha256(read(a,length)).hexdigest()} for n,a,length in
                                       (('init',0xfffffff005726c34,108),('free',0xfffffff005726ca0,492))},
            'source_must_preserve_object_on_unqualified_init_failure':True,'allocator_set_collection_release_parent_and_thread_apis_are_peers':True,
            'actual_original_start_parser_or_collection_elements_executed':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Seven unchanged full original init paths and six full free paths with explicit allocator/set/collection/native-parent/release/thread peers. '
                    'A failed original expansion allocation makes init return false; forcing original free then reads unmapped 0x20. '
                    'This is an instruction-level hazard audit, not an assertion that a real allocator fails or runtime free is safe. Source retains objects after initialization attempts.'}
    (ROOT/'reports/ios16-hid-object-lifetime.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: seven original HID init/free paths; null-expansion free hazard confirmed, peers explicit')

if __name__=='__main__':main()
