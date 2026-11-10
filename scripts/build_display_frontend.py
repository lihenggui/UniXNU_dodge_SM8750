#!/usr/bin/env python3
"""Build a bounded real iPhone packet/queue frontend without publishing a driver."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tomllib

from check_display_frontend_host import check as check_host
from check_ios16_swap import original_input
from ios16_display_cache import DisplayCache
from native_driver_build import ROOT,TREE,NATIVE,archive_imports,build_objects,inspect_object,macho,require,sha,symbols
from prepare_ios16_display_userland import derive as userland_contract,emulate as original_userland_cases

FIXTURE=ROOT/'profiles/os/ios-16.7.16-20H392/display-frontend.json'
HEADER=FIXTURE.parent/'graphics/OriginalLegacyPacketABI.h'
DEPENDENCIES=('ios16-display-interface','ios16-display-emulation','ios16-display-lifecycle','ios16-producer','ios16-request-fields','ios16-display-userland',
    'ios16-surface-backing','ios16-gpu-swap-bridge','ios16-software-refresh','a830-backend')


def derive():
    classes,_,_,read=original_input();vptr=int(classes['classes']['IOMobileFramebufferLegacy']['vptr'],16)
    table=struct.unpack('<338Q',read(vptr,338*8))
    require(table[178]==0xfffffff005c14930 and table[276]==0xfffffff005c192b8 and table[282]==0xfffffff005c1ad10,
        'Exact iPhone packet/validation/submit slots changed')
    require(struct.unpack('<7I',read(0xfffffff005bfde54,28))==
        (0xf94007e2,0xf9406c40,0xf9400fe1,0xf9400008,0xf942c908,0xd63f0100,0xb81fc3a0),
        'Original packet caller self/packet/opaque submitter/status dataflow differs')
    require(struct.unpack('<2I',read(0xfffffff005bfddd0,8))==(0xf111b108,0x1a9f17e8),
        'Original packet caller no longer requires exact 1132-byte structure')
    require(struct.unpack('<2I',read(0xfffffff005a4e7ec,8))==(0xb9400c00,0xd65f03c0) and
        struct.unpack('<Q',read(0xfffffff006deb2a0,8))[0]==0xfffffff005a4e7ec,
        'Original IOSurface ID getter/import no longer reads its actual 32-bit ID at +12')
    def block(address,size):return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    return {'schema_version':1,'product':'iPhone10,3','build':'20H392','original_kernelcache_sha256':classes['original_kernelcache_sha256'],
        'packet_bytes':1132,'packet_slot':178,'packet_entry':block(table[178],5628),'packet_callsite':block(0xfffffff005bfde54,28),
        'packet_prototype':'int32_t (self, const packet *, opaque submitter)','packet_size_check':block(0xfffffff005bfddd0,8),
        'validation_slot':282,'submit_kick_slot':276,'surface_id_leaf':block(0xfffffff005a4e7ec,8),'surface_id_word_offset':12,
        'maximum_reserved_requests':16,'accepted_packet':'Unmodified SwapBegin + layer-0 full-frame SetLayer defaults only',
        'all_other_packet_bytes_required_zero':True,'original_request_builder_body_executed':False,'full_family_lifecycle_qualified':False}


def guard_cases(contract,obj):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    _,_,_,read=original_input();data=obj.read_bytes();image=macho(data)
    text,=[s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text']
    require(struct.unpack_from('<I',data,text['command_offset']+60)[0]==0,'Native packet/geometry probes have external relocations')
    code=data[text['fileoff']:text['fileoff']+text['size']]
    functions={s['name']:s['value']-text['va'] for s in symbols(data) if s['kind']&14 and s['name'].startswith('_iphone_')}
    require(set(functions)=={'_iphone_packet_admit','_iphone_geometry_admit'},'Native frontend probes differ')
    fields=json.loads((FIXTURE.parent/'display-request-fields.json').read_text())
    base,original,idcode,packet,display,request,context,surface,output,stack,stop=0x100000,0x110000,0x160000,0x200000,0x220000,0x230000,0x240000,0x250000,0x260000,0x300000,0x400000
    results=[]
    def inspect_packet(payload,width,height,layer,nonnull):
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        objects={packet:1132,display:5728,request:2424,context:64,surface:1168,output:16,stack:16384}
        for address,length in ((base,4096),(original,5*4096),(idcode,4096),(stop,4096),*((a,(n+4095)&~4095) for a,n in objects.items())):uc.mem_map(address,length)
        uc.mem_write(base,code);uc.mem_write(packet,payload);uc.mem_write(output,b'\xcc'*16)
        uc.mem_write(display+5208,struct.pack('<2I',width,height));uc.mem_write(request+788,payload[80:84])
        if nonnull:uc.mem_write(request+2184+layer*8,struct.pack('<Q',surface))
        uc.mem_write(surface+12,struct.pack('<I',0x42424242));uc.mem_write(idcode,read(int(contract['surface_id_leaf']['address'],16),8))
        uc.mem_write(context,struct.pack('<Q',request));uc.mem_write(context+56,struct.pack('<Q',packet))
        for index,block in enumerate(fields['builder_blocks']):uc.mem_write(original+index*4096,read(int(block['address'],16),block['bytes']))
        uc.reg_write(reg.UC_ARM64_REG_CPACR_EL1,3<<20);phase=['native'];writes=[]
        def memory(engine,kind,address,size,value,user):
            require(any(a<=address and address+size<=a+n for a,n in objects.items()),'Frontend native/original field comparison escaped exact data windows')
            if kind==UC_MEM_WRITE:
                require(stack<=address and address+size<=stack+16384 or
                    (request<=address and address+size<=request+2424 if phase[0]=='builder' else output<=address and address+size<=output+16),
                    'Native frontend guard wrote request/packet data')
                writes.append((address,size))
        uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
        def run(address,*arguments):
            for index,value in enumerate(arguments):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(index)),value)
            uc.reg_write(reg.UC_ARM64_REG_SP,stack+0x3f00);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
            uc.emu_start(address,stop,timeout=500000,count=200000)
            require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop,'Native frontend guard failed to return');return uc.reg_read(reg.UC_ARM64_REG_X0)
        admitted=run(base+functions['_iphone_packet_admit'],packet,len(payload),width,height,output)
        expected=int(nonnull and layer==0)
        require(admitted==expected and bytes(uc.mem_read(packet,1132))==payload,'Native packet filter disagrees with actual original userland defaults')
        if admitted:require(struct.unpack('<2I',uc.mem_read(output,8))==(0x10203040,0x42424242),'Native packet identity differs')
        phase[0]='builder'
        for index,block in enumerate(fields['builder_blocks']):
            sp=stack+0x3000;fp=sp+0x180;start=original+index*4096
            uc.reg_write(reg.UC_ARM64_REG_SP,sp);uc.reg_write(reg.UC_ARM64_REG_X29,fp);uc.reg_write(reg.UC_ARM64_REG_LR,stop)
            uc.mem_write(sp+0x88,struct.pack('<Q',context));uc.mem_write(sp+0xb0,struct.pack('<Q',display));uc.mem_write(fp-0x68,struct.pack('<I',layer))
            if block['name']=='secondary':
                uc.reg_write(reg.UC_ARM64_REG_X0,display);uc.reg_write(reg.UC_ARM64_REG_X1,request);uc.reg_write(reg.UC_ARM64_REG_X2,packet)
                uc.emu_start(start,stop,timeout=100000,count=128);require(uc.reg_read(reg.UC_ARM64_REG_PC)==stop,'Original secondary writer escaped')
            else:
                uc.emu_start(start,start+block['bytes'],timeout=100000,count=128)
                require(uc.reg_read(reg.UC_ARM64_REG_PC)==start+block['bytes'],'Original field block escaped')
        phase[0]='native';before=bytes(uc.mem_read(request,2424))
        geometry=run(base+functions['_iphone_geometry_admit'],request,0x10203040,0x42424242,width,height)
        require(geometry==expected and bytes(uc.mem_read(request,2424))==before,'Native geometry policy disagrees with original userland -> kernel field dataflow')
        require(run(idcode,surface)==0x42424242,'Original IOSurface ID leaf differs')
        if expected:
            for defect in ('ready-word-is-not-disable','transform','float-one-is-not-default','dimension','cancelled'):
                changed=bytearray(before)
                if defect=='ready-word-is-not-disable':struct.pack_into('<I',changed,796,1)
                elif defect=='transform':struct.pack_into('<I',changed,580,1)
                elif defect=='float-one-is-not-default':struct.pack_into('<I',changed,564,0x3f800000)
                elif defect=='dimension':struct.pack_into('<I',changed,816,width+1)
                else:changed[1354]=1
                uc.mem_write(request,bytes(changed))
                require(run(base+functions['_iphone_geometry_admit'],request,0x10203040,0x42424242,width,height)==int(defect=='ready-word-is-not-disable'),
                    'Native geometry mutation policy differs: '+defect)
        results.append({'case':f'original-layer-{layer}-{width}x{height}-'+('surface' if nonnull else 'disabled'),'result':'PASS',
            'packet_admitted':bool(admitted),'geometry_admitted':bool(geometry),'unchanged_original_kernel_builder_blocks':5,'original_surface_id_leaf_executed':True})
    with DisplayCache() as cache:
        original_cases=original_userland_cases(cache,userland_contract(cache),inspect_packet)
    return {'cases':results,'original_userland_case_count':len(original_cases),'original_instruction_bytes_changed':False,
        'original_allocation_and_surface_binding_are_fixtures':True,'native_guard_cpu_target':'arm64-apple-ios16.0'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--record-fixture',action='store_true');args=parser.parse_args();contract=derive()
    if args.record_fixture:
        require(not FIXTURE.exists(),'Reviewed frontend fixture already exists');FIXTURE.write_text(json.dumps(contract,indent=2)+'\n');return
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['iphone_display_frontend']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'] and json.loads(FIXTURE.read_text())==contract,'Exact frontend packet/bindings evidence changed')
    for name in DEPENDENCIES:
        report=json.loads((ROOT/'reports'/f'{name}.json').read_text());require('PASS' in report['result'],'Frontend dependency failed: '+name)
    out=ROOT/'build/ios16-display-frontend';driver=ROOT/'drivers/DodgeDisplay';host=check_host(out)
    probe=out/'frontend-guards.cpp';probe.write_text('#include "OriginalLegacyPacketABI.h"\n'
        'extern "C" bool iphone_packet_admit(const void *p,unsigned n,uint32_t w,uint32_t h,IPhone16Swap::PacketIdentity *o){return IPhone16Swap::defaultPacket(p,n,w,h,o);}\n'
        'extern "C" bool iphone_geometry_admit(const IOMFBSwapIORequest *r,uint32_t i,uint32_t s,uint32_t w,uint32_t h){return IPhone16Swap::defaultRequestGeometry(r,{i,s},w,h);}\n')
    obj,probe_obj=build_objects([driver/'DodgeDisplayFrontend.cpp',probe],out,[HEADER.parent])
    # Check real ordinary ARM64/iOS16 objects; the shared native recipes keep
    # the kernel's general-register-only code generation and instrumentation.
    for path in (obj,probe_obj):inspect_object(path.read_bytes())
    cpu=guard_cases(contract,probe_obj)
    profile=tomllib.loads((FIXTURE.parent/'profile.toml').read_text());slide=int(profile['kernel']['prelink']['slide'],0)
    bindings={'_native_iphone_submit_default_packet':int(contract['packet_entry']['address'],16)+slide,
        '_native_iphone_surface_id':int(contract['surface_id_leaf']['address'],16)+slide}
    assembly=out/'original-frontend-bindings.S';assembly.write_text(''.join(f'.globl {name}\n.set {name}, {address:#x}\n' for name,address in sorted(bindings.items())))
    binding=out/'original-frontend-bindings.o'
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',assembly,'-o',binding],check=True)
    inspect_object(binding.read_bytes());require({s['name']:s['value'] for s in symbols(binding.read_bytes()) if s['kind']==3}==bindings,'Original frontend absolute bindings differ')
    objects=[obj,binding];archive=out/'libDodgeDisplayFrontend.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    for path in objects:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,path.name])==path.read_bytes(),'Frontend archive readback differs')
    imports=archive_imports(objects);backend=json.loads((ROOT/'reports/a830-backend.json').read_text())
    require('_dodge_adreno_display_timeline' in imports['required_board_or_original_imports'] and
        '_dodge_adreno_display_timeline' in backend['imports']['defined'],'Frontend must strongly import the coherent candidate Adreno timeline')
    backend_inputs={**backend['source_sha256'],**backend['header_sha256']}
    fence_sources=[ROOT/path for path in backend_inputs if Path(path).name in ('NativeAdrenoPublish.cpp','NativeAdrenoRing.cpp','NativeAdrenoRing.h')]
    require(len(fence_sources)==3,'Actual producer timeline source evidence is incomplete')
    for path in fence_sources:require(sha(path)==backend_inputs[str(path.relative_to(ROOT))],'Actual producer timeline source changed')
    paths=[Path(__file__),ROOT/'scripts/check_display_frontend_host.py',ROOT/'scripts/prepare_ios16_display_userland.py',
        ROOT/'scripts/ios16_display_cache.py',driver/'DodgeDisplayFrontend.cpp',driver/'DodgeDisplayFrontend.h',
        driver/'DodgeGpuSwapBridge.cpp',driver/'DodgeGpuSwapBridge.h',driver/'DodgeDisplayTransfer.h',driver/'DodgeSurfaceBacking.h',ROOT/'tests/DodgeDisplayFrontendTest.cpp',
        driver/'DodgeSoftwareRefresh.cpp',driver/'DodgeSoftwareRefresh.h',
        driver/'DodgeAdrenoTimeline.h',
        *fence_sources,*[TREE/'.cache/xnu-work/iokit/Kernel'/name for name in ('IOEventSource.cpp','IOTimerEventSource.cpp','IOWorkLoop.cpp')],
        *sorted(HEADER.parent.glob('OriginalLegacy*ABI.h')),*sorted((ROOT/'tests/gpu_swap_include').rglob('*.h'))]
    report={'result':'DARWIN22_BOUNDED_IPHONE_DISPLAY_FRONTEND_CANDIDATE_PASS','native_kernel_sha256':sha(NATIVE),
        'original_kernelcache_sha256':contract['original_kernelcache_sha256'],'builder_sha256':sha(Path(__file__)),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in paths},
        'dependency_report_sha256':{name:sha(ROOT/'reports'/f'{name}.json') for name in DEPENDENCIES},
        'objects':[{'path':str(path.relative_to(ROOT)),'sha256':sha(path)} for path in objects],
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'imports':imports,
        'bindings':{name:hex(address) for name,address in bindings.items()},'native_probe':str(probe_obj.relative_to(ROOT)),'native_probe_sha256':sha(probe_obj),
        'host_tests':host,'host_case_count':len(host['cases']),'host_binary_sha256':sha(out/'display-frontend-host'),
        'host_sanitizers':['address','undefined','leak'],'native_guard_tests':cpu,'immutable_full_packet_copy':True,
        'request_surface_and_backing_references_held':True,'original_ready_words_observed':True,
        'original_display_mode_matches_gop_and_rechecked':True,
        'original_all_startup_queues_empty_required':True,
        'creation_enters_workloop_with_retained_inputs':True,'creation_rechecks_loop_and_gate_identity':True,
        'dequeued_requests_reconciled_after_bounded_queue_audit':True,'ledger_entry_detached_before_virtual_releases':True,
        'adreno_first_successful_target_preserved':True,'adreno_query_failure_holds_frame':True,
        'adreno_first_recovery_epoch_preserved':True,'adreno_epoch_change_latches_refusal':True,'adreno_snapshot_nonblocking':True,
        'adreno_observed_timeline_regression_latches_refusal':True,
        'producer_retry_nanoseconds':200000,'producer_retry_uses_gated_iotimer':True,'producer_timeout_never_retires':True,
        'cpu_producer_mode_explicit':True,'adreno_timeline_epoch_or_fault_recovery_qualified':False,
        'default_transfer_cpu_copy':True,'default_adreno_producer_wait':True,'experimental_presenter_explicit':True,
        'software_refresh_connected':True,'software_refresh_initially_disabled':True,'software_refresh_stopped_before_owner_release':True,
        'request_reservation_guard_rechecked_before_copy_and_retirement':True,'drain_before_stop_owner_release':True,
        'original_request_builder_body_executed':False,'original_completion_lifecycle_executed':False,
        'original_iokit_objects_executed':False,'general_composition_or_color_abi_qualified':False,
        'gpu_failure_quiescence_qualified':False,'concrete_legacy_subclass_installed':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Actual native guarded packet/queue frontend with exact original entry/ID aliases, bounded 16-request ownership ledger, '
                'real completion bridge and bounded CPU scanout. Adreno producers are awaited by default; GPU presenter handoff is explicit and experimental. '
                'The strongly imported locked Adreno snapshot captures one recovery epoch/target per request before the original builder; epoch changes latch refusal. '
                'a gated 200us timer keeps waiting through busy or unavailable queries without timeout retirement. CPU producer mode is explicit. '
                'Optional software refresh starts disabled and is stopped with the frontend, using a separate timer on the same original work loop. '
                'Sanitized peers exercise producer waits, retries, refresh ownership, drain/reentrancy and consecutive frames. '
                'Native guards consume packets generated by unchanged original userspace setters and fields from five unchanged original kernel blocks. '
                'Only default full-frame layer-0 packets are accepted. Full original lifecycle, a concrete Legacy subclass, general composition/color state '
                'and GPU fault quiescence remain unqualified; no default kernel/provider is enabled.'}
    (ROOT/'reports/ios16-display-frontend.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: native bounded iPhone display frontend, '+str(len(host['cases']))+' sanitized cases, original userland -> kernel-field -> native-guard CPU comparisons; provider unselected')


if __name__=='__main__':main()
