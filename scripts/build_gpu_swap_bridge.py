#!/usr/bin/env python3
"""Build the real Darwin22 GPU completion bridge without installing a queue hook."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct

import capstone
from check_gpu_swap_bridge_host import check as check_host
from check_ios16_swap import original_input
from native_driver_build import ROOT, NATIVE, archive_imports, build_objects, exports, inspect_object, macho, pinned_sources, require, sha, symbols
from native_prelink import backed_offset


def main():
    references=pinned_sources(('pagani_reference',))
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    graphics=ROOT/'profiles/os/ios-16.7.16-20H392/graphics'
    driver=ROOT/'drivers/DodgeDisplay'
    completion=json.loads((ROOT/'reports/ios16-swap-completion.json').read_text())
    queue=json.loads((ROOT/'reports/ios16-display-swap.json').read_text())
    producer=json.loads((ROOT/'reports/ios16-producer.json').read_text())
    for name,report in (('iphone_display_completion',completion),('iphone_display_swap',queue),('iphone_display_producer',producer)):
        pin=lock[name]
        require('PASS' in report['result'] and sha(ROOT/pin['path'])==pin['sha256']==report['contract_sha256'] and
                sha(ROOT/pin['header'])==pin['header_sha256']==report['header_sha256'],
                'Current exact iPhone queue/completion ABI checks required: '+name)
    require(completion['native_kernel_sha256']==sha(NATIVE) and
            completion['original_kernelcache_sha256']==queue['original_kernelcache_sha256'] and
            completion['queue_header_sha256']==queue['header_sha256'] and queue['read_only_eligibility_cases']==13,
            'Completion and queue checks used different kernel/header inputs')
    require(producer['native_kernel_sha256']==sha(NATIVE) and producer['original_kernelcache_sha256']==queue['original_kernelcache_sha256'] and
            producer['queue_header_sha256']==queue['header_sha256'],'Producer guards used different native/original queue inputs')
    binding=ROOT/'build/ios16-swap-completion/original-completion-binding.o'
    require(sha(ROOT/completion['archive'])==completion['archive_sha256'] and
            subprocess.check_output(['/usr/bin/llvm-ar-14','p',ROOT/completion['archive'],binding.name])==binding.read_bytes(),
            'Original completion absolute alias changed')
    require({symbol['name']:symbol['value'] for symbol in symbols(binding.read_bytes()) if symbol['kind']==3}==
            {'_native_iphone_complete_current':int(completion['binding_address'],16)},'Wrong original completion address')
    out=ROOT/'build/ios16-gpu-swap-bridge'
    host=check_host(out)
    reference=references['pagani_reference']/'drivers/NativeMobileDisplay/NativeLegacyRequest.h'
    obj,=build_objects([driver/'DodgeGpuSwapBridge.cpp'],out,[graphics,reference.parent])
    decoder=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    data=obj.read_bytes();image=inspect_object(data);instruction_count=0
    for section in (s for segment in image['segments'] for s in segment['sections'] if s['name']=='__text'):
        code=data[section['fileoff']:section['fileoff']+section['size']]
        instructions=list(decoder.disasm(code,section['va']))
        require(len(instructions)*4==len(code),'Undecoded native swap bridge instruction')
        require(not any(re.search(r'\b(?:[vqdsh][0-9]+)(?:\.|\b)',i.op_str.lower()) for i in instructions),
                'FP/SIMD in native swap bridge')
        instruction_count+=len(instructions)
    # The host peer records this call. Independently inspect the *actual*
    # native-kernel implementation used by the production ARM64 object.
    native=NATIVE.read_bytes();native_image=macho(native)
    names={name:address for address,group in exports(native,native_image).items() for name in group}
    classes,original,original_image,read=original_input()
    original_names={name:address for address,group in exports(original,original_image).items() for name in group}
    getter_name='__ZNK9IOService11getWorkLoopEv'
    require(struct.unpack('<Q',read(original_names['__ZTV9IOService']+16+111*8,8))[0]==original_names[getter_name] and
            struct.unpack_from('<Q',native,backed_offset(native_image['segments'],names['__ZTV9IOService']+16+111*8,8,len(native)))[0]==names[getter_name],
            'Original/native IOService work-loop getter slot differs')
    vptr=int(classes['classes']['IOMobileFramebufferLegacy']['vptr'],16)
    getter,=struct.unpack('<Q',read(vptr+111*8,8));getter_bytes=read(getter,24)
    require(getter==0xfffffff005c122bc and struct.unpack('<6I',getter_bytes)==
            (0xd10043ff,0xf90007e0,0xf94007e8,0xf949dd00,0x910043ff,0xd65f03c0),
            'Original Legacy getter no longer returns its +5048 work loop')
    barrier=names['_OSSynchronizeIO'];at=backed_offset(native_image['segments'],barrier,8,len(native))
    barrier_bytes=native[at:at+8]
    require([(i.mnemonic,i.op_str) for i in decoder.disasm(barrier_bytes,barrier)]==[('dsb','sy'),('ret','')],
            'Actual native I/O store completion barrier differs')
    objects=[obj,binding];imports=archive_imports(objects)
    require('_OSSynchronizeIO' in imports['native_public_imports'],'Actual bridge does not import the verified I/O barrier')
    expected={'_boot_progress_display_copy','_boot_progress_display_failed','_boot_progress_display_handoff',
              '_boot_progress_peripheral_frame','_native_gop_gpu_offer','_native_legacy_overlay_rows'}
    require(set(imports['required_board_or_original_imports'])==expected,'Unexpected swap bridge imports: '+repr(imports))
    require({'_native_legacy_gpu_complete','_native_iphone_complete_current'}<=set(imports['defined']),
            'Actual GPU completion bridge or exact original alias absent')
    archive=out/'libDodgeGpuSwapBridge.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','t',archive],text=True).splitlines()==[path.name for path in objects],
            'Unexpected swap bridge archive members')
    for path in objects:
        require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,path.name])==path.read_bytes(),
                'Swap bridge archive readback differs')
    sources=[driver/'DodgeGpuSwapBridge.cpp',driver/'DodgeGpuSwapBridge.h',driver/'DodgeDisplayTransfer.h',driver/'DodgeSurfaceBacking.h',driver/'DodgeSurfaceLayout.h',
             graphics/'OriginalLegacySwapABI.h',graphics/'OriginalLegacySwapCompletionABI.h',graphics/'OriginalLegacyProducerABI.h',reference,
             ROOT/'tests/DodgeGpuSwapBridgeTest.cpp',ROOT/'scripts/check_gpu_swap_bridge_host.py',Path(__file__),
             *sorted((ROOT/'tests/gpu_swap_include').rglob('*.h'))]
    report={'result':'DARWIN22_GPU_SWAP_BRIDGE_SOURCE_CANDIDATE_PASS','target':'arm64-apple-ios16.0',
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':completion['original_kernelcache_sha256'],
            'builder_sha256':sha(Path(__file__)),'source_revision':lock['pagani_reference']['revision'],
            'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in sources},
            'queue_report_sha256':sha(ROOT/'reports/ios16-display-swap.json'),
            'completion_report_sha256':sha(ROOT/'reports/ios16-swap-completion.json'),
            'producer_report_sha256':sha(ROOT/'reports/ios16-producer.json'),
            'completion_binding_archive_sha256':completion['archive_sha256'],
            'objects':[{'path':str(path.relative_to(ROOT)),'sha256':sha(path)} for path in objects],
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'archive_member_readback':True,'imports':imports,
            'host_tests':host,'host_case_count':len(host['cases']),'host_binary_sha256':sha(out/'swap-bridge-host'),
            'host_sanitizers':['address','undefined','leak'],'native_instruction_count':instruction_count,'native_fp_simd_absent':True,
            'native_io_barrier':{'address':hex(barrier),'instructions':['dsb sy','ret'],'sha256':hashlib.sha256(barrier_bytes).hexdigest()},
            'original_workloop_getter':{'slot':111,'address':hex(getter),'field':5048,'sha256':hashlib.sha256(getter_bytes).hexdigest()},
            'overflow_instrumentation_retained':True,'uses_workloop_runAction':True,
            'request_and_memory_references_held_until_observer_returns':True,'cpu_fallback_uses_actual_pixel_stores':True,
            'original_producer_ready_words_rechecked':True,
            'default_transfer_cpu_copy':True,'cpu_copy_requires_no_presenter':True,'experimental_presenter_requires_quiescence_contract':True,
            'original_completion_body_executed':False,'original_iokit_objects_executed':False,
            'request_reservation_frontend_installed':False,'producer_fence_qualified':False,
            'gpu_failure_quiescence_qualified':False,'default_kernel_selected':False,'hardware_tested':False,
            'scope':'Actual bridge and bounded scalar pixel copy compiled against Darwin22, with the exact original iPhone completion alias. '
                    'The default mode copies completed producer pixels on the CPU and never offers to a presenter. GPU presenter handoff is explicit '
                    'and still requires the caller to ensure failed/abandoned GPU work is quiescent before callback. '
                    'Sanitized tests execute actual bridge/copy code with software IOKit, presenter and completion peers. '
                    'No original queue hook, original retirement, producer fence, GPU failure quiescence, hardware latch or vblank is qualified.'}
    (ROOT/'reports/ios16-gpu-swap-bridge.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"PASS: actual Darwin22 GPU swap bridge, exact iPhone completion alias and {len(host['cases'])} sanitized peer cases; no queue hook installed")


if __name__=='__main__':
    main()
