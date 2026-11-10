#!/usr/bin/env python3
"""Build a disabled-by-default software refresh source and real diagnostic counters."""
import json
from pathlib import Path
import re
import subprocess

import capstone
from check_software_refresh_host import check as check_host
from native_driver_build import ROOT, NATIVE, TREE, archive_imports, build_objects, inspect_object, require, sha


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    interface=json.loads((ROOT/'reports/ios16-refresh-interface.json').read_text())
    bridge=json.loads((ROOT/'reports/ios16-gpu-swap-bridge.json').read_text())
    pin=lock['iphone_display_refresh']
    require(interface['result']=='IOS16_ORIGINAL_REFRESH_SENDER_ARM64_CHECK_PASS' and
            interface['native_kernel_sha256']==bridge['native_kernel_sha256']==sha(NATIVE) and
            interface['original_kernelcache_sha256']==bridge['original_kernelcache_sha256'] and
            interface['contract_sha256']==pin['sha256']==sha(ROOT/pin['path']) and
            interface['header_sha256']==pin['header_sha256']==sha(ROOT/pin['header']) and
            interface['queue_header_sha256']==sha(ROOT/'profiles/os/ios-16.7.16-20H392/graphics/OriginalLegacySwapABI.h') and
            interface['notification_head_offset']==4992 and bridge['original_workloop_getter']['field']==5048,
            'Current exact iPhone refresh/list/work-loop checks required')
    binding=ROOT/'build/ios16-refresh-interface/original-refresh-binding.o'
    require(sha(ROOT/interface['archive'])==interface['archive_sha256'] and
            subprocess.check_output(['/usr/bin/llvm-ar-14','p',ROOT/interface['archive'],binding.name])==binding.read_bytes(),
            'Original refresh absolute binding changed')
    driver=ROOT/'drivers/DodgeDisplay';out=ROOT/'build/ios16-software-refresh'
    host=check_host(out)
    obj,=build_objects([driver/'DodgeSoftwareRefresh.cpp'],out,[ROOT/pin['header'].rsplit('/',1)[0]])
    objects=[obj,binding];imports=archive_imports(objects)
    require(not imports['required_board_or_original_imports'],'Software refresh has unresolved native imports: '+repr(imports))
    require({'_native_gop_vsync','_native_iphone_refresh_notify','_dodge_software_refresh_create',
             '_dodge_software_refresh_set_enabled','_dodge_software_refresh_status','_dodge_software_refresh_stop'}<=set(imports['defined']),
            'Actual timer/controller diagnostic entry points absent')
    require({'_mach_absolute_time','_mach_continuous_time','_nanoseconds_to_absolutetime'}<=set(imports['native_public_imports']),
            'Software refresh must use actual native clocks and conversion')
    decoder=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    data=obj.read_bytes();image=inspect_object(data);instruction_count=0
    for section in (s for segment in image['segments'] for s in segment['sections'] if s['name']=='__text'):
        code=data[section['fileoff']:section['fileoff']+section['size']];instructions=list(decoder.disasm(code,section['va']))
        require(len(instructions)*4==len(code),'Undecoded native software-refresh instruction')
        require(not any(re.search(r'\b(?:[vqdsh][0-9]+)(?:\.|\b)',i.op_str.lower()) for i in instructions),'FP/SIMD in software refresh')
        instruction_count+=len(instructions)
    archive=out/'libDodgeSoftwareRefresh.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','t',archive],text=True).splitlines()==[path.name for path in objects],
            'Unexpected software-refresh archive member list')
    for path in objects:
        require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,path.name])==path.read_bytes(),'Software-refresh archive readback differs')
    graphics=ROOT/'profiles/os/ios-16.7.16-20H392/graphics'
    sources=[driver/'DodgeSoftwareRefresh.cpp',driver/'DodgeSoftwareRefresh.h',graphics/'OriginalLegacyRefreshABI.h',
             graphics/'OriginalLegacySwapABI.h',ROOT/'tests/DodgeSoftwareRefreshTest.cpp',
             ROOT/'scripts/check_software_refresh_host.py',Path(__file__),*sorted((ROOT/'tests/gpu_swap_include').rglob('*.h'))]
    kernel_sources=[TREE/'.cache/xnu-work/iokit/Kernel'/name for name in ('IOEventSource.cpp','IOTimerEventSource.cpp','IOWorkLoop.cpp')]
    report={'result':'DARWIN22_SOFTWARE_REFRESH_SOURCE_CANDIDATE_PASS','target':'arm64-apple-ios16.0','native_kernel_sha256':sha(NATIVE),
            'original_kernelcache_sha256':interface['original_kernelcache_sha256'],'builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in sources},
            'actual_kernel_event_source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in kernel_sources},
            'refresh_interface_report_sha256':sha(ROOT/'reports/ios16-refresh-interface.json'),
            'workloop_audit_report_sha256':sha(ROOT/'reports/ios16-gpu-swap-bridge.json'),
            'objects':[{'path':str(path.relative_to(ROOT)),'sha256':sha(path)} for path in objects],
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'archive_member_readback':True,
            'imports':imports,'host_tests':host,'host_case_count':len(host['cases']),'host_binary_sha256':sha(out/'software-refresh-host'),
            'host_sanitizers':['address','undefined','leak'],'native_instruction_count':instruction_count,'native_fp_simd_absent':True,
            'overflow_instrumentation_retained':True,'software_rate_hz':60,'created_disabled':True,
            'diagnostic_fields':['configured_software_rate','original_sender_invocation_attempts','late_software_deadlines'],
            'counts_advance_only_after_actual_callback_or_deadline_observation':True,
            'original_notification_lifecycle_qualified':False,'kernel_timer_runtime_executed':False,
            'frontend_invoked':False,'default_kernel_selected':False,'hardware_vblank_generated':False,'hardware_tested':False,
            'scope':'Actual IOTimerEventSource/work-loop controller, fixed audited 60Hz nominal cadence and original sender absolute binding. '
                    'Sanitized tests use explicit scheduler/IOKit/sender peers; the separate ARM64 test executes the unchanged sender. '
                    'Diagnostic counters describe software attempts and deadlines, never acknowledged delivery or panel vblank. '
                    'The frontend, original registration lifecycle and runtime timers remain unqualified and unselected.'}
    (ROOT/'reports/ios16-software-refresh.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"PASS: actual Darwin22 software refresh and diagnostics; {len(host['cases'])} sanitized cases; created disabled, no hardware vblank")


if __name__=='__main__':main()
