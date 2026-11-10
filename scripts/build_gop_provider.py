#!/usr/bin/env python3
"""Build the real-class GOP nub publisher and late graphics entry, offline."""
import json
from pathlib import Path
import subprocess

from check_gop_provider_host import check as check_host
from check_gpu_link import assemble
from native_driver_build import ROOT,TREE,NATIVE,archive_imports,build_objects,inspect_object,require,sha,symbols
from prepare_gop_provider import FIXTURE,HEADER,derive,header


def main():
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_gop_provider']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'],'Reviewed original GOP provider contract changed')
    fixture=derive()
    require(fixture==json.loads(FIXTURE.read_text()) and HEADER.read_text()==header(fixture),'Stale original GOP provider contract/header')
    lifecycle=json.loads((ROOT/'reports/ios16-graphics-lifecycle.json').read_text())
    require('PASS' in lifecycle['result'] and lifecycle['native_kernel_sha256']==sha(NATIVE) and
            lifecycle['explicit_module_gpu_display_boot_coordinator_built'],'Need current real graphics module/boot entry')
    for p,h in lifecycle['source_sha256'].items():require(sha(ROOT/p)==h,'Stale graphics preparation dependency: '+p)
    out=ROOT/'build/ios16-gop-provider';out.mkdir(parents=True,exist_ok=True)
    host=check_host(out)
    compiled=build_objects([ROOT/'drivers/DodgeDisplay/DodgeGopProvider.cpp'],out,[HEADER.parent])
    require(all(not s['size'] for p in compiled for seg in inspect_object(p.read_bytes())['segments'] for s in seg['sections']
                if s['name']=='__mod_init_func'),'Provider or hardware creation entered early constructors')
    aliases={fixture['alias']:int(fixture['linked_metaclass'],16)}
    absolute=assemble(out,'original-gop-provider-metadata',''.join(f'.globl {n}\n.set {n},{a:#x}\n' for n,a in aliases.items()))
    require({s['name']:s['value'] for s in symbols(absolute.read_bytes()) if s['kind']==3}==aliases and
            all(not s['size'] for seg in inspect_object(absolute.read_bytes())['segments'] for s in seg['sections']),
            'Provider alias contains implementation bytes or a substituted identity')
    objects=[*compiled,absolute];archive=out/'libDodgeGopProvider.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    for p in objects:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'GOP archive member differs')
    imports=archive_imports(objects)
    require(set(imports['required_board_or_original_imports'])=={'_dodge_graphics_prepare','_dodge_graphics_status','_dodge_graphics_boot'},
            'Unexpected GOP provider dependency')
    files=[Path(__file__),ROOT/'scripts/prepare_gop_provider.py',ROOT/'scripts/check_gop_provider_host.py',ROOT/'scripts/check_gpu_link.py',
           ROOT/'scripts/native_driver_build.py',FIXTURE,HEADER,ROOT/'drivers/DodgeDisplay/DodgeGopProvider.cpp',
           ROOT/'drivers/DodgeDisplay/DodgeGopProvider.h',ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.h',
           ROOT/'drivers/DodgeDisplay/DodgeGraphicsLifecycle.h',ROOT/'tests/DodgeGopProviderTest.cpp',
           *sorted((ROOT/'tests/gop_provider_include').rglob('*.h')),
           *[TREE/'.cache/xnu-work'/p for p in ('iokit/Kernel/IOService.cpp','iokit/IOKit/IOService.h','iokit/IOKit/IODeviceMemory.h',
               'libkern/c++/OSObject.cpp','libkern/c++/OSMetaClass.cpp','libkern/libkern/c++/OSMetaClass.h')]]
    report={'result':'IOS16_REAL_CLASS_GOP_PROVIDER_SOURCE_AND_OWNERSHIP_PASS','builder_sha256':sha(Path(__file__)),
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':fixture['original_kernelcache_sha256'],
            'graphics_lifecycle_report_sha256':sha(ROOT/'reports/ios16-graphics-lifecycle.json'),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'contract':str(FIXTURE.relative_to(ROOT)),
            'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
            'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in objects],
            'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
            'imports':imports,'original_metadata_aliases':{n:hex(a) for n,a in aliases.items()},'host_tests':host,
            'host_binary':str((out/'gop-provider-host').relative_to(ROOT)),'host_binary_sha256':sha(out/'gop-provider-host'),
            'real_original_metaclass_allocator_used':True,'original_instance_bytes':216,'inherited_public_init_used':True,
            'private_apple_fields_written':False,'apple_bus_initializer_called':False,'fake_meta_cast_implementation':False,
            'actual_current_dt_platform_required':True,'pe_console_memory_descriptor_required':True,'device_memory_property_read_back':True,
            'original_get_resources_fast_path_required':True,'mode_and_resources_rechecked_after_publication':True,
            'one_nub_published_per_boot':True,'published_nub_and_original_metadata_pinned':True,'unpublished_failures_unwound_and_retryable':True,
            'explicit_late_provider_to_gpu_display_entry_built':True,'early_initializer_present':False,
            'native_entry_invoked':False,'runtime_provider_registered':False,'apple_bus_or_clock_functions_qualified':False,
            'runtime_qualified':False,'default_kernel_selected':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual ARM64 factory allocates the exact original AppleARMIODevice, invokes inherited public IOService init, '
                    'installs a real PE-console physical-memory descriptor with readback, attaches the current IODTPlatformExpert and requests publication. '
                    'An explicit late entry connects preparation, provider publication and the existing GPU/display coordinator. '
                    'Sanitized source tests use explicit IOKit, PE, allocation and boot peers; original allocation and actual publication are not executed here. '
                    'No Apple bus initializer, private fields, fake class hierarchy or automatic startup; runtime matching, memory mapping and hardware remain unqualified.'}
    (ROOT/'reports/ios16-gop-provider.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: real-class GOP provider and late graphics entry built; exact metadata alias and '+str(host['case_count'])+' sanitized ownership cases')


if __name__=='__main__':main()
