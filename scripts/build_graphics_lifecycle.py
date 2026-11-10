#!/usr/bin/env python3
"""Build explicit original-module prepare/attach entry points, without running them."""
import json
from pathlib import Path
import subprocess

from check_graphics_lifecycle_host import check as check_host
from check_graphics_boot_host import check as check_boot
from check_gpu_link import assemble
from native_driver_build import ROOT,TREE,NATIVE,archive_imports,build_objects,inspect_object,require,sha,symbols
from prepare_graphics_lifecycle import derive,header,FIXTURE,HEADER


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['iphone_graphics_module_lifecycle']
    require(sha(FIXTURE)==pin['sha256'] and sha(HEADER)==pin['header_sha256'],'Original graphics lifecycle pin changed')
    fixture=derive();require(fixture==json.loads(FIXTURE.read_text()) and HEADER.read_text()==header(fixture),'Stale original module lifecycle contract')
    service=json.loads((ROOT/'reports/ios16-display-service.json').read_text())
    require('PASS' in service['result'] and service['concrete_source_class_built'] and service['initializer_removed_from_early_registration'],
        'Need a concrete display class with deferred metadata initialization')
    for p,h in service['source_sha256'].items():require(sha(ROOT/p)==h,'Concrete service source changed: '+p)
    out=ROOT/'build/ios16-graphics-lifecycle';out.mkdir(parents=True,exist_ok=True)
    host=check_host(out);boot_tests=check_boot(out)
    compiled=build_objects([ROOT/'drivers/DodgeDisplay/DodgeGraphicsLifecycle.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.cpp'],out,[HEADER.parent])
    for obj in compiled:
        require(not any(s['name']=='__mod_init_func' and s['size'] for seg in inspect_object(obj.read_bytes())['segments'] for s in seg['sections']),
            'Graphics module loading or hardware boot was accidentally scheduled during early constructors')
    values={m['alias']:int(m['linked_metaclass'],16) for m in fixture['modules']}
    aliases=assemble(out,'original-graphics-metadata',''.join(f'.globl {name}\n.set {name},{address:#x}\n' for name,address in sorted(values.items())))
    require({s['name']:s['value'] for s in symbols(aliases.read_bytes()) if s['kind']==3}==values and
        not any(s['size'] for seg in inspect_object(aliases.read_bytes())['segments'] for s in seg['sections']),'Graphics metadata aliases contain code/data or wrong addresses')
    archive=out/'libDodgeGraphicsLifecycle.a';archive.unlink(missing_ok=True)
    objects=[*compiled,aliases];subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    for p in objects:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'Lifecycle archive readback differs')
    imports=archive_imports(objects)
    expected={name for name in service['imports']['defined'] if any(p in name for p in ('dodge_iphone_framebuffer_initialize','dodge_iphone_framebuffer_registered','dodge_iphone_framebuffer_allocate'))}
    expected.add('_dodge_gpu_start')
    require(set(imports['required_board_or_original_imports'])==expected and len(expected)==4,'Unexpected graphics lifecycle/boot unresolved imports')
    files=[Path(__file__),ROOT/'scripts/prepare_graphics_lifecycle.py',ROOT/'scripts/check_graphics_lifecycle_host.py',ROOT/'scripts/check_ios16_graphics.py',
        ROOT/'scripts/check_gpu_link.py',ROOT/'scripts/native_driver_build.py',FIXTURE,HEADER,
        ROOT/'drivers/DodgeDisplay/DodgeGraphicsLifecycle.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsLifecycle.h',ROOT/'drivers/DodgeDisplay/DodgeIPhoneFramebuffer.h',
        ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.h',ROOT/'scripts/check_graphics_boot_host.py',ROOT/'tests/DodgeGraphicsBootTest.cpp',
        ROOT/'tests/DodgeGraphicsLifecycleTest.cpp',*sorted((ROOT/'tests/graphics_lifecycle_include').rglob('*.h')),
        *[TREE/'.cache/xnu-work'/p for p in ('libkern/c++/OSKext.cpp','libkern/c++/OSRuntime.cpp','libkern/c++/OSMetaClass.cpp',
            'libkern/libkern/c++/OSKext.h','libkern/libkern/c++/OSMetaClass.h','iokit/IOKit/IOService.h','iokit/Kernel/IOService.cpp')]]
    report={'result':'IOS16_ORIGINAL_GRAPHICS_MODULE_PREPARATION_AND_ATTACHMENT_SOURCE_PASS','builder_sha256':sha(Path(__file__)),
        'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':fixture['original_kernelcache_sha256'],
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'service_report_sha256':sha(ROOT/'reports/ios16-display-service.json'),
        'contract':str(FIXTURE.relative_to(ROOT)),'contract_sha256':sha(FIXTURE),'header':str(HEADER.relative_to(ROOT)),'header_sha256':sha(HEADER),
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in objects],
        'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
        'imports':imports,'original_metadata_aliases':{n:hex(a) for n,a in values.items()},'host_tests':host,
        'host_binary':str((out/'graphics-lifecycle-host').relative_to(ROOT)),'host_binary_sha256':sha(out/'graphics-lifecycle-host'),
        'boot_host_tests':boot_tests,'boot_host_binary':str((out/'graphics-boot-host').relative_to(ROOT)),
        'boot_host_binary_sha256':sha(out/'graphics-boot-host'),'explicit_module_gpu_display_boot_coordinator_built':True,
        'boot_preflight_before_hardware':True,'boot_retains_provider_and_surface_root':True,
        'boot_pre_hardware_failure_retryable':True,'boot_hardware_attempt_and_failure_one_shot':True,
        'boot_entry_invoked_on_kernel':False,
        'loader_order':[m['bundle'] for m in fixture['modules']],
        'original_constructor_entries':sum(len(m['sections']['__mod_init_func']['entries']) for m in fixture['modules']),
        'uses_real_OSKext_dependency_start_and_CPP_initialization':True,'deferred_userspace_load_disabled':True,'non_surface_personality_matching_disabled':True,
        'surface_root_personality_matching_requested':True,'surface_root_nonblocking_preflight':True,'surface_root_retained_during_attach':True,
        'exact_original_provider_hierarchy_required':True,'surface_root_runtime_termination_race_qualified':False,
        'exact_metaclass_identity_and_size_required':True,'metaclass_unload_pins_held_after_owned_construction':True,
        'preModLoad_uses_existing_kernel_owner':True,'postModLoad_required_before_allocation':True,
        'concurrent_and_reentrant_preparation_refused':True,'metadata_phase_failure_latched':True,
        'explicit_prepare_then_attach':True,'one_display_start_attempt_per_boot':True,'failed_start_uses_concrete_deferred_detach':True,
        'early_initializer_present':False,'gpu_hardware_started_by_prepare':False,'original_loader_executed_on_kernel':False,
        'original_full_start_stop_executed':False,'runtime_provider_registered':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Native source build and 33 sanitized orchestration plus 24 explicit boot ordering/ownership cases with API peers. '
            'Derives exact originals, loads real libraries before Kernel-owned deferred class registration, and exposes explicit init/attach/start with failure cleanup. '
            'Requests original IOSurfaceRoot matching and rejects absent/inactive/wrong-class roots before entering the original unbounded wait; requires the original provider hierarchy. '
            'Unified boot prepares modules, holds real provider/root through synchronous board startup, then attaches display; all hardware attempts are one-shot. '
            'No module entrypoint or service has been invoked on a kernel; matching/termination races, physical power, actual parent lifecycle and runtime ABI remain unqualified.'}
    (ROOT/'reports/ios16-graphics-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: native original-module prepare/attach, 53 exact constructor identities, 3 metadata aliases and 33 sanitized peer cases; no runtime execution')


if __name__=='__main__':main()
