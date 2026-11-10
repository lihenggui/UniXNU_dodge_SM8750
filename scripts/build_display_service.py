#!/usr/bin/env python3
"""Build the experimental concrete iPhone GOP class without installing a provider."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tomllib

from check_display_service_host import check as check_host,check_integration
from check_ios16_swap import original_input
from native_driver_build import ROOT,TREE,NATIVE,archive_imports,build_objects,inspect_object,macho,require,sha,symbols
from native_prelink import backed_offset,exports

DRIVER=ROOT/'drivers/DodgeDisplay'
ABI=ROOT/'profiles/os/ios-16.7.16-20H392/graphics'
INIT='__GLOBAL__sub_I_DodgeIPhoneFramebuffer.cpp'
CLASS='22DodgeIPhoneFramebuffer'
DEPENDENCIES=('ios16-display-interface','ios16-display-subclass','ios16-display-lifecycle','ios16-display-frontend','gpu-link-probe')


def run(command,log):
    result=subprocess.run(command,capture_output=True,text=True,timeout=120)
    log.write_text(result.stdout+result.stderr)
    require(result.returncode==0,'Display service command failed; see '+str(log))


def main():
    out=ROOT/'build/ios16-display-service';out.mkdir(parents=True,exist_ok=True)
    reports={name:json.loads((ROOT/'reports'/f'{name}.json').read_text()) for name in DEPENDENCIES}
    require(all('PASS' in report['result'] for report in reports.values()),'A display service dependency failed')
    interface=reports['ios16-display-interface'];contract=json.loads((ROOT/interface['contract']).read_text())
    require(sha(ABI/'OriginalLegacyFramebufferABI.h')==interface['header_sha256'],'Concrete class uses a stale exact Legacy header')
    subclass=reports['ios16-display-subclass']
    bank=ROOT/subclass['binding_object']
    require(sha(bank)==subclass['binding_object_sha256'] and subclass['original_binding_count']==171,'Reviewed inherited bindings changed')
    host=check_host(out)
    integration=check_integration(out)
    core,obj=build_objects([DRIVER/'DodgeDisplayService.cpp',DRIVER/'DodgeIPhoneFramebuffer.cpp'],out,[ABI],['-Wno-overloaded-virtual'])
    original=obj.read_bytes();late=out/'DodgeIPhoneFramebuffer.late.o'
    objcopy=ROOT/'.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    run([str(objcopy),'--remove-section=__DATA,__mod_init_func','--globalize-symbol='+INIT,str(obj),str(late)],out/'defer-initializer.log')
    transformed=late.read_bytes();before=inspect_object(original);after=inspect_object(transformed)
    def section(data,image,name):
        s,=[s for seg in image['segments'] for s in seg['sections'] if s['name']==name]
        return data[s['fileoff']:s['fileoff']+s['size']]
    require(section(original,before,'__text')==section(transformed,after,'__text'),'Deferral changed concrete class instructions')
    require(not any(s['name']=='__mod_init_func' for seg in after['segments'] for s in seg['sections']),
            'Original-parent class remains scheduled during early source startup')
    late_names=symbols(transformed)
    require(any(s['name']==INIT and s['kind']&1 and s['kind']&14 for s in late_names),'Actual deferred class initializer is not callable')
    slide=int(tomllib.loads((ABI.parent/'profile.toml').read_text())['kernel']['prelink']['slide'],0)
    classes,original_raw,original_image,read=original_input()
    require(classes['original_kernelcache_sha256']==contract['original_kernelcache_sha256'],'Concrete class and originals use different kernels')
    parent_vptr=int(classes['classes']['IOMobileFramebufferService']['vptr'],16)
    original_exports={name:address for address,names in exports(original_raw,original_image).items() for name in names}
    require(struct.unpack('<Q',read(parent_vptr+86*8,8))[0]==original_exports['__ZN9IOService5startEPS_'] and
            struct.unpack('<Q',read(parent_vptr+87*8,8))[0]==original_exports['__ZN9IOService4stopEPS_'],
            'Partial-start cleanup requires the verified direct IOService parent lifecycle')
    legacy_vptr=int(contract['legacy_vptr'],16)
    original_table=struct.unpack('<338Q',read(legacy_vptr,338*8))
    inherited={s['name']:s['value'] for s in symbols(bank.read_bytes()) if s['kind']==3}
    # -fapple-kext qualified base calls load that base's actual vtable. This is
    # the table symbol, including its two-word header, not an invented method.
    table_alias={'__ZTV25IOMobileFramebufferLegacy':legacy_vptr-16+slide}
    def assemble(name,values):
        source=out/(name+'.S');source.write_text(''.join(f'.globl {key}\n.set {key},{value:#x}\n' for key,value in sorted(values.items())))
        output=source.with_suffix('.o')
        run([str(ROOT/'.toolchains/xnu-linux/llvm/bin/clang'),'-target','arm64-apple-ios16.0','-c',str(source),'-o',str(output)],source.with_suffix('.log'))
        raw=output.read_bytes();image=inspect_object(raw)
        require({s['name']:s['value'] for s in symbols(raw) if s['kind']==3}==values and
                not any(s['size'] for seg in image['segments'] for s in seg['sections']),'Absolute aliases have code/data or wrong targets')
        return output
    table_object=assemble('original-legacy-vtable-binding',table_alias)
    bank_copy=out/'original-legacy-bindings.o';shutil.copyfile(bank,bank_copy)
    objects=[core,late,bank_copy,table_object]
    archive=out/'libDodgeIPhoneFramebuffer.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    for path in objects:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,path.name])==path.read_bytes(),'Concrete class archive readback differs')
    gpu=ROOT/reports['gpu-link-probe']['isolated_kernel'];require(sha(gpu)==reports['gpu-link-probe']['isolated_kernel_sha256'],'GPU integration kernel changed')
    native=gpu.read_bytes();native_image=macho(native)
    public={name:address for address,names in exports(native,native_image).items() for name in names}
    available={}
    for s in symbols(native):
        if not s['kind']&0xe0 and s['kind']&14:available.setdefault(s['name'],set()).add(s['value'])
    defined={s['name'] for path in objects for s in symbols(path.read_bytes()) if not s['kind']&0xe0 and s['kind']&14}
    undefined={s['name'] for path in objects for s in symbols(path.read_bytes()) if s['kind']==1}-defined
    native_aliases={}
    for name in sorted(undefined):
        require(name in public or len(available.get(name,()))==1,'Unresolved concrete service dependency: '+name)
        native_aliases[name]=public[name] if name in public else next(iter(available[name]))
    native_object=assemble('fixture-native-bindings',native_aliases)
    linked=out/'display-service.macho'
    command=[str(ROOT/'.toolchains/xnu-linux/CommandLineTools/usr/bin/ld'),'-arch','arm64','-static','-platform_version','ios','16.0','16.0',
             '-e','__Z33dodge_iphone_framebuffer_initializev','-no_uuid','-pagezero_size','0','-image_base','0xfffffff005000000',
             *map(str,objects),str(native_object),'-o',str(linked)]
    # Use the actual compiler-emitted spelling; the C++ API intentionally does
    # not share a fabricated C entry point with any original component.
    initialize=[s['name'] for s in late_names if s['kind']&14 and 'dodge_iphone_framebuffer_initialize' in s['name']]
    require(len(initialize)==1,'Owned class initializer API is missing');command[command.index('-e')+1]=initialize[0]
    run(command,out/'link.log');(out/'link-command.json').write_text(json.dumps(command,indent=2)+'\n')
    raw=linked.read_bytes();image=macho(raw);linked_names={s['name']:s for s in symbols(raw) if not s['kind']&0xe0}
    require(not any(s['kind']==1 for s in linked_names.values()),'Strict display fixture has undefined symbols')
    aliases={**inherited,**table_alias,**native_aliases}
    require(all(linked_names[name]['kind']==3 and linked_names[name]['value']==address for name,address in aliases.items()),'A native/original alias was lost')
    own_vtable=next(s for s in late_names if s['name']=='__ZTV'+CLASS)
    const=next(s for seg in after['segments'] for s in seg['sections'] if s['name']=='__const')
    roff,count=struct.unpack_from('<2I',transformed,const['command_offset']+56)
    slots={};own=[];native_slots=[];original_slots=[]
    offset=own_vtable['value']-const['va']+16
    for index in range(count):
        address,bits=struct.unpack_from('<2I',transformed,roff+index*8)
        if not offset<=address<offset+338*8:continue
        require(bits>>24==0x0e and (address-offset)%8==0,'Owned vtable pointer relocation differs')
        slot=(address-offset)//8;symbol=late_names[bits&0xffffff];name=symbol['name'];require(slot not in slots,'Duplicate owned vtable slot')
        slots[slot]=name
        if 'DodgeIPhoneFramebuffer' in name:
            require(symbol['kind']&14==14,'Owned override lacks implementation');own.append(slot)
        elif 'IOMobileFramebufferLegacy' in name:
            require(inherited.get(name)==original_table[slot]+slide,'Inherited original slot differs: '+str(slot));original_slots.append(slot)
        else:
            native_vptr=public['__ZTV9IOService']+16
            require(slot<168 and native_aliases[name]==struct.unpack_from('<Q',native,backed_offset(native_image['segments'],native_vptr+slot*8,8,len(native)))[0],
                    'Inherited native IOService slot differs: '+str(slot));native_slots.append(slot)
    require(set(slots)==set(range(338)) and set(contract['abstract_slots'])<=set(own),'Concrete vtable is incomplete or abstract')
    pointer=linked_names['__ZTV'+CLASS]['value']+16
    at=backed_offset(image['segments'],pointer,338*8,len(raw));expected=[linked_names[slots[i]]['value'] for i in range(338)]
    require(list(struct.unpack_from('<338Q',raw,at))==expected,'Concrete class vtable readback differs')
    corrupt=bytearray(raw);corrupt[at+243*8]^=1
    require(list(struct.unpack_from('<338Q',corrupt,at))!=expected,'Corrupted concrete backend slot was accepted')
    from ios16_service_emulation import emulate
    cpu=emulate(linked,read,slide,native,native_image,native_aliases,table_alias)
    inputs=[Path(__file__),ROOT/'scripts/ios16_service_emulation.py',ROOT/'scripts/ios16_parent_stop_emulation.py',ROOT/'scripts/check_display_service_host.py',ROOT/'scripts/native_driver_build.py',
            *[TREE/'.cache/xnu-work'/p for p in ('libkern/c++/OSMetaClass.cpp','libkern/c++/OSObject.cpp','libkern/libkern/c++/OSMetaClass.h','iokit/Kernel/IOService.cpp')],
            ROOT/'tests/DodgeDisplayServiceTest.cpp',ROOT/'tests/DodgeDisplayFrontendTest.cpp',ROOT/'tests/DodgeDisplayServiceIntegrationCases.h',
            *[DRIVER/name for name in ('DodgeDisplayService.cpp','DodgeDisplayService.h','DodgeIPhoneFramebuffer.cpp','DodgeIPhoneFramebuffer.h',
                'DodgeDisplayFrontend.cpp','DodgeDisplayFrontend.h','DodgeGpuSwapBridge.cpp','DodgeGpuSwapBridge.h','DodgeSoftwareRefresh.cpp','DodgeSoftwareRefresh.h')],
            *[ABI/name for name in ('OriginalLegacyFramebufferABI.h','OriginalLegacyLifecycleABI.h','OriginalLegacySwapABI.h')],
            *sorted((ROOT/'tests/gpu_swap_include').rglob('*.h'))]
    report={'result':'IOS16_CONCRETE_GOP_DISPLAY_SOURCE_AND_GATED_LIFECYCLE_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in inputs},
            'dependency_report_sha256':{name:sha(ROOT/'reports'/f'{name}.json') for name in DEPENDENCIES},
            'native_kernel_sha256':sha(NATIVE),'gpu_kernel_sha256':sha(gpu),'original_kernelcache_sha256':contract['original_kernelcache_sha256'],
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
            'objects':[{'path':str(path.relative_to(ROOT)),'sha256':sha(path)} for path in objects],
            'imports':archive_imports(objects),'native_binding_count':len(native_aliases),'original_binding_count':len(inherited)+1,
            'original_vtable_alias':{name:hex(address) for name,address in table_alias.items()},
            'linked_fixture':str(linked.relative_to(ROOT)),'linked_fixture_sha256':sha(linked),'strict_no_undefined':True,
            'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
            'link_manifest':str((out/'link-command.json').relative_to(ROOT)),'link_manifest_sha256':sha(out/'link-command.json'),
            'host_tests':host,'host_case_count':len(host['cases']),'host_binary_sha256':sha(out/'display-service-host'),
            'host_sanitizers':['address','undefined','leak'],'arm64_tests':cpu,
            'integration_tests':integration,'integration_case_count':len(integration['cases']),
            'integration_binary_sha256':sha(out/'display-service-integration-host'),
            'native_vtable_entries':338,'strict_link_pointer_readbacks':338,'own_override_slots':sorted(own),
            'original_inherited_slots':len(original_slots),'native_inherited_slots':len(native_slots),
            'all_abstract_slots_have_source_entries':True,'slot243_source_call_prototype_qualified':False,
            'slot243_raw_leaf_register_equivalence':True,'vtable_corruption_control':'REJECTED',
            'initializer':INIT,'initializer_removed_from_early_registration':True,'initializer_staging_preserves_instructions':True,
            'initializer_requires_original_parent_registration':True,'initializer_requires_serialized_loader_context':True,
            'allocation_requires_owned_metaclass_postModLoad_registration':True,
            'concrete_instance_bytes':5768,'client_creation_uses_gated_admission':True,
            'detach_deferred_until_drain_and_parent_stop_return':True,'detached_original_loop_survives_in_controller':True,
            'partial_parent_failure_cleanup_after_start_return_and_drain':True,'original_partial_parent_stop_cpu_cases':11,
            'original_qualified_parent_start_and_stop_are_native_ioservice':True,
            'parent_registration_checks_executed_on_kernel':False,'original_parent_full_start_stop_executed':False,
            'concrete_source_class_built':True,'runtime_provider_registered':False,'physical_power_implemented':False,
            'default_kernel_selected':False,'gpu_candidate_includes_service':False,'hardware_tested':False,
            'scope':'Concrete source subclass plus GOP/mode/frontend and deferred stop coordination. CPU glue checks use explicit parent/core/IOKit peers; '
                    '60 host coordinator cases use an explicit frontend peer; ten additional cases run the actual coordinator/frontend/bridge/refresh together. '
                    'Original request allocation/builder/completion, backing and IOKit remain peers in those integration cases. '
                    'Strict fixture binds imports to the real GPU kernel and original iPhone component addresses, without implementation stubs. '
                    'No provider or metadata has been registered in a kernel; no full original start/stop, power or graphics runtime qualification.'}
    (ROOT/'reports/ios16-display-service.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: concrete iPhone GOP class, 338 vtable readbacks, {len(host["cases"])} lifecycle sanitizer cases and {len(cpu["cases"])} ARM64 cases; no runtime installation')


if __name__=='__main__':main()
