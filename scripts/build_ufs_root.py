#!/usr/bin/env python3
"""Build the complete read-only iPhone UFS/root publisher, without activating it."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from check_gpu_link import ABSENT,assemble,native_link_command,run
from check_ufs_lifecycle_host import check as check_host
from check_system_late_host import check as check_system
from native_driver_build import ROOT,TREE,OBJDIR,NATIVE,archive_imports,build_objects,inspect_object,pinned_sources,require,sha,symbols,macho
from native_prelink import backed_offset
from prepare_storage_abi import FIXTURE,HEADER,stage_headers

INIT='__GLOBAL__sub_I_NativeUfs.cpp'


def concrete_methods(obj):
    raw=obj.read_bytes();image=inspect_object(raw);names=symbols(raw)
    table=next(s for s in names if s['name']=='__ZTV14NativeUfsBlock')
    section=next(s for seg in image['segments'] for s in seg['sections'] if s['va']<=table['value']<s['va']+s['size'])
    reloc,count=struct.unpack_from('<2I',raw,section['command_offset']+56);at=table['value']+16;slots={}
    for i in range(count):
        address,bits=struct.unpack_from('<2I',raw,reloc+8*i);v=section['va']+address
        if at<=v<at+190*8:
            require(bits>>24==14 and (v-at)%8==0,'Unexpected concrete UFS block vtable relocation')
            slots[(v-at)//8]=names[bits&0xffffff]['name']
    require(set(slots)==set(range(190)) and '___cxa_pure_virtual' not in slots.values(),'Concrete UFS block still has missing/abstract slots')
    return [slots[i] for i in range(190)]


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['iphone_storage_abi'];overlay=lock['dodge_ufs_root_overlay']
    abi=json.loads((ROOT/'reports/ios16-storage-abi.json').read_text());fixture=json.loads(FIXTURE.read_text())
    require('PASS' in abi['result'] and abi['builder_sha256']==sha(ROOT/'scripts/prepare_storage_abi.py') and
            abi['contract_sha256']==pin['sha256']==sha(FIXTURE) and abi['header_sha256']==pin['header_sha256']==sha(HEADER),
            'Need the current independently derived iPhone storage class/header contract')
    for p,h in abi['source_sha256'].items():require(sha(ROOT/p)==h,'Storage ABI input changed: '+p)
    refs=pinned_sources(('pagani_reference','sm8750'));reference=refs['pagani_reference']/'drivers/NativeUfs';shared=refs['sm8750']/'kits'
    out=ROOT/'build/cph2653-ufs-root';out.mkdir(parents=True,exist_ok=True)
    source=out/'source/NativeUfs.cpp';source.parent.mkdir(parents=True,exist_ok=True)
    patch=ROOT/overlay['path'];base=reference/'NativeUfs.cpp'
    require(sha(patch)==overlay['sha256'] and sha(base)==overlay['base_source_sha256'],'Reviewed UFS overlay/base changed')
    protected={str(p.relative_to(ROOT)):sha(p) for p in (NATIVE,TREE.parent/'kernel/kernel.macho',ROOT/'build/cph2653-native-bringup/boot.img',
        ROOT/'build/cph2653-display-prelink/kernel.macho',ROOT/'build/cph2653-display-bringup/boot.img')}
    display_path=ROOT/'reports/ios16-display-kernel.json';display=json.loads(display_path.read_text())
    require('PASS' in display['result'] and display['linked_source_objects']==64 and
            sha(ROOT/display['isolated_kernel'])==display['isolated_kernel_sha256'],'Need the current isolated full display kernel')
    for name,h in display['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==h,'Display dependency changed: '+name)
    require(sha(ROOT/display['input_manifest'])==display['input_manifest_sha256'],'Display input manifest changed')
    for path,h in json.loads((ROOT/display['input_manifest']).read_text()).items():require(sha(ROOT/path)==h,'Recorded display/native link input changed: '+path)
    with tempfile.TemporaryDirectory(prefix='source-',dir=out) as temp:
        work=Path(temp);(work/'NativeUfs.cpp').write_bytes(base.read_bytes())
        result=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(patch)],cwd=work,capture_output=True,text=True)
        (out/'overlay.log').write_text(result.stdout+result.stderr)
        require(not result.returncode and 'offset' not in result.stdout.lower(),'UFS overlay does not apply exactly')
        source.write_bytes((work/'NativeUfs.cpp').read_bytes())
    _,include,target=stage_headers(ROOT/'build/ios16-storage-abi')
    host=check_host(out);system_host=check_system(out)
    objects=build_objects([source,ROOT/'drivers/DodgeStorage/DodgeUfsLifecycle.cpp',ROOT/'drivers/DodgeStorage/DodgeSystemLate.cpp'],out,[include,reference,shared,HEADER.parent],
        ['-Wno-deprecated-declarations','-Wno-macro-redefined','-include',str(target),'-DNATIVE_UFS_PROBE_ONLY=0',
         '-DNATIVE_UFS_SM8750=1','-DNATIVE_UFS_READ_ONLY=1','-DNATIVE_VERIFIED_BLOCK=0','-DUFS_ROOT_PARTITION="unixnu"'])
    original=objects[0];late=out/'NativeUfs.late.o';objcopy=ROOT/'.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    run([str(objcopy),'--remove-section=__DATA,__mod_init_func','--globalize-symbol='+INIT,str(original),str(late)],out/'defer-initializer.log')
    def text(path):
        raw=path.read_bytes();section=next(s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name']=='__text')
        return raw[section['fileoff']:section['fileoff']+section['size']]
    require(text(original)==text(late),'Deferral changed UFS implementation instructions')
    require(all(not s['size'] for p in (late,*objects[1:]) for seg in inspect_object(p.read_bytes())['segments'] for s in seg['sections'] if s['name']=='__mod_init_func'),
            'Original-parent UFS classes still run during early constructors')
    require(any(s['name']==INIT and s['kind']&1 and s['kind']&14 for s in symbols(late.read_bytes())),'Deferred native UFS initializer is not callable')
    methods=concrete_methods(late);overrides=[]
    all_names=list(dict.fromkeys([*methods,*[r['name'] for r in fixture['methods']]]))
    readable=dict(zip(all_names,subprocess.check_output(['/usr/bin/llvm-cxxfilt-14'],input='\n'.join(n[1:] for n in all_names)+'\n',text=True).splitlines()))
    def tail(name):return readable[name].split('::',1)[1]
    for row,actual in zip(fixture['methods'],methods):
        own=actual.startswith(('__ZN14NativeUfsBlock','__ZNK14NativeUfsBlock'))
        if row['name']=='___cxa_pure_virtual':require(own,'Original required transport operation is not implemented')
        elif actual!=row['name']:
            require(own and (row['slot'] in (0,1) or tail(actual)==tail(row['name'])),'Concrete UFS override changed slot/prototype: '+str(row['slot']))
        if own:overrides.append(row['slot'])
    slide=int(fixture['slide'],0)
    possible={r['name']:int(r['address'],16)+slide for r in fixture['methods'] if r['kind']=='original'}
    possible.update({'__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass':int(fixture['protected_constructor'],16)+slide,
                     '__ZN20IOBlockStorageDeviceD2Ev':int(fixture['protected_destructor'],16)+slide,
                     '__ZN20IOBlockStorageDevice10gMetaClassE':int(fixture['metaclass'],16)+slide,
                     '__ZTV20IOBlockStorageDevice':int(fixture['vptr'],16)+slide-16,
                     '_dodge_original_storage_meta':int(fixture['metaclass'],16)+slide})
    imports=archive_imports([late,*objects[1:]])
    require(not any(re.search(r'IOBlockStorageDeviceD[01]Ev$',n) for n in imports['required_board_or_original_imports']),
            'Concrete UFS calls an original abstract deleting/complete destructor')
    needed=set(imports['required_board_or_original_imports'])-{'_dodge_graphics_schedule'}
    require(needed<=possible.keys(),'Unclassified UFS original imports: '+repr(sorted(needed-possible.keys())))
    aliases={n:possible[n] for n in needed};absolute=assemble(out,'original-storage-bindings',''.join(f'.globl {n}\n.set {n},{a:#x}\n' for n,a in sorted(aliases.items())))
    require({s['name']:s['value'] for s in symbols(absolute.read_bytes()) if s['kind']==3}==aliases and
            all(not s['size'] for seg in inspect_object(absolute.read_bytes())['segments'] for s in seg['sections']),
            'Original storage bindings contain substituted code or incorrect addresses')
    members=[late,*objects[1:],absolute];archive=out/'libDodgeUfsRoot.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*members],check=True)
    for p in members:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'Root archive member differs')
    imports=archive_imports(members)
    require(set(imports['required_board_or_original_imports'])=={'_dodge_graphics_schedule'},'Root archive has unknown non-graphics dependencies')
    require(set(imports['optional_weak_imports'])<={'_boot_progress_poll'},'Unexpected optional UFS import')
    # Optimizers may fold the match string into immediate byte comparisons.
    # Execute the actual extracted source rather than search object strings.
    def probe_extract(path):
        value=path.read_text();pieces=[]
        if 'static const char kDodgeUfsCompatible' in value:
            at=value.index('#if defined(NATIVE_UFS_SM8750) && NATIVE_UFS_SM8750\nstatic const char kDodgeUfsCompatible')
            pieces.append(value[at:value.index('\n#endif',at)+7])
        for signature in ('static bool contains (','IOService *NativeUfs::probe ('):
            at=value.index(signature);pieces.append(value[at:value.index('\n}\n',at)+3])
        return '\n'.join(pieces)
    extract=out/'NativeUfsProbe.extracted.h';probe=out/'ufs-probe-host'
    def probe_check(path,binary):
        extract.write_text(probe_extract(path))
        subprocess.run(['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                        '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie','-DNATIVE_UFS_SM8750=1',
                        '-I',out,ROOT/'tests/DodgeUfsProbeTest.cpp','-o',binary],check=True)
        return subprocess.run([binary],capture_output=True,text=True,timeout=30,
                              env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    old=probe_check(base,out/'ufs-old-match-rejected');require(old.returncode!=0,'Unmodified reference unexpectedly matches the target correctly')
    checked_probe=probe_check(source,probe);(out/'ufs-probe-host.log').write_text(checked_probe.stdout+checked_probe.stderr)
    require(checked_probe.returncode==0 and checked_probe.stdout.startswith('PASS:'),'Actual patched UFS probe matching failed')
    publication=out/'root-publication-host'
    subprocess.run(['/usr/bin/g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie',reference/'tests/RootPublication.cpp','-o',publication],check=True)
    result=subprocess.run([publication],capture_output=True,text=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
    (out/'root-publication-host.log').write_text(result.stdout+result.stderr)
    require(result.returncode==0 and result.stdout.startswith('PASS:'),'Actual root-window publication coordinator host regression failed')
    # Preserve the 64-object display candidate. Only this new combined link
    # replaces its IOBSD object, adding root-before-graphics scheduling.
    system_pin=lock['dodge_system_late_overlay'];system_patch=ROOT/system_pin['path'];old_overlay=display['native_object_overlay']
    old_bsd=ROOT/old_overlay['patched_source'];require(sha(system_patch)==system_pin['sha256'] and sha(old_bsd)==system_pin['base_source_sha256'],'Combined IOBSD patch/base changed')
    bsd_source=out/'bsd/IOKitBSDInit.cpp';bsd_source.parent.mkdir(exist_ok=True);bsd_source.write_bytes(old_bsd.read_bytes())
    result=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(system_patch)],cwd=bsd_source.parent,capture_output=True,text=True)
    (out/'system-overlay.log').write_text(result.stdout+result.stderr)
    require(not result.returncode and 'offset' not in result.stdout.lower(),'Combined IOBSD overlay does not apply exactly')
    recipe=OBJDIR/'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json';record=json.loads(recipe.read_text().strip().rstrip(','));bsd_command=[];i=0
    while i<len(record['arguments']):
        value=record['arguments'][i]
        if value==record['file']:bsd_command.append(str(bsd_source))
        elif value in ('-o','-MF','-MJ'):i+=1
        elif value not in ('-MD','-MP'):bsd_command.append(value)
        i+=1
    bsd_object=out/'IOKitBSDInit.system.cpo';bsd_command+=['-o',str(bsd_object)]
    run(bsd_command,out/'system-bsd-compile.log',record['directory']);inspect_object(bsd_object.read_bytes())
    bsd_manifest=out/'system-bsd-compile.json';bsd_manifest.write_text(json.dumps({'arguments':bsd_command,'directory':record['directory'],'recipe_sha256':sha(recipe)},indent=2)+'\n')
    command,inputs,linker=native_link_command(out)
    previous_commands=json.loads((ROOT/display['command_manifest']).read_text());command=previous_commands['display'][:-2]
    previous_absence=str(ROOT/'build/cph2653-display-kernel/absent-weak-imports.o')
    require(command.count(previous_absence)==1,'Display absence adapter does not have one reviewed input')
    command.remove(previous_absence)
    previous_filelist=ROOT/display['native_filelist'];new_filelist=out/'combined-native.filelist';rows=previous_filelist.read_text().splitlines()
    old_object=str(ROOT/old_overlay['replacement_object']);require(rows.count(old_object)==1,'Display filelist does not uniquely identify its IOBSD object')
    new_filelist.write_text(''.join((str(bsd_object) if row==old_object else row)+'\n' for row in rows))
    old_arg='-Wl,-filelist,'+str(previous_filelist);require(command.count(old_arg)==1,'Display link filelist argument changed')
    command[command.index(old_arg)]='-Wl,-filelist,'+str(new_filelist)
    baseline_names={s['name'] for s in symbols((ROOT/display['isolated_kernel']).read_bytes()) if not s['kind']&0xe0 and s['kind']&14}
    rebound_diagnostics=set(ABSENT)&set(imports['defined'])
    require(rebound_diagnostics=={'_native_ufs_block_reads','_native_ufs_block_failures'},'Combined source supplied unexpected former diagnostics')
    absent_names=(set(ABSENT)-rebound_diagnostics)|(set(imports['optional_weak_imports'])-baseline_names)
    absent=assemble(out,'absent-ufs-observers',''.join(f'.globl {n}\n.set {n},0\n' for n in sorted(absent_names)))
    candidate=out/'mach.storage';link_command=[*command,'-Wl,-force_load,'+str(archive),str(absent),'-o',str(candidate)]
    run(link_command,out/'storage-link.log',OBJDIR)
    raw=candidate.read_bytes();image=macho(raw);names={s['name']:s for s in symbols(raw) if not s['kind']&0xe0}
    require(image['kind']==2 and not any(s['kind']==1 for s in names.values()),'Actual full UFS source kernel is not a strict no-undefined link')
    for name in rebound_diagnostics:
        require(names[name]['kind']&14==14 and names[name]['value'] and any(s['initprot']&2 and s['va']<=names[name]['value']<s['va']+s['size'] for s in image['segments']),
                'Real UFS diagnostic counter remained an absent absolute symbol')
    for name in absent_names:require(names[name]['kind']==3 and not names[name]['value'],'Absent combined diagnostic is not a pure null address')
    for n,a in aliases.items():require(names[n]['kind']==3 and names[n]['value']==a,'Full source kernel changed an original storage alias')
    actual_vptr=names['__ZTV14NativeUfsBlock']['value']+16
    at=backed_offset(image['segments'],actual_vptr,190*8,len(raw));values=struct.unpack_from('<190Q',raw,at)
    require(list(values)==[names[n]['value'] for n in methods],'Full native UFS kernel vtable readback differs')
    real={n:s['value'] for n,s in names.items() if n.startswith('_dodge_ufs_') and s['kind']&14==14}
    require(len(real)==8 and all(any(seg['initprot']&4 and seg['va']<=a<seg['va']+seg['size'] for seg in image['segments']) for a in real.values()),
            'Native storage metadata/factory entries are missing')
    system_entries={n:s['value'] for n,s in names.items() if n.startswith('_dodge_system_') and s['kind']&14==14}
    require(len(system_entries)==2,'Combined root/graphics scheduler entries are absent')
    combined_entries={n:hex(names[n]['value']) for n in {*display['real_linked_entry_points'],*real,*system_entries}}
    require(len(combined_entries)==52,'Combined native entry inventory changed')
    a=names['_IOKitBSDInit']['value'];at=backed_offset(image['segments'],a,72,len(raw));hook=raw[at:at+72];calls={}
    for j,word in enumerate(struct.unpack('<18I',hook)):
        if word&0xfc000000==0x94000000:
            delta=word&0x3ffffff;calls[a+j*4+4*(delta-(1<<26) if delta&(1<<25) else delta)]=a+j*4
    publish=names['__ZN9IOService15publishResourceEPKcP8OSObject']['value'];schedule=system_entries['_dodge_system_schedule']
    require(publish in calls and schedule in calls and calls[publish]<calls[schedule],'Combined native IOBSD hook does not publish before scheduling')
    hook_record={'address':hex(a),'bytes':72,'sha256':hashlib.sha256(hook).hexdigest(),'publish_call':hex(calls[publish]),'schedule_call':hex(calls[schedule]),'schedule_target':hex(schedule)}
    sizes={}
    for label in ('driver','block'):
        a=real['_dodge_ufs_'+label+'_bytes'];at=backed_offset(image['segments'],a,8,len(raw));first,ret=struct.unpack_from('<2I',raw,at)
        require(first&0xffe0001f==0x52800000 and ret==0xd65f03c0,'Actual native storage size leaf changed')
        sizes[label]=(first>>5)&65535
    require(sizes=={'driver':152,'block':216},'Actual native UFS driver/block object sizes changed')
    deferred=names[INIT]['value'];early=0
    for s in (s for seg in image['segments'] for s in seg['sections'] if s['name']=='__mod_init_func'):
        at=backed_offset(image['segments'],s['va'],s['size'],len(raw));pointers=struct.unpack_from('<'+str(s['size']//8)+'Q',raw,at);early+=len(pointers)
        require(deferred not in pointers,'Actual full kernel still runs UFS constructors early')
    require(all(sha(ROOT/p)==h for p,h in protected.items()),'Root build changed a protected default/display artifact')
    inputs.update([archive,absent,Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_gpu_link.py',ROOT/'reports/ios16-storage-abi.json',candidate,
                   display_path,ROOT/display['command_manifest'],new_filelist,bsd_source,bsd_object,bsd_manifest])
    for path in json.loads((ROOT/display['input_manifest']).read_text()):inputs.add(ROOT/path)
    manifest=out/'link-inputs.json';manifest.write_text(json.dumps({str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)},indent=2)+'\n')
    commands=out/'link-command.json';commands.write_text(json.dumps(link_command,indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/prepare_storage_abi.py',ROOT/'scripts/check_ufs_lifecycle_host.py',ROOT/'scripts/native_driver_build.py',
           ROOT/'scripts/check_gpu_link.py',ROOT/'drivers/DodgeStorage/DodgeUfsLifecycle.cpp',ROOT/'drivers/DodgeStorage/DodgeUfsLifecycle.h',
           ROOT/'drivers/DodgeStorage/DodgeSystemLate.cpp',ROOT/'drivers/DodgeStorage/DodgeSystemLate.h',ROOT/'tests/DodgeSystemLateTest.cpp',ROOT/'scripts/check_system_late_host.py',
           ROOT/'tests/DodgeUfsLifecycleTest.cpp',ROOT/'tests/DodgeUfsProbeTest.cpp',*[p for directory in ('ufs_lifecycle_include','graphics_lifecycle_include','graphics_late_include') for p in sorted((ROOT/'tests'/directory).rglob('*.h'))],
           FIXTURE,HEADER,source,base,patch,system_patch,bsd_source,recipe,reference/'tests/RootPublication.cpp',*sorted(reference.glob('*.h')),*sorted((shared/'Sm8750Platform').glob('*.h'))]
    report={'result':'IOS16_COMPLETE_READ_ONLY_UFS_ROOT_PUBLISHER_NATIVE_SOURCE_PASS','builder_sha256':sha(Path(__file__)),
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':fixture['original_kernelcache_sha256'],
            'storage_abi_report_sha256':sha(ROOT/'reports/ios16-storage-abi.json'),'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
            'source_revision':lock['pagani_reference']['revision'],'soc_revision':lock['sm8750']['revision'],'overlay':overlay,
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in members],
            'display_kernel_report_sha256':sha(display_path),'combined_source_objects':68,'combined_native_entries':combined_entries,
            'combined_original_bindings':{**display['original_absolute_bindings_preserved'],**{n:hex(a) for n,a in aliases.items()}},
            'former_weak_diagnostics_now_real_storage':{n:hex(names[n]['value']) for n in sorted(rebound_diagnostics)},
            'remaining_absent_weak_diagnostics':sorted(absent_names),
            'native_object_overlay':{'patch':system_pin,'source':str(bsd_source.relative_to(ROOT)),'source_sha256':sha(bsd_source),
                                     'object':str(bsd_object.relative_to(ROOT)),'object_sha256':sha(bsd_object),
                                     'compile_manifest':str(bsd_manifest.relative_to(ROOT)),'compile_manifest_sha256':sha(bsd_manifest)},
            'combined_native_filelist':str(new_filelist.relative_to(ROOT)),'combined_native_filelist_sha256':sha(new_filelist),'actual_iobsd_hook':hook_record,
            'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
            'imports':imports,'original_bindings':{n:hex(a) for n,a in aliases.items()},'original_binding_count':len(aliases),
            'concrete_vtable_entries':190,'concrete_override_slots':overrides,'compiled_instance_bytes':sizes,
            'host_tests':host,'host_binary':str((out/'ufs-lifecycle-host').relative_to(ROOT)),'host_binary_sha256':sha(out/'ufs-lifecycle-host'),
            'combined_scheduling_host_tests':system_host,'combined_scheduling_host_binary':str((out/'system-late-host').relative_to(ROOT)),
            'combined_scheduling_host_binary_sha256':sha(out/'system-late-host'),
            'root_publication_host_test':{'result':'PASS','binary':str(publication.relative_to(ROOT)),'sha256':sha(publication),
                                          'scope':'Actual production prepare/rollback/order/dispatch/media-failure/retained-started-device/ancestor decisions; registry/transport operations are peers'},
            'probe_matching_host_test':{'result':'PASS','case_count':11,'binary':str(probe.relative_to(ROOT)),'sha256':sha(probe),
                                       'extract':str(extract.relative_to(ROOT)),'extract_sha256':sha(extract),'unmodified_reference_control':'REJECTED',
                                       'scope':'Actual staged contains/probe source; property and type peers, no native object layout or MMIO execution'},
            'isolated_kernel':str(candidate.relative_to(ROOT)),'isolated_kernel_sha256':sha(candidate),'strict_no_undefined':True,
            'native_entries':{n:hex(a) for n,a in real.items()},'concrete_vptr':hex(actual_vptr),'initializer':INIT,
            'initializer_removed_from_early_registration':True,'initializer_instructions_unchanged':True,'actual_early_constructor_count':early,
            'link_manifest':str(manifest.relative_to(ROOT)),'link_manifest_sha256':sha(manifest),'link_command':str(commands.relative_to(ROOT)),'link_command_sha256':sha(commands),
            'probe_only':False,'read_only':True,'root_publication_built':True,'root_layout_and_async_media_publication_included':True,
            'original_parent_library_loaded_before_deferred_classes':True,'one_shot_start_after_explicit_root_argument':True,
            'driver_and_provider_retained_after_hardware_start_attempt':True,'start_failure_dma_quiescence_or_rollback_qualified':False,
            'source_public_storage_base_implementation_linked':False,'original_components_embedded':False,'metadata_or_hardware_entry_invoked':False,
            'root_authenticated':False,'owner_trust_enabled':False,'physical_partition_created_or_modified':False,'default_kernel_selected':False,
            'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'storage_family_abi_runtime_qualified':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Complete read-only SM8750 controller/root-window source plus exact iPhone original-class bindings and a real OSKext/deferred Kernel-registration/start coordinator. '
                    'All 190 concrete slots and 152/216-byte source classes read back in an actual native-kernel link. Public storage reference implementation is never linked. '
                    'Sanitized lifecycle tests use explicit metadata/loader/controller/IOKit peers. Original components are not embedded in this MH_EXECUTE, entries are not invoked, '
                    'no physical partition or authenticated root exists, and actual UFS transport, DMA/reset, storage matching and runtime ABI remain unqualified.'}
    (ROOT/'reports/ios16-ufs-root.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: full read-only UFS/root publisher, 190 concrete slots, '+str(len(aliases))+' original aliases and '+str(host['case_count'])+' sanitized lifecycle cases; strict isolated native kernel link')


if __name__=='__main__':main()
