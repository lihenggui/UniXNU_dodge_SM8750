#!/usr/bin/env python3
"""Build the concrete CPH2653 input driver and an isolated combined kernel."""
import difflib
import hashlib
import json
import plistlib
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from check_gpu_link import assemble,run
from check_input_host import check as check_host
from native_driver_build import ROOT,TREE,OBJDIR,NATIVE,archive_imports,build_objects,inspect_object,pinned_sources,require,sha,symbols,macho
from native_prelink import backed_offset
from prepare_hid_source_interface import concrete_methods,HEADER,CONTRACT,BASE
from prepare_input_hardware import derive,HEADER as BOARD,FACTS
from input_geni_overlay import verify as verify_geni,BASE as GENI_BASE,PATCH as GENI_PATCH

OUT=ROOT/'build/cph2653-input-native'
INIT='__GLOBAL__sub_I_DodgeInput.cpp'
SLIDE=-0x1000000

def edge_personality(data):
    prefix=b'<array><dict><key>IOClass</key><string>DodgeHidEventDriver</string>'
    require(data.count(prefix)==1,'Source edge personality class marker is not unique')
    start=data.index(prefix);end=data.index(b'\0',start);require(end-start<4096,'Source edge personality extent changed')
    raw=data[start:end];value=plistlib.loads(b'<plist version="1.0">'+raw+b'</plist>');require(len(value)==1,'Source edge personality count changed')
    entry=value[0]
    require(entry['CFBundleIdentifier']=='__kernel__' and entry['IOProviderClass']=='IOHIDInterface' and entry['IOProbeScore']==1000 and
            entry['Transport']=='SPI' and entry['IOPropertyMatch']=={'Product':'Dodge S3910'} and
            entry['DeviceUsagePairs']==[{'DeviceUsagePage':13,'DeviceUsage':4}] and entry['DigitizerCollectionDispatch'] is True,
            'Source edge personality namespace/product/usage contract changed')
    mi=macho(data);require(any(s['fileoff']<=start and end<=s['fileoff']+s['filesize'] and not s['initprot']&2 for s in mi['segments']),
                           'Source edge personality is writable')
    return {'personality':entry,'sha256':hashlib.sha256(raw).hexdigest()}

def fresh(report):
    data=json.loads(report.read_text());require('PASS' in data['result'],'Dependency is not passing: '+str(report))
    for path,digest in data.get('source_sha256',{}).items():require(sha(ROOT/path)==digest,'Dependency source changed: '+path)
    return data

def read_table(data,methods):
    names={s['name']:s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
    image=macho(data);vptr=names['__ZTV10DodgeInput']['value']+16
    at=backed_offset(image['segments'],vptr,207*8,len(data));actual=struct.unpack_from('<207Q',data,at)
    require(list(actual)==[names[n]['value'] for n in methods],'Concrete input vtable readback changed')
    return vptr

def text_audit(obj,opaque):
    raw=obj.read_bytes();image=inspect_object(raw);table=symbols(raw);loads=[];guard_calls=0
    for section in (s for seg in image['segments'] for s in seg['sections'] if s['name']=='__text'):
        start,count=struct.unpack_from('<2I',raw,section['command_offset']+56)
        for i in range(count):
            at,bits=struct.unpack_from('<2I',raw,start+8*i)
            if not (bits>>27)&1:continue
            name=table[bits&0xffffff]['name']
            require(name not in opaque,'Opaque HID slot has a source text reference')
            require(name!='_geni_spi_transfer','Input class bypasses its terminal transport guard')
            if name=='_dodge_geni_transfer':
                require(bits>>28==2,'Input terminal guard is not a direct ARM64 call');guard_calls+=1
            if name=='__ZTV11IOHIDDevice' and bits>>28==6:
                # Actual Apple kext ABI qualified calls load the parent table
                # from GOT, then a fixed original slot. Itanium prefix=16.
                word,=struct.unpack_from('<I',raw,section['fileoff']+at+4)
                require(word&0xffc00000==0xf9400000,'Parent HID table use has an unreviewed instruction')
                offset=((word>>10)&4095)*8;slot=(offset-16)//8
                require(offset>=16 and slot in (14,86,87),'Source calls an unqualified original parent slot')
                loads.append(slot)
    require(set(loads)=={14,86,87},'Expected real parent free/start/stop table loads are missing')
    require(guard_calls==1,'Concrete input class lost its sole guarded transfer call')
    return loads

def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());OUT.mkdir(parents=True,exist_ok=True)
    source_report=ROOT/'reports/ios16-hid-source-interface.json';calls_report=ROOT/'reports/ios16-hid-source-calls.json'
    interface=fresh(source_report);calls=fresh(calls_report);require(calls['interface_report_sha256']==sha(source_report),'Original caller tests are stale')
    lifetime_report=ROOT/'reports/ios16-hid-object-lifetime.json';lifetime=fresh(lifetime_report)
    require(lifetime['source_must_preserve_object_on_unqualified_init_failure'] and lifetime['case_count']==7 and
            lifetime['unsafe_partial_free_control']['unsafe_free_fault_at_0x20_confirmed'],'Original HID partial-init/free audit missing')
    firmware_report=ROOT/'reports/ios16-touch-firmware.json';firmware=fresh(firmware_report)
    cold_report=ROOT/'reports/ios16-input-cold-host.json';cold=fresh(cold_report)
    require(cold['firmware_sha256']==firmware['firmware_sha256'] and not cold['synthetic_firmware'],'Need target cold input source tests')
    clock_report=ROOT/'reports/ios16-input-clock.json';clock=fresh(clock_report)
    require(clock['stopped_unvoted_non_dfs_xo_root_initialization_implemented'] and clock['source_host_cases']==135,'Need current target clock/source evidence')
    transfer_report=ROOT/'reports/ios16-input-transfer-host.json';transfer=fresh(transfer_report)
    require(transfer['dma_command_data_and_idle_all_required'] and transfer['terminal_error_disables_future_io'] and
            transfer['tests']['original-control']['result']=='REJECTED','Need current GENI transport/terminal evidence')
    edge_path=ROOT/'reports/ios16-hid-edge-source.json';edge=fresh(edge_path)
    require(edge['concrete_vtable_entries']==219 and edge['original_binding_count']==71 and edge['initializer_removed_from_early_registration'],
            'Need current concrete source event/edge archive')
    geni_source=verify_geni()
    blob=ROOT/firmware['firmware'];require(sha(blob)==firmware['firmware_sha256'],'Original touch firmware bytes changed')
    board,facts=derive();require(BOARD.read_text()==board and json.loads(FACTS.read_text())==facts,'Target input facts/header changed')
    pin=lock['iphone_hid_source_interface'];require(sha(HEADER)==pin['header_sha256'] and sha(CONTRACT)==pin['sha256'],'Bounded original HID interface pin changed')
    parent=json.loads(BASE.read_text());refs=pinned_sources(('pagani_reference','sm8750'));reference=refs['pagani_reference']/'drivers/PaganiInput'
    shared=refs['sm8750']/'kits/Sm8750Platform';source=ROOT/'drivers/DodgeInput/DodgeInput.cpp';overlay=lock['dodge_input_overlay'];patch=ROOT/overlay['path'];base=reference/'PaganiInput.cpp'
    require(sha(patch)==overlay['sha256'] and sha(base)==overlay['base_source_sha256'] and sha(source)==overlay['output_source_sha256'],'Reviewed input overlay/source changed')
    with tempfile.TemporaryDirectory(prefix='overlay-',dir=OUT) as temp:
        work=Path(temp);(work/'PaganiInput.cpp').write_bytes(base.read_bytes())
        r=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(patch)],cwd=work,capture_output=True,text=True)
        (OUT/'overlay.log').write_text(r.stdout+r.stderr)
        require(not r.returncode and 'offset' not in r.stdout.lower() and (work/'PaganiInput.cpp').read_bytes()==source.read_bytes(),'Input overlay does not apply exactly')
    root_path=ROOT/'reports/ios16-ufs-root.json';root=fresh(root_path)
    require(root['combined_source_objects']==68 and sha(ROOT/root['isolated_kernel'])==root['isolated_kernel_sha256'],'Need current combined storage/display candidate')
    for path,digest in json.loads((ROOT/root['link_manifest']).read_text()).items():require(sha(ROOT/path)==digest,'Storage link input changed: '+path)
    protected={**root['protected_default_artifact_sha256'],root['isolated_kernel']:root['isolated_kernel_sha256']}
    for p in ('build/cph2653-storage-prelink/kernel.macho','build/cph2653-system-bringup/boot.img'):protected[p]=sha(ROOT/p)
    host=check_host(OUT)
    files=[source,reference/'S3910.c',geni_source,ROOT/'drivers/DodgeInput/DodgeInputStatus.cpp',
           ROOT/'drivers/DodgeInput/DodgeInputLifecycle.cpp',ROOT/'drivers/DodgeInput/DodgeInputLate.cpp',ROOT/'drivers/DodgeInput/DodgeGeniFirmware.cpp',
           ROOT/'drivers/DodgeInput/DodgeTouchClock.cpp',ROOT/'drivers/DodgeInput/DodgeGeniTransfer.cpp']
    target=ROOT/'sources/iphoneos-sdk/iPhoneOS16.5.sdk/usr/include/TargetConditionals.h'
    includes=[BOARD.parent,HEADER.parent,ROOT/'build/ios16-hid-abi/include',reference,shared,GENI_BASE.parent,ROOT/'drivers/DodgeStorage',ROOT/'drivers/DodgeDisplay']
    objects=build_objects(files,OUT,includes,['-include',str(target),'-Wno-macro-redefined'])
    original=objects[0];late=OUT/'DodgeInput.late.o';objcopy=ROOT/'.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    run([str(objcopy),'--remove-section=__DATA,__mod_init_func','--globalize-symbol='+INIT,str(original),str(late)],OUT/'defer.log')
    def text(path):
        data=path.read_bytes();s=next(s for seg in inspect_object(data)['segments'] for s in seg['sections'] if s['name']=='__text');return data[s['fileoff']:s['fileoff']+s['size']]
    require(text(late)==text(original),'Deferral changed source instructions')
    firmware_object=assemble(OUT,'stock-touch-firmware',(ROOT/firmware['assembly']).read_text())
    members=[late,*objects[1:],firmware_object,*[ROOT/o['path'] for o in edge['objects']]];methods=concrete_methods(late,'DodgeInput')
    owned=[i for i,n in enumerate(methods) if '10DodgeInput' in n]
    require(owned==[0,1,7,14,86,87,111,171,173,180] and '___cxa_pure_virtual' not in methods,'Unexpected concrete input override/abstract slot')
    aliases={};opaque=set()
    for actual,row in zip(methods,parent['methods']):
        if row['slot'] in owned:continue
        if row['native_inherited_exact']:require(actual==row['public_reference_declaration'],'Native inherited HID method changed')
        else:
            aliases[actual]=int(row['address'],16)+SLIDE
            if 'dodgeOpaque' in actual:opaque.add(actual)
    aliases.update({'__ZN11IOHIDDeviceC2EPK11OSMetaClass':int(parent['protected_constructor'],16)+SLIDE,
                    '__ZN11IOHIDDeviceD2Ev':int(parent['protected_destructor'],16)+SLIDE,
                    '__ZN11IOHIDDevice10gMetaClassE':int(parent['metaclass'],16)+SLIDE,
                    '__ZTV11IOHIDDevice':int(parent['vptr'],16)+SLIDE-16,'_dodge_original_hid_meta':int(parent['metaclass'],16)+SLIDE})
    require(len(opaque)==35 and all(not re.search(r'IOHIDDeviceD[01]Ev$',n) for n in aliases),'Unqualified abstract HID destructor binding')
    calls=text_audit(late,opaque)
    imports=archive_imports(members);external=set(root['combined_native_entries'])
    require(set(imports['required_board_or_original_imports'])<=set(aliases)|external,'Unclassified input imports: '+repr(set(imports['required_board_or_original_imports'])-set(aliases)-external))
    require(not imports['optional_weak_imports'],'Input introduced unclassified weak imports')
    binding=assemble(OUT,'original-hid-bindings',''.join(f'.globl {n}\n.set {n},{a:#x}\n' for n,a in sorted(aliases.items())))
    require(all(not s['size'] for seg in inspect_object(binding.read_bytes())['segments'] for s in seg['sections']),'HID binding substitutes implementation')
    members.append(binding);archive=OUT/'libDodgeInput.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*members],check=True)
    for p in members:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'Input archive member differs')
    # Add a queue-only input call after the existing combined system scheduler.
    old_bsd=ROOT/root['native_object_overlay']['source'];bsd=OUT/'bsd/IOKitBSDInit.cpp';bsd.parent.mkdir(exist_ok=True)
    before=old_bsd.read_text();after=before.replace('extern "C" IOReturn dodge_system_schedule(void);','extern "C" IOReturn dodge_system_schedule(void);\nextern "C" IOReturn dodge_input_schedule(void);')
    after=after.replace('\t(void)dodge_system_schedule();','\t(void)dodge_system_schedule();\n\t(void)dodge_input_schedule();')
    require(after!=before and after.count('(void)dodge_input_schedule();')==1,'Input IOBSD hook changed');bsd.write_text(after)
    bsd_patch=ROOT/'patches/oneplus13/0007-ios16-queue-input.patch'
    expected=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/IOKitBSDInit.cpp',tofile='b/IOKitBSDInit.cpp'))
    require(bsd_patch.read_text()==expected,'Reviewed input scheduling patch changed')
    recipe=OBJDIR/'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json';record=json.loads(recipe.read_text().strip().rstrip(','));command=[];i=0
    while i<len(record['arguments']):
        value=record['arguments'][i]
        if value==record['file']:command.append(str(bsd))
        elif value in ('-o','-MF','-MJ'):i+=1
        elif value not in ('-MD','-MP'):command.append(value)
        i+=1
    bsd_object=OUT/'IOKitBSDInit.input.cpo';command+=['-o',str(bsd_object)];run(command,OUT/'bsd-compile.log',record['directory'])
    rows=(ROOT/root['combined_native_filelist']).read_text().splitlines();old_object=str(ROOT/root['native_object_overlay']['object'])
    require(rows.count(old_object)==1,'Input base BSD object is ambiguous')
    filelist=OUT/'combined-native.filelist';filelist.write_text(''.join((str(bsd_object) if row==old_object else row)+'\n' for row in rows))
    command=json.loads((ROOT/root['link_command']).read_text())[:-2];arg='-Wl,-filelist,'+str(ROOT/root['combined_native_filelist']);require(command.count(arg)==1,'Input filelist argument changed')
    command[command.index(arg)]='-Wl,-filelist,'+str(filelist)
    candidate=OUT/'mach.input';command+=['-Wl,-force_load,'+str(archive),'-o',str(candidate)];run(command,OUT/'link.log',OBJDIR)
    data=candidate.read_bytes();image=macho(data);names={s['name']:s for s in symbols(data) if not s['kind']&0xe0}
    require(image['kind']==2 and not any(s['kind']==1 for s in names.values()),'Combined input kernel has undefined symbols')
    for n,a in aliases.items():require(names[n]['kind']==3 and names[n]['value']==a,'Original HID alias changed: '+n)
    vptr=read_table(data,methods);entries={n:hex(s['value']) for n,s in names.items() if n.startswith('_dodge_input_') and s['kind']&14==14}
    cold_entries={n:hex(names[n]['value']) for n in ('_dodge_geni_prepare','_dodge_geni_parse','_dodge_touch_spi_firmware','_dodge_touch_clock_prepare','_dodge_geni_transfer')}
    edge_entries={n:hex(names[n]['value']) for n in ('_dodge_hid_edge_prepare','_dodge_hid_edge_driver_bytes','_dodge_hid_edge_driver_meta','_dodge_hid_edge_instance_pinned')}
    combined={n:hex(names[n]['value']) for n in {*root['combined_native_entries'],*entries,*cold_entries,*edge_entries}}
    from prepare_hid_event_abi import methods as event_methods
    edge_methods=event_methods(ROOT/edge['objects'][0]['path'],'DodgeHidEventDriver',219)
    edge_vptr=names['__ZTV19DodgeHidEventDriver']['value']+16;edge_at=backed_offset(image['segments'],edge_vptr,219*8,len(data))
    require(list(struct.unpack_from('<219Q',data,edge_at))==[names[n]['value'] for n in edge_methods],'Concrete event source table readback changed')
    for n,a in edge['original_bindings'].items():require(names[n]['kind']==3 and names[n]['value']==int(a,16),'Original event binding changed: '+n)
    size_at=backed_offset(image['segments'],names['_dodge_hid_edge_driver_bytes']['value'],8,len(data));size_mov,size_ret=struct.unpack_from('<2I',data,size_at)
    require(size_mov&0xffe0001f==0x52800000 and size_ret==0xd65f03c0,'Concrete event size leaf changed');edge_size=(size_mov>>5)&65535
    personality=edge_personality(data)
    start=names['_dodge_touch_spi_firmware']['value'];end=names['_dodge_touch_spi_firmware_end']['value']
    require(end-start==firmware['firmware_bytes'],'Embedded SPI firmware extent changed')
    at=backed_offset(image['segments'],start,end-start,len(data));require(hashlib.sha256(data[at:at+end-start]).hexdigest()==firmware['firmware_sha256'],'Embedded SPI firmware readback changed')
    require(any(s['va']<=start and end<=s['va']+s['size'] and not s['initprot']&2 for s in image['segments']),'Embedded SPI firmware is writable')
    require(len(entries)>=15,'Input metadata/diagnostic/lifecycle/worker entries missing')
    deferred=names[INIT]['value'];early=0
    for s in (s for seg in image['segments'] for s in seg['sections'] if s['name']=='__mod_init_func'):
        at=backed_offset(image['segments'],s['va'],s['size'],len(data));values=struct.unpack_from('<'+str(s['size']//8)+'Q',data,at);early+=len(values)
        require(deferred not in values and names[edge['initializer']]['value'] not in values,'Input/event class still registers its original parent early')
    # Actual IOBSD machine code must queue storage/graphics before input.
    a=names['_IOKitBSDInit']['value'];at=backed_offset(image['segments'],a,80,len(data));hook=data[at:at+80];branches={}
    for j,w in enumerate(struct.unpack('<20I',hook)):
        if w&0xfc000000==0x94000000:
            delta=w&0x3ffffff;branches[a+j*4+4*(delta-(1<<26) if delta&(1<<25) else delta)]=a+j*4
    wanted=[names[n]['value'] for n in ('__ZN9IOService15publishResourceEPKcP8OSObject','_dodge_system_schedule','_dodge_input_schedule')]
    require(all(n in branches for n in wanted) and [branches[n] for n in wanted]==sorted(branches[n] for n in wanted),'Actual IOBSD queue order changed')
    size_address=names['_dodge_input_driver_bytes']['value'];at=backed_offset(image['segments'],size_address,8,len(data));mov,ret=struct.unpack_from('<2I',data,at)
    require(mov&0xffe0001f==0x52800000 and ret==0xd65f03c0,'Input size leaf changed');size=(mov>>5)&65535
    require(size>208,'Concrete input state missing')
    require(all(sha(ROOT/p)==h for p,h in protected.items()),'Input build modified a protected artifact')
    link_command=OUT/'link-command.json';link_command.write_text(json.dumps(command,indent=2)+'\n')
    source_files=[Path(__file__),ROOT/'scripts/check_input_host.py',ROOT/'scripts/prepare_input_hardware.py',ROOT/'scripts/prepare_hid_source_interface.py',
                  ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_hid_object_lifetime.py',ROOT/'scripts/prepare_input_firmware.py',ROOT/'scripts/check_input_cold_host.py',
                  ROOT/'scripts/prepare_input_clock.py',ROOT/'scripts/check_input_clock_host.py',ROOT/'tests/DodgeTouchClockTest.cpp',
                  ROOT/'scripts/input_geni_overlay.py',ROOT/'scripts/check_input_transfer_host.py',ROOT/'tests/DodgeGeniTransferTest.cpp',GENI_BASE,GENI_PATCH,
                  ROOT/'hardware/dodge-touch-clock.json',ROOT/'hardware/dodge-spi-firmware.json',HEADER,CONTRACT,BASE,FACTS,patch,bsd_patch,base,target,*files,
                  *sorted((ROOT/'drivers/DodgeInput').glob('*.h')),*sorted(reference.glob('*.h')),*sorted(shared.glob('*.h')),
                  ROOT/'tests/DodgeInputLifecycleTest.cpp',ROOT/'tests/DodgeTouchPowerTest.cpp',ROOT/'tests/DodgeInputLateTest.cpp',ROOT/'tests/DodgePmicGpioTest.cpp',ROOT/'tests/DodgeGeniFirmwareTest.cpp',ROOT/'tests/input_lifecycle_include/OriginalHidDeviceABI.h',
                  *[p for d in ('ufs_lifecycle_include','graphics_lifecycle_include','graphics_late_include') for p in sorted((ROOT/'tests'/d).rglob('*.h'))]]
    source_files += [ROOT/p for p in edge['source_sha256'] if ROOT/p not in source_files]
    inputs={ROOT/p for p in json.loads((ROOT/root['link_manifest']).read_text())}|{archive,bsd,bsd_object,filelist,link_command,blob,ROOT/firmware['assembly'],*members,*source_files}
    manifest=OUT/'link-inputs.json';manifest.write_text(json.dumps({str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)},indent=2)+'\n')
    report={'result':'IOS16_CPH2653_INPUT_COMPLETE_SOURCE_AND_STRICT_NATIVE_LINK_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in source_files},'dependency_report_sha256':{p.name:sha(p) for p in (source_report,calls_report,lifetime_report,firmware_report,cold_report,clock_report,transfer_report,edge_path,root_path,ROOT/'reports/ios16-input-hardware.json')},
            'source_reference_revision':lock['pagani_reference']['revision'],'source_overlay':overlay,
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in members],
            'compiled_instance_bytes':size,'concrete_vtable_entries':207,'concrete_override_slots':owned,'concrete_vptr':hex(vptr),
            'original_bindings':{n:hex(a) for n,a in aliases.items()},'original_binding_count':len(aliases),
            'combined_original_bindings':{**root['combined_original_bindings'],**{n:hex(a) for n,a in aliases.items()},**edge['original_bindings']},
            'edge_original_bindings':edge['original_bindings'],'edge_concrete_instance_bytes':edge_size,'edge_concrete_vtable_entries':219,
            'edge_source_report_sha256':sha(edge_path),'edge_concrete_vptr':hex(edge_vptr),'edge_native_entries':edge_entries,
            'edge_personality_readback':personality,'edge_personality_registered_in_kernel_namespace':'__kernel__',
            'opaque_slots_preserve_original_pointers':35,'opaque_source_text_references':0,'qualified_original_parent_table_calls':calls,
            'combined_source_objects':68+len(members),'native_entries':entries,'combined_native_entries':combined,
            'cold_input_entries':cold_entries,'embedded_spi_firmware_sha256':firmware['firmware_sha256'],'embedded_spi_firmware_bytes':end-start,
            'embedded_spi_firmware_read_only':True,'cold_host_tests':cold,
            'isolated_kernel':str(candidate.relative_to(ROOT)),'isolated_kernel_sha256':sha(candidate),'strict_no_undefined':True,
            'compile_manifest':str((OUT/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(OUT/'compile-commands.json'),
            'link_command':str(link_command.relative_to(ROOT)),'link_command_sha256':sha(link_command),'link_manifest':str(manifest.relative_to(ROOT)),'link_manifest_sha256':sha(manifest),
            'native_object_overlay':{'source':str(bsd.relative_to(ROOT)),'object':str(bsd_object.relative_to(ROOT)),'patch':str(bsd_patch.relative_to(ROOT))},
            'actual_iobsd_hook':{'address':hex(a),'bytes':len(hook),'sha256':hashlib.sha256(hook).hexdigest(),'queue_call_order':[hex(branches[n]) for n in wanted]},
            'host_tests':host,'initializer':INIT,'initializer_instructions_unchanged':True,'initializer_removed_from_early_registration':True,'early_constructor_count':early,
            'target_avdd_gpio_adoption_and_vdd_vote_built':True,'cold_gpio_or_spi_firmware_loading_complete':False,
            'validated_gpio_input_or_disabled_transition_implemented':True,'empty_idle_qup4_spi_firmware_loading_implemented':True,
            'stopped_unvoted_non_dfs_xo_root_initialization_implemented':True,'warm_spi_adoption_checks_foreign_dma_gpi_and_fifo':True,
            'local_geni_transport_overlay':lock['dodge_geni_transfer_overlay'],'dma_command_data_and_idle_all_required':True,
            'bounded_cancel_abort_and_channel_reset_ack_implemented':True,'terminal_transfer_error_disables_future_io':True,
            'concrete_input_uses_exactly_one_direct_guard_call':True,'concrete_input_calls_raw_transport_directly':False,
            'start_and_stop_serialized_on_input_workloop':True,'reentrant_stop_deferred_until_source_callback_exit':True,
            'parent_cleanup_latched_before_original_start':True,'deferred_stop_provider_retained':True,
            'objects_and_provider_pinned_before_original_init':True,'failed_init_or_attach_is_latched_without_release':True,
            'private_event_fields_or_vtables_modified':False,'edge_gesture_annotation_implemented':True,
            'boot_argument':'dodge-input=1','enabled_by_default':False,'original_hid_parent_runtime_qualified':False,
            'original_hid_implementation_embedded':False,'metadata_or_hardware_entries_invoked':False,'hardware_tested':False,
            'default_artifacts_unchanged':True,'protected_default_artifact_sha256':protected,'ready_for_ios_boot':False,
            'scope':'Full source S3910 transport/descriptor/report/key polling + target rail policy, native HID subclass, deferred original-parent loader and one-shot pinned lifecycle. '
                    'Start/stop use the input gate, with parent cleanup latched before original start, callback drain and deferred provider retention. '
                    'A concrete source event subclass marks edge origins through bounded original APIs, with deferred Kernel metadata registration, one pinned init/start attempt and exact personality readback. '
                    'Strict separate combined source kernel; 207 concrete slots read back. Full iPhone private HID/Event ABI, hardware power/DMA/reset, full original device start/element report processing, '
                    'touch coordinate orientation and UI gestures remain unqualified. No default artifacts or device state changed.'}
    (ROOT/'reports/ios16-input-native.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: input concrete {size}-byte/207-slot source; {len(aliases)} original aliases, {68+len(members)} objects, strict isolated kernel; no activation')

if __name__=='__main__':main()
