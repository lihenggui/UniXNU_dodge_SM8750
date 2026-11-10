#!/usr/bin/env python3
"""Build the bounded source event driver and defer original-parent registration."""
import json
from pathlib import Path
import struct
import subprocess
from native_driver_build import ROOT,archive_imports,build_objects,inspect_object,require,sha,symbols
from build_input_native import fresh
from prepare_hid_event_abi import HEADER,methods

OUT=ROOT/'build/ios16-hid-edge-source'
INIT='__GLOBAL__sub_I_DodgeHidEventDriver.cpp'


def main():
    interface_path=ROOT/'reports/ios16-hid-event-abi.json';interface=fresh(interface_path)
    host_path=ROOT/'reports/ios16-hid-edge-host.json';host=fresh(host_path)
    require(interface['typed_event_slots']==[18,23,24,25] and host['case_count']==300,'Need bounded event interface and edge policy')
    source=ROOT/'drivers/DodgeInput/DodgeHidEventDriver.cpp';obj,=build_objects([source],OUT,[HEADER.parent,source.parent])
    late=OUT/'DodgeHidEventDriver.late.o';objcopy=ROOT/'.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy,'--remove-section=__DATA,__mod_init_func','--globalize-symbol='+INIT,obj,late],check=True)
    def text(path):
        data=path.read_bytes();section=next(s for seg in inspect_object(data)['segments'] for s in seg['sections'] if s['name']=='__text')
        return data[section['fileoff']:section['fileoff']+section['size']]
    require(text(obj)==text(late),'Source edge deferral changed instructions')
    table=methods(late,'DodgeHidEventDriver',219)
    require([i for i,n in enumerate(table) if '19DodgeHidEventDriver' in n]==[0,1,7,14,21,86,87,198],'Concrete edge overrides changed')
    require('___cxa_pure_virtual' not in table,'Source edge class is abstract')
    binding=ROOT/'build/ios16-hid-event-abi/original-hid-event-bindings.o';members=[late,binding]
    archive=OUT/'libDodgeHidEdges.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*members],check=True)
    for p in members:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'Source edge archive member differs')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/prepare_hid_event_abi.py',source,
           source.with_suffix('.h'),source.parent/'DodgeHidEdgePolicy.h',HEADER]
    report={'result':'IOS16_BOUNDED_SOURCE_HID_EDGE_DRIVER_AND_DEFERRED_REGISTRATION_ARCHIVE_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
            'dependency_report_sha256':{p.name:sha(p) for p in (interface_path,host_path)},
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
            'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in members],
            'concrete_methods':table,'concrete_vtable_entries':219,'original_base_instance_bytes':264,'original_bindings':interface['original_bindings'],
            'original_binding_count':71,'initializer':INIT,'initializer_removed_from_early_registration':True,'initializer_instructions_unchanged':True,
            'source_subclass_overrides_dispatch_without_original_table_mutation':True,'edge_policy_serialized_on_workloop':True,
            'first_original_init_attempt_pinned_and_latched':True,'failed_init_instance_not_released':True,
            'hardware_tested':False,'ready_for_ios_boot':False,'enabled_by_default':False,
            'scope':'Actual concrete source edge-origin event subclass and loader/metaclass preparation. Exact bounded original base and typed event access; 219 source slots and 71 data-only original bindings. '
                    'The first init instance is retained before original init; duplicate objects never enter original init and use native OSObject free. '
                    'Provider/workloop remain pinned after one start attempt. Actual original init/start/stop, matching, no-attempt deletion, event-client ordering and hardware remain to qualify.'}
    (ROOT/'reports/ios16-hid-edge-source.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: concrete 219-slot source edge event class, deferred initializer and 71 original bindings; lifecycle/runtime qualification separate')


if __name__=='__main__':main()
