#!/usr/bin/env python3
"""Reproduce/check the opt-in input + storage + display local candidate."""
import argparse
import json
from pathlib import Path
import subprocess
from native_driver_build import ROOT,NATIVE,require,sha

STAGES={'ios16-hid-source-interface':'prepare_hid_source_interface.py','ios16-hid-source-calls':'check_hid_source_calls.py',
        'ios16-hid-object-lifetime':'check_hid_object_lifetime.py','ios16-hid-event-abi':'prepare_hid_event_abi.py','ios16-input-hardware':'prepare_input_hardware.py',
        'ios16-touch-firmware':'prepare_input_firmware.py','ios16-input-cold-host':'check_input_cold_host.py','ios16-input-clock':'prepare_input_clock.py',
        'ios16-input-transfer-host':'check_input_transfer_host.py','ios16-hid-edge-host':'check_hid_edge_host.py','ios16-hid-edge-source':'build_hid_edge.py',
        'ios16-input-native':'build_input_native.py','ios16-input-prelink':'build_input_prelink.py','ios16-input-kernel':'check_input_kernel.py',
        'ios16-input-cold-kernel':'check_input_cold_kernel.py','ios16-input-clock-kernel':'check_input_clock_kernel.py',
        'ios16-input-transfer-kernel':'check_input_transfer_kernel.py','ios16-input-hid-parser':'check_hid_parser.py',
        'ios16-input-drain-kernel':'check_input_drain_kernel.py','ios16-hid-event-kernel':'check_hid_event_kernel.py',
        'ios16-hid-edge-kernel':'check_hid_edge_kernel.py','ios16-input-payload':'build_input_payload.py'}


def main():
    p=argparse.ArgumentParser();p.add_argument('--check-only',action='store_true');args=p.parse_args()
    if not args.check_only:
        for name,script in STAGES.items():
            python=ROOT/('.venv-gpu/bin/python' if name in ('ios16-hid-source-calls','ios16-hid-object-lifetime','ios16-input-kernel','ios16-input-cold-kernel','ios16-input-clock-kernel','ios16-input-transfer-kernel','ios16-input-hid-parser','ios16-input-drain-kernel','ios16-hid-event-kernel','ios16-hid-edge-kernel') else '.venv-uefi/bin/python')
            subprocess.run([python,ROOT/'scripts'/script],check=True)
    reports={n:json.loads((ROOT/'reports'/f'{n}.json').read_text()) for n in STAGES};artifacts={}
    for n,r in reports.items():
        require('PASS' in r['result'] and r['builder_sha256']==sha(ROOT/'scripts'/STAGES[n]),'Stale input stage: '+n)
        for path,h in r['source_sha256'].items():require(sha(ROOT/path)==h,'Input source changed: '+path)
        for field in ('header','contract','fact_manifest','reference_object','public_reference_object','binary','compile_manifest','cpu_cases','firmware','assembly','archive','isolated_kernel','link_manifest','link_command',
                      'candidate','sealed_native','emission_record','post_record','sealed_post_record','payload','boot_image'):
            if field in r and field+'_sha256' in r:
                require(sha(ROOT/r[field])==r[field+'_sha256'],'Input artifact changed: '+field);artifacts[r[field]]=r[field+'_sha256']
        for item in r.get('objects',[]):require(sha(ROOT/item['path'])==item['sha256'],'Input object changed');artifacts[item['path']]=item['sha256']
        for path,h in r.get('protected_default_artifact_sha256',{}).items():require(sha(ROOT/path)==h,'Input protected artifact changed: '+path)
        for name,h in r.get('dependency_report_sha256',{}).items():
            report=ROOT/'reports'/(name if name.endswith('.json') else name+'.json');require(sha(report)==h,'Input dependency report changed: '+name)
        require(not any(r.get(k) for k in ('ready_for_ios_boot','hardware_tested','runtime_qualified','enabled_by_default')),'Input stage overstates qualification')
    interface,calls,lifetime,event_abi,hardware,firmware,cold_host,clock,transfer_host,edge_host,edge_source,source,prelink,cpu,cold_cpu,clock_cpu,transfer_cpu,parser,drain,event_cpu,edge_cpu,payload=[reports[n] for n in STAGES]
    require(interface['concrete_vtable_entries']==207 and interface['compiled_probe_instance_bytes']==208 and not interface['full_private_prototypes_qualified'] and
            calls['interface_report_sha256']==sha(ROOT/'reports/ios16-hid-source-interface.json') and calls['case_count']==16 and len(calls['negative_controls'])==2,
            'Bounded original HID caller/interface evidence incomplete')
    require(lifetime['case_count']==7 and lifetime['unsafe_partial_free_control']['unsafe_free_fault_at_0x20_confirmed'] and
            source['objects_and_provider_pinned_before_original_init'] and source['failed_init_or_attach_is_latched_without_release'],
            'Original HID partial initialization hazard was not handled')
    require(not hardware['donor_ldob16_selected'] and not hardware['raw_gpio_flags_used_as_logical_level'],'Wrong target GPIO/rail interpretation')
    require(source['combined_source_objects']==81 and len(source['combined_original_bindings'])==332 and source['original_binding_count']==53 and
            source['compiled_instance_bytes']==1560 and source['concrete_vtable_entries']==207 and source['opaque_source_text_references']==0 and source['strict_no_undefined'] and
            source['initializer_removed_from_early_registration'] and not source['private_event_fields_or_vtables_modified'],'Native input source evidence incomplete')
    for key,count in (('power',26),('lifecycle',30),('late',28)):
        test=source['host_tests'][key];require(test['result']=='PASS' and test['case_count']==count and all(c['result']=='PASS' for c in test['cases']),'Input host cases incomplete: '+key)
        require(sha(ROOT/test['binary'])==test['sha256'],'Input host binary changed');artifacts[test['binary']]=test['sha256']
    require(firmware['firmware_words']==442 and firmware['configuration_entries']==69 and firmware['independent_original_module_payload_identical'] and
            source['embedded_spi_firmware_sha256']==firmware['firmware_sha256']==cold_host['firmware_sha256'] and not cold_host['synthetic_firmware'] and
            source['validated_gpio_input_or_disabled_transition_implemented'] and source['empty_idle_qup4_spi_firmware_loading_implemented'],
            'Exact stock firmware/cold preparation evidence missing')
    require(cold_host['case_count']==2813 and cold_host['tests']['geni']['fault_injections']==535 and cold_host['tests']['gpio']['case_count']==73,'Cold host coverage changed')
    require(clock['source_host_cases']==135 and clock['stopped_unvoted_non_dfs_xo_root_initialization_implemented'] and
            source['stopped_unvoted_non_dfs_xo_root_initialization_implemented'] and source['warm_spi_adoption_checks_foreign_dma_gpi_and_fifo'],
            'Cold clock and warm ownership evidence incomplete')
    test=clock['host_tests'];require(sha(ROOT/test['binary'])==test['sha256'],'Clock host binary changed');artifacts[test['binary']]=test['sha256']
    require(transfer_host['case_count']==224 and transfer_host['tests']['original-control']['result']=='REJECTED' and
            source['dma_command_data_and_idle_all_required'] and source['terminal_transfer_error_disables_future_io'] and
            source['concrete_input_uses_exactly_one_direct_guard_call'] and not source['concrete_input_calls_raw_transport_directly'],
            'Full GENI transfer/terminal ownership evidence incomplete')
    for test in transfer_host['tests'].values():
        require(sha(ROOT/test['binary'])==test['sha256'],'Transfer host/control binary changed');artifacts[test['binary']]=test['sha256']
    for test in cold_host['tests'].values():
        require(sha(ROOT/test['binary'])==test['sha256'],'Cold host binary changed');artifacts[test['binary']]=test['sha256']
    require(prelink['input_source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and prelink['native_source_input_sha256']==source['isolated_kernel_sha256'] and
            prelink['pointer_sites_read_back']==63889 and len(prelink['components'])==28 and len(prelink['kernel_interfaces'])==7 and
            prelink['combined_original_aliases']==332 and prelink['original_hid_parent_words_read_back']==209 and prelink['concrete_input_vtable_entries_read_back']==207 and
            prelink['darwinboot_production_parser']=='PASS' and all(c['result']=='REJECTED' for c in prelink['negative_controls']),'Original input prelink checks incomplete')
    require(cpu['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            cpu['candidate_sha256']==prelink['candidate_sha256'] and cpu['case_count']==11 and all(c['result']=='PASS' for c in cpu['cases']) and cpu['negative_controls'][0]['result']=='REJECTED',
            'Current input CPU checks missing')
    require(cold_cpu['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and cold_cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            cold_cpu['candidate_sha256']==prelink['candidate_sha256'] and cold_cpu['case_count']==18 and all(c['result']=='PASS' for c in cold_cpu['cases']),
            'Current linked cold parser/loader CPU checks missing')
    require(clock_cpu['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and clock_cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            clock_cpu['candidate_sha256']==prelink['candidate_sha256'] and clock_cpu['case_count']==18 and all(c['result']=='PASS' for c in clock_cpu['cases']),
            'Current linked target clock CPU checks missing')
    require(transfer_cpu['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and transfer_cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            transfer_cpu['candidate_sha256']==prelink['candidate_sha256'] and transfer_cpu['case_count']==20 and all(c['result']=='PASS' for c in transfer_cpu['cases']),
            'Current linked full GENI transfer/terminal CPU checks missing')
    require(parser['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and parser['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            parser['candidate_sha256']==prelink['candidate_sha256'] and parser['case_count']==12 and parser['report_case_count']==52 and
            parser['original_parser_instructions_unchanged'] and parser['actual_native_touch_decode_and_hid_report_executed'] and
            all(c['result']=='PASS' for c in parser['cases']) and parser['negative_controls'][0]['result']=='REJECTED',
            'Current original iPhone HID parser/native report checks missing')
    require(drain['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and drain['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            drain['candidate_sha256']==prelink['candidate_sha256'] and drain['case_count']==27 and all(c['result']=='PASS' for c in drain['cases']) and
            drain['deferred_provider_pin_balanced'] and drain['reentrant_stop_defers_parent_until_tick_exit'] and drain['negative_controls'][0]['result']=='REJECTED' and
            source['parent_cleanup_latched_before_original_start'] and source['start_and_stop_serialized_on_input_workloop'],
            'Current source gate/reentrant-stop/callback-drain evidence missing')
    require(event_abi['original_event_bytes']==80 and event_abi['original_event_slots']==37 and event_abi['original_driver_bytes']==264 and
            event_abi['original_driver_slots']==219 and event_abi['original_binding_count']==71 and event_abi['bindings_contain_no_implementation_bytes'] and
            event_cpu['interface_report_sha256']==sha(ROOT/'reports/ios16-hid-event-abi.json') and event_cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            event_cpu['candidate_sha256']==prelink['candidate_sha256'] and event_cpu['case_count']==32 and
            all(c['result']=='PASS' for c in event_cpu['cases']) and event_cpu['negative_controls'][0]['result']=='REJECTED',
            'Bounded original iPhone event source/bindings/body qualification incomplete')
    require(edge_host['case_count']==300 and edge_source['concrete_vtable_entries']==219 and edge_source['original_binding_count']==71 and
            source['edge_concrete_instance_bytes']==552 and source['edge_concrete_vtable_entries']==219 and source['edge_gesture_annotation_implemented'] and
            prelink['concrete_edge_vtable_entries_read_back']==219 and prelink['original_event_driver_parent_words_read_back']==221 and
            source['edge_personality_registered_in_kernel_namespace']=='__kernel__' and
            edge_cpu['source_report_sha256']==sha(ROOT/'reports/ios16-input-native.json') and edge_cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-input-prelink.json') and
            edge_cpu['candidate_sha256']==prelink['candidate_sha256'] and edge_cpu['case_count']==40 and
            all(c['result']=='PASS' for c in edge_cpu['cases']) and all(c['result']=='REJECTED' for c in edge_cpu['negative_controls']) and
            edge_cpu['unsafe_original_event_free_null_expansion_confirmed'],'Source edge class/parent/lifecycle evidence incomplete')
    require(payload['candidate_sha256']==prelink['candidate_sha256'] and payload['linked_source_objects']==81 and payload['original_components']==28 and
            payload['phone_operations']=='none' and not payload['explicit_input_argument_enabled'] and not payload['original_userspace_included'],'Input payload scope changed')
    for path,h in payload['artifacts'].items():require(sha(ROOT/path)==h,'Input payload artifact changed');artifacts[path]=h
    for path,h in json.loads((ROOT/source['link_manifest']).read_text()).items():require(sha(ROOT/path)==h,'Input native link manifest input changed: '+path)
    report={'result':'CPH2653_IOS16_INPUT_STORAGE_DISPLAY_OFFLINE_SOURCE_STACK_PASS','builder_sha256':sha(Path(__file__)),
            'stages':{n:{'report':'reports/'+n+'.json','report_sha256':sha(ROOT/'reports'/f'{n}.json'),'result':r['result']} for n,r in reports.items()},
            'artifacts':artifacts,'native_kernel_sha256':sha(NATIVE),'combined_source_objects':81,'combined_original_aliases':332,
            'native_entries':len(source['combined_native_entries']),'host_cases':3556,'lifecycle_and_existing_power_host_cases':84,'cold_gpio_and_firmware_host_cases':2813,'target_clock_host_cases':135,'transfer_terminal_host_cases':224,
            'edge_policy_host_cases':300,'source_edge_cpu_cases':40,
            'original_hid_caller_cpu_cases':16,'original_hid_lifetime_cpu_cases':7,'prelinked_source_cpu_cases':11,'prelinked_cold_firmware_cpu_cases':18,'prelinked_target_clock_cpu_cases':18,'prelinked_transfer_terminal_cpu_cases':20,
            'original_hid_parser_cpu_cases':12,'native_hid_report_metadata_cases':52,'original_hid_parser_qualified_for_linked_descriptors':True,
            'prelinked_input_stop_drain_cpu_cases':27,'start_stop_gated_and_reentrant_stop_defers_parent':True,
            'original_typed_event_accessor_and_dispatch_cpu_cases':32,'event_source_bindings':71,'event_edge_implementation_linked':True,
            'original_components':28,'original_pointer_readbacks':63889,'boot_image':payload['boot_image'],
            'source_private_event_vtable_or_fields_modified':False,'cold_pin_or_spi_firmware_loading_complete':False,'edge_gesture_annotation_implemented':True,
            'validated_gpio_direction_enable_initialization_implemented':True,'empty_idle_qup4_spi_firmware_loading_implemented':True,
            'stopped_unvoted_non_dfs_xo_root_initialization_implemented':True,'warm_spi_adoption_checks_foreign_dma_gpi_and_fifo':True,
            'dma_command_data_and_idle_all_required':True,'bounded_cancel_abort_and_channel_reset_ack_implemented':True,
            'terminal_transfer_error_disables_future_io':True,'post_error_reuse_enabled':False,'unchanged_original_early_dma_completion_control_rejected':True,
            'input_enabled_by_default':False,'hardware_tested':False,'ready_for_ios_boot':False,'all_ios_port_code_complete':False,
            'remaining':['Qualify actual SPMI/GPIO/VDD/clock/SPI/SMMU/DMA/reset takeover and touch orientation. Cold paths cover validated GPIO mode/enable, stopped unvoted non-DFS SE4 XO initialization and idle empty QUP4 stock SPI loading; shared-domain power/PLL/electrical recovery beyond these conditions remains incomplete.',
                         'Qualify full original IOHIDDevice and EventDriver lifecycle, element report dispatch, matching/client ordering and UI. Bounded source edge subclass/registration, 71 original data-only bindings, 32 original accessor/default-dispatch and 40 source edge/lifetime/loader paths are checked offline; full original parent lifecycle remains peer-bound.',
                         'Complete authenticated root, writable APFS Data, original crypto/security/PMGR lifecycle and remaining graphics/network/audio/charging/thermal code.'],
            'scope':'Twenty-two reproducible offline stages. Input polling/report/target-power policy, validated GPIO direction/enable, target clock ownership/XO initialization/live fractional-rate adoption, exact stock SPI firmware programming, full local GENI command/data/idle completion and terminal error/cancel/abort/reset-ACK policy, actual original iPhone C HID parser/cleanup and native report metadata, gated source start/stop and reentrant callback drain, concrete source edge subclass/deferred registration/kernel personality with bounded original accessor/dispatch checks and initialization pins, original-parent deferred loader and pinned one-shot lifecycle, '
                    'strict original iPhone prelink and local FAT/Android v4 container. Host and CPU evidence never imply working touch, UI or a complete iOS port.'}
    (ROOT/'reports/input-stack.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: twenty-two current input stages, 81 objects / 332 aliases / 3556 host cases / 201 CPU paths + 52 report cases; source edge class linked, no complete iOS or hardware qualification')

if __name__=='__main__':main()
