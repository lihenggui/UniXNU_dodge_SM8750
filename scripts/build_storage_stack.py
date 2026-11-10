#!/usr/bin/env python3
"""Build/check the isolated complete read-only UFS + display source route."""
import argparse
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT,NATIVE,require,sha

STAGES={'ios16-storage-abi':'prepare_storage_abi.py','ios16-ufs-root':'build_ufs_root.py',
        'ios16-storage-prelink':'build_ufs_prelink.py','ios16-ufs-kernel':'check_ufs_kernel.py','ios16-system-payload':'build_system_payload.py'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if not args.check_only:
        for name,script in STAGES.items():
            python=ROOT/('.venv-gpu/bin/python' if name=='ios16-ufs-kernel' else '.venv-uefi/bin/python')
            subprocess.run([python,ROOT/'scripts'/script],check=True)
    reports={n:json.loads((ROOT/'reports'/f'{n}.json').read_text()) for n in STAGES};artifacts={}
    for name,report in reports.items():
        require('PASS' in report['result'] and report['builder_sha256']==sha(ROOT/'scripts'/STAGES[name]),'Stale or failed storage stage: '+name)
        for path,h in report['source_sha256'].items():require(sha(ROOT/path)==h,'Storage source changed: '+path)
        for field in ('archive','compile_manifest','isolated_kernel','link_manifest','link_command','candidate','sealed_native','emission_record',
                      'post_record','sealed_post_record','cpu_cases','host_binary','combined_scheduling_host_binary','combined_native_filelist'):
            if field in report:
                require(sha(ROOT/report[field])==report[field+'_sha256'],'Storage artifact changed: '+field);artifacts[report[field]]=report[field+'_sha256']
        for item in report.get('objects',report.get('reference_objects',[])):
            require(sha(ROOT/item['path'])==item['sha256'],'Storage object changed');artifacts[item['path']]=item['sha256']
        for path,h in report.get('protected_default_artifact_sha256',{}).items():require(sha(ROOT/path)==h,'Protected/default artifact changed: '+path)
        require(not report.get('runtime_qualified') and not report.get('hardware_tested') and not report.get('ready_for_ios_boot'),
                'Offline storage stage overstates runtime qualification')
    abi,source,prelink,cpu,payload=[reports[n] for n in STAGES]
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    require(abi['contract_sha256']==lock['iphone_storage_abi']['sha256'] and abi['header_sha256']==lock['iphone_storage_abi']['header_sha256'] and
            abi['public_reference']==lock['iostorage_headers_reference'] and abi['instance_bytes']==144 and abi['vtable_entries']==190 and abi['pure_virtual_slots']==14 and
            abi['uses_real_pinned_iphone_sdk_conditionals'] and not abi['public_reference_implementation_linked_or_executed'],'Storage ABI provenance changed')
    require(source['storage_abi_report_sha256']==sha(ROOT/'reports/ios16-storage-abi.json') and source['display_kernel_report_sha256']==sha(ROOT/'reports/ios16-display-kernel.json') and
            source['native_kernel_sha256']==sha(NATIVE) and source['combined_source_objects']==68 and len(source['combined_native_entries'])==52 and
            len(source['combined_original_bindings'])==208 and source['original_binding_count']==12 and source['concrete_vtable_entries']==190 and
            source['compiled_instance_bytes']=={'driver':152,'block':216} and source['strict_no_undefined'] and
            source['root_publication_built'] and source['root_layout_and_async_media_publication_included'] and source['read_only'] and not source['probe_only'],
            'Full storage source/combined kernel evidence is incomplete')
    require(source['host_tests']['case_count']==32 and source['combined_scheduling_host_tests']['case_count']==25 and
            source['probe_matching_host_test']['case_count']==11 and source['probe_matching_host_test']['unmodified_reference_control']=='REJECTED' and
            source['root_publication_host_test']['result']=='PASS' and source['initializer_removed_from_early_registration'] and source['actual_early_constructor_count']==99,
            'Storage source lacks lifecycle/matching/publication/ordering checks')
    for field in ('host_tests','combined_scheduling_host_tests'):
        require(source[field]['result']=='PASS' and all(c['result']=='PASS' for c in source[field]['cases']),'Storage source host case failed')
    for field in ('root_publication_host_test','probe_matching_host_test'):
        test=source[field];require(sha(ROOT/test['binary'])==test['sha256'],'Storage production host binary changed');artifacts[test['binary']]=test['sha256']
    probe=source['probe_matching_host_test'];require(sha(ROOT/probe['extract'])==probe['extract_sha256'],'UFS probe extraction changed')
    overlay=source['native_object_overlay'];require(overlay['patch']==lock['dodge_system_late_overlay'],'System hook patch changed')
    for field in ('source','object','compile_manifest'):
        require(sha(ROOT/overlay[field])==overlay[field+'_sha256'],'System overlay changed: '+field);artifacts[overlay[field]]=overlay[field+'_sha256']
    require(source['overlay']==lock['dodge_ufs_root_overlay'] and sha(ROOT/source['overlay']['path'])==source['overlay']['sha256'] and
            sha(ROOT/overlay['patch']['path'])==overlay['patch']['sha256'],'Storage overlay content changed')
    require(set(source['former_weak_diagnostics_now_real_storage'])=={'_native_ufs_block_reads','_native_ufs_block_failures'} and
            len(source['remaining_absent_weak_diagnostics'])==7,'Real UFS counters were not connected correctly')
    require(prelink['root_source_report_sha256']==sha(ROOT/'reports/ios16-ufs-root.json') and prelink['native_source_input_sha256']==source['isolated_kernel_sha256'] and
            prelink['combined_source_objects']==68 and prelink['original_aliases_read_back']==208 and prelink['native_source_entries_preserved']==52 and
            prelink['pointer_sites_read_back']==58962 and len(prelink['components'])==27 and len(prelink['kernel_interfaces'])==7 and
            prelink['darwinboot_production_parser']=='PASS' and len(prelink['negative_controls'])==7 and
            all(c['result']=='REJECTED' for c in prelink['negative_controls']),'Combined storage prelink is stale or incomplete')
    require(cpu['prelink_report_sha256']==sha(ROOT/'reports/ios16-storage-prelink.json') and cpu['root_source_report_sha256']==sha(ROOT/'reports/ios16-ufs-root.json') and
            cpu['candidate_sha256']==prelink['candidate_sha256'] and cpu['case_count']==len(cpu['cases'])==11 and
            all(c['result']=='PASS' for c in cpu['cases']) and cpu['full_original_display_lifecycle_on_combined_kernel_cases']==3 and
            cpu['negative_controls'][0]['result']=='REJECTED','Linked storage/display/IOBSD CPU evidence is stale or incomplete')
    require(payload['candidate_sha256']==prelink['candidate_sha256'] and payload['linked_source_objects']==68 and payload['native_source_entries']==52 and
            payload['storage_before_graphics_iobsd_hook_linked'] and not payload['explicit_root_argument_enabled'] and not payload['explicit_graphics_argument_enabled'] and
            not payload['original_userspace_included'] and payload['boot_payload_packaged'] and payload['phone_operations']=='none','Combined container scope changed')
    for name,h in payload['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==h,'System payload dependency changed: '+name)
    for path,h in payload['artifacts'].items():require(sha(ROOT/path)==h,'System payload artifact changed');artifacts[path]=h
    report={'result':'CPH2653_IOS16_READ_ONLY_STORAGE_DISPLAY_OFFLINE_SOURCE_STACK_PASS','native_kernel_sha256':sha(NATIVE),
            'stages':{n:{'report':'reports/'+n+'.json','report_sha256':sha(ROOT/'reports'/f'{n}.json'),'result':r['result']} for n,r in reports.items()},
            'artifacts':artifacts,'combined_source_objects':68,'original_bindings':208,'native_entries':52,'host_lifecycle_cases':32,'host_scheduling_cases':25,
            'host_matching_cases':11,'linked_cpu_cases':11,'boot_image':payload['boot_image'],'root_window_publication_source_built':True,
            'default_artifacts_unchanged':True,'root_authenticated':False,'original_userspace_included':False,'physical_partition_modified':False,
            'root_argument_enabled_by_default':False,'graphics_argument_enabled_by_default':False,'hardware_tested':False,'ready_for_ios_boot':False,'all_ios_port_code_complete':False,
            'remaining':['Qualify actual UFS/SMMU/DMA ownership and reset, physical partition layout and original storage completion/matching ABI.',
                         'Finish authenticated APFS root and writable Data preparation, actual crypto/security/power lifecycle.',
                         'Complete and qualify touch/HID, remaining private graphics ABI, networking/audio/charging/thermal services.'],
            'scope':'Five current source/build/static-prelink/CPU/container stages. Full read-only transport/root-window publisher and combined opt-in startup are compiled, '
                    'linked with exact iPhone originals and packaged locally. No phone, physical storage, authenticated root or working iOS result.'}
    (ROOT/'reports/storage-stack.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: five current storage/display stages, 68 objects / 208 aliases / 52 entries; source and artifacts fresh, runtime and whole-iOS completion false')


if __name__=='__main__':main()
