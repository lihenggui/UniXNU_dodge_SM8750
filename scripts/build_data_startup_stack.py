#!/usr/bin/env python3
"""Build/check the separate queued Data startup, exact loader handoff and container."""
import argparse
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

STAGES = (
    ('ios16-data-startup', 'build_data_startup.py'),
    ('ios16-data-startup-prelink', 'build_data_startup_prelink.py'),
    ('ios16-data-startup-kernel', 'check_data_startup_kernel.py'),
    ('ios16-data-payload', 'build_data_payload.py'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_data_stack.py', '--check-only'], check=True)
    if not args.check_only:
        for name, script in STAGES:
            interpreter = '.venv-gpu/bin/python' if name == 'ios16-data-startup-kernel' else '.venv-uefi/bin/python'
            subprocess.run([ROOT / interpreter, ROOT / 'scripts' / script], check=True)
    reports, artifacts, hashes = {}, {}, {}
    def digest(path):
        if path not in hashes: hashes[path] = sha(path)
        return hashes[path]
    for name, script in STAGES:
        path = ROOT / 'reports' / (name + '.json')
        report = json.loads(path.read_text())
        require('PASS' in report['result'] and report['builder_sha256'] == digest(ROOT / 'scripts' / script), 'Data startup stage is stale: ' + name)
        for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
            require(digest(ROOT / filename) == value, 'Data startup source/dependency/artifact changed: ' + filename)
        require(not any(report.get(key) for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                    'ramblock_metadata_registered_or_started', 'original_apfs_data_mount_qualified', 'source_data_default_enabled')),
                'Data startup stage overstates qualification: ' + name)
        reports[name] = report
        for filename, value in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == value, 'Conflicting Data startup artifact')
            artifacts[filename] = value
        artifacts[str(path.relative_to(ROOT))] = digest(path)
    source, prelink, cpu, payload = [reports[name] for name, _ in STAGES]
    require(source['combined_source_objects'] == prelink['combined_source_objects'] == payload['linked_source_objects'] == 84 and
            source['combined_original_aliases'] == prelink['combined_original_aliases'] == 332 and
            len(source['combined_native_entries']) == prelink['native_source_entries_preserved'] == payload['native_source_entries'] == 85,
            'Data startup source/link geometry differs')
    host = source['host_tests']
    require(host['case_count'] == len(host['cases']) == 30 and all(c['result'] == 'PASS' for c in host['cases']) and
            cpu['case_count'] == 43 and cpu['scheduler_case_count'] == len(cpu['scheduling_cases']) == 13 and
            cpu['data_case_count'] == len(cpu['data_cases']) == 30 and all(c['result'] == 'PASS' for c in cpu['scheduling_cases'] + cpu['data_cases']) and
            cpu['candidate_sha256'] == prelink['candidate_sha256'] == payload['candidate_sha256'], 'Data startup host/CPU evidence incomplete')
    require(len(prelink['components']) == 28 and len(prelink['kernel_interfaces']) == 7 and prelink['pointer_sites_read_back'] == 63889 and
            prelink['actual_iobsd_hook'] == source['actual_iobsd_hook'] and prelink['darwinboot_production_parser'] == 'PASS' and
            payload['logical_data_bytes'] == 2 << 30 and payload['packed_seed_bytes'] == 721024 and
            payload['actual_loader_adt_and_packed_parsers_passed'] and payload['loader_keeps_packed_input'] and
            not payload['loader_dense_2GiB_allocation_required'] and payload['source_data_startup_and_payload_wired'] and
            payload['all_original_adt_values_preserved'] and payload['boot_header_version'] == 4, 'Data payload/loader evidence incomplete')
    controls = [c for report in reports.values() for c in report['negative_controls']]
    require(len(controls) == 24 and all(c['result'] == 'REJECTED' for c in controls), 'Data startup rejection controls differ')
    base_path = ROOT / 'reports/data-stack.json'; base = json.loads(base_path.read_text())
    report = {'result': 'CPH2653_IPHONE_IOS16_DATA_STARTUP_AND_PAYLOAD_STACK_PASS', 'builder_sha256': digest(Path(__file__)),
              'source_sha256': {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
              'base_data_report': str(base_path.relative_to(ROOT)), 'base_data_report_sha256': digest(base_path),
              'stages': {name: {'report': 'reports/' + name + '.json', 'sha256': digest(ROOT / 'reports' / (name + '.json')), 'result': reports[name]['result']}
                         for name, _ in STAGES},
              'artifacts': [{'path': filename, 'sha256': value, 'role': 'Separate default-off Data startup/loader/container evidence'} for filename, value in sorted(artifacts.items())],
              'new_scheduler_host_cases': 30, 'total_distinct_data_source_host_cases': base['host_cases'] + 30,
              'prelinked_cpu_cases_this_candidate': 43, 'new_scheduler_cpu_cases': 13, 'retained_data_cpu_cases_rerun': 30,
              'startup_negative_controls': 24, 'combined_source_objects': 84, 'native_entries': 85, 'combined_original_aliases': 332,
              'original_components': 28, 'kernel_interfaces': 7, 'original_pointer_sites_read_back': 63889,
              'boot_image': payload['boot_image'], 'boot_image_bytes': payload['boot_image_bytes'], 'boot_image_sha256': payload['boot_image_sha256'],
              'packed_seed_bytes': payload['packed_seed_bytes'], 'logical_data_bytes': 2 << 30,
              'source_data_startup_and_payload_route_wired': True, 'data_source_default_enabled': False,
              'original_data_mount_qualified': False, 'writable_data_runtime_qualified': False,
              'original_userspace_or_root_windows_in_boot_container': False, 'hardware_tested': False, 'phone_operations': 'none',
              'default_kernel_selected': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'remaining': ['Prepare and qualify the exact iPhone original APFS Data mount, complete parent/registry/media matching and crypto/power lifecycle.',
                            'Complete remaining private graphics/event ABI and platform peripherals; all host/CPU evidence remains separate from phone execution.'],
              'scope': 'Four additional isolated startup stages retain the six-stage/83-object Data baseline. '
                       'The 84-object candidate queues Data after system scheduling and packages the exact 2 GiB seed with a preserved iPhone ADT and PackedRAMDisk handoff. '
                       'Thirty new scheduler sanitizer cases, 43 CPU paths in this candidate, 24 rejection controls, original pointer/code and full FAT/Android container readback pass. '
                       'The default-off route does not claim original Data mount, physical loader allocation, registry/UI or a working iPhone system.'}
    (ROOT / 'reports/data-startup-stack.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: four Data startup stages / 84 objects / 30 scheduler sanitizer cases / 43 CPU paths / 24 rejection controls; packed seed/container read back')


if __name__ == '__main__':
    main()
