#!/usr/bin/env python3
"""Build/check the exact-iPhone APFS request, init mount route and isolated container."""
import argparse
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

STAGES = (
    ('ios16-apfs-mount-abi', 'prepare_apfs_mount_abi.py', 'uefi'),
    ('ios16-apfs-mount-program', 'check_apfs_mount_program.py', 'gpu'),
    ('ios16-apfs-mount-source', 'build_apfs_mount_args.py', 'uefi'),
    ('ios16-data-mount-native', 'build_data_mount_source.py', 'uefi'),
    ('ios16-data-mount-prelink', 'build_data_mount_prelink.py', 'uefi'),
    ('ios16-data-mount-kernel', 'check_data_mount_kernel.py', 'gpu'),
    ('ios16-data-mount-payload', 'build_data_mount_payload.py', 'uefi'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_data_startup_stack.py', '--check-only'], check=True)
    if not args.check_only:
        for name, script, environment in STAGES:
            subprocess.run([ROOT / ('.venv-' + environment + '/bin/python'), ROOT / 'scripts' / script], check=True)
    reports, artifacts, cache = {}, {}, {}
    def digest(path):
        if path not in cache: cache[path] = sha(path)
        return cache[path]
    for name, script, _ in STAGES:
        path = ROOT / 'reports' / (name + '.json')
        report = json.loads(path.read_text())
        require('PASS' in report['result'] and report['builder_sha256'] == digest(ROOT / 'scripts' / script), 'Data mount stage is stale: ' + name)
        for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
            require(digest(ROOT / filename) == value, 'Data mount source/dependency/artifact changed: ' + filename)
        require(not any(report.get(key) for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                    'full_apfs_mount_qualified', 'original_apfs_data_mount_qualified', 'original_root_authentication_qualified',
                    'source_data_default_enabled', 'source_data_mount_default_enabled', 'filesystem_mounted_in_host_or_phone')),
                'Data mount stage overstates runtime qualification: ' + name)
        reports[name] = report
        for filename, value in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == value, 'Conflicting Data mount artifact')
            artifacts[filename] = value
        artifacts[str(path.relative_to(ROOT))] = digest(path)
    abi, program, helper, native, prelink, cpu, payload = [reports[name] for name, _, _ in STAGES]
    require(abi['user_buffer_bytes'] == 336 and abi['apfs_copyin_bytes'] == 324 and program['case_count'] == 19 and
            program['pinned_original_apple_getmntopts_source_executed_in_host_peer'] and
            helper['sanitizer_case_count'] == 16 and helper['original_request_comparison_count'] == 12, 'Exact ordinary-request evidence differs')
    require(native['combined_source_objects'] == prelink['combined_source_objects'] == payload['linked_source_objects'] == 87 and
            len(native['combined_native_entries']) == prelink['native_source_entries_preserved'] == payload['native_source_entries'] == 91 and
            native['combined_original_aliases'] == prelink['combined_original_aliases'] == 332, 'Init mount source/link geometry differs')
    require(native['init_boot_call_site_wired'] and prelink['init_boot_call_site_wired'] and payload['init_boot_call_site_wired'] and
            native['actual_init_hook'] == prelink['actual_init_hook'] and native['actual_iobsd_hook'] == prelink['actual_iobsd_hook'],
            'Actual IOBSD/init source hooks differ')
    require(cpu['case_count'] == 80 and [len(cpu[key]) for key in ('request_cases', 'original_copyin_cases', 'mount_coordinator_cases', 'actual_init_function_cases')]
            == [12, 4, 52, 12] and all(row['result'] == 'PASS' for key in ('request_cases', 'original_copyin_cases', 'mount_coordinator_cases', 'actual_init_function_cases')
                                      for row in cpu[key]), 'Actual Data mount CPU paths are incomplete')
    require(cpu['candidate_sha256'] == prelink['candidate_sha256'] == payload['candidate_sha256'] and
            len(prelink['components']) == 28 and len(prelink['kernel_interfaces']) == 7 and prelink['pointer_sites_read_back'] == 63889 and
            prelink['darwinboot_production_parser'] == 'PASS', 'Exact original prelink/readback evidence differs')
    require(payload['actual_loader_adt_and_packed_parsers_passed'] and payload['loader_keeps_packed_input'] and
            not payload['loader_dense_2GiB_allocation_required'] and payload['packed_seed_bytes'] == 721024 and
            payload['logical_data_bytes'] == 1 << 31 and payload['boot_image_bytes'] == 170557440 and payload['boot_header_version'] == 4 and
            payload['all_original_adt_values_preserved'] and not payload['original_userspace_included'] and not payload['original_root_windows_included'],
            'Data mount development container evidence differs')
    controls = [control for report in reports.values() for control in report['negative_controls']]
    require(len(controls) == 32 and all(row['result'] == 'REJECTED' for row in controls), 'Data mount rejection controls differ')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    require(program['option_library_reference'] == lock['apfs_mount_options_reference'], 'Apple option parser pin changed')
    previous = ROOT / 'reports/data-startup-stack.json'
    report = {'result': 'CPH2653_IPHONE_IOS16_INIT_DATA_MOUNT_PREPARATION_STACK_PASS', 'builder_sha256': digest(Path(__file__)),
              'source_sha256': {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
              'base_data_startup_report': str(previous.relative_to(ROOT)), 'base_data_startup_report_sha256': digest(previous),
              'stages': {name: {'report': 'reports/' + name + '.json', 'sha256': digest(ROOT / 'reports' / (name + '.json')),
                               'result': reports[name]['result']} for name, _, _ in STAGES},
              'artifacts': [{'path': name, 'sha256': value, 'role': 'Isolated exact-iPhone APFS/init/Data preparation; runtime limits follow stage report'}
                            for name, value in sorted(artifacts.items())],
              'new_request_sanitizer_cases': 16, 'total_data_source_sanitizer_cases': 123,
              'original_mount_program_cpu_cases': 19, 'source_and_original_prefix_cpu_cases': 80,
              'source_request_cpu_cases': 12, 'original_apfs_copyin_cpu_cases': 4, 'mount_coordinator_cpu_cases': 52, 'actual_init_cpu_cases': 12,
              'negative_controls': 32, 'combined_source_objects': 87, 'native_entries': 91, 'combined_original_aliases': 332,
              'original_components': 28, 'kernel_interfaces': 7, 'original_pointer_sites_read_back': 63889,
              'boot_image': payload['boot_image'], 'boot_image_bytes': payload['boot_image_bytes'], 'boot_image_sha256': payload['boot_image_sha256'],
              'packed_seed_bytes': payload['packed_seed_bytes'], 'logical_seed_bytes': payload['logical_data_bytes'],
              'init_boot_call_site_wired': True, 'source_data_mount_default_enabled': False,
              'original_apfs_data_mount_qualified': False, 'original_root_authentication_qualified': False,
              'writable_data_runtime_qualified': False, 'hardware_tested': False, 'phone_operations': 'none',
              'default_kernel_selected': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'remaining': ['Qualify actual original storage parent/IORegistry/media and the complete APFS mount/crypto lifecycle on the native platform.',
                            'Qualify the complete original-root boot/security path, remaining private graphics/event ABI and board peripherals.'],
              'scope': 'Seven additional isolated stages preserve the six-stage Data seeds and four-stage startup candidate. Exact original iPhone '
                       'mount_apfs and APFS copyin define the ordinary request, with a pinned Apple C option-parser peer. Sixteen new sanitizer cases, '
                       '19 original-program and 80 source/original-prefix CPU paths, 32 rejection controls and an 87-object/91-entry strict prelink pass. '
                       'Actual load_init_program calls a default-off bounded process-context Data gate before init loading; failures stop that modeled route. '
                       'The separate packed-seed/ADT/FAT/Android container is read back. Explicit peers do not authenticate or mount a real filesystem '
                       'and no working iPhone iOS or complete-port result is claimed.'}
    (ROOT / 'reports/data-mount-stack.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: seven init/Data mount stages / 87 objects / 19 original-program + 80 native/original-prefix CPU paths / 32 rejection controls / container readback')


if __name__ == '__main__':
    main()
