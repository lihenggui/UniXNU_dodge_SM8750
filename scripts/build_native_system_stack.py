#!/usr/bin/env python3
"""Build/check both native iPhone owner-system packages, preserving all default artifacts."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess
import sys

from native_driver_build import ROOT, require, sha

REPORT = ROOT / 'reports/ios16-native-system-stack.json'
STAGES = (
    ('portable', 'check_owner_system_host', (), 'ios16-owner-system-host'),
    ('calendar', 'build_platform_calendar', (), 'ios16-platform-calendar'),
    ('TRNG', 'build_native_entropy', (), 'ios16-native-entropy'),
    ('user_entropy', 'build_user_entropy', (), 'ios16-user-entropy'),
    ('store_host', 'check_native_store_host', (), 'ios16-native-store-host'),
    ('root_policies', 'prepare_native_root_policies', (), 'ios16-native-root-policies'),
    ('root_policy_loader', 'check_root_policy_source_host', (), 'ios16-root-policy-source-host'),
    ('seed_sync', 'build_seed_sync', (), 'ios16-seed-close-sync'),
    ('hid_lifecycle_source', 'build_hid_lifecycle', (), 'ios16-hid-lifecycle-source'),
    ('original_hid_lifetime', 'check_hid_original_lifecycle', (), 'ios16-hid-original-lifecycle'),
    ('kernel', 'build_native_system', (), 'ios16-native-system-kernel'),
    ('persistent_kernel', 'build_native_system', ('--persistent-data',), 'ios16-native-system-kernel-persistent'),
    ('hid_lifecycle', 'check_hid_lifecycle_kernel', (), 'ios16-hid-lifecycle-kernel'),
    ('seed_lifecycle', 'check_seed_sync_kernel', (), 'ios16-seed-close-kernel'),
    ('original_prng', 'check_native_prng', (), 'ios16-native-prng-check'),
    ('startup', 'check_native_system', (), 'ios16-native-system-check'),
    ('persistent_startup', 'check_native_system', ('--persistent-data',), 'ios16-native-system-check-persistent'),
    ('payload', 'build_native_system_payload', (), 'ios16-native-system-payload'),
    ('persistent_payload', 'build_native_system_payload', ('--persistent-data',), 'ios16-native-system-payload-persistent'),
)


def collect():
    stages, reports = {}, {}
    for name, module, arguments, filename in STAGES:
        path = ROOT / 'reports' / (filename + '.json');row = json.loads(path.read_text())
        importlib.import_module(module).check_report(row)
        require('PASS' in row['result'] and row['hardware_tested'] is False, 'Incomplete native system stage: ' + name)
        script = ROOT / 'scripts' / (module + '.py')
        stages[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path), 'builder': str(script.relative_to(ROOT)),
            'builder_sha256': sha(script), 'arguments': list(arguments)};reports[name] = row
    kernel, persistent = reports['kernel'], reports['persistent_kernel']
    require(not kernel['persistent_store_capable'] and persistent['persistent_store_capable'] and
        kernel['candidate_sha256'] != persistent['candidate_sha256'] and kernel['ufs_methods'] == persistent['ufs_methods'] and
        kernel['components'] == persistent['components'] and kernel['root_transports_readonly'] and persistent['root_transports_readonly'],
        'Native system variants differ in their root identity/interface or persistence capability')
    for variant in ('payload', 'persistent_payload'):
        package = reports[variant]
        require(package['root_image_sha256'] == reports['payload']['root_image_sha256'] and package['original_POST_tests_in_model'] == 18,
            'Native system packages differ in original roots or actual POST coverage')
        require(package['boot_image_bytes'] <= package['captured_boot_partition_bytes'], 'Native system package exceeds its captured boot capacity')
    return {'result': 'IOS16_NATIVE_SYSTEM_SOURCE_AND_LOCAL_PACKAGES_STACK_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__))}, 'stages': stages,
        'linked_source_and_binding_objects': kernel['linked_source_and_binding_objects'], 'original_components': len(kernel['components']),
        'pointer_sites_read_back': kernel['pointer_sites_read_back'], 'native_store_host_cases': reports['store_host']['case_count'],
        'TRNG_host_cases': reports['TRNG']['host_cases'], 'calendar_host_cases': reports['calendar']['host_cases'],
        'user_reseed_host_requests': reports['user_entropy']['host_concurrent_reseeds'],
        'original_PRNG_counter_reads': reports['original_prng']['execution']['real_counters_read'],
        'original_PRNG_paths_resolved': reports['original_prng']['execution']['unique_paths_resolved'],
        'seed_close_sync_host_cases': reports['seed_sync']['host_cases'],
        'seed_close_native_cases': len(reports['seed_lifecycle']['native_cases']),
        'original_seed_save_cases': len(reports['seed_lifecycle']['original_saver_cases']),
        'HID_lifecycle_host_cases': len(reports['hid_lifecycle_source']['host_cases']),
        'HID_lifecycle_native_cases': len(reports['hid_lifecycle']['cases']),
        'original_HID_lifetime_cases': len(reports['original_hid_lifetime']['cases']),
        'external_policy_host_cases': reports['root_policies']['host_cases'],
        'external_policy_loader_host_cases': reports['root_policy_loader']['case_count'],
        'boot_partition_bytes': reports['payload']['captured_boot_partition_bytes'],
        'boot_image_bytes': reports['payload']['boot_image_bytes'],
        'captured_root_partition_present': reports['root_policies']['root_partition_present_in_capture'],
        'boot_image': reports['payload']['boot_image'], 'persistent_boot_image': reports['persistent_payload']['boot_image'],
        'root_image': reports['payload']['root_image'], 'root_image_sha256': reports['payload']['root_image_sha256'],
        'root_image_bytes': reports['payload']['root_image_bytes'], 'build_jobs': 4, 'host_limits': 'inherited',
        'hardware_tested': False, 'physical_storage_written': False, 'hardware_data_protection': False,
        'full_system_booted': False, 'graphical_interface_tested': False, 'all_ios_port_code_complete': False, 'phone_operations': 'none',
        'remaining_source': ['SM8750 security-state/PMGR mapping and battery/charging/thermal/sleep',
            'complete original graphics/Metal/client and HID lifetime integration',
            'saved PRNG-seed crash/replacement and persistent-installation policy',
            'network/Bluetooth/audio/cellular board transports and iPhone clients'],
        'scope': 'Nineteen local source/check/package stages for native SM8750 owner-development iPhone boot. '
        'Both kernels retain signed read-only OS/SystemOS windows, original iPhone components and the exact firmware memory patch. '
        'The persistent-capable variant confines writes to an explicitly opened bounded Data overlay; neither package resets existing Data. '
        'Actual EFI/native/original crypto POST and startup/refusal/client instruction models pass. Source preparation remains incomplete '
        'for the listed subsystems; host results do not qualify native hardware or a working graphical system.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__);mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true');mode.add_argument('--record-existing', action='store_true');args = parser.parse_args()
    if not args.check_only and not args.record_existing:
        for name, module, arguments, _ in STAGES:
            print('BUILD:', name, flush=True)
            subprocess.run([sys.executable, ROOT / 'scripts' / (module + '.py'), *arguments], cwd=ROOT, check=True)
    report = collect()
    if args.check_only:require(json.loads(REPORT.read_text()) == report, 'Native system stack record is stale')
    else:REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native system source, nineteen stages and two local iPhone boot/root packages within captured boot capacity')


if __name__ == '__main__':main()
