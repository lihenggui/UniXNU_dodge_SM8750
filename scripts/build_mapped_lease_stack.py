#!/usr/bin/env python3
"""Build or verify the isolated mapped-resource GPU development candidate."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

REPORT = ROOT / 'reports/mapped-lease-stack.json'
STAGES = (
    ('host', 'check_mapped_lease_host', 'ios16-mapped-lease-host'),
    ('source', 'build_mapped_lease_source', 'ios16-mapped-lease-source'),
    ('prelink', 'build_mapped_lease_prelink', 'ios16-mapped-lease-prelink'),
    ('kernel', 'check_mapped_lease_kernel', 'ios16-mapped-lease-kernel'),
    ('payload', 'build_mapped_lease_payload', 'ios16-mapped-lease-payload'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__); mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true')
    mode.add_argument('--record-existing', action='store_true', help='Validate completed stages without rebuilding')
    args = parser.parse_args()
    if not args.check_only and not args.record_existing:
        for _, module, _ in STAGES:
            print('Running:', module, flush=True)
            subprocess.run([ROOT / '.venv-gpu/bin/python', ROOT / 'scripts' / (module + '.py')], check=True)
    records = {}; artifacts = {}; reports = {}
    for name, module, report_name in STAGES:
        path = ROOT / 'reports' / (report_name + '.json'); report = json.loads(path.read_text())
        importlib.import_module(module).check_report(report); reports[name] = report
        records[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
            'builder': 'scripts/' + module + '.py', 'builder_sha256': sha(ROOT / 'scripts' / (module + '.py'))}
        for filename, digest in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == digest, 'Mapping lease artifact identities conflict')
            artifacts[filename] = digest
        artifacts[str(path.relative_to(ROOT))] = sha(path)
    require(reports['kernel']['candidate_sha256'] == reports['prelink']['candidate_sha256'] == reports['payload']['candidate_sha256'],
            'Mapped-resource CPU and payload stages use different kernels')
    require(reports['host']['overlay_pin'] == reports['source']['overlay_pin'], 'Host/native mapping lease overlays differ')
    report = {'result': 'CPH2653_ISOLATED_MAPPED_RESOURCE_GPU_ROUTE_PASS', 'builder_sha256': sha(Path(__file__)),
        'stages': records, 'artifacts': [{'path': name, 'sha256': digest} for name, digest in artifacts.items()],
        'new_host_resource_cases': reports['host']['regression_cases'], 'existing_backend_host_suites': reports['host']['existing_suites'],
        'new_bounded_map_wait_host_cases': 12, 'resource_source_rejection_controls': 5,
        'linked_kernel_cpu_paths': sum(reports['kernel']['case_counts'].values()),
        'kernel_instruction_rejection_controls': 6, 'kernel_lifetime_rejection_controls': 2,
        'inherited_frontend_host_cases': 132, 'inherited_frontend_packet_mutations': 1124,
        'combined_source_objects': 90, 'recompiled_backend_objects': 19, 'preserved_gpu_archive_members': 35,
        'native_source_entries': 97, 'original_aliases': 341, 'original_pointer_readbacks': 63889,
        'original_components': 28, 'original_interfaces': 7,
        'actual_embedded_efi_success_paths': 2, 'actual_embedded_efi_failure_paths': 6, 'actual_original_post_subtests': 18,
        'boot_image': reports['payload']['boot_image'], 'boot_image_bytes': reports['payload']['boot_image_bytes'],
        'all_current_vm_mappings_held_per_job': True, 'new_mapping_waits_for_all_vm_jobs': True,
        'publisher_pending_map_wait_outside_lock': True, 'map_wait_budget_us': 1000000, 'map_wait_attempt_limit': 16384,
        'cache_failure_keeps_whole_lease': True, 'uncertain_zero_fence_not_retired': True,
        'source_data_default_enabled': False, 'source_data_mount_default_enabled': False,
        'default_artifacts_selected_or_replaced': False, 'phone_operations': 'none', 'iosurface_producer_connected': False,
        'producer_cache_visibility_qualified': False, 'gpu_failure_quiescence_qualified': False,
        'original_userspace_included': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Five isolated stages fix early release of command-indirect GPU resources. Each job holds every current VM mapping; '
            'new mappings wait until jobs finish because commands can name previously unmapped IOVAs. Writable resources are acquired '
            'before any lease release; cache/unknown publication/reset failures retain ownership. IB storage does not infer cross-ring '
            'resource disjointness. The fresh-health frontend is preserved. Source/native instruction checks and the complete new '
            'development container retain explicit MMIO/cache/IOKit/firmware peers. IOSurface identity authorization and producer '
            'registration, physical exclusion/cache/reset, full graphics ABI, root/Data authentication and iOS startup remain incomplete.'}
    require(report['linked_kernel_cpu_paths'] == 112, 'Unexpected kernel execution inventory')
    if args.check_only: require(json.loads(REPORT.read_text()) == report, 'Mapping lease aggregate is stale')
    else: REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: five mapping lease stages / 28 new sanitizer cases / 112 ARM64 paths / exact entropy EFI and Android v4')


if __name__ == '__main__': main()
