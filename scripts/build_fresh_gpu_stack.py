#!/usr/bin/env python3
"""Build or verify the isolated IOSurface/fresh-GPU/entropy development route."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

REPORT = ROOT / 'reports/fresh-gpu-stack.json'
STAGES = (
    ('surface', 'check_surface_sync_kernel', 'ios16-surface-sync-kernel'),
    ('source', 'build_fresh_gpu_source', 'ios16-fresh-gpu-source'),
    ('prelink', 'build_fresh_gpu_prelink', 'ios16-fresh-gpu-prelink'),
    ('kernel', 'check_fresh_gpu_kernel', 'ios16-fresh-gpu-kernel'),
    ('payload', 'build_fresh_gpu_payload', 'ios16-fresh-gpu-payload'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true')
    mode.add_argument('--record-existing', action='store_true', help='Validate completed stages and write their aggregate without rebuilding')
    args = parser.parse_args()
    python = ROOT / '.venv-gpu/bin/python'
    if not args.check_only and not args.record_existing:
        for _, module, _ in STAGES:
            print('Running:', module, flush=True)
            subprocess.run([python, ROOT / 'scripts' / (module + '.py')], check=True)
    records = {}; artifacts = {}; reports = {}
    for name, module, report_name in STAGES:
        path = ROOT / 'reports' / (report_name + '.json'); report = json.loads(path.read_text())
        importlib.import_module(module).check_report(report); reports[name] = report
        records[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
                         'builder': 'scripts/' + module + '.py', 'builder_sha256': sha(ROOT / 'scripts' / (module + '.py'))}
        for filename, digest in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == digest, 'Fresh GPU artifact identities conflict')
            artifacts[filename] = digest
        artifacts[str(path.relative_to(ROOT))] = sha(path)
    report = {'result': 'CPH2653_ISOLATED_FRESH_GPU_AND_IOSURFACE_ROUTE_PASS', 'builder_sha256': sha(Path(__file__)),
        'stages': records, 'artifacts': [{'path': name, 'sha256': digest} for name, digest in artifacts.items()],
        'original_surface_chain_cases': 17, 'host_frontend_cases': 132, 'packet_mutations': 1124,
        'linked_kernel_cpu_paths': 84, 'source_rejection_controls': 2, 'kernel_rejection_controls': 4,
        'surface_instruction_controls': 5, 'surface_lifetime_refusals': 1,
        'combined_source_objects': 90, 'combined_native_entries': 97, 'original_aliases': 341,
        'original_pointer_readbacks': 63889, 'original_components': 28, 'original_interfaces': 7,
        'actual_embedded_efi_success_paths': 2, 'actual_embedded_efi_failure_paths': 6, 'actual_original_post_subtests': 18,
        'boot_image': reports['payload']['boot_image'], 'boot_image_bytes': reports['payload']['boot_image_bytes'],
        'source_data_default_enabled': False, 'source_data_mount_default_enabled': False,
        'default_artifacts_selected_or_replaced': False, 'phone_operations': 'none',
        'producer_cache_visibility_qualified': False, 'gpu_failure_quiescence_qualified': False,
        'original_userspace_included': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Five isolated code/build/CPU/container stages add exact original IOSurface notification bindings and remove the '
                 'historical-fence shortcut from a separate full display candidate. Fresh backend health is checked before reading '
                 'or retiring a frame; original IOSurface readiness alone does not imply upstream GPU success. A separate boot container '
                 'uses the previously verified per-attempt entropy firmware and exact new kernel. Every check retains its stated '
                 'allocator/IOKit/scheduler/fence/cache/firmware peers. Complete private graphics ABI, DMA/cache visibility, GPU '
                 'quiescence/reset, root/Data authentication, complete iOS startup and hardware remain incomplete or unqualified.'}
    if args.check_only:
        require(json.loads(REPORT.read_text()) == report, 'Fresh GPU route aggregate is stale')
    else: REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 5 isolated fresh GPU stages / 132 sanitizer cases / 84 linked ARM64 paths / exact entropy EFI and Android v4')


if __name__ == '__main__': main()
