#!/usr/bin/env python3
"""Build or verify the isolated task-aware original IOSurface identity route."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

REPORT = ROOT / 'reports/surface-identity-stack.json'
STAGES = (
    ('source', 'build_surface_identity', 'ios16-surface-identity-source'),
    ('prelink', 'build_surface_identity_prelink', 'ios16-surface-identity-prelink'),
    ('kernel', 'check_surface_identity_kernel', 'ios16-surface-identity-kernel'),
)


def main():
    p = argparse.ArgumentParser(description=__doc__); mode = p.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true'); mode.add_argument('--record-existing', action='store_true'); args = p.parse_args()
    if not args.check_only and not args.record_existing:
        for _, module, name in STAGES:
            command = [ROOT / '.venv-gpu/bin/python', ROOT / 'scripts' / (module + '.py')]
            if (ROOT / 'reports' / (name + '.json')).exists(): command += ['--check-only']
            subprocess.run(command, check=True)
    stages = {}; artifacts = {}; reports = {}
    for name, module, report_name in STAGES:
        path = ROOT / 'reports' / (report_name + '.json'); report = json.loads(path.read_text())
        importlib.import_module(module).check_report(report); reports[name] = report
        stages[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
                       'builder': 'scripts/' + module + '.py', 'builder_sha256': sha(ROOT / 'scripts' / (module + '.py'))}
        for filename, digest in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == digest, 'Identity artifact identities conflict'); artifacts[filename] = digest
        artifacts[str(path.relative_to(ROOT))] = sha(path)
    require(reports['kernel']['candidate_sha256'] == reports['prelink']['candidate_sha256'], 'Identity CPU and prelink candidates differ')
    report = {'result': 'CPH2653_ISOLATED_TASK_AWARE_SURFACE_IDENTITY_ROUTE_PASS', 'builder_sha256': sha(Path(__file__)),
        'stages': stages, 'artifacts': [{'path': path, 'sha256': digest} for path, digest in artifacts.items()],
        'host_cases': 13, 'host_source_rejection_controls': 3, 'original_identity_ARM64_cases': 20,
        'source_to_original_identity_ARM64_cases': 17, 'existing_regression_ARM64_cases': 112,
        'linked_kernel_cpu_paths': sum(reports['kernel']['case_counts'].values()),
        'kernel_instruction_rejection_controls': 7, 'original_invariant_refusals': 5,
        'combined_source_objects': 92, 'native_source_entries': 99, 'original_aliases': 342,
        'original_components': 28, 'original_interfaces': 7, 'original_pointer_readbacks': 63889,
        'candidate': reports['prelink']['candidate'], 'candidate_sha256': reports['prelink']['candidate_sha256'],
        'current_task_authorized_lookup_and_custom_reference_lifetime_executed': True,
        'IOKit_task_lock_matching_type_process_and_base_client_refs_are_peers': True,
        'actual_original_surface_allocator_or_root_initialization_executed': False,
        'GPU_import_backing_associated': False, 'iosurface_producer_connected': False,
        'default_artifacts_selected_or_replaced': False, 'phone_operations': 'none', 'new_boot_image_built': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'A kernel-callable current-task bridge, its original IOSurfaceRoot binding and their real source-to-original '
            'permission/custom-reference chain are implemented in an isolated full kernel. Original lookup/table/cache/client '
            'membership and +1000 CAS reference algorithms execute; +12 remains the surface ID. Existing GPU/surface/display '
            'regressions pass in the new prelink. Provider/mutex/task/process/base-client primitives remain explicit peers. '
            'The helper is not connected to user GPU import/submit; backing association/stability, producer grant/callback/cancel, '
            'physical cache/reset and iOS boot remain incomplete. Previous development images remain preserved; no new image is packaged.'}
    require(report['linked_kernel_cpu_paths'] == 149, 'Unexpected identity CPU inventory')
    if args.check_only: require(json.loads(REPORT.read_text()) == report, 'Identity aggregate is stale')
    else: REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: isolated current-task identity / 13 sanitizer cases / 149 ARM64 paths / 92-object strict prelink')


if __name__ == '__main__': main()
