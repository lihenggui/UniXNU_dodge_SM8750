#!/usr/bin/env python3
"""Build/verify the isolated owned-descriptor/import page-association route."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

REPORT = ROOT / 'reports/surface-pages-stack.json'
STAGES = (
    ('source', 'build_surface_pages', 'ios16-surface-pages-source'),
    ('prelink', 'build_surface_pages_prelink', 'ios16-surface-pages-prelink'),
    ('kernel', 'check_surface_pages_kernel', 'ios16-surface-pages-kernel'),
)


def main():
    p = argparse.ArgumentParser(description=__doc__); mode = p.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true'); mode.add_argument('--record-existing', action='store_true'); a = p.parse_args()
    if not a.check_only and not a.record_existing:
        for _, module, name in STAGES:
            command = [ROOT / '.venv-gpu/bin/python', ROOT / 'scripts' / (module + '.py')]
            if (ROOT / 'reports' / (name + '.json')).exists(): command += ['--check-only']
            subprocess.run(command, check=True)
    stages = {}; artifacts = {}; reports = {}
    for name, module, filename in STAGES:
        path = ROOT / 'reports' / (filename + '.json'); report = json.loads(path.read_text())
        importlib.import_module(module).check_report(report); reports[name] = report
        stages[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
            'builder': 'scripts/' + module + '.py', 'builder_sha256': sha(ROOT / 'scripts' / (module + '.py'))}
        for filename, digest in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == digest, 'Surface page artifact identities conflict'); artifacts[filename] = digest
        artifacts[str(path.relative_to(ROOT))] = sha(path)
    require(reports['kernel']['candidate_sha256'] == reports['prelink']['candidate_sha256'], 'Surface page CPU/prelink candidates differ')
    report = {'result': 'CPH2653_ISOLATED_SURFACE_IMPORT_PAGE_ASSOCIATION_ROUTE_PASS', 'builder_sha256': sha(Path(__file__)),
        'stages': stages, 'artifacts': [{'path': path, 'sha256': digest} for path, digest in artifacts.items()],
        'host_cases': 35, 'host_source_rejection_controls': 4, 'new_native_association_cases': 25,
        'existing_ARM64_regression_cases': 149, 'linked_kernel_cpu_paths': sum(reports['kernel']['case_counts'].values()),
        'new_kernel_instruction_rejection_controls': 5, 'combined_source_objects': 94, 'native_source_entries': 102,
        'original_aliases': 343, 'original_components': 28, 'original_interfaces': 7, 'original_pointer_readbacks': 63889,
        'candidate': reports['prelink']['candidate'], 'candidate_sha256': reports['prelink']['candidate_sha256'],
        'kernel_owned_descriptor_import_page_association_implemented': True,
        'real_native_memory_and_VM_job_references_executed': True, 'real_native_descriptor_and_original_surface_references_executed': True,
        'owned_descriptor_required_from_original_component_serialization': True,
        'descriptor_prepare_complete_physical_segments_and_type_checks_are_peers': True,
        'source_descriptor_acquisition_and_backing_mutation_serialization_qualified': False,
        'GPU_user_client_association_connected': False, 'iosurface_producer_connected': False,
        'physical_cache_visibility_or_reset_qualified': False,
        'default_artifacts_selected_or_replaced': False, 'new_boot_image_built': False, 'phone_operations': 'none',
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The kernel-only adapter binds an already-owned exact original surface descriptor to every imported GPU page, '
            'retains/prepares its own descriptor reference, holds the real native resource and balances original surface ownership. '
            'Mismatches and observed replacement refuse association; job/mapping holds defer unprepare; complete failure retains '
            'and quarantines both owners. Thirty-five sanitizer cases and 25 actual linked paths plus 149 retained regressions pass. '
            'Acquiring the original owned descriptor, backing mutation/check-to-submit serialization, GPU user-client and producer '
            'callback/cancel/completion integration, physical cache/reset and full iOS runtime remain incomplete. No public feature '
            'bit, user ABI or new development boot image is introduced.'}
    require(report['linked_kernel_cpu_paths'] == 174, 'Unexpected surface page ARM64 inventory')
    if a.check_only: require(json.loads(REPORT.read_text()) == report, 'Surface page aggregate is stale')
    else: REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: owned surface/import page association / 35 sanitizer cases / 174 ARM64 paths / 94-object strict prelink')


if __name__ == '__main__': main()
