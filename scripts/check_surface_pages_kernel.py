#!/usr/bin/env python3
"""Run exact surface/import page association, native references and retained regressions."""
import argparse
import json
from pathlib import Path

from build_surface_pages_prelink import REPORT as PRELINK_REPORT, check_report as check_prelink
from check_surface_identity_kernel import REPORT as BASE_REPORT, check_report as check_base
from check_mapped_lease_kernel import lifecycle_settings
from check_adreno_display_timeline import cpu_cases as timeline_cases
from check_display_kernel_lifecycle import emulate as lifecycle_case
from fresh_gpu_execution import cases as health_cases
from mapped_lease_execution import run_cases as lease_cases, wait_cases
from native_driver_build import ROOT, require, macho, symbols
from prepare_initial_data import sha
from prepare_surface_identity import checked as identity_contract
from prepare_surface_memory import checked as memory_contract
from prepare_surface_sync import checked as sync_contract
from surface_identity_execution import run_cases as identity_cases, source_cases as identity_source_cases
from surface_sync_execution import run_cases as sync_cases
from surface_pages_execution import layouts, cases, controls

OUT = ROOT / 'build/cph2653-surface-pages-kernel'
REPORT = ROOT / 'reports/ios16-surface-pages-kernel.json'
RESULT = 'IOS16_SURFACE_IMPORT_PAGE_ASSOCIATION_NATIVE_ARM64_PASS'
COUNTS = {'surface_page_association': 25, 'original_identity': 20, 'source_to_original_identity': 17,
    'native_snapshot_and_epoch': 22, 'native_frontend_and_snapshot': 13, 'original_surface_chain': 17,
    'display_lifecycle': 32, 'native_mapped_resource': 16, 'native_map_wait': 12}


def check_report(report):
    contract, pin = memory_contract()
    require(report['result'] == RESULT and report['case_counts'] == COUNTS and report['memory_pin'] == pin and
            len(report['instruction_controls']) == 5, 'Incomplete surface page ARM64 evidence')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Surface page ARM64 evidence changed: ' + name)
    require(sha(ROOT / report['candidate']) == report['candidate_sha256'] and
        not any(report[k] for k in ('native_memory_and_VM_reference_algorithms_are_peers', 'native_OSObject_reference_algorithms_are_peers',
            'original_surface_reference_algorithm_is_peer', 'GPU_user_client_association_connected', 'iosurface_producer_connected',
            'hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Surface page candidate/scope changed')


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--check-only', action='store_true'); a = p.parse_args()
    if a.check_only or REPORT.exists():
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved surface page association / 174 ARM64 paths / five controls'); return
    prelink = json.loads(PRELINK_REPORT.read_text()); check_prelink(prelink)
    base = json.loads(BASE_REPORT.read_text()); check_base(base); contract, pin = memory_contract()
    path = ROOT / prelink['candidate']; raw = path.read_bytes(); facts, artifacts, recipe = layouts(OUT)
    probe = ROOT / 'build/cph2653-surface-identity-kernel/probe/IdentityProbe.o'
    page_rows = cases(raw, facts, probe); control_rows = controls(raw, facts, probe)
    print('PASS: 25 actual association/native memory/native descriptor/original surface paths / five instruction controls', flush=True)
    identity, _ = identity_contract(); identity_rows = identity_cases(raw, identity, probe); identity_source_rows = identity_source_cases(raw, identity, probe)
    backend_path = ROOT / 'reports/adreno-display-timeline.json'; backend = json.loads(backend_path.read_text())
    previous = json.loads((ROOT / 'reports/ios16-mapped-lease-kernel.json').read_text())
    snapshot_rows, trace = timeline_cases(raw, macho(raw), symbols(raw), backend['native_layouts'])
    health_rows = health_cases(raw, previous['compiler_layout'], backend['native_layouts'], trace)
    sync, _ = sync_contract(); sync_rows = sync_cases(raw, sync, ROOT / 'build/ios16-surface-producer-execution/SurfaceSyncProbe.o')
    lease_rows = lease_cases(raw, previous['mapped_resource_layout']); wait_rows = wait_cases(raw, previous['mapped_resource_layout'])
    print('PASS: retained identity, snapshot/health, notification and VM-resource/wait paths', flush=True)
    lifecycle_rows = []
    for index, setting in enumerate(lifecycle_settings()):
        lifecycle_rows.append(lifecycle_case(path, setting))
        if index % 8 == 7: print('PASS:', index + 1, 'source/original display lifecycle paths', flush=True)
    rows = {'surface_page_association': page_rows, 'original_identity': identity_rows, 'source_to_original_identity': identity_source_rows,
        'native_snapshot_and_epoch': snapshot_rows, 'native_frontend_and_snapshot': health_rows, 'original_surface_chain': sync_rows,
        'display_lifecycle': lifecycle_rows, 'native_mapped_resource': lease_rows, 'native_map_wait': wait_rows}
    require({k: len(v) for k, v in rows.items()} == COUNTS, 'Surface page execution count differs')
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({'cases': rows, 'instruction_controls': control_rows,
        'compiler_layouts': facts, 'native_trace': trace}, indent=2) + '\n'); artifacts.append(evidence)
    sources = [Path(__file__), ROOT / 'scripts/surface_pages_execution.py', ROOT / 'scripts/prepare_surface_memory.py',
        ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/check_adreno_display_timeline.py',
        ROOT / 'scripts/fresh_gpu_execution.py', ROOT / 'scripts/mapped_lease_execution.py', ROOT / 'scripts/surface_identity_execution.py',
        ROOT / 'scripts/surface_sync_execution.py', ROOT / 'scripts/check_display_kernel_lifecycle.py', ROOT / 'scripts/check_mapped_lease_kernel.py',
        ROOT / 'scripts/native_driver_build.py', recipe, probe]
    dependencies = [PRELINK_REPORT, BASE_REPORT, backend_path, ROOT / 'reports/ios16-mapped-lease-kernel.json', ROOT / 'reports/ios16-surface-sync-kernel.json']
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(path.relative_to(ROOT)),
        'candidate_sha256': sha(path), 'memory_pin': pin, 'compiler_layouts': facts, 'case_counts': COUNTS,
        'instruction_controls': control_rows, 'kernel_import_page_association_implemented': True,
        'native_memory_and_VM_reference_algorithms_are_peers': False, 'native_OSObject_reference_algorithms_are_peers': False,
        'original_surface_reference_algorithm_is_peer': False, 'surface_descriptor_getter_is_peer': False,
        'descriptor_prepare_complete_physical_segments_and_type_checks_are_peers': True,
        'source_descriptor_acquisition_and_backing_mutation_serialization_qualified': False,
        'actual_VM_mapping_or_TLB_unmap_executed_by_new_cases': False, 'final_descriptor_or_surface_destructors_executed': False,
        'GPU_user_client_association_connected': False, 'iosurface_producer_connected': False,
        'physical_cache_visibility_or_reset_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Twenty-five new paths execute actual source page association/current checks/rollback/unprepare/quarantine, original '
            'descriptor getter and surface custom release, native descriptor OSObject/tagged reference chain, native memory holds '
            'and retirement, and native VM job holds/write acquisition/retirement. Compiler layout probe text equals production '
            'object text. Existing 149 identity/GPU/notification/display paths rerun in this candidate. Descriptor prepare/complete, '
            'physical-segment reporting, metadata casts and cache effects are explicit peers; descriptor acquisition requires a '
            'preexisting valid owner and original-component serialization. New VM cases use prepopulated mapping records and '
            'explicit mapping/TLB-quiescence fixture steps, without real map/unmap execution. Surfaces/descriptors retain external '
            'fixture references, so final destructors are not executed. Observation before/after a page walk is not check-to-submit '
            'exclusion. GPU user-client import association, original backing acquisition/serialization, producer callbacks/cancel '
            'and device/cache/reset/complete iOS runtime remain incomplete or unqualified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 174 actual-kernel paths / 94-object strict prelink / five new instruction controls')


if __name__ == '__main__': main()
