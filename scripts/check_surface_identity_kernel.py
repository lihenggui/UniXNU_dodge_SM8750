#!/usr/bin/env python3
"""Execute source identity -> original authorization/lifetime and GPU regressions."""
import argparse
import json
from pathlib import Path
import subprocess

from build_surface_identity_prelink import REPORT as PRELINK_REPORT, check_report as check_prelink
from check_mapped_lease_kernel import REPORT as BASE_REPORT, check_report as check_base, lifecycle_settings
from check_adreno_display_timeline import cpu_cases as timeline_cases, parse_layout
from check_display_kernel_lifecycle import emulate as lifecycle_case
from fresh_gpu_execution import cases as health_cases
from mapped_lease_execution import run_cases as lease_cases, wait_cases
from native_driver_build import ROOT, build_objects, require, macho, symbols
from prepare_initial_data import sha
from prepare_surface_identity import checked, HEADER
from prepare_surface_sync import checked as checked_sync
from surface_sync_execution import run_cases as surface_cases
from surface_identity_execution import run_cases, source_cases, instruction_controls, invariant_controls

OUT = ROOT / 'build/cph2653-surface-identity-kernel'
REPORT = ROOT / 'reports/ios16-surface-identity-kernel.json'
RESULT = 'IOS16_SOURCE_TO_ORIGINAL_SURFACE_IDENTITY_ARM64_PASS'


def check_report(report):
    require(report['result'] == RESULT and report['case_counts'] == {'original_identity': 20, 'source_to_original_identity': 17,
        'native_snapshot_and_epoch': 22, 'native_frontend_and_snapshot': 13, 'original_surface_chain': 17,
        'display_lifecycle': 32, 'native_mapped_resource': 16, 'native_map_wait': 12} and
        len(report['instruction_controls']) == 7 and len(report['original_invariant_controls']) == 5,
        'Incomplete source/original identity execution evidence')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Identity kernel evidence changed: ' + name)
    require(sha(ROOT / report['candidate']) == report['candidate_sha256'] and
        not any(report[k] for k in ('original_lookup_or_custom_references_are_peers', 'GPU_import_backing_associated',
            'iosurface_producer_connected', 'hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete')),
        'Identity kernel scope or candidate changed')


def text_bytes(path):
    raw = path.read_bytes(); image = macho(raw)
    text, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
    return raw[text['fileoff']:text['fileoff'] + text['size']]


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only or REPORT.exists():
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved identity / 149 ARM64 paths / seven instruction and five invariant controls'); return
    prelink = json.loads(PRELINK_REPORT.read_text()); check_prelink(prelink)
    base = json.loads(BASE_REPORT.read_text()); check_base(base); contract, pin = checked()
    path = ROOT / prelink['candidate']; raw = path.read_bytes(); OUT.mkdir(parents=True, exist_ok=True)
    probe = OUT / 'IdentityProbe.cpp'
    probe.write_text('#include <IOKit/IOService.h>\n#include "OriginalIOSurfaceIdentityABI.h"\n'
        'extern "C" OSObject *dodge_identity_lookup(IOService *r,uint32_t i,task *t){return native_iphone_surface_copy_for_task(r,i,t);}\n'
        'extern "C" void dodge_identity_retain(OSObject *s){s->retain();}\n'
        'extern "C" void dodge_identity_release(OSObject *s){s->release();}\n')
    obj, = build_objects([probe], OUT / 'probe', [HEADER.parent])
    recipe = ROOT / 'build/cph2653-surface-identity/native/compile-commands.json'
    record, = json.loads(recipe.read_text()); command = record['arguments'][:]; layout_obj = OUT / 'identity-layout.o'
    command[command.index('-o') + 1] = str(layout_obj); command += ['-Xclang', '-fdump-record-layouts']
    process = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
    layout_log = OUT / 'identity-layout.log'; layout_log.write_text(process.stdout + process.stderr)
    require(process.returncode == 0 and text_bytes(layout_obj) == text_bytes(ROOT / 'build/cph2653-surface-identity/native/DodgeSurfaceIdentity.o'),
            'Identity layout probe differs from production object instructions')
    layout = parse_layout(layout_log.read_text(), 'DodgeSurfaceIdentity', ('surface', 'id'))
    require(layout == {'bytes': 16, 'fields': {'surface': 0, 'id': 8}}, 'Native identity record layout differs from bounded model')
    identity_rows = run_cases(raw, contract, obj); source_rows = source_cases(raw, contract, obj)
    controls = instruction_controls(raw, contract, obj); invariants = invariant_controls(raw, contract, obj)
    for name, function in (('source-resolver-always-success', '_dodge_copy_current_surface'),
                           ('source-release-removed', '_dodge_release_surface_identity')):
        try: source_cases(raw, contract, obj, (function, (0x52800000, 0xd65f03c0)))
        except ValueError as error: controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Native identity source control accepted: ' + name)
    print('PASS: 20 original lookup/custom-lifetime and 17 actual source-to-original paths / 12 controls', flush=True)
    backend_path = ROOT / 'reports/adreno-display-timeline.json'; backend = json.loads(backend_path.read_text())
    snapshot_rows, trace = timeline_cases(raw, macho(raw), symbols(raw), backend['native_layouts'])
    health_rows = health_cases(raw, base['compiler_layout'], backend['native_layouts'], trace)
    sync, _ = checked_sync(); surface_rows = surface_cases(raw, sync, ROOT / 'build/ios16-surface-producer-execution/SurfaceSyncProbe.o')
    lease_rows = lease_cases(raw, base['mapped_resource_layout']); wait_rows = wait_cases(raw, base['mapped_resource_layout'])
    print('PASS: preserved native snapshot, fresh-health, original surface notifications and resource/wait paths', flush=True)
    lifecycle_rows = []
    for index, setting in enumerate(lifecycle_settings()):
        lifecycle_rows.append(lifecycle_case(path, setting))
        if index % 8 == 7: print('PASS:', index + 1, 'actual source/original display lifecycle paths', flush=True)
    evidence = OUT / 'cpu-cases.json'
    evidence.write_text(json.dumps({'original_identity_cases': identity_rows, 'source_identity_cases': source_rows,
        'instruction_controls': controls, 'original_invariant_controls': invariants, 'compiler_identity_layout': layout,
        'snapshot_cases': snapshot_rows, 'health_cases': health_rows, 'surface_cases': surface_rows,
        'mapped_resource_cases': lease_rows, 'map_wait_cases': wait_rows, 'display_lifecycle_cases': lifecycle_rows}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/surface_identity_execution.py', ROOT / 'scripts/prepare_surface_identity.py',
        ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/check_adreno_display_timeline.py',
        ROOT / 'scripts/fresh_gpu_execution.py', ROOT / 'scripts/mapped_lease_execution.py', ROOT / 'scripts/surface_sync_execution.py',
        ROOT / 'scripts/check_display_kernel_lifecycle.py', ROOT / 'scripts/check_mapped_lease_kernel.py',
        ROOT / 'scripts/native_driver_build.py', recipe]
    artifacts = [obj, OUT / 'probe/compile-commands.json', layout_obj, layout_log, evidence]
    dependencies = [PRELINK_REPORT, BASE_REPORT, backend_path, ROOT / 'reports/ios16-surface-sync-kernel.json']
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(path.relative_to(ROOT)),
        'candidate_sha256': sha(path), 'identity_pin': pin, 'compiler_identity_layout': layout,
        'native_trace': trace, 'case_counts': {'original_identity': len(identity_rows), 'source_to_original_identity': len(source_rows),
            'native_snapshot_and_epoch': len(snapshot_rows), 'native_frontend_and_snapshot': len(health_rows),
            'original_surface_chain': len(surface_rows), 'display_lifecycle': len(lifecycle_rows),
            'native_mapped_resource': len(lease_rows), 'native_map_wait': len(wait_rows)},
        'instruction_controls': controls, 'original_invariant_controls': invariants,
        'original_lookup_or_custom_references_are_peers': False, 'source_resolution_algorithm_is_peer': False,
        'IOKit_matching_task_metacast_mutex_process_and_base_client_refs_are_peers': True,
        'original_process_logging_paths_executed': False, 'final_surface_destructor_executed': False,
        'original_allocator_and_root_initialization_executed': False,
        'GPU_import_backing_associated': False, 'iosurface_producer_connected': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Actual new prelinked source resolves the root and calls the original task-aware lookup, which executes task-client '
            'cache lookup, client membership, owner/restricted/global-sharing policy, protected table lookup, custom try-retain and '
            'virtual surface retain/release with its real CAS reference counter at +1000. The surface ID at +12 is preserved. '
            'Bounded records/canaries and native compiler identity layout are checked. Original primitive locks, process lookup '
            '(null process), base client refs and source IOKit matching/type/task primitives are explicit peers; no authorization '
            'or custom surface reference algorithm is replaced. Seven instruction controls and five original invariant refusals '
            'are checked. Existing 112 native GPU/resource/surface/display paths rerun in this candidate. Actual allocator/root '
            'initialization, nonnull-process logging, final surface destruction, backing-page association/stability, GPU producer '
            'registration, hardware cache/reset and iOS startup remain unqualified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: identity candidate / 149 actual-kernel ARM64 paths / seven instruction and five invariant controls')


if __name__ == '__main__': main()
