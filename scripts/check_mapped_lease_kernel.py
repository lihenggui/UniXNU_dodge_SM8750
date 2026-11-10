#!/usr/bin/env python3
"""Check the actual fresh-health prelinked kernel, snapshot, IOSurface and display paths."""
import argparse
import json
from pathlib import Path

from build_mapped_lease_prelink import REPORT as PRELINK_REPORT, check_report as check_prelink
from check_adreno_display_timeline import cpu_cases as timeline_cases
from check_display_kernel_lifecycle import emulate as lifecycle_case
from fresh_gpu_execution import Health, cases as health_cases, layouts
from mapped_lease_execution import layouts as lease_layouts, run_cases as lease_cases, wait_cases
from native_driver_build import ROOT, macho, require, symbols
from prepare_initial_data import sha
from prepare_surface_sync import checked as checked_sync
from surface_sync_execution import run_cases as surface_cases

OUT = ROOT / 'build/cph2653-mapped-lease-wait-kernel'
REPORT = ROOT / 'reports/ios16-mapped-lease-kernel.json'
RESULT = 'IOS16_MAPPED_LEASE_HEALTH_SURFACE_DISPLAY_ARM64_PASS'


def lifecycle_settings():
    cases = [{'name': 'default-software-gop'}, {'name': 'optional-serializer-allocation-failed', 'serializer_failure': True},
        {'name': 'original-background-thread-before-stop', 'thread_success': True},
        {'name': 'original-background-thread-after-detach', 'thread_success': True, 'thread_after_detach': True},
        {'name': 'full-original-stop-after-busy-drain', 'busy_drain': True},
        {'name': 'late-thread-after-busy-drain', 'busy_drain': True, 'thread_success': True, 'thread_after_detach': True},
        {'name': 'optional-benchmark-timer', 'bootarg': 'iomfb_benchmark_fps', 'boot_value': 60},
        {'name': 'optional-benchmark-timer-allocation-failed', 'bootarg': 'iomfb_benchmark_fps', 'boot_value': 60, 'timer_failure': 2, 'failure': True},
        {'name': 'optional-benchmark-timer-add-failed', 'bootarg': 'iomfb_benchmark_fps', 'boot_value': 60, 'add_failure': 4, 'failure': True},
        {'name': 'coordinator-allocation-failed', 'core_failure': True, 'failure': True},
        {'name': 'original-software-root-missing', 'root_failure': True, 'failure': True},
        {'name': 'original-matching-allocation-failed', 'matching_failure': True, 'failure': True},
        {'name': 'original-interrupt-allocation-failed', 'interrupt_failure': True, 'failure': True},
        {'name': 'original-interrupt-add-failed', 'add_failure': 2, 'failure': True},
        {'name': 'original-timer-allocation-failed', 'timer_failure': 1, 'failure': True},
        {'name': 'original-timer-add-failed', 'add_failure': 3, 'failure': True},
        {'name': 'native-gop-hook-refused', 'hardware_failure': True, 'failure': True},
        {'name': 'original-lock-allocation-failed', 'lock_failure': True, 'failure': True},
        {'name': 'original-recursive-lock-allocation-failed', 'recursive_failure': True, 'failure': True},
        {'name': 'native-publication-action-refused', 'publication_refused': True, 'failure': True},
        {'name': 'original-gate-allocation-failed', 'gate_failure': True, 'init_failure': True},
        {'name': 'original-workloop-allocation-failed', 'loop_failure': True, 'init_failure': True},
        {'name': 'original-init-add-gate-failed', 'add_failure': 1, 'init_failure': True},
        {'name': 'native-base-init-refused', 'base_init_failure': True, 'init_failure': True}]
    cases += [{'name': 'client-' + kind, 'client': kind} for kind in
        ('success', 'allocation-failed', 'init-failed', 'attach-failed', 'start-failed', 'admission-denied', 'null-output', 'after-stop')]
    return cases


def check_report(report):
    require(report['result'] == RESULT and report['case_counts'] ==
            {'native_snapshot_and_epoch': 22, 'native_frontend_and_snapshot': 13, 'original_surface_chain': 17, 'display_lifecycle': 32, 'native_mapped_resource': 16, 'native_map_wait': 12} and
            len(report['instruction_controls']) == 6 and len(report['lifetime_controls']) == 2,
            'Incomplete fresh GPU actual-kernel evidence')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Fresh GPU kernel evidence changed: ' + name)
    require(sha(ROOT / report['candidate']) == report['candidate_sha256'] and report['hardware_tested'] is False and
            report['producer_cache_visibility_qualified'] is False and report['all_ios_port_code_complete'] is False,
            'Fresh GPU kernel identity or scope changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: existing fresh GPU 112 actual-kernel paths and eight controls'); return
    prelink = json.loads(PRELINK_REPORT.read_text()); check_prelink(prelink); path = ROOT / prelink['candidate']; raw = path.read_bytes()
    OUT.mkdir(exist_ok=True); facts, artifacts, recipe = layouts(OUT)
    backend_path = ROOT / 'reports/adreno-display-timeline.json'; backend = json.loads(backend_path.read_text())
    snapshot_rows, trace = timeline_cases(raw, macho(raw), symbols(raw), backend['native_layouts'])
    print('PASS:', len(snapshot_rows), 'actual linked native snapshot/epoch paths', flush=True)
    health_rows = health_cases(raw, facts, backend['native_layouts'], trace)
    print('PASS:', len(health_rows), 'actual native frontend plus real snapshot paths', flush=True)
    controls = []
    for name, function, reason in (
        ('gpuReady-always-success', '__ZL8gpuReadyP20DodgeDisplayFrontendR18DodgeFrontendEntry', 'capture the initial completed target'),
        ('gpuCurrent-always-success', '__ZL10gpuCurrentPK20DodgeDisplayFrontendRK18DodgeFrontendEntry', 'Historical target bypassed fresh backend refusal'),
    ):
        try: health_cases(raw, facts, backend['native_layouts'], trace, (function, (0x52800020, 0xd65f03c0)))
        except ValueError as error:
            require(reason in str(error), 'Fresh GPU instruction control failed for an unrelated reason')
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Missing native fresh-GPU check accepted: ' + name)
    sync, _ = checked_sync(); probe = ROOT / 'build/ios16-surface-producer-execution/SurfaceSyncProbe.o'
    surface_rows = surface_cases(raw, sync, probe)
    print('PASS:', len(surface_rows), 'actual original IOSurface/display callback-chain paths in new kernel', flush=True)
    lifecycle_rows = []
    for index, setting in enumerate(lifecycle_settings()):
        lifecycle_rows.append(lifecycle_case(path, setting))
        if index % 8 == 7: print('PASS:', index + 1, 'actual source/original display lifecycle paths', flush=True)
    lifetime_controls = []
    for setting, reason in (
        ({'name': 'lost-provider-lifetime-pin', 'thread_success': True, 'thread_after_detach': True, 'lost_provider_pin': True},
         'Provider died before the retained original background thread completed'),
        ({'name': 'unreviewed-native-allocator', 'unreviewed_native_call': True}, 'Unreviewed lifecycle instruction'),
    ):
        try: lifecycle_case(path, setting)
        except ValueError as error:
            require(reason in str(error), 'Display lifetime control failed for an unrelated reason')
            lifetime_controls.append({'case': setting['name'], 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Display lifetime or unknown-native control accepted')
    lease_facts, lease_artifacts, lease_recipe = lease_layouts(OUT / 'lease-layouts')
    lease_rows = lease_cases(raw, lease_facts)
    wait_rows = wait_cases(raw, lease_facts)
    print('PASS:', len(lease_rows), 'actual linked VM/memory resource lease paths', flush=True)
    print('PASS:', len(wait_rows), 'actual linked bounded map-wait paths', flush=True)
    for name, function, reason in (
        ('hold-skipped', 'hold', 'Actual full mapped hold is missing or differs'),
        ('memory-reference-increment-skipped', 'memory_hold', 'Actual full mapped hold is missing or differs'),
        ('write-acquisition-skipped', 'memory_acquire', 'Actual complete write acquisition/retirement is missing'),
    ):
        try: lease_cases(raw, lease_facts, (function, (0x52800000, 0xd65f03c0)))
        except ValueError as error:
            require(reason in str(error), 'Native lease instruction control failed for an unrelated reason: ' + str(error))
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Native lease instruction control accepted: ' + name)
    try: wait_cases(raw, lease_facts, control=True)
    except ValueError as error:
        require('Bounded native map waiting did not honor' in str(error), 'Map-wait instruction control failed for an unrelated reason')
        controls.append({'case': 'map-wait-always-success', 'result': 'REJECTED', 'reason': str(error)})
    else: raise ValueError('Native map-wait instruction control accepted')
    artifacts += lease_artifacts
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({
        'mapped_resource_layout': lease_facts, 'mapped_resource_cases': lease_rows, 'native_map_wait_cases': wait_rows,
        'compiler_layout': facts, 'backend_layout': backend['native_layouts'], 'native_trace': trace,
        'snapshot_cases': snapshot_rows, 'health_cases': health_rows, 'surface_cases': surface_rows,
        'display_lifecycle_cases': lifecycle_rows, 'instruction_controls': controls, 'lifetime_controls': lifetime_controls}, indent=2) + '\n')
    artifacts += [evidence]
    files = [Path(__file__), ROOT / 'scripts/mapped_lease_execution.py', lease_recipe, ROOT / 'scripts/fresh_gpu_execution.py', ROOT / 'scripts/check_adreno_display_timeline.py',
             ROOT / 'scripts/check_display_kernel_lifecycle.py', ROOT / 'scripts/surface_sync_execution.py',
             ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/prepare_surface_sync.py', ROOT / 'scripts/native_driver_build.py',
             recipe, ROOT / 'build/cph2653-fresh-gpu-source/source/DodgeDisplayFrontend.cpp']
    dependencies = [PRELINK_REPORT, backend_path, ROOT / 'reports/ios16-surface-sync-kernel.json',
                    ROOT / 'reports/ios16-display-kernel-lifecycle.json', ROOT / 'reports/ios16-fresh-gpu-source.json']
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(path.relative_to(ROOT)), 'candidate_sha256': sha(path),
        'compiler_layout': facts, 'native_trace': trace,
        'case_counts': {'native_snapshot_and_epoch': len(snapshot_rows), 'native_frontend_and_snapshot': len(health_rows),
                        'original_surface_chain': len(surface_rows), 'display_lifecycle': len(lifecycle_rows), 'native_mapped_resource': len(lease_rows), 'native_map_wait': len(wait_rows)},
        'instruction_controls': controls, 'lifetime_controls': lifetime_controls,
        'native_mapped_resource_algorithms_are_peers': False, 'mapped_resource_layout': lease_facts,
        'native_map_wait_algorithm_is_peer': False, 'map_wait_clock_idle_attempt_are_explicit_peers': True,
        'iosurface_producer_connected': False, 'native_frontend_and_snapshot_algorithms_are_peers': False, 'original_surface_algorithms_are_peers': False,
        'snapshot_mutex_and_fence_read_are_peers': True, 'original_surface_and_display_primitive_peers': True,
        'native_readonly_admission_writes_entry': False, 'full_frontend_uses_real_iokit_objects': False,
        'original_surface_5056_lifecycle_executed': False, 'producer_cache_visibility_qualified': False,
        'gpu_failure_quiescence_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Sixteen additional paths execute actual linked VM hold/retire, memory references and acquisition, late-map rejection and conservative ring dependency checks. '
                 'Four compiler layout probes match production object text; three new instruction controls are rejected. Allocation/cache effects remain peers, without GPU completion or visibility qualification. '
                 'Actual new prelinked kernel instructions also run 22 native snapshot/epoch paths, 13 fresh frontend-helper-to-real-snapshot '
                 'paths, 17 original IOSurface/display notification-chain paths and 32 complete source/original display lifecycle paths. '
                 'The native compiler measures the exact private frontend/entry layout; its probe text equals the production object. '
                 'Fresh admission leaves all entry bytes unchanged. Unknown/poisoned/busy/preempted snapshots hold the old target; '
                 'successful epoch/regression observations latch refusal. Six instruction controls and two display lifetime controls fail. '
                 'Mutex/fence-cache reads and the previously documented platform/IOKit/allocator/scheduler/final display callbacks remain '
                 'explicit peers. Whole native frontend/bridge integration is separately tested under sanitizers. No actual IOKit allocator, '
                 'GPU cache/DMA/SMMU visibility, presenter quiescence, +5056 original-surface lifecycle, MMIO or phone boot is qualified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: fresh GPU candidate / 112 actual-kernel paths / eight controls / no phone operations')


if __name__ == '__main__': main()
