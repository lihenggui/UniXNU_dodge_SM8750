#!/usr/bin/env python3
"""Build exact iPhone IOSurface sync bindings and execute their original queue chain."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, build_objects, inspect_object, require, symbols
from prepare_initial_data import sha
from prepare_surface_sync import FIXTURE, HEADER, checked
from surface_sync_execution import Execution, run_cases

OUT = ROOT / 'build/ios16-surface-producer-execution'
REPORT = ROOT / 'reports/ios16-surface-sync-kernel.json'
RESULT = 'IPHONE16_ORIGINAL_IOSURFACE_NOTIFICATION_CHAIN_PASS'
DEPENDENCIES = ('ios16-crypto-prelink', 'ios16-producer', 'ios16-surface-interface', 'ios16-display-frontend')


def check_report(report):
    require(report['result'] == RESULT and len(report['cpu_cases']) == 17 and len(report['instruction_controls']) == 5,
            'Incomplete original IOSurface sync execution report')
    contract, pin = checked()
    require(report['contract'] == contract and report['sync_pin'] == pin, 'Surface sync contract changed')
    for field in ('source_sha256', 'artifacts', 'dependency_report_sha256'):
        for name, digest in report[field].items():
            path = ROOT / ('reports/' + name + '.json' if field == 'dependency_report_sha256' else name)
            require(path.is_file() and sha(path) == digest, 'Surface sync evidence changed: ' + str(path))
    require(sha(ROOT / report['candidate']) == report['candidate_sha256'], 'Surface sync linked candidate changed')
    require(report['gpu_quiescence_or_cache_visibility_qualified'] is False and report['hardware_tested'] is False and
            report['all_ios_port_code_complete'] is False, 'Surface sync report exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: existing original IOSurface sync evidence and artifacts'); return
    contract, pin = checked(); OUT.mkdir(parents=True, exist_ok=True)
    dependencies = {}
    for name in DEPENDENCIES:
        path = ROOT / 'reports' / (name + '.json'); document = json.loads(path.read_text())
        require('PASS' in document['result'], 'Surface sync dependency failed: ' + name)
        dependencies[name] = sha(path)
    prelink = json.loads((ROOT / 'reports/ios16-crypto-prelink.json').read_text())
    candidate = ROOT / prelink['candidate']
    require(sha(candidate) == prelink['candidate_sha256'], 'Validated linked crypto/display candidate changed')
    probe = OUT / 'SurfaceSyncProbe.cpp'
    probe.write_text('#include "OriginalIOSurfaceSyncABI.h"\n#include "OriginalLegacyProducerABI.h"\n'
        'extern "C" bool dodge_sync_read(OSObject *s,OSObject **o,uint32_t label,IPhone16SurfaceSyncCallback cb,void *t,void *c)'
        '{return native_iphone_surface_register_sync(s,o,IPhone16SurfaceSync::Read,label,cb,t,c,0);}\n'
        'extern "C" bool dodge_sync_write(OSObject *s,OSObject **o,uint32_t label,IPhone16SurfaceSyncCallback cb,void *t,void *c)'
        '{return native_iphone_surface_register_sync(s,o,IPhone16SurfaceSync::Write,label,cb,t,c,0);}\n'
        'extern "C" int32_t dodge_sync_signal(OSObject *o,int32_t s){return native_iphone_surface_signal_sync(o,s);}\n'
        'extern "C" bool dodge_sync_ready(const IOMFBSwapIORequest *r){return IPhone16Swap::producersReady(r);}\n')
    obj, = build_objects([probe], OUT, [HEADER.parent]); inspect_object(obj.read_bytes())
    bindings = {name: int(address, 16) - 0x1000000 for name, address in contract['bindings'].items()}
    assembly = OUT / 'original-surface-sync-bindings.S'
    assembly.write_text(''.join('.globl ' + name + '\n.set ' + name + ', ' + hex(address) + '\n'
                                for name, address in sorted(bindings.items())))
    binding = OUT / 'original-surface-sync-bindings.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0', '-c', assembly,
                    '-o', binding], check=True)
    require({s['name']: s['value'] for s in symbols(binding.read_bytes()) if s['kind'] == 3} == bindings,
            'Compiled original surface sync absolute bindings differ')
    archive = OUT / 'libIPhone16SurfaceSyncBindings.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, binding], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, binding.name]) == binding.read_bytes(),
            'Surface sync bindings archive readback differs')
    raw = candidate.read_bytes(); rows = run_cases(raw, contract, obj)
    print('PASS:', len(rows), 'actual IOSurface/display notification-chain cases', flush=True)
    controls = []
    for name, address, word in (
        ('registration-return-without-notifier', 0xfffffff005a51a94, 0xd65f03c0),
        ('signal-return-without-completion', 0xfffffff005a62480, 0xd65f03c0),
        ('root-worker-skipped', 0xfffffff005a593b0, 0xd65f03c0),
        ('access-compatibility-always-true', 0xfffffff005a51564, 0x14000002),
        ('display-ready-store-skipped', 0xfffffff005c0c1a8, 0xd503201f),
    ):
        try: run_cases(raw, contract, obj, (address, word))
        except ValueError as error:
            controls.append({'case': name, 'result': 'REJECTED', 'instruction_address': hex(address), 'reason': str(error)})
        else: raise ValueError('Surface sync checker accepted a broken original algorithm: ' + name)
        print('REJECTED:', name, flush=True)
    # A live, unsigned access is not safe to destroy. Let the real notifier
    # lifetime implementation enforce this invariant through its real panic.
    e = Execution(raw, contract, obj); surface = e.surface(); _, token = e.begin(surface)
    try: e.release(token)
    except ValueError as error:
        require('Original synchronization panic' in str(error), 'Unsigned release reached an unrelated failure')
        lifetime = {'case': 'release-before-signal', 'result': 'ORIGINAL_PANIC', 'reason': str(error)}
    else: raise ValueError('Original notifier unexpectedly accepted release before signal')
    evidence = OUT / 'cpu-cases.json'
    evidence.write_text(json.dumps({'cpu_cases': rows, 'instruction_controls': controls, 'lifetime_control': lifetime}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/surface_sync_execution.py', ROOT / 'scripts/prepare_surface_sync.py',
             ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/check_ios16_swap.py',
             ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_initial_data.py', FIXTURE, HEADER,
             HEADER.parent / 'OriginalLegacyProducerABI.h', HEADER.parent / 'OriginalLegacySwapABI.h']
    artifacts = [obj, binding, archive, OUT / 'compile-commands.json', evidence]
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': dependencies, 'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'sync_pin': pin, 'contract': contract,
        'native_target': 'arm64-apple-ios16.0', 'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
        'bindings': {name: hex(address) for name, address in bindings.items()}, 'cpu_cases': rows,
        'instruction_controls': controls, 'lifetime_control': lifetime,
        'original_access_registration_executed': True, 'original_compatibility_predicate_executed': True,
        'original_surface_and_root_queue_walkers_executed': True, 'original_signal_executed': True,
        'original_notifier_retain_release_and_destructors_executed': True,
        'original_family_registration_gate_action_and_ready_update_executed': True,
        'source_readonly_producer_guard_executed': True, 'iosurface_completion_or_queue_algorithms_are_peers': False,
        'source_frontend_or_full_original_cancellation_executed': False,
        'writer_error_automatically_propagates_to_waiting_reader': False,
        'separate_sync_bindings_archive_built': True, 'new_bindings_selected_in_default_kernel': False,
        'gpu_quiescence_or_cache_visibility_qualified': False, 'hardware_tested': False,
        'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Original iPhone IOSurface access registration, compatibility, use counts, notifier ownership, '
                 'signal, root enqueue/worker, surface walker, family registration/callback/gated ready update and native read-only '
                 'guard execute from the validated linked candidate. Native typed calls exercise the exact eight-argument ABI, '
                 'high-bit labels and 64-bit callback values; the original wrapper supplies its internal ninth stack argument. '
                 'Fixtures supply exact bounded surface/root/request objects and metadata. Primitive allocation, base OSObject '
                 'construction/init/delete dispatch, mutex/time/trace, registry use-count notification, scheduler event wake, '
                 'display gate primitive, final display kick and final family cancellation are explicit peers. '
                 'Real notification retain/release/destructors execute; every successful case drains native queues and releases '
                 'tickets with exact counts and object canaries. One reader-error status is explicitly injected into its test '
                 'notification. A writer error does not automatically reach the reader: readiness is not GPU success. '
                 'No actual IOSurface allocator/module initialization, renderer, GPU fence/cache/SMMU, full original cancellation, '
                 'complete frontend, phone boot or hardware functionality is qualified. Original files and frozen earlier artifacts are unchanged.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original IOSurface queue chain /', len(rows), 'cases / 5 instruction controls / original lifetime refusal')


if __name__ == '__main__': main()
