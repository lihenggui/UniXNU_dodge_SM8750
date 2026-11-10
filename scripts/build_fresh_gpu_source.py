#!/usr/bin/env python3
"""Build an isolated iPhone display candidate that rechecks current Adreno health."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from build_crypto_source import check_report as check_crypto, hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from check_gpu_link import run
from fresh_gpu_overlay import BASE, PATCH, replace_once, stage
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, macho, require, symbols
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-fresh-gpu-source'
REPORT = ROOT / 'reports/ios16-fresh-gpu-source.json'
RESULT = 'IOS16_FRESH_GPU_HEALTH_DISPLAY_SOURCE_LINK_PASS'


def host_checks(out, frontend):
    out.mkdir(parents=True, exist_ok=True)
    fixture = ROOT / 'tests/DodgeDisplayFrontendTest.cpp'; text = fixture.read_text()
    before = '''    run("passed-gpu-target-is-not-queried-again-after-producer-callback",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && gpuQueries==1);
        gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
        assert(!f.kick() && offered.context && gpuQueries==1);completeOffer();
    });'''
    after = '''    run("passed-gpu-target-rechecks-health-after-producer-callback",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && gpuQueries==1);
        gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
        const unsigned queries=gpuQueries;
        assert(f.kick()==kIOReturnBusy && f.status().producerWaiting && !offered.context && gpuQueries>queries);
        gpuKnown=true;f.tick();assert(offered.context);completeOffer();
    });'''
    text = replace_once(text, before, after)
    text = replace_once(text, '    std::printf("{\\"result\\":\\"PASS\\",\\"cases\\":[");',
                        '#include "DodgeDisplayFreshGpuCases.h"\n    std::printf("{\\"result\\":\\"PASS\\",\\"cases\\":[");')
    staged_fixture = out / fixture.name; staged_fixture.write_text(text)
    driver = ROOT / 'drivers/DodgeDisplay'
    command = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-pthread',
        '-I', ROOT / 'tests/gpu_swap_include', '-I', driver, '-I', ROOT / 'tests',
        '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics',
        '-I', ROOT / 'sources/UniXNU-Pagani-Drivers/drivers/NativeMobileDisplay', staged_fixture]
    suffix = [driver / 'DodgeGpuSwapBridge.cpp', driver / 'DodgeSoftwareRefresh.cpp']
    artifacts = [staged_fixture]; controls = []
    mutant = out / 'DodgeDisplayFrontend.no-fresh-admission.cpp'
    mutant.write_text(replace_once(frontend.read_text(), 'gpuCurrent(front,*front->active) && matches(front,*front->active,true);',
                                  '(!front->requiresAdreno || front->active->gpuPassed) && matches(front,*front->active,true);')
                      .replace('static bool gpuCurrent(', 'static __attribute__((unused)) bool gpuCurrent('))
    for name, source, expected in (('fresh', frontend, True), ('historical-cached-fence', BASE, False),
                                    ('missing-fresh-admission', mutant, False)):
        binary = out / ('display-' + name); log = out / (name + '.log')
        subprocess.run([*command, source, *suffix, '-o', binary], check=True)
        process = subprocess.run([binary], capture_output=True, text=True, timeout=60,
            env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1', 'UBSAN_OPTIONS': 'halt_on_error=1'})
        log.write_text(process.stdout + process.stderr)
        if expected:
            require(process.returncode == 0, 'Fresh GPU sanitized frontend cases failed; inspect ' + str(log))
            report = json.loads(process.stdout)
            require(report['result'] == 'PASS' and len(set(report['cases'])) == len(report['cases']), 'Incomplete fresh GPU host cases')
            artifacts += [binary, log]
        else:
            require(process.returncode != 0 and 'Assertion' in process.stderr and 'producerWaiting' in process.stderr,
                    'Fresh GPU tests accepted an unsafe source variant: ' + name)
            controls.append({'case': name, 'result': 'REJECTED', 'returncode': process.returncode,
                             'log': str(log.relative_to(ROOT)), 'log_sha256': sha(log)})
            artifacts += [log]
    expected_count = json.loads((ROOT / 'reports/ios16-display-frontend.json').read_text())['host_case_count'] + 11
    require(len(report['cases']) == expected_count and report['noncanonical_byte_mutations'] == 1124,
            'Fresh GPU baseline plus regression case count differs')
    return report, controls, artifacts


def check_report(report):
    require(report['result'] == RESULT and len(report['combined_original_bindings']) == 341 and
            len(report['combined_native_entries']) == 97 and len(report['source_controls']) == 2,
            'Incomplete fresh GPU source report')
    for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Fresh GPU source evidence changed: ' + filename)
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_display_fresh_gpu']
    require(report['overlay_pin'] == pin and report['gpu_failure_quiescence_qualified'] is False and
            report['hardware_tested'] is False and report['all_ios_port_code_complete'] is False,
            'Fresh GPU source pins or scope changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: isolated fresh GPU display source/link evidence'); return
    base_path = ROOT / 'reports/ios16-crypto-source.json'; base = json.loads(base_path.read_text()); check_crypto(base)
    sync_path = ROOT / 'reports/ios16-surface-sync-kernel.json'; sync = json.loads(sync_path.read_text())
    from check_surface_sync_kernel import check_report as check_sync
    check_sync(sync)
    frontend, pin = stage(OUT / 'source')
    print('CHECK: actual frontend/bridge sanitizer baseline and fresh-GPU regressions', flush=True)
    host, controls, artifacts = host_checks(OUT / 'host', frontend)
    print('PASS:', len(host['cases']), 'sanitizer cases / 1124 packet mutations / 2 rejected source variants', flush=True)
    native = OUT / 'native'
    obj, = build_objects([frontend], native, [ROOT / 'drivers/DodgeDisplay', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics'])
    inspect_object(obj.read_bytes())
    gpu = json.loads((ROOT / 'reports/gpu-kernel-candidate.json').read_text()); old_archive = ROOT / gpu['archive']
    require(sha(old_archive) == gpu['archive_sha256'], 'Frozen GPU source archive changed')
    members = subprocess.check_output(['/usr/bin/llvm-ar-14', 't', old_archive], text=True).splitlines()
    require(len(members) == len(set(members)) == 54 and members.count(obj.name) == 1, 'GPU archive member inventory differs')
    directory = OUT / 'members'; directory.mkdir(exist_ok=True)
    inputs = []
    for name in members:
        if name == obj.name: inputs.append(obj); continue
        path = directory / name; path.write_bytes(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', old_archive, name]))
        require(sha(path) == gpu['object_sha256'][name], 'Frozen GPU member changed: ' + name); inputs.append(path)
    archive = OUT / 'libDodgeA830FreshHealth.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, *inputs], check=True)
    for path in inputs:
        require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, path.name]) == path.read_bytes(), 'Fresh GPU archive readback differs')
    command = json.loads((ROOT / base['link_command']).read_text())
    old_flag = '-Wl,-force_load,' + str(old_archive)
    require(command.count(old_flag) == 1 and command[-2] == '-o', 'Frozen source link command shape changed')
    command[command.index(old_flag)] = '-Wl,-force_load,' + str(archive)
    command[-2:] = ['-Wl,-force_load,' + str(ROOT / sync['archive']), '-o', str(OUT / 'mach.fresh-gpu')]
    print('LINK: complete 90-object iPhone candidate with fresh display checks and exact surface sync aliases', flush=True)
    run(command, OUT / 'link.log', OBJDIR)
    candidate = OUT / 'mach.fresh-gpu'; raw = candidate.read_bytes()
    names = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Fresh GPU source imports unresolved')
    bindings = {**base['combined_original_bindings'], **sync['bindings']}
    require(len(bindings) == 341, 'Fresh GPU original alias set differs')
    for name, value in bindings.items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Fresh GPU original alias changed: ' + name)
    entries = {}
    for name in base['combined_native_entries']:
        require(names[name]['kind'] & 14 == 14, 'Fresh GPU native entry disappeared: ' + name)
        entries[name] = hex(names[name]['value'])
    link = OUT / 'link-command.json'; link.write_text(json.dumps(command, indent=2) + '\n')
    paths = [Path(__file__), ROOT / 'scripts/fresh_gpu_overlay.py', BASE, PATCH, ROOT / 'tests/DodgeDisplayFrontendTest.cpp',
             ROOT / 'tests/DodgeDisplayFreshGpuCases.h', *[ROOT / 'drivers/DodgeDisplay' / name for name in
             ('DodgeDisplayFrontend.h', 'DodgeGpuSwapBridge.cpp', 'DodgeGpuSwapBridge.h', 'DodgeAdrenoTimeline.h', 'DodgeSoftwareRefresh.cpp')],
             ROOT / 'scripts/build_crypto_source.py', ROOT / 'scripts/build_data_startup.py', ROOT / 'scripts/build_data_mount_source.py',
             ROOT / 'scripts/check_gpu_link.py', ROOT / 'scripts/native_driver_build.py']
    artifacts += [frontend, obj, native / 'compile-commands.json', archive, candidate, link]
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in paths},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (base_path, sync_path, ROOT / 'reports/gpu-kernel-candidate.json',
                                                                                            ROOT / 'reports/ios16-display-frontend.json')},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'overlay_pin': pin,
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'link_command': str(link.relative_to(ROOT)),
        'combined_source_objects': 90, 'combined_original_bindings': bindings, 'combined_native_entries': entries,
        'actual_crypto_hooks': hook_readbacks(raw), 'actual_iobsd_hook': hook_readback(raw), 'actual_init_hook': init_hook_readback(raw),
        'host_tests': host, 'source_controls': controls, 'original_surface_sync_report': str(sync_path.relative_to(ROOT)),
        'old_gpu_members_preserved': 53, 'frontend_rechecks_after_historical_fence_pass': True,
        'frontend_rechecks_after_backing_construction': True, 'admission_rechecks_before_copy_and_retirement': True,
        'failed_health_query_retains_request_and_retries': True, 'epoch_or_observed_regression_latches_refusal': True,
        'first_fence_target_preserved': True, 'cpu_only_producer_mode_preserved': True,
        'source_frontend_in_isolated_linked_candidate': True, 'default_kernel_selected': False,
        'original_iosurface_allocator_or_full_frontend_executed': False,
        'gpu_failure_quiescence_qualified': False, 'producer_cache_visibility_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'A separate complete source kernel replaces one of the 54 GPU archive objects with the reviewed fresh-health frontend. '
                 'All 53 other GPU members, 97 source entry names, previous original aliases, crypto/IOBSD/init hooks and default flags survive. '
                 'Two new exact IOSurface aliases produce 341 aliases and 90 source/binding objects. The frontend samples the same locked '
                 'nonblocking native timeline after a prior fence pass, after backing creation and in read-only admission before copy/retirement. '
                 'Unknown health holds ownership and arms its existing timer; observed epoch changes/regressions refuse the old request. '
                 'The original first target is retained, and CpuOnly does not query the GPU. Actual frontend/bridge source runs under '
                 'ASan/UBSan/LSan with explicit original-builder/IOKit/backing/presenter/timeline peers; two unsafe source controls fail. '
                 'Original IOSurface algorithms are separately executed by the dependency report. Full original object creation/frontend, '
                 'cache visibility, GPU/presenter quiescence, real hardware and complete iOS boot remain unqualified.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: isolated fresh GPU source kernel / 90 objects / 97 entries / 341 aliases')


if __name__ == '__main__': main()
