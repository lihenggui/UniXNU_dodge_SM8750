#!/usr/bin/env python3
"""Exercise actual mapped-resource leases, failures and existing backend suites."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess

from fresh_gpu_overlay import replace_once
from mapped_lease_overlay import BASE, FILES, IMPL, MAP_GUARD, PATCH, WAIT, stage
from native_driver_build import ROOT, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-mapped-lease-wait/host'
REPORT = ROOT / 'reports/ios16-mapped-lease-host.json'
RESULT = 'IOS16_MAPPED_RESOURCE_LIFETIME_SANITIZER_PASS'


def check_report(report):
    require(report['result'] == RESULT and report['regression_cases'] == 16 and
            report['bounded_map_wait_cases'] == 12 and len(report['existing_suites']) == 3 and len(report['source_controls']) == 5,
            'Incomplete mapped-resource host checks')
    from mapped_lease_overlay import checked
    require(checked()[2] == report['overlay_pin'], 'Mapped-resource overlay pin changed')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Mapped-resource host evidence changed: ' + name)
    require(report['hardware_tested'] is False and report['iosurface_producer_connected'] is False and
            report['all_ios_port_code_complete'] is False, 'Mapped-resource host report exceeds scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: recorded mapped-resource host evidence'); return
    OUT.mkdir(parents=True, exist_ok=True); backend, pin = stage(OUT.parent / 'source')
    includes = OUT / 'include'; fixture = OUT / 'fixture'; fixture.mkdir(exist_ok=True)
    for name in ('IOKit/IOTypes.h', 'IOKit/IOLib.h', 'IOKit/IOBufferMemoryDescriptor.h', 'kern/task.h', 'sys/resource_private.h'):
        path = includes / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('#include "XnuMemoryFixture.h"\n')
    source_fixture = BASE / 'tests'; artifacts = []
    for name in ('XnuMemoryFixture.h', 'test_vm.cpp', 'test_submit.cpp', 'test_userclient.cpp'):
        path = fixture / name; text = (source_fixture / name).read_text()
        if name == 'test_submit.cpp':
            text = replace_once(text, '&p.tables,32,40,0x800000,65536,0,16,',
                                '&p.tables,32,40,0x800000,1048576,0,256,')
            text = replace_once(text, '}\n/* Physical-page maintenance', '    return 0;\n}\n/* Physical-page maintenance')
            # This fixture predates the pinned VM's separate hang counter and
            # recoverable-client policy. Keep its recovery checks, updating
            # those two stale expectations to the actual pinned API contract.
            text = replace_once(text, 'p.vm.faults()==1 && !p.vm.unusable()',
                                'p.vm.hangs()==1 && !p.vm.faults() && !p.vm.unusable()')
            text = replace_once(text, '''        /* A VM a hang made unusable submits nothing more. */
        p.vm.noteHang(true);
        CHECK(p.submit.submit(&buffer,1,0,&fence)==kIOReturnNotPermitted);''',
                '''        /* The pinned VM counts recoverable hangs separately from faults. */
        p.vm.noteHang(true);
        CHECK(p.submit.submit(&buffer,1,0,&fence)==kIOReturnSuccess && fence==4);
        fencemem[1]=4;CHECK(p.submit.wait(4,&ringclock,1000)==kIOReturnSuccess);''')
            text = replace_once(text, '1 unusable-VM refusal', '1 recovered-VM retry')
        if name == 'test_userclient.cpp':
            text = replace_once(text, '}\n/* Physical-page maintenance', '    return 0;\n}\n/* Physical-page maintenance')
            text = replace_once(text,
                '''        CHECK(p.client.releaseAll(&ringclock,1000)==kIOReturnSuccess && p.client.liveObjects()==0);
        CHECK(p.execbuf.outstanding()==1 && other.liveObjects()==1);''',
                '''        // The other job can reference any mapping in this shared VM.
        CHECK(p.client.releaseAll(&ringclock,1000)==kIOReturnBusy && p.client.liveObjects()==1);
        CHECK(p.execbuf.outstanding()==1 && other.liveObjects()==1);''')
            text = replace_once(text,
                '''        CHECK(other.releaseAll(&ringclock,1000)==kIOReturnSuccess && p.execbuf.outstanding()==0);
        CHECK(other.deviceInfo(&got)==kIOReturnNotReady);''',
                '''        CHECK(other.releaseAll(&ringclock,1000)==kIOReturnSuccess && p.execbuf.outstanding()==0);
        CHECK(p.client.releaseAll(&ringclock,1000)==kIOReturnSuccess && !p.client.liveObjects());
        CHECK(other.deviceInfo(&got)==kIOReturnNotReady);''')
        path.write_text(text); artifacts.append(path)
    smmu = ROOT / 'sources/UniXNU/kits/ArmSmmu4K'; pm4 = ROOT / 'sources/UniXNU/kits/AdrenoPM4'
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie']
    c = ['/usr/bin/gcc', '-std=gnu11', *flags]; cpp = ['/usr/bin/g++', '-std=c++17', *flags,
        '-Wno-missing-field-initializers', '-Wno-class-memaccess', '-DNATIVE_ADRENO_HOST_TEST',
        '-I', includes, '-I', fixture, '-I', backend, '-I', smmu, '-I', pm4]
    commands = []
    def compile_c(path):
        obj = OUT / (path.stem + '.o'); command = [*c, '-c', path, '-o', obj]
        subprocess.run(command, check=True, capture_output=True); return obj, list(map(str, command))
    files = [smmu / (name + '.c') for name in ('ArmSmmu4KContext', 'ArmSmmu4KProgram', 'ArmSmmu4KLive', 'ArmSmmu4KStreams')]
    files.append(pm4 / 'AdrenoPM4.c')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        objects = list(pool.map(compile_c, files))
    commands += [command for _, command in objects]; common_objects = [obj for obj, _ in objects]
    names = ('NativeAdrenoMemory', 'NativeAdrenoSmmuMemory', 'NativeAdrenoVm', 'NativeAdrenoRing',
             'NativeAdrenoPreempt', 'NativeAdrenoSubmit', 'NativeAdrenoTimer', 'NativeAdrenoUserClient')
    def compile_cpp(name):
        path = backend / (name + '.cpp'); obj = OUT / (name + '.o')
        command = [*cpp, '-c', path, '-o', obj]; process = subprocess.run(command, capture_output=True, text=True)
        require(process.returncode == 0, 'Host backend compile failed: ' + name + '\n' + process.stderr)
        return obj, list(map(str, command))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        objects = list(pool.map(compile_cpp, names))
    commands += [command for _, command in objects]; cpp_objects = {obj.stem: obj for obj, _ in objects}
    common_objects += list(cpp_objects.values())
    peers = OUT / 'bootarg-peer.cpp'
    peers.write_text('#include "NativeAdrenoMemory.h"\n'
        'extern "C" __attribute__((weak)) int PE_parse_boot_argn(const char *,void *,int){return 0;}\n'
        '__attribute__((weak)) bool NativeAdrenoPagesUncached(const NativeAdrenoPhysicalSpan *,size_t){return false;}\n')
    peer_obj = OUT / 'bootarg-peer.o'; subprocess.run([*cpp, '-c', peers, '-o', peer_obj], check=True, capture_output=True)
    common_objects.append(peer_obj); artifacts.append(peers)
    # The pinned provider fixtures retain kernel-style allocations and poisoned
    # objects until process exit. ASan/UBSan are enabled; leak detection is not
    # claimed for these provider fixtures, following their upstream runner.
    env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'}
    suites = []
    for name in ('vm', 'submit', 'userclient', 'mapped', 'map-wait'):
        source = (ROOT / 'tests/DodgeMappedLeaseTest.cpp' if name == 'mapped' else
                  ROOT / 'tests/DodgeMapWaitTest.cpp' if name == 'map-wait' else fixture / ('test_' + name + '.cpp'))
        binary = OUT / name
        inputs = common_objects if name in ('userclient', 'map-wait') else [p for p in common_objects if p != cpp_objects['NativeAdrenoUserClient']]
        command = [*cpp, source, *inputs, '-no-pie', '-o', binary]
        process = subprocess.run(command, capture_output=True, text=True)
        require(process.returncode == 0, 'Host fixture compile failed: ' + name + '\n' + process.stderr)
        commands.append(list(map(str, command)))
        process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=60)
        log = OUT / (name + '.log'); log.write_text(process.stdout + process.stderr)
        require(process.returncode == 0 and 'PASS:' in process.stdout, 'Mapped-resource suite failed; inspect ' + str(log))
        if name == 'mapped': require('PASS: 16 mapped-resource regression cases' in process.stdout, 'Incomplete regressions')
        if name == 'map-wait': require('PASS: 12 bounded map-wait integration cases' in process.stdout, 'Incomplete map waiting checks')
        suites.append(name); artifacts += [binary, log]; print('PASS: actual backend sanitizer suite /', name, flush=True)
    variants = []
    before = (BASE / 'NativeAdrenoSubmit.cpp').read_text(); after = (backend / 'NativeAdrenoSubmit.cpp').read_text()
    variants.append(('historical-IB-only-hold', 'NativeAdrenoSubmit', before, 'target.deviceReferences()==2'))
    variants.append(('skip-write-acquisition', 'NativeAdrenoVm',
        (backend / 'NativeAdrenoVm.cpp').read_text().replace('#include "DodgeMappedLease.inc"',
            '#include "DodgeMappedLease.no-acquire.inc"'), 'fixture.physical_calls>calls'))
    (backend / 'DodgeMappedLease.no-acquire.inc').write_text(replace_once(IMPL.read_text(), '    if(acquire_writes) {',
        '    (void)acquire_writes;\n    if(false) {'))
    variants.append(('allow-late-mapping', 'NativeAdrenoVm',
        replace_once((backend / 'NativeAdrenoVm.cpp').read_text(), MAP_GUARD, ''), 'kIOReturnBusy'))
    variants.append(('zero-fence-treated-as-complete', 'NativeAdrenoSubmit', replace_once(after,
        '    for(const auto &job:jobs_)if(job.active && !job.fence)return poison();\n', ''), 'restarts'))
    controls = []
    for name, stem, text, expected in variants:
        source = OUT / (name + '.cpp'); source.write_text(text); obj = OUT / (name + '.o')
        command = [*cpp, '-c', source, '-o', obj]; subprocess.run(command, check=True, capture_output=True); commands.append(list(map(str, command)))
        binary = OUT / name
        inputs = [p if p != cpp_objects[stem] else obj for p in common_objects if p != cpp_objects['NativeAdrenoUserClient']]
        command = [*cpp, ROOT / 'tests/DodgeMappedLeaseTest.cpp', *inputs, '-no-pie', '-o', binary]
        subprocess.run(command, check=True, capture_output=True); commands.append(list(map(str, command)))
        process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=60)
        log = OUT / (name + '.log'); log.write_text(process.stdout + process.stderr)
        require(process.returncode != 0 and expected in process.stderr and 'AddressSanitizer' not in process.stderr,
            'Regression suite did not reject the intended defect: ' + name + '\n' + process.stderr)
        controls.append({'case': name, 'result': 'REJECTED', 'returncode': process.returncode, 'log': str(log.relative_to(ROOT))})
        artifacts.append(log); print('REJECTED: source control /', name, flush=True)
    mutant = OUT / 'DodgeMapWait.no-retry.inc'
    mutant.write_text(replace_once(WAIT.read_text(), 'if(status!=kIOReturnBusy || !pending)return status;', 'if(true)return status;'))
    source = OUT / 'wait-no-retry.cpp'
    source.write_text((ROOT / 'tests/DodgeMapWaitTest.cpp').read_text().replace('"DodgeMapWait.inc"', '"DodgeMapWait.no-retry.inc"'))
    binary = OUT / 'wait-no-retry'; command = [*cpp, source, *common_objects, '-no-pie', '-o', binary]
    subprocess.run(command, check=True, capture_output=True); commands.append(list(map(str, command)))
    process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=60)
    log = OUT / 'wait-no-retry.log'; log.write_text(process.stdout + process.stderr)
    require(process.returncode != 0 and '!f.run()' in process.stderr, 'Wait fixture accepted a missing map retry')
    controls.append({'case': 'wait-no-retry', 'result': 'REJECTED', 'returncode': process.returncode, 'log': str(log.relative_to(ROOT))})
    artifacts.append(log); print('REJECTED: source control / wait-no-retry', flush=True)
    command_path = OUT / 'compile-commands.json'; command_path.write_text(json.dumps(commands, indent=2) + '\n'); artifacts.append(command_path)
    artifacts += [backend / name for name in (*FILES, IMPL.name, WAIT.name)]
    sources = [Path(__file__), ROOT / 'scripts/mapped_lease_overlay.py', IMPL, WAIT, PATCH,
               ROOT / 'tests/DodgeMappedLeaseTest.cpp', ROOT / 'tests/DodgeMapWaitTest.cpp',
               *[source_fixture / name for name in ('XnuMemoryFixture.h', 'test_vm.cpp', 'test_submit.cpp', 'test_userclient.cpp')]]
    sources += files
    report = {'result': RESULT, 'overlay_pin': pin, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'regression_cases': 16,
        'bounded_map_wait_cases': 12, 'existing_suites': [name for name in suites if name not in ('mapped', 'map-wait')], 'source_controls': controls,
        'sanitizers': ['address', 'undefined'], 'leak_detection': False, 'compiler_jobs': 4,
        'fixture_updates': ['test-only 1 MiB aperture for 160 resources',
            'explicit return for renamed main', 'pinned VM hang counter and recoverable-client expectations',
            'shared-VM client teardown waits for the other client job'],
        'new_mapping_waits_for_all_vm_jobs': True, 'cache_failure_keeps_complete_lease': True,
        'unknown_publication_zero_fence_never_retires': True, 'indirect_resource_use_proven_from_IBs': False,
        'iosurface_producer_connected': False, 'physical_cache_or_reset_qualified': False,
        'hardware_tested': False, 'all_ios_port_code_complete': False,
        'scope': 'Actual pinned memory/VM/ring/submit code with a reviewed seven-file overlay. Sixteen resource regressions, twelve bounded map-wait integration cases and '
            'three existing suites use bounded allocation, cache, CP and SMMU peers. A larger test-only aperture permits 160 targets. '
            'Historical IB-only holding, missing acquisition, late mapping, zero-fence retirement and missing map retry are rejected. '
            'The actual wait helper and user-client map/fence code retry pending maps outside fixture locks with time/poll bounds, while duplicate maps and other failures return directly. '
            'The existing wire ABI lacks resource access/IOSurface identities; all current mappings are conservatively held per job. '
            'This does not provide IOSurface producer notification or qualify physical cache exclusion/reset/iOS boot.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
