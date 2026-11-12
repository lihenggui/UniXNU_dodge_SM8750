#!/usr/bin/env python3
"""Run native A830 software-controller tests on a Linux host."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from build_native_a830 import stage_source
from native_driver_build import ROOT, pinned_sources, require, sha

SUITES = ('test_start', 'test_vm', 'test_submit', 'test_userclient', 'test_a830smmu',
          'test_a830gmufw', 'test_a830gmu', 'test_a830hfi', 'test_a830cp', 'test_a830fence',
          'test_a830irq', 'test_a830powerstate', 'test_a830recovery', 'test_a830dcvs',
          'test_sm8750_power')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', action='store_true', help='test the iPhone submission and map-wait adapter')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    refs = pinned_sources(('native_a830_reference', 'native_a830_smmu_reference'))
    out = ROOT / ('build/cph2653-native-a830-runtime-host' if args.runtime else 'build/cph2653-native-a830-host')
    stage = out / 'source'
    files = stage_source(refs['native_a830_reference'], stage, lock['native_a830_darwin22_overlay'])
    shutil.copytree(refs['native_a830_reference'] / 'tests', stage / 'tests', dirs_exist_ok=True)
    runtime = None
    suites = SUITES
    if args.runtime:
        from native_a830_runtime import apply_runtime
        runtime = apply_runtime(stage)
        fixture = ROOT / 'tests/DodgeNativeA830RuntimeTest.cpp'
        shutil.copyfile(fixture, stage / 'tests/test_dodge_runtime.cpp')
        wait_fixture = ROOT / 'tests/DodgeMapWaitTest.cpp'
        wait_source = wait_fixture.read_text().replace('#include "test_userclient.cpp"',
            '#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wreturn-type"\n'
            '#include "test_userclient.cpp"\n#pragma clang diagnostic pop')
        (stage / 'tests/test_dodge_mapwait.cpp').write_text(wait_source)
        suites = ('test_vm', 'test_dodge_runtime', 'test_dodge_mapwait')
        files += [fixture, wait_fixture, ROOT / runtime['path'], ROOT / 'scripts/native_a830_runtime.py']
        files += [ROOT / runtime['surface_overlay']['path'], ROOT / 'tests/DodgeNativeSurfacePeers.cpp',
                  ROOT / 'tests/DodgeNativeSurfacePeers.h']
        files += [ROOT / runtime['recovery_overlay']['path']]
        files += [p for p in (ROOT / 'tests/native_surface_include').rglob('*') if p.is_file()]
        shutil.copyfile(ROOT / 'tests/DodgeNativeSurfacePeers.h', stage / 'tests/DodgeNativeSurfacePeers.h')
        hint = ROOT / 'drivers/DodgeGpu/DodgeSurfaceImportHint.h'
        shutil.copyfile(hint, stage / hint.name)
        files += [hint]
        files += [ROOT / 'drivers/DodgeGpu/DodgeNativeA830Console.cpp']
        files += [ROOT / name for name in runtime['support_sha256']]
    barriers = 0
    for name in ('NativeAdrenoMemory.cpp', 'Adreno830Start.cpp', 'Adreno830Device.h'):
        path = stage / name
        text, count = re.subn(r'__asm__\s+volatile\("dsb sy"\s*:::\s*"memory"\)',
                             '__atomic_thread_fence(__ATOMIC_SEQ_CST)', path.read_text())
        barriers += count
        path.write_text(text)
    require(barriers == 6, 'Native A830 host barrier sites changed')
    kits = out / 'dependencies/kits'
    kits.mkdir(parents=True, exist_ok=True)
    pm4 = ROOT / 'sources/UniXNU/kits/AdrenoPM4'
    pin = subprocess.check_output(['git', '-C', str(pm4.parent.parent), 'ls-tree',
                                   'HEAD', 'kits/AdrenoPM4'], text=True).split()[2]
    require(subprocess.check_output(['git', '-C', str(pm4), 'rev-parse', 'HEAD'], text=True).strip() == pin
            and not subprocess.check_output(['git', '-C', str(pm4), 'status', '--porcelain']),
            'Native A830 host PM4 dependency differs from the core gitlink')
    for name, target in (('ArmSmmu4K', refs['native_a830_smmu_reference']), ('AdrenoPM4', pm4)):
        link = kits / name
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
        require(link.resolve() == target.resolve(), 'Native A830 host dependency points elsewhere')
    peer = out / 'darwin22-free-peer.h'
    peer.write_text('''#include "XnuMemoryFixture.h"
#include <limits>
inline size_t IOMallocArraySize(size_t h,size_t e,size_t n) {
 return e && n>(std::numeric_limits<size_t>::max()-h)/e?std::numeric_limits<size_t>::max():h+e*n;
}
template<class T> T *os_ptr_load_and_erase(T *&p) {T *v=p;p=nullptr;return v;}
inline void IOFreeData(void *p,size_t) {fixtureMetadataFree(p);}
''')
    if args.runtime:
        with peer.open('a') as stream:
            stream.write('inline void *IOMallocZero(size_t n) {return fixtureMetadata(n);}\n'
                         'inline void IOFree(void *p,size_t) {fixtureMetadataFree(p);}\n'
                         'constexpr IOReturn kIOReturnAborted=-9;\n')
    spec = importlib.util.spec_from_file_location('a830_host_tests', stage / 'tests/run-host-tests.py')
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    # The pinned status record and model configurations omit trailing zero
    # fields. Clang 18 diagnoses these aggregate initializers under -Wextra.
    tests.FLAGS += ['-fno-pie', '-Wno-deprecated-volatile', '-Wno-missing-field-initializers']
    if args.runtime:
        tests.FLAGS += ['-I', str(ROOT / 'tests/native_surface_include')]
    original = tests.run
    commands, executions = [], {}
    cc = shutil.which('clang-14') or shutil.which('clang')
    cxx_compiler = shutil.which('clang++-14') or shutil.which('clang++')
    require(cc and cxx_compiler, 'Install Clang for the native A830 host tests')

    def run(command, **kwargs):
        command = [str(c) for c in command]
        if command[0] == 'xcrun':
            cxx = command[1] == 'clang++'
            command = [(cxx_compiler if cxx else cc), *command[2:]]
            command = [('-std=c++2b' if c == '-std=c++23' else c) for c in command]
            if cxx:
                command += ['-include', str(peer), '-I', str(stage / 'tests')]
            if '-c' not in command:
                command += ['-no-pie']
            commands.append(command)
        # Upstream fake controllers intentionally live until process exit.
        kwargs['env'] = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0', 'UBSAN_OPTIONS': 'halt_on_error=1'}
        result = original(command, **kwargs)
        name = Path(command[0]).name
        if name in suites:
            executions[name] = {'returncode': result.returncode, 'output': result.stdout.strip()}
        return result

    tests.run = run
    if args.runtime:
        runtime_sources = tests.KNOWN['test_userclient'][0] + ['DodgeNativeSurface.cpp',
                           str(ROOT / 'tests/DodgeNativeSurfacePeers.cpp'),
                           str(ROOT / 'drivers/DodgeGpu/DodgeNativeA830Console.cpp')]
        tests.KNOWN['test_dodge_runtime'] = (runtime_sources,
            ['smmu', 'pm4', 'proc'], None, 'iPhone runtime adapter')
        tests.KNOWN['test_dodge_mapwait'] = (runtime_sources,
            ['smmu', 'pm4', 'proc'], None, 'iPhone bounded map wait')
    before = sys.argv
    sys.argv = [str(stage / 'tests/run-host-tests.py'), '--unixnu', str(kits.parent),
                '--out', str(out), *suites]
    try:
        tests.main()
    except SystemExit as exit_status:
        require(exit_status.code == 0, 'Native A830 host suite failed')
    finally:
        sys.argv = before
        (out / 'compile-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    require(set(executions) == set(suites) and all(r['returncode'] == 0 for r in executions.values()),
            'Native A830 host suite coverage is incomplete')
    files += [Path(__file__), ROOT / 'scripts/build_native_a830.py', ROOT / lock['native_a830_darwin22_overlay']['path']]
    report = {'result': 'NATIVE_A830_SOFTWARE_CONTROLLER_TESTS_PASS', 'suite_count': len(suites),
              'builder_sha256': sha(Path(__file__)),
              'source_revisions': {name: lock[name]['revision'] for name in refs},
              'runtime_overlay': runtime,
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'tests': executions, 'sanitizers': ['address', 'undefined'], 'leak_sanitizer': False,
              'host_barrier_peers': barriers, 'host_architecture': 'x86_64',
              'hardware_tested': False,
              'scope': 'Production source through upstream controller/allocator peers. Six ARM barriers '
                       'use host atomic fences; data-free calls use allocator peers. Kernel objects '
                       'are built separately by build_native_a830.py.'}
    report_path = ROOT / ('reports/native-a830-runtime-host.json' if args.runtime else 'reports/native-a830-host.json')
    report_path.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
