#!/usr/bin/env python3
"""Check recovered-device status and failed-surface display admission on the host."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from fresh_gpu_overlay import replace_once
from native_a830_userspace import display
from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/cph2653-native-a830-recovery-host'
REPORT = ROOT / 'reports/native-a830-recovery-host.json'


def check_report(report):
    require(report['result'] == 'NATIVE_A830_RECOVERY_AND_SURFACE_DISPLAY_HOST_PASS' and
            report['turnip_status_calls'] == 11 and report['frontend_cases'] == 136 and
            not report['hardware_tested'], 'Incomplete native recovery host report')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native recovery test input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true')
    mode.add_argument('--frontend-only', action='store_true', help='Run display recovery tests without a Mesa checkout')
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual Turnip recovery and native display admission');return
    OUT.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    mesa = ROOT / '.cache/gpu-work/mesa-native-a830/src/freedreno/vulkan/tu_knl_darwin.cc'
    pin = lock['native_a830_mesa_recovery_overlay']
    production = ''
    if not args.frontend_only:
        require(sha(mesa) == pin['after_sha256']['src/freedreno/vulkan/tu_knl_darwin.cc'], 'Build native Turnip before its recovery tests')
        text = mesa.read_text();start = text.index('// A diagnostic count of ended work;')
        function = text.index('darwin_device_check_status(struct tu_device *device)', start)
        at = text.index('{', function);depth = 1;end = at + 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}');end += 1
        production = text[start:end] + '\n'
    llvm = shutil.which('clang++-14') or shutil.which('clang++')
    require(llvm, 'Install Clang for recovery host tests')
    flags = [llvm, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fno-pie', '-no-pie',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread']
    env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1', 'UBSAN_OPTIONS': 'halt_on_error=1'}
    commands, artifacts, controls = [], [], []
    fixture = ROOT / 'tests/DodgeTurnipRecoveryTest.cpp'
    turnip_cases = () if args.frontend_only else (
        ('recovered', production, True),
        ('loses-device', replace_once(production, '      device->fault_count = reply.faults;',
            '      device->fault_count = reply.faults;\n      return vk_device_set_lost(&device->vk,"old device-loss behavior");'), False),
        ('loses-during-restart', replace_once(production, 'kr == kIOReturnUnsupported || kr == kIOReturnBusy',
            'kr == kIOReturnUnsupported'), False))
    for name, source, passing in turnip_cases:
        stage = OUT / name;stage.mkdir(exist_ok=True);include = stage / 'TurnipRecovery.inc';include.write_text(source)
        binary = stage / 'test'
        command = [*flags, '-I', stage, '-I', ROOT / 'sources/Adreno830-native', fixture, '-o', binary]
        subprocess.run(command, check=True, capture_output=True);commands.append(list(map(str, command)))
        result = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=30)
        log = stage / 'run.log';log.write_text(result.stdout + result.stderr);artifacts += [include, binary, log]
        require((result.returncode == 0) == passing, 'Turnip recovery control disagrees: ' + name)
        if not passing:
            require('Assertion' in result.stderr, 'Recovery control failed outside its behavior assertion')
            controls.append({'case': name, 'result': 'REJECTED'})

    frontend_stage, frontend_pin = display(OUT / 'frontend-source')
    test = (ROOT / 'tests/DodgeDisplayFrontendTest.cpp').read_text()
    old = '''    run("passed-gpu-target-is-not-queried-again-after-producer-callback",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && gpuQueries==1);
        gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
        assert(!f.kick() && offered.context && gpuQueries==1);completeOffer();
    });'''
    new = '''    run("passed-gpu-target-rechecks-health-after-producer-callback",[]{
        Fixture f;f.create();producerDone=false;assert(!f.submit() && gpuQueries==1);
        gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
        const unsigned queries=gpuQueries;
        assert(f.kick()==kIOReturnBusy && f.status().producerWaiting && !offered.context && gpuQueries>queries);
        gpuKnown=true;f.tick();assert(offered.context);completeOffer();
    });'''
    test = replace_once(test, old, new)
    test = replace_once(test, 'static bool gpuKnown=true;',
        'static uint32_t recoveryFailedID;\n'
        'extern "C" bool dodge_native_surface_visible(OSObject *,uint32_t id) {return id!=recoveryFailedID;}\n'
        'static bool gpuKnown=true;')
    test = replace_once(test, '        now=1000;', '        recoveryFailedID=0;now=1000;')
    test = replace_once(test, '    std::printf("{\\"result\\":\\"PASS\\",\\"cases\\":[");',
        '#include "DodgeDisplayFreshGpuCases.h"\n#include "DodgeDisplayRecoveryCases.h"\n'
        '    std::printf("{\\"result\\":\\"PASS\\",\\"cases\\":[");')
    staged_fixture = OUT / 'DodgeDisplayFrontendTest.cpp';staged_fixture.write_text(test)
    frontend = frontend_stage / 'DodgeDisplayFrontend.cpp';binary = OUT / 'frontend'
    command = [*flags, '-I', ROOT / 'tests/gpu_swap_include', '-I', ROOT / 'drivers/DodgeDisplay', '-I', ROOT / 'tests',
        '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics',
        '-I', ROOT / 'sources/UniXNU-Pagani-Drivers/drivers/NativeMobileDisplay', staged_fixture, frontend,
        ROOT / 'drivers/DodgeDisplay/DodgeGpuSwapBridge.cpp', ROOT / 'drivers/DodgeDisplay/DodgeSoftwareRefresh.cpp', '-o', binary]
    subprocess.run(command, check=True, capture_output=True);commands.append(list(map(str, command)))
    process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=60)
    log = OUT / 'frontend.log';log.write_text(process.stdout + process.stderr)
    require(not process.returncode, 'Native display recovery cases failed; inspect frontend.log')
    cases = json.loads(process.stdout)
    require(cases['result'] == 'PASS' and len(cases['cases']) == 136 and cases['noncanonical_byte_mutations'] == 1124,
            'Native display regression coverage differs')
    if args.frontend_only:
        print('PASS: 136 native display recovery cases and 1124 packet mutations')
        return
    artifacts += [staged_fixture, frontend, binary, log]
    source_files = [Path(__file__), ROOT / 'scripts/native_a830_userspace.py', ROOT / 'scripts/fresh_gpu_overlay.py',
        ROOT / 'tests/DodgeTurnipRecoveryTest.cpp', ROOT / 'tests/DodgeDisplayFrontendTest.cpp',
        ROOT / 'tests/DodgeDisplayFreshGpuCases.h', ROOT / 'tests/DodgeDisplayRecoveryCases.h', mesa,
        ROOT / pin['path'], ROOT / frontend_pin['path'], ROOT / 'drivers/DodgeDisplay/DodgeGpuSwapBridge.cpp',
        ROOT / 'drivers/DodgeDisplay/DodgeSoftwareRefresh.cpp']
    command_file = OUT / 'compile-commands.json';command_file.write_text(json.dumps(commands, indent=2) + '\n');artifacts.append(command_file)
    report = {'result': 'NATIVE_A830_RECOVERY_AND_SURFACE_DISPLAY_HOST_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'turnip_status_calls': 11, 'frontend_cases': 136, 'packet_mutations': 1124, 'controls': controls,
        'sanitizers': ['address', 'undefined', 'leak'], 'hardware_tested': False,
        'scope': 'Actual staged Turnip status functions and native display frontend with transport, timeline and IOKit peers. '
                 'Recovered devices retain their identity; terminal errors still lose them. Failed surfaces remain blocked '
                 'until repaired, and old epochs cannot be reused. Physical reset, rendering and iOS boot remain untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 11 actual Turnip status calls, two rejected old behaviors and 136 native display cases')


if __name__ == '__main__':
    main()
