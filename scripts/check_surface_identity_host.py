#!/usr/bin/env python3
"""Sanitize the real current-task identity bridge with explicit IOKit peers."""
import os
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require


def run(out):
    out.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'drivers/DodgeGpu/DodgeSurfaceIdentity.cpp'
    test = ROOT / 'tests/DodgeSurfaceIdentityTest.cpp'
    flags = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-fno-pie', '-no-pie', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
        '-I', ROOT / 'tests/surface_identity_include', '-I', source.parent,
        '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics']
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1')
    binary = out / 'identity-test'; subprocess.run([*flags, test, source, '-o', binary], check=True)
    process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=30)
    log = out / 'identity-tests.log'; log.write_text(process.stdout + process.stderr)
    require(process.returncode == 0 and 'PASS: 13 actual identity source cases' in process.stdout, 'Identity sanitizer cases failed')
    controls = []; text = source.read_text()
    for name, before, after in (
        ('kernel-worker-check-removed', 'if(!caller || caller==kernel_task)', 'if(!caller)'),
        ('rejected-result-reference-leaked', 'surface->release();status=kIOReturnNotReady;', 'status=kIOReturnNotReady;'),
        ('virtual-result-release-removed', 'if(surface)surface->release();', '(void)surface;'),
    ):
        require(text.count(before) == 1, 'Identity source control target changed')
        modified = out / (name + '.cpp'); modified.write_text(text.replace(before, after))
        executable = out / name; subprocess.run([*flags, test, modified, '-o', executable], check=True)
        result = subprocess.run([executable], env=env, capture_output=True, text=True, timeout=30)
        (out / (name + '.log')).write_text(result.stdout + result.stderr)
        require(result.returncode != 0, 'Identity source control accepted: ' + name)
        controls.append({'case': name, 'result': 'REJECTED'})
    return {'cases': 13, 'source_controls': controls, 'sanitizers': ['address', 'undefined', 'leak'],
            'artifacts': [binary, log]}


if __name__ == '__main__': print(run(ROOT / 'build/cph2653-surface-identity/host'))
