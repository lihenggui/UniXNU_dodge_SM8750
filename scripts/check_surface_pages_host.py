#!/usr/bin/env python3
"""Sanitize exact-page association and rollback with explicit provider/reference peers."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(out):
    out.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'drivers/DodgeGpu/DodgeSurfacePages.cpp'; test = ROOT / 'tests/DodgeSurfacePagesTest.cpp'
    flags = ['/usr/bin/g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fno-pie', '-no-pie',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
        '-I', ROOT / 'tests/surface_pages_include', '-I', source.parent, '-I', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics']
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
    binary = out / 'pages-test'; subprocess.run([*flags, test, source, '-o', binary], check=True)
    process = subprocess.run([binary], env=env, capture_output=True, text=True, timeout=30)
    log = out / 'pages-tests.log'; log.write_text(process.stdout + process.stderr)
    if process.returncode or 'PASS: 35 actual surface page-association cases' not in process.stdout:
        raise ValueError('Surface page sanitizer cases failed: ' + str(log))
    controls = []; body = source.read_text()
    for name, before, after in (
        ('every-other-page-skipped', 'offset+=4096', 'offset+=8192'),
        ('job-reference-release-guard-removed', 'if(p->memory->deviceReferences()!=1)return kIOReturnBusy;', ''),
        ('complete-error-ownership-lost', 'if(status) {p->quarantined=true;p->memory->quarantine();return status;}\n        p->prepared=false;', '(void)status;\n        p->prepared=false;'),
        ('post-walk-backing-check-removed',
         'if(native_iphone_surface_memory(p->identity.surface)!=p->backing ||\n        !extent(p->identity,p->bytes) || p->backing->getLength()!=p->bytes)return kIOReturnNotReady;', ''),
    ):
        if body.count(before) != 1: raise ValueError('Surface page control target changed: ' + name)
        mutated = out / (name + '.cpp'); mutated.write_text(body.replace(before, after))
        executable = out / name; subprocess.run([*flags, test, mutated, '-o', executable], check=True)
        result = subprocess.run([executable], env=env, capture_output=True, text=True, timeout=30)
        (out / (name + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode == 0: raise ValueError('Surface page source control accepted: ' + name)
        controls.append({'case': name, 'result': 'REJECTED'})
    return {'cases': 35, 'source_controls': controls, 'sanitizers': ['address', 'undefined'], 'artifacts': [binary, log]}


if __name__ == '__main__': print(run(ROOT / 'build/cph2653-surface-pages/host'))
