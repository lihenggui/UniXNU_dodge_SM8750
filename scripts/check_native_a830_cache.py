#!/usr/bin/env python3
"""Run production Turnip cache/retirement functions with Vulkan and kernel peers."""
import argparse
import base64
import json
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request

from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/cph2653-native-a830-cache-host'
REPORT = ROOT / 'reports/native-a830-cache-host.json'
REVISION = '85fda3b36405bcaea8bffc64aa4f2651dc90770d'
PIPELINE = 'src/freedreno/vulkan/tu_pipeline.cc'
DARWIN = 'src/freedreno/vulkan/tu_knl_darwin.cc'
RAW_SHA = '24d816aa5ce2a27821ab120b910ec777221982bdbbeb830b29e7f4bd432e9347'


def sections(patch):
    lines = patch.splitlines(True);index = 0
    while index + 1 < len(lines):
        if not lines[index].startswith('--- ') or not lines[index + 1].startswith('+++ '):
            index += 1;continue
        name = lines[index + 1].split()[1].removeprefix('b/');end = index + 2
        while end < len(lines) and not lines[end].startswith(('diff --git ', '--- a/', '--- /dev/null')):end += 1
        if name in (PIPELINE, DARWIN):yield ''.join(lines[index:end])
        index = end


def production(lock, restore):
    pin = lock['native_a830_mesa_cache_overlay'];stage = ROOT / '.cache/gpu-work/mesa-native-a830'
    if not restore and all((stage / name).is_file() and sha(stage / name) == pin['after_sha256'][name] for name in (PIPELINE, DARWIN)):
        return stage
    require(lock['mesa_reference']['revision'] == REVISION, 'Review cache tests against the selected Mesa revision')
    stage = OUT / 'source';stage.mkdir(parents=True, exist_ok=True)
    raw = OUT / 'tu_pipeline.original.cc'
    if not raw.exists():
        url = 'https://chromium.googlesource.com/external/gitlab.freedesktop.org/mesa/mesa/+/' + REVISION + '/' + PIPELINE + '?format=TEXT'
        raw.write_bytes(base64.b64decode(urllib.request.urlopen(url, timeout=60).read(), validate=True))
    require(sha(raw) == RAW_SHA, 'Pinned Mesa source download changed')
    target = stage / PIPELINE;target.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(raw, target)
    (stage / DARWIN).unlink(missing_ok=True)
    specs = [*lock['mesa_runtime_patches'], *(lock[name] for name in
        ('native_a830_mesa_surface_overlay', 'native_a830_mesa_recovery_overlay', 'native_a830_mesa_cache_overlay'))]
    for index, spec in enumerate(specs):
        patch = ROOT / spec['path'];require(sha(patch) == spec['sha256'], 'Turnip patch changed: ' + spec['path'])
        selected = ''.join(sections(patch.read_text()))
        if not selected:continue
        selected_path = OUT / ('selected-' + str(index) + '.patch');selected_path.write_text(selected)
        result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', selected_path], cwd=stage,
            capture_output=True, text=True)
        require(not result.returncode, 'Cannot restore production cache source: ' + result.stdout + result.stderr)
    require(all(sha(stage / name) == pin['after_sha256'][name] for name in (PIPELINE, DARWIN)), 'Restored Turnip source differs from the cross-build')
    return stage


def function(text, name):
    match = re.search(r'(?m)^' + re.escape(name) + r'\(', text);require(match, 'Missing production function ' + name)
    start = text.rfind('\nstatic ', 0, match.start()) + 1;at = text.index('{', match.end());end = at + 1;depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}');end += 1
    return text[start:end] + '\n'


def check_report(report):
    require(report['result'] == 'NATIVE_A830_CACHE_AND_RETIREMENT_HOST_PASS' and report['cases'] == 19 and
        report['concurrent_lookups'] == 800 and not report['hardware_tested'], 'Incomplete Turnip cache report')
    for path, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / path) == digest, 'Turnip cache input changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--restore-source', action='store_true', help='Restore the two source files from their pinned inputs')
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: production Turnip shader sharing and buffer retirement');return
    OUT.mkdir(parents=True, exist_ok=True);lock = json.loads((ROOT / 'upstream.lock.json').read_text());stage = production(lock, args.restore_source)
    pipeline, darwin = (stage / name for name in (PIPELINE, DARWIN))
    source = OUT / 'TurnipCache.inc'
    source.write_text(''.join(function(pipeline.read_text(), name) for name in ('tu_pipeline_cache_lookup', 'tu_pipeline_cache_insert')) +
        ''.join(function(darwin.read_text(), name) for name in ('darwin_collect_retired', 'darwin_bo_init', 'dw_wait_fence_locked_free')))
    compiler = shutil.which('clang++-14') or shutil.which('clang++');require(compiler, 'Install Clang for cache tests')
    fixture = ROOT / 'tests/DodgeTurnipCacheTest.cpp';binary = OUT / 'test'
    command = [compiler, '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-pie', '-no-pie', '-pthread',
        '-I', OUT, '-I', ROOT / lock['native_a830_reference']['path'], fixture, '-o', binary]
    subprocess.run(command, check=True)
    result = subprocess.run([binary], capture_output=True, text=True, timeout=60)
    log = OUT / 'run.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode, 'Production Turnip cache test failed; inspect run.log')
    counts = json.loads(result.stdout);pin = lock['native_a830_mesa_cache_overlay']
    report = {'result': 'NATIVE_A830_CACHE_AND_RETIREMENT_HOST_PASS', **counts,
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (Path(__file__), fixture, pipeline, darwin, ROOT / pin['path'])},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in (source, binary, log)},
        'sanitizers': ['address', 'undefined'], 'hardware_tested': False,
        'scope': 'Production shader-cache and buffer-allocation/retirement functions with Vulkan reference-cache and kernel transport peers. '
                 'Checks device isolation, reference release, concurrent lookup, cache-hit I/O avoidance, completed-buffer reuse, '
                 'latched failures, allocation cleanup and opportunistic fence observation. No shader executes.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 19 production Turnip cache cases and 800 concurrent lookups under sanitizers')


if __name__ == '__main__':main()
