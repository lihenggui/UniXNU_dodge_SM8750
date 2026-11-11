#!/usr/bin/env python3
"""Stage the CPH2653 surface-ID adapters after the pinned userspace patches."""
import json
import shutil
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha
from prepare_sources import patch_series_state


def overlay(base, stage, name):
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())[name]
    patch = ROOT / pin['path']
    require(sha(patch) == pin['sha256'], 'Native A830 userspace adapter changed')
    shutil.copytree(base, stage, dirs_exist_ok=True, ignore_dangling_symlinks=True,
                    ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
    for path, digest in pin['before_sha256'].items():
        require(sha(stage / path) == digest, 'Native A830 userspace base changed: ' + path)
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
                             cwd=stage, capture_output=True, text=True)
    (stage.parent / (stage.name + '-overlay.log')).write_text(process.stdout + process.stderr)
    require(not process.returncode and 'offset' not in process.stdout.lower(), 'Userspace adapter did not apply exactly')
    for path, digest in pin['after_sha256'].items():
        require(sha(stage / path) == digest, 'Native A830 userspace output changed: ' + path)
    for path, spec in pin.get('support', {}).items():
        source = ROOT / path
        require(sha(source) == spec['sha256'], 'Native A830 userspace support changed')
        shutil.copyfile(source, stage / spec['destination'])
    return stage, pin


def metal():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    source = pinned_sources(('a830_metal_reference',))['a830_metal_reference']
    base = ROOT / '.cache/gpu-work/AdrenoMetal'
    if not base.exists():
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', source, base], check=True)
        subprocess.run(['git', '-C', base, 'checkout', '--quiet', '--detach', lock['a830_metal_reference']['revision']], check=True)
    require(subprocess.check_output(['git', '-C', base, 'rev-parse', 'HEAD'], text=True).strip() ==
            lock['a830_metal_reference']['revision'], 'Native Metal adapter has an unexpected base')
    patch_series_state(base, lock['iphone_metal_frontend_patches'], True)
    return overlay(base, ROOT / '.cache/gpu-work/AdrenoMetal-native-a830', 'native_a830_metal_surface_overlay')
