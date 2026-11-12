#!/usr/bin/env python3
"""Apply the locked iPhone runtime adapter to an isolated native A830 tree."""
import json
import shutil
import subprocess

from native_driver_build import ROOT, require, sha


def apply_runtime(stage):
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pins = [lock['native_a830_runtime_overlay'], lock['native_a830_surface_overlay'], lock['native_a830_recovery_overlay']]
    support = {}
    for pin in pins:
        patch = ROOT / pin['path']
        require(sha(patch) == pin['sha256'], 'Native A830 runtime patch changed')
        for name, digest in pin['before_sha256'].items():
            require(sha(stage / name) == digest, 'Native A830 runtime base changed: ' + name)
        result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
                                cwd=stage, capture_output=True, text=True)
        (stage.parent / (patch.stem + '.log')).write_text(result.stdout + result.stderr)
        require(not result.returncode and 'offset' not in result.stdout.lower(), 'Native A830 runtime patch did not apply exactly')
        for name, digest in pin['after_sha256'].items():
            require(sha(stage / name) == digest, 'Native A830 runtime output changed: ' + name)
        for name, digest in pin['support_sha256'].items():
            source = ROOT / name
            require(sha(source) == digest, 'Native A830 runtime support changed: ' + name)
            shutil.copyfile(source, stage / source.name)
        support.update(pin['support_sha256'])
    return {**pins[0], 'surface_overlay': pins[1], 'recovery_overlay': pins[2], 'support_sha256': support}
