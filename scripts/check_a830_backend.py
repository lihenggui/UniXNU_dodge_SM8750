#!/usr/bin/env python3
"""Run the pinned A830 production tests with ASan/UBSan; no hardware access."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha
from optional_gpu_calls import stage_optional_calls
from adreno_display_timeline import stage_display_timeline


def main():
    names = ('a830_backend_reference', 'a830_firmware_reference', 'a830_build_reference')
    sources = pinned_sources(names)
    gpu, optional_overlay = stage_optional_calls('backend', sources['a830_backend_reference'])
    gpu, timeline_overlay = stage_display_timeline(gpu)
    out = ROOT / 'build/cph2653-a830-tests'
    script = out / 'scripts/check-adreno-a830.py'
    script.parent.mkdir(parents=True, exist_ok=True)
    reference = sources['a830_build_reference'] / 'scripts/check-adreno-a830.py'
    shutil.copyfile(reference, script)
    paths = {'drivers/Adreno740': gpu,
             'kits/AdrenoFirmware': sources['a830_firmware_reference']}
    support = {}
    for name in ('AdrenoPM4', 'ArmSmmu4K'):
        path = ROOT / 'sources/UniXNU/kits' / name
        pin = subprocess.check_output(['git', '-C', str(path.parent.parent), 'ls-tree', 'HEAD', 'kits/' + name], text=True).split()[2]
        require(subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip() == pin,
                'Unexpected support revision: ' + name)
        require(not subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True),
                'Support reference is modified: ' + name)
        paths['kits/' + name], support[name] = path, pin
    for relative, source in paths.items():
        dest = out / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            if relative == 'drivers/Adreno740' and dest.resolve() in (sources['a830_backend_reference'].resolve(),ROOT/'.cache/gpu-work/kernel-optional/backend'):
                dest.unlink()
                dest.symlink_to(source, target_is_directory=True)
            require(dest.resolve() == source.resolve(), 'Unexpected test source link: ' + relative)
        else:
            require(not dest.exists(), 'Test staging path is occupied: ' + relative)
            dest.symlink_to(source, target_is_directory=True)
    log_path = out / 'tests.log'
    # The fixtures exercise the actual production source selected by the
    # consuming integration script. They model MMIO, allocation and peers.
    env = dict(os.environ, CC='/usr/bin/gcc', CXX='/usr/bin/g++',
               ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
    with log_path.open('w') as log:
        process = subprocess.run([ROOT / '.venv-uefi/bin/python', script], env=env,
                                 stdout=log, stderr=subprocess.STDOUT, timeout=600)
    require(process.returncode == 0, 'A830 tests failed; see ' + str(log_path))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    report = {'result': 'A830_BACKEND_HOST_TESTS_PASS','builder_sha256':sha(Path(__file__)),
              'suites': ['diagnostics', 'ring', 'cpinit', 'irq', 'timer', 'a830_hwinit', 'gpu',
                         'hfi-startup', 'system-memory', 'gmuctx', 'gpuctx', 'userclient'],
              'sanitizers': ['address', 'undefined'],
              'source_revisions': {name: lock[name]['revision'] for name in names},
              'support_revisions': support, 'integration_script_sha256': sha(reference),
              'optional_call_overlay': optional_overlay,
              'display_timeline_overlay': timeline_overlay,
              'log': str(log_path.relative_to(ROOT)), 'log_sha256': sha(log_path),
              'compiler': subprocess.check_output([env['CXX'], '--version'], text=True).splitlines()[0],
              'hardware_tested': False, 'scope': 'Production command/memory/HFI paths over software peers, not device execution.'}
    (ROOT / 'reports/a830-backend-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 12 existing A830 backend suites under ASan/UBSan; no hardware exercised')


if __name__ == '__main__':
    main()
