#!/usr/bin/env python3
"""Run the existing presenter ownership and target board SMMU software regressions."""
import json
import os
import shutil
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha
from optional_gpu_calls import stage_optional_calls


def main():
    sources = pinned_sources(('oneplus13t_reference', 'pagani_reference', 'sm8750', 'a830_backend_reference'))
    presenter, optional_overlay = stage_optional_calls('presenter', sources['pagani_reference'] / 'drivers/NativeMobileDisplay')
    out = ROOT / 'build/cph2653-gpu-handoff-tests'
    references = out / 'refs'
    device = references / 'UniXNU-Pagani_SM8750'
    (device / 'scripts').mkdir(parents=True, exist_ok=True)
    (device / 'package').mkdir(exist_ok=True)
    target_board = ROOT / 'build/cph2653-gpu-board/source/PaganiGpu.cpp'
    require(target_board.is_file(), 'Build the target GPU board source first')
    shutil.copyfile(target_board, device / 'package/PaganiGpu.cpp')
    helper = ROOT / 'drivers/DodgeDisplay/DodgeOptionalCalls.h'
    shutil.copyfile(helper, device / 'package' / helper.name)
    container = references / 'UniXNU-Pagani-Drivers'
    if container.is_symlink():
        require(container.resolve() == sources['pagani_reference'].resolve(), 'Unexpected presenter test reference')
        container.unlink()
    (container / 'drivers').mkdir(parents=True, exist_ok=True)
    for child in (sources['pagani_reference'] / 'drivers').iterdir():
        dest = container / 'drivers' / child.name
        selected = presenter if child.name == 'NativeMobileDisplay' else child
        if dest.is_symlink():
            require(dest.resolve() == selected.resolve(), 'Unexpected staged presenter test input')
        else:
            require(not dest.exists(), 'Occupied presenter test staging path')
            dest.symlink_to(selected, target_is_directory=selected.is_dir())
    links = {'UniXNU-sm8750-common': sources['sm8750'],
             'UniXNU/kits': ROOT / 'sources/UniXNU/kits', 'UniXNU/drivers/Adreno740': sources['a830_backend_reference']}
    for name, source in links.items():
        dest = references / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            require(dest.resolve() == source.resolve(), 'Unexpected handoff test source link')
        else:
            require(not dest.exists(), 'Handoff test staging path is occupied')
            dest.symlink_to(source, target_is_directory=True)
    scripts = ['test-gpu-presenter.py', 'test-gpu-smmu.py']
    env = dict(os.environ, CC='gcc', CXX='g++', ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
    with (out / 'tests.log').open('w') as log:
        for name in scripts:
            source = sources['oneplus13t_reference'] / 'scripts' / name
            script = device / 'scripts' / name
            shutil.copyfile(source, script)
            subprocess.run([ROOT / '.venv-uefi/bin/python', script], env=env, check=True,
                           stdout=log, stderr=subprocess.STDOUT, timeout=180)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    report = {'result': 'GPU_HANDOFF_AND_TARGET_BOARD_HOST_TESTS_PASS', 'sanitizers': ['address', 'undefined'],
              'source_revisions': {name: lock[name]['revision'] for name in sources},
              'target_board_source_sha256': sha(target_board),
              'optional_call_overlay': optional_overlay, 'optional_call_helper_sha256': sha(helper),
              'test_scripts': {name: sha(sources['oneplus13t_reference'] / 'scripts' / name) for name in scripts},
              'log': str((out / 'tests.log').relative_to(ROOT)), 'log_sha256': sha(out / 'tests.log'),
              'hardware_tested': False, 'scope': 'Actual presenter methods and target board SMMU/status code over software allocation/MMIO peers.'}
    (ROOT / 'reports/gpu-handoff-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print((out / 'tests.log').read_text().strip())


if __name__ == '__main__':
    main()
