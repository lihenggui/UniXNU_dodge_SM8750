#!/usr/bin/env python3
"""Exercise the patched production SimpleFb driver with software UEFI services."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pin = lock['simplefb_patch']
    source = ROOT / 'uefi/Mu-Silicium'
    driver = source / pin['target']
    require(sha(ROOT / pin['path']) == pin['sha256'], 'SimpleFb patch digest changed')
    require(sha(driver) == pin['after_sha256'], 'SimpleFb source differs from reviewed patch')
    original = subprocess.check_output(['git', '-C', source, 'show', 'HEAD:' + pin['target']])
    require(hashlib.sha256(original).hexdigest() == pin['before_sha256'], 'Original SimpleFb source changed')
    with tempfile.TemporaryDirectory(prefix='simplefb-clean-patch-') as temporary:
        path = Path(temporary) / pin['target']
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        subprocess.run(['git', 'apply', '--check', str(ROOT / pin['path'])], cwd=temporary, check=True)
        subprocess.run(['git', 'apply', str(ROOT / pin['path'])], cwd=temporary, check=True)
        require(sha(path) == pin['after_sha256'], 'SimpleFb clean patch application differs')
    dsc = source / 'Platforms/OnePlus/dodgePkg/dodge.dsc'
    geometry = {name: int(re.search(r'PcdFrameBuffer' + name + r'\|(\d+)', dsc.read_text())[1])
                for name in ('Width', 'Height', 'ColorDepth')}
    require(geometry == {'Width': 1440, 'Height': 3168, 'ColorDepth': 32},
            'Dodge static geometry differs from the tested firmware configuration')
    test = ROOT / 'tests/SimpleFbTest.c'
    video = ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver/BootVideo.h'
    out = ROOT / 'build/simplefb-tests'
    out.mkdir(parents=True, exist_ok=True)
    executable = out / 'simplefb-test'
    include = [source / 'Mu_Basecore/MdePkg/Include', source / 'Mu_Basecore/MdePkg/Include/X64',
               source / 'Mu_Basecore/MdeModulePkg/Include', source / 'Mu_Basecore/ArmPkg/Include',
               source / 'Silicon/Silicium/SiliciumPkg/Include']
    command = ['gcc', '-std=c11', '-g', '-O1', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-DMDEPKG_NDEBUG', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
               '-DSIMPLEFB_SOURCE="' + str(driver) + '"',
               '-DSIMPLEFB_VIDEO_HEADER="' + str(video) + '"']
    for path in include:
        command += ['-I', str(path)]
    command += [str(test), '-o', str(executable)]
    subprocess.run(command, check=True)
    env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1', 'UBSAN_OPTIONS': 'halt_on_error=1'}
    result = subprocess.check_output([executable], text=True, env=env)
    print(result, end='')
    record = {'result': 'PRODUCTION_SIMPLEFB_HOST_TEST_PASS',
              'runner_sha256': sha(Path(__file__)), 'clean_patch_application': True,
              'driver_sha256': sha(driver), 'test_sha256': sha(test), 'video_helper_sha256': sha(video),
              'patch': pin, 'output': result.strip(), 'sanitizers': ['address', 'undefined'],
              'configured_geometry': geometry, 'configured_geometry_source_sha256': sha(dsc),
              'real_edk2_types': True, 'software_boot_services': True,
              'framebuffer_accessed': False, 'runtime_scanout_geometry_qualified': False,
              'phone_operations': 'none'}
    (ROOT / 'reports/simplefb-tests.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
