#!/usr/bin/env python3
"""Cross-build the pinned production Turnip Darwin backend for iPhone iOS 16."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from native_driver_build import ROOT, ios_userspace_linker, pinned_sources, require, sha
from prepare_sources import patch_series_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configure-only', action='store_true')
    args = parser.parse_args()
    sources = pinned_sources(('mesa_reference', 'iphoneos_sdk_reference', 'a830_backend_reference'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pins = json.loads((ROOT / 'sources/UniXNU/scripts/data/adreno-compiler-inputs.json').read_text())
    require(pins['mesa']['commit'] == lock['mesa_reference']['revision'], 'Mesa compiler/source pins differ')
    original = sources['mesa_reference']
    require(subprocess.check_output(['git', '-C', original, 'rev-parse', 'HEAD^{tree}'], text=True).strip() == pins['mesa']['tree'],
            'Unexpected Mesa source tree')
    work = ROOT / '.cache/gpu-work/mesa'
    if not work.exists():
        work.parent.mkdir(parents=True, exist_ok=True)
        # A shared clone of a shallow partial clone makes upload-pack enumerate
        # missing blobs. Borrow its object database directly and keep our own
        # sparse index and worktree; missing objects retain the public promisor.
        subprocess.run(['git', 'init', '--quiet', work], check=True)
        (work / '.git/objects/info/alternates').write_text(str(original / '.git/objects') + '\n')
        for key, value in (('remote.origin.url', lock['mesa_reference']['repository']),
                           ('remote.origin.promisor', 'true'), ('remote.origin.partialclonefilter', 'blob:none')):
            subprocess.run(['git', '-C', work, 'config', key, value], check=True)
        shallow = original / '.git/shallow'
        if shallow.exists():
            (work / '.git/shallow').write_bytes(shallow.read_bytes())
        subprocess.run(['git', '-C', work, 'sparse-checkout', 'init', '--cone'], check=True)
        subprocess.run(['git', '-C', work, 'sparse-checkout', 'set', *pins['mesa']['sparse_directories']], check=True)
        subprocess.run(['git', '-C', work, 'checkout', '--quiet', '--detach', pins['mesa']['commit']], check=True)
    require(subprocess.check_output(['git', '-C', work, 'rev-parse', 'HEAD'], text=True).strip() == pins['mesa']['commit'],
            'Patched Mesa has an unexpected base')
    specs = lock['mesa_runtime_patches']
    require([p['path'] for p in specs] == ['sources/UniXNU/' + p for p in pins['patches']], 'Mesa patch order differs')
    # One recorded patch omits Git's new-file metadata. Git 2.34's cached
    # application treats its /dev/null as an indexed path. Add only the
    # explicit mode in a derived local copy, then audit final bytes against
    # the unchanged upstream series below.
    normalized = []
    patch_dir = ROOT / '.cache/gpu-work/mesa-patches'
    patch_dir.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        original_patch = ROOT / spec['path']
        require(sha(original_patch) == spec['sha256'], 'Recorded Mesa patch digest differs')
        data = original_patch.read_bytes()
        data = re.sub(rb'(diff --git [^\n]+\n)(--- /dev/null\n)', rb'\1new file mode 100644\n\2', data)
        path = patch_dir / original_patch.name
        path.write_bytes(data)
        normalized.append({'path': str(path.relative_to(ROOT)), 'sha256': sha(path)})
    patch_series_state(work, normalized, True)
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
    from mesa_patch_identity import validate_recorded_patches
    (ROOT / 'sources/UniXNU/.cache').mkdir(exist_ok=True)
    validate_recorded_patches(ROOT / 'sources/UniXNU', work, pins)
    sdk = sources['iphoneos_sdk_reference'] / 'iPhoneOS16.5.sdk'
    llvm = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin'
    clang = ROOT / '.toolchains/xnu-linux/llvm/bin/clang'
    linker = ios_userspace_linker()
    out = ROOT / 'build/cph2653-turnip-ios16'
    out.mkdir(parents=True, exist_ok=True)
    flags = ['-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk), '-fstack-protector-strong', '-mlinker-version=1115']
    link_flags = flags + ['-fuse-ld=' + str(linker), '-Wl,-adhoc_codesign']
    cross = out / 'ios16.cross'
    cross.write_text('[binaries]\n' +
                     ''.join(f'{name} = {value!r}\n' for name, value in {
                         'c': [str(clang), *flags], 'cpp': [str(clang), '--driver-mode=g++', *flags],
                         'objc': [str(clang), *flags],
                         'ar': str(llvm / 'llvm-ar'), 'strip': '/usr/bin/llvm-strip-14',
                         'pkg-config': '/usr/bin/false'}.items()) +
                     "[host_machine]\nsystem = 'darwin'\ncpu_family = 'aarch64'\ncpu = 'arm64'\nendian = 'little'\n" +
                     '[properties]\nneeds_exe_wrapper = true\n[built-in options]\n' +
                     ''.join(f'{name} = {flags!r}\n' for name in ('c_args', 'cpp_args', 'objc_args')) +
                     ''.join(f'{name} = {link_flags!r}\n' for name in ('c_link_args', 'cpp_link_args', 'objc_link_args')))
    options = ['-Dgallium-drivers=', '-Dvulkan-drivers=freedreno', '-Dfreedreno-kmds=darwin',
               '-Dtu-darwin-abi-dir=' + str(sources['a830_backend_reference']), '-Dplatforms=macos',
               '-Dglx=disabled', '-Degl=disabled', '-Dgbm=disabled', '-Dopengl=false', '-Dgles1=disabled',
               '-Dgles2=disabled', '-Dllvm=disabled', '-Dshared-glapi=disabled', '-Dxmlconfig=disabled',
               '-Dshader-cache=enabled', '-Dtools=', '-Dbuild-tests=false', '-Dvideo-codecs=', '-Dvulkan-layers=',
               '-Dlibunwind=disabled', '-Dlmsensors=disabled', '-Dvalgrind=disabled', '-Dexpat=disabled',
               '-Dzstd=disabled', '-Dbuildtype=release', '-Db_ndebug=true']
    diff = subprocess.check_output(['git', '-C', work, 'diff', 'HEAD', '--binary'])
    untracked = subprocess.check_output(['git', '-C', work, 'ls-files', '--others', '--exclude-standard', '-z']).split(b'\0')
    extras = {name.decode(): sha(work / name.decode()) for name in untracked if name and (work / name.decode()).is_file()}
    profile = {'mesa_revision': pins['mesa']['commit'], 'target': 'arm64-apple-ios16.0',
               'source_diff_sha256': hashlib.sha256(diff).hexdigest(), 'extra_sources': extras,
               'patch_guard_sha256': sha(ROOT / 'sources/UniXNU/scripts/mesa_patch_identity.py'),
               'compiler': subprocess.check_output([clang, '--version'], text=True).strip(),
               'options': options, 'build_script_sha256': sha(Path(__file__)), 'cross_file_sha256': sha(cross),
               'sdk_revision': lock['iphoneos_sdk_reference']['revision']}
    source_id = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    build_id = hashlib.sha256(json.dumps({'mesa_revision': pins['mesa']['commit'],
        'source_diff_sha256': profile['source_diff_sha256'], 'extra_sources': extras}, sort_keys=True).encode()).hexdigest()[:40]
    options += ['-Dtu-builtin-source-id=' + source_id, '-Dtu-builtin-pack-header=', '-Dtu-build-id=' + build_id]
    (out / 'builtin-build-profile.json').write_text(json.dumps({'source_id': source_id, 'profile': profile,
        'embedded_pack_sha256': None, 'builtin_pack_required': False}, indent=2) + '\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('IR3_', 'FD_MESA_', 'NIR_', 'MESA_SHADER_', 'TU_'))}
    env.update(PATH=str(ROOT / '.venv-gpu/bin') + ':' + str(ROOT / '.toolchains/gpu-host/bin') + ':' +
               str(ROOT / '.toolchains/gpu-host/usr/bin') + ':' + env.get('PATH', ''),
               CC=str(clang), CXX=str(clang), CFLAGS='', CXXFLAGS='', CPPFLAGS='', LDFLAGS='')
    require((ROOT / '.toolchains/gpu-host/bin/glslangValidator').exists(), 'Build pinned GPU host shader tools first')
    meson = ROOT / '.venv-gpu/bin/meson'
    command = ([meson, 'configure', out] if (out / 'build.ninja').exists() else
               [meson, 'setup', out, work, '--wrap-mode=nodownload', '--cross-file', cross])
    with (out / 'configure.log').open('w') as log:
        process = subprocess.run(command + options, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    require(process.returncode == 0, 'Turnip configure failed; see ' + str(out / 'configure.log'))
    if args.configure_only:
        print('PASS: iOS 16 Turnip Darwin backend configured')
        return
    with (out / 'build.log').open('w') as log:
        process = subprocess.run(['ninja', '-C', out, '-j4'], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    require(process.returncode == 0, 'Turnip build failed; see ' + str(out / 'build.log'))
    library = out / 'src/freedreno/vulkan/libvulkan_freedreno.dylib'
    names = subprocess.check_output([llvm / 'llvm-nm', '--defined-only', '--extern-only', library], text=True)
    require('_vk_icdGetInstanceProcAddr' in names, 'The real Vulkan ICD entry is absent')
    report = {'result': 'IOS16_TURNIP_CROSS_BUILD_PASS', 'target': 'arm64-apple-ios16.0',
              'library': str(library.relative_to(ROOT)), 'library_sha256': sha(library),
              'mesa_revision': pins['mesa']['commit'], 'patches': specs, 'source_id': source_id,
              'build_id': build_id, 'profile': profile, 'backend': 'darwin',
              'abi_header_sha256': sha(sources['a830_backend_reference'] / 'NativeAdrenoABI.h'),
              'hardware_tested': False, 'scope': 'Actual production Vulkan/IR3 library cross-build, not GPU shader execution.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/turnip-ios16.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: production iOS 16 Turnip/IR3 library with the Darwin IOKit backend')


if __name__ == '__main__':
    main()
