#!/usr/bin/env python3
"""Cross-build the A830 Metal frontend for the selected ordinary-arm64 iPhone."""
import argparse
import concurrent.futures
import json
import plistlib
import shutil
import struct
import subprocess

from native_driver_build import ROOT, inspect_object, ios_userspace_linker, pinned_sources, require, sha
from prepare_sources import patch_series_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objects-only', action='store_true')
    parser.add_argument('--native-a830', action='store_true', help='build the native surface-ID frontend and libraries')
    args = parser.parse_args()
    sources = pinned_sources(('a830_metal_reference', 'a830_backend_reference', 'iphoneos_sdk_reference', 'pagani_reference'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    frontend = ROOT / '.cache/gpu-work/AdrenoMetal'
    if not frontend.exists():
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', sources['a830_metal_reference'], frontend], check=True)
        subprocess.run(['git', '-C', frontend, 'checkout', '--quiet', '--detach', lock['a830_metal_reference']['revision']], check=True)
    require(subprocess.check_output(['git', '-C', frontend, 'rev-parse', 'HEAD'], text=True).strip() == lock['a830_metal_reference']['revision'],
            'Unexpected Metal frontend base')
    patch_series_state(frontend, lock['iphone_metal_frontend_patches'], True)
    native_overlay = None
    if args.native_a830:
        from native_a830_userspace import metal
        frontend, native_overlay = metal()
    sdk = sources['iphoneos_sdk_reference'] / 'iPhoneOS16.5.sdk'
    clang = ROOT / '.toolchains/xnu-linux/llvm/bin/clang'
    llvm = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin'
    out = ROOT / ('build/cph2653-native-a830-metal-plugin' if args.native_a830 else 'build/cph2653-metal-plugin')
    out.mkdir(parents=True, exist_ok=True)
    shader_lines = ['// Generated from the pinned GLSL, not recorded A740 commands.', '#pragma once', '#include <stdint.h>']
    compiler = ROOT / '.toolchains/gpu-host/usr/bin/glslangValidator'
    validator = ROOT / '.toolchains/gpu-host/usr/bin/spirv-val'
    shader_hashes = {}
    for source in sorted((frontend / 'shaders').glob('smoke_*')):
        spv = out / (source.name + '.spv')
        subprocess.run([compiler, '-V', '--target-env', 'vulkan1.1', source, '-o', spv], check=True, capture_output=True)
        subprocess.run([validator, '--target-env', 'vulkan1.1', spv], check=True, capture_output=True)
        data = spv.read_bytes()
        words = struct.unpack('<%dI' % (len(data) // 4), data)
        shader_lines.append('static const uint32_t kSpv_' + source.name.replace('.', '_') + '[] = {' +
                            ','.join(hex(w) for w in words) + '};')
        shader_hashes[source.name] = {'glsl_sha256': sha(source), 'spirv_sha256': sha(spv)}
    (out / 'NativeTurnipShaders.h').write_text('\n'.join(shader_lines) + '\n')
    base = [str(clang), '-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk), '-O2', '-g',
            '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong', '-mlinker-version=1115',
            '-DNATIVE_ADRENO_SKIP_A740_REPLAY=1', '-DNATIVE_ADRENO_SP_CORES=6']
    includes = [sources['a830_backend_reference'], ROOT / 'sources/UniXNU/kits/AdrenoPM4',
                ROOT / '.cache/gpu-work/mesa/include', out,
                sources['pagani_reference'] / 'drivers/NativeMobileDisplay',
                ROOT / 'sources/UniXNU/drivers/NativeMobileDisplay', ROOT / 'sources/UniXNU/drivers/GopFramebuffer']
    cpp = [*base, '--driver-mode=g++', '-std=c++17', '-fobjc-arc', '-Wno-deprecated-declarations',
           '-Wno-unused-but-set-global']
    for path in includes:
        cpp += ['-I', str(path)]
    files = [frontend / name for name in ('NativeAdrenoMetalPlugin.mm', 'NativeBridgeMetalFrontend.mm',
                                         'NativeAdrenoProbeDaemon.cpp', 'NativeOsLogExport.mm')]
    commands = [[*cpp, '-c', str(path), '-o', str(out / (path.stem + '.o'))] for path in files]
    pm4 = ROOT / 'sources/UniXNU/kits/AdrenoPM4/AdrenoPM4.c'
    commands.append([*base, '-std=c11', '-c', str(pm4), '-o', str(out / 'AdrenoPM4.o')])
    (out / 'compile-commands.json').write_text(json.dumps(commands, indent=2) + '\n')

    def compile_one(command):
        obj = out / command[-1]
        with obj.with_suffix('.log').open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if not result.returncode:
            inspect_object(obj.read_bytes())
        return obj.name, result.returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(compile_one, commands))
    require(not any(results.values()), 'Metal frontend compile failed; see individual object logs: ' + repr(results))
    report = {'result': 'IOS16_METAL_FRONTEND_OBJECTS_PASS', 'target': 'arm64-apple-ios16.0',
              'a740_replay_disabled': True, 'sp_topology': 6, 'sp_topology_is_active_measurement': False,
              'shader_fixtures': shader_hashes, 'object_sha256': {name: sha(out / name) for name in results},
              'frontend_revision': lock['a830_metal_reference']['revision'],
              'ios16_interface_patches': lock['iphone_metal_frontend_patches'],
              'native_surface_overlay': native_overlay,
              'sdk_scope': 'iOS 16.5 cross-build headers/stubs; runtime private ABI is not qualified.',
              'hardware_tested': False, 'linked': False}
    if args.objects_only:
        (ROOT / ('reports/native-a830-metal-plugin.json' if args.native_a830 else 'reports/metal-plugin.json')).write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: actual iOS 16 Metal plugin/frontend/probe objects and validated shader fixtures')
        return
    bridge = ROOT / 'build/cph2653-metal-bridge/target/aarch64-apple-ios/release/libadreno_metal_bridge.a'
    turnip = ROOT / 'build/cph2653-turnip-ios16/src/freedreno/vulkan/libvulkan_freedreno.dylib'
    if args.native_a830:
        bridge = ROOT / 'build/cph2653-native-a830-metal-bridge/target/aarch64-apple-ios/release/libadreno_metal_bridge.a'
        turnip = ROOT / 'build/cph2653-native-a830-turnip/src/freedreno/vulkan/libvulkan_freedreno.dylib'
    require(bridge.exists() and turnip.exists(), 'Build the pinned Rust bridge and Turnip first')
    bundle = out / 'NativeAdrenoMetal.bundle'
    bundle.mkdir(exist_ok=True)
    executable = bundle / 'NativeAdrenoMetal'
    link = [*base, '--driver-mode=g++', '--ld-path=' + str(ios_userspace_linker()),
            out / 'NativeAdrenoMetalPlugin.o', out / 'NativeBridgeMetalFrontend.o', out / 'AdrenoPM4.o',
            bridge, '-bundle', '-Wl,-dead_strip', '-Wl,-adhoc_codesign', '-lobjc',
            '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOSurface', '-o', executable]
    with (out / 'link.log').open('w') as log:
        result = subprocess.run(link, stdout=log, stderr=subprocess.STDOUT, timeout=900)
    require(result.returncode == 0, 'Metal bundle link failed; see build/cph2653-metal-plugin/link.log')
    shutil.copyfile(turnip, bundle / turnip.name)
    (bundle / 'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier='org.blu-sharky.NativeAdrenoMetal',
        CFBundleExecutable='NativeAdrenoMetal', CFBundlePackageType='BNDL', CFBundleVersion='1',
        CFBundleShortVersionString='1', NSPrincipalClass='NativeAdrenoMetalDevice', MinimumOSVersion='16.0')))
    daemon = out / 'adrenoprobed'
    daemon_link = [*base, '--driver-mode=g++', '--ld-path=' + str(ios_userspace_linker()),
                   out / 'NativeAdrenoProbeDaemon.o', out / 'NativeOsLogExport.o', out / 'AdrenoPM4.o',
                   '-framework', 'Foundation', '-lz', '-Wl,-adhoc_codesign', '-o', daemon]
    with (out / 'daemon-link.log').open('w') as log:
        result = subprocess.run(daemon_link, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    require(result.returncode == 0, 'Diagnostic daemon link failed; see daemon-link.log')
    report.update(result='IOS16_METAL_PLUGIN_CROSS_BUILD_PASS', linked=True,
                  bundle=str(bundle.relative_to(ROOT)), executable_sha256=sha(executable),
                  rust_bridge_sha256=sha(bridge), turnip_sha256=sha(turnip),
                  daemon_sha256=sha(daemon),
                  original_discovery_abi_qualified=False, code_signature_independently_verified=False)
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / ('reports/native-a830-metal-plugin.json' if args.native_a830 else 'reports/metal-plugin.json')).write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: A830 iOS 16 Metal bundle linked with the real Rust bridge and staged Turnip')


if __name__ == '__main__':
    main()
