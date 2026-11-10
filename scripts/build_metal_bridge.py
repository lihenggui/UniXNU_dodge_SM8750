#!/usr/bin/env python3
"""Cross-build the pinned A830 Metal Rust bridge for iPhone iOS 16 on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha
from prepare_sources import patch_series_state
from reviewed_source_tree import reviewed_tree


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true', help='Prepare patched inputs, fixtures and manifest')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    sources = pinned_sources(('metal2vulkan_reference', 'a830_metal_reference', 'iphoneos_sdk_reference'))
    original = sources['metal2vulkan_reference']
    frontend = sources['a830_metal_reference']
    sdk = sources['iphoneos_sdk_reference'] / 'iPhoneOS16.5.sdk'
    work = ROOT / '.cache/gpu-work/metal2vulkan'
    if not work.exists():
        work.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(original), str(work)], check=True)
        subprocess.run(['git', '-C', str(work), 'checkout', '--quiet', '--detach', lock['metal2vulkan_reference']['revision']], check=True)
    require(subprocess.check_output(['git', '-C', str(work), 'rev-parse', 'HEAD'], text=True).strip() ==
            lock['metal2vulkan_reference']['revision'], 'Patched translator has an unexpected base')
    patch_series_state(work, lock['metal_runtime_patches'], True)
    source_tree = reviewed_tree(work, lock['metal_runtime_patches'])
    out = ROOT / 'build/cph2653-metal-bridge'
    out.mkdir(parents=True, exist_ok=True)
    rust = ROOT / lock['gpu_rust_toolchain']['prefix']
    tools = rust / 'lib/rustlib/x86_64-unknown-linux-gnu/bin'
    llvm_as = tools / 'llvm-as'
    require(llvm_as.exists(), 'Install the locked workspace Rust/LLVM tools first')
    fixtures = {
        'NMB_FIXTURE_AIR': work / 'crates/metal2vulkan-validation/fixtures/public/examples/runtime_examples.ll',
        'NMB_FC_AIR': work / 'crates/metal2vulkan-validation/fixtures/public/kernel_function_constant_gate_fold.ll',
        'NMB_SCANOUT_AIR': frontend / 'shaders/scanout_convert.ll'}
    assembled = {}
    for name, source in fixtures.items():
        destination = out / (name.lower() + '.air')
        subprocess.run([str(llvm_as), str(source), '-o', str(destination)], check=True)
        data = destination.read_bytes()
        if data.startswith(bytes.fromhex('dec0170b')):
            magic, version, offset, size, _ = struct.unpack_from('<5I', data)
            require(version == 0 and offset >= 20 and offset + size <= len(data), 'Invalid LLVM bitcode wrapper')
            data = data[offset:offset + size]
        require(data.startswith(b'BC\xc0\xde'), 'Fixture is not real LLVM bitcode')
        subprocess.run([str(tools / 'llvm-dis'), '-disable-output', str(destination)], check=True)
        assembled[name] = str(destination)
    manifest = out / 'Cargo.toml'
    manifest.write_text('\n'.join([
        '[package]', 'name = "adreno-metal-bridge"', 'version = "0.1.0"', 'edition = "2024"',
        'rust-version = "1.98"', '[workspace]', '[lib]', 'crate-type = ["staticlib"]',
        'path = ' + json.dumps(str(frontend / 'bridge/NativeMetalBridge.rs')),
        '[dependencies]',
        'metal2vulkan = { path = ' + json.dumps(str(work / 'crates/metal2vulkan')) + ', features = ["ash"] }',
        'metal2vulkan-runtime = { path = ' + json.dumps(str(work / 'crates/metal2vulkan-runtime')) + ' }',
        'libc = "0.2"', 'sha2 = { version = "0.10", features = ["asm"] }',
        '[profile.release]', 'panic = "unwind"', 'debug = 1', 'lto = "fat"', 'codegen-units = 1', '']))
    runtime_input = lock['metal2vulkan_reference']['revision'] + '\n' + '\n'.join(p['sha256'] for p in lock['metal_runtime_patches'])
    runtime_id = hashlib.sha256(runtime_input.encode()).hexdigest()[:32]
    clang = ROOT / '.toolchains/xnu-linux/llvm/bin/clang'
    env = dict(os.environ, PATH=str(rust / 'bin') + ':' + os.environ.get('PATH', ''),
               CARGO_HOME=str(ROOT / '.cache/cargo'), CARGO_BUILD_JOBS='4',
               SDKROOT=str(sdk), IPHONEOS_DEPLOYMENT_TARGET='16.0',
               NMB_RUNTIME_ID=runtime_id, **assembled)
    env.update(CC_aarch64_apple_ios=str(clang), AR_aarch64_apple_ios=str(tools / 'llvm-ar'),
               CFLAGS_aarch64_apple_ios=shlex.join(['-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk)]))
    cargo = rust / 'bin/cargo'
    snapshot = ROOT / 'profiles/os/ios-16.7.16-20H392/graphics/bridge-Cargo.lock'
    if snapshot.exists():
        shutil.copyfile(snapshot, out / 'Cargo.lock')
    with (out / 'fetch.log').open('w') as log:
        command = [cargo, 'fetch', '--manifest-path', manifest, '--target', 'aarch64-apple-ios']
        if snapshot.exists():
            command.append('--locked')
        process = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    require(process.returncode == 0, 'Cargo dependency fetch failed; see build/cph2653-metal-bridge/fetch.log')
    if not snapshot.exists():
        shutil.copyfile(out / 'Cargo.lock', snapshot)
    if args.prepare_only:
        print('PASS: 24 pinned runtime patches, real AIR fixtures, iOS 16 manifest and locked Rust dependencies')
        return
    with (out / 'build.log').open('w') as log:
        process = subprocess.run([cargo, 'build', '--release', '--locked', '--manifest-path', manifest,
                                  '--target', 'aarch64-apple-ios', '--target-dir', out / 'target'],
                                 env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    require(process.returncode == 0, 'iOS 16 Metal bridge build failed; see build/cph2653-metal-bridge/build.log')
    archive = out / 'target/aarch64-apple-ios/release/libadreno_metal_bridge.a'
    require(archive.read_bytes().startswith(b'!<arch>\n'), 'Rust bridge is not a static archive')
    report = {'result': 'IOS16_METAL_RUST_BRIDGE_CROSS_BUILD_PASS', 'target': 'aarch64-apple-ios',
              'minimum_os': '16.0', 'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
              'translator_revision': lock['metal2vulkan_reference']['revision'],
              'frontend_revision': lock['a830_metal_reference']['revision'],
              'runtime_patches': lock['metal_runtime_patches'], 'runtime_id': runtime_id,
              'translator_source_tree': source_tree,
              'rust_version': subprocess.check_output([rust / 'bin/rustc', '--version'], text=True).strip(),
              'cargo_lock_sha256': sha(snapshot), 'fixture_source_sha256': {name: sha(path) for name, path in fixtures.items()},
              'sdk_reference_revision': lock['iphoneos_sdk_reference']['revision'],
              'sdk_scope': 'Patched iOS 16.5 cross-build headers/stubs, not private ABI evidence for iPhone 20H392',
              'objc_frontend_linked': False, 'turnip_linked': False, 'code_signed': False,
              'hardware_tested': False, 'scope': 'Actual Rust static library cross-build; no Metal device or shader execution.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/metal-rust-bridge.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: actual iOS 16 Rust Metal bridge archive with the pinned runtime and 24 reviewed patches')


if __name__ == '__main__':
    main()
