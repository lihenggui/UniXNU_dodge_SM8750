#!/usr/bin/env python3
"""Build the pinned offline translator consumer and validate production shader translations."""
import json
import os
import shutil
import struct
import subprocess
import tomllib

from native_driver_build import ROOT, pinned_sources, require, sha
from prepare_sources import patch_series_state
from reviewed_source_tree import reviewed_tree


def main():
    sources = pinned_sources(('a830_metal_reference', 'metal2vulkan_reference'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    work = ROOT / '.cache/gpu-work/metal2vulkan'
    require(subprocess.check_output(['git', '-C', work, 'rev-parse', 'HEAD'], text=True).strip() ==
            lock['metal2vulkan_reference']['revision'], 'Offline compiler uses another translator base')
    states = patch_series_state(work, lock['metal_runtime_patches'], False)
    require(all(state == 'already-applied' for state in states), 'Production translator runtime patches are missing')
    source_tree = reviewed_tree(work, lock['metal_runtime_patches'])
    out = ROOT / 'build/cph2653-metal-translation-tests'
    out.mkdir(parents=True, exist_ok=True)
    frontend = sources['a830_metal_reference']
    original_consumer = frontend / 'tools/MetalVulkanProbe.rs'
    stage = out / 'source'
    stage.mkdir(exist_ok=True)
    consumer = stage / original_consumer.name
    shutil.copyfile(original_consumer, consumer)
    consumer_patch = lock['metal_translation_consumer_patch']
    patch = ROOT / consumer_patch['path']
    require(sha(patch) == consumer_patch['sha256'], 'Reviewed offline consumer API patch changed')
    subprocess.run(['git', 'apply', '--check', '--directory=' + str(stage.relative_to(ROOT)), patch], cwd=ROOT, check=True)
    subprocess.run(['git', 'apply', '--directory=' + str(stage.relative_to(ROOT)), patch], cwd=ROOT, check=True)
    dependency_spec = lock['metal_translation_dependencies']
    dependency_lock = ROOT / dependency_spec['path']
    require(sha(dependency_lock) == dependency_spec['sha256'], 'Reviewed offline translator dependencies changed')
    native_lock = ROOT / lock['metal_bridge_dependencies']['path']
    require(sha(native_lock) == lock['metal_bridge_dependencies']['sha256'], 'Native bridge dependency snapshot changed')
    def registry(path):
        packages = tomllib.loads(path.read_text())['package']
        return {(p['name'], p['version'], p['checksum']) for p in packages if 'source' in p}
    require(registry(dependency_lock) <= registry(native_lock), 'Offline/compiler registry packages differ from production iOS bridge')
    manifest = out / 'Cargo.toml'
    manifest.write_text('\n'.join(['[package]', 'name = "native-metal-vulkan-probe"', 'version = "0.1.0"',
        'edition = "2021"', 'rust-version = "1.98"', '[workspace]', '[[bin]]', 'name = "adreno-metal-vulkan-probe"',
        'path = ' + json.dumps(str(consumer)), '[dependencies]',
        'metal2vulkan = { path = ' + json.dumps(str(work / 'crates/metal2vulkan')) + ', features = ["serde"] }',
        'serde_json = "=1.0.154"', '[profile.release]', 'incremental = true', '']))
    shutil.copyfile(dependency_lock, out / 'Cargo.lock')
    rust = ROOT / '.toolchains/rust-gpu'
    env = dict(os.environ, PATH=str(rust / 'bin') + ':' + os.environ.get('PATH', ''),
               CARGO_HOME=str(ROOT / '.cache/cargo'), CARGO_BUILD_JOBS='4')
    with (out / 'build.log').open('w') as log:
        result = subprocess.run([rust / 'bin/cargo', 'build', '--release', '--locked', '--manifest-path', manifest,
                                 '--target-dir', out / 'target', '-j4'], env=env,
                                stdout=log, stderr=subprocess.STDOUT, timeout=900)
    require(result.returncode == 0, 'Offline translator consumer build failed; see ' + str(out / 'build.log'))
    binary = out / 'target/release/adreno-metal-vulkan-probe'
    require(binary.read_bytes()[:5] == b'\x7fELF\x02', 'Offline translator is not a real host ELF binary')
    needed = subprocess.check_output(['readelf', '-d', binary], text=True)
    require('vulkan' not in needed.lower(), 'Offline translator unexpectedly links a Vulkan loader')
    floor_profile = work / 'crates/metal2vulkan-validation/profiles/vk12-floor.json'
    profile_data = json.loads(floor_profile.read_text())
    turnip_source = ROOT / '.cache/gpu-work/mesa/src/freedreno/vulkan/tu_device.cc'
    text = turnip_source.read_text()
    feature_names = ('shaderStorageImageReadWithoutFormat', 'shaderStorageImageWriteWithoutFormat')
    for name in feature_names:
        require(text.count('features->' + name + ' = true;') == 1, 'Pinned production Turnip does not advertise expected feature: ' + name)
        profile_data['capabilities']['vulkan10requirements']['features']['VkPhysicalDeviceFeatures'][name] = True
    profile_data['provenance']['oneplus13_test_override'] = {
        'source': 'Production Turnip feature declarations, not device measurements',
        'source_sha256': sha(turnip_source), 'features': list(feature_names)}
    profile = out / 'turnip-declared-profile.json'
    profile.write_text(json.dumps(profile_data, indent=2) + '\n')
    examples = ROOT / 'build/cph2653-metal-bridge/nmb_fixture_air.air'
    scanout = ROOT / 'build/cph2653-metal-bridge/nmb_scanout_air.air'
    require(examples.exists() and scanout.exists(), 'Build the exact production AIR fixtures first')
    colors = out / 'color-attachments.json'
    colors.write_text('{"0":"BGRA8Unorm"}\n')
    cases = [('compute-buffer', [profile, examples, 'scale_and_offset']),
             ('compute-texture', [profile, examples, 'invert_texels']),
             ('render-colored', ['--color-attachments', colors, profile, examples, 'colored_vertex', examples, 'colored_fragment']),
             ('scanout-opaque', [profile, scanout, 'scanout_opaque']),
             ('scanout-half-convert', [profile, scanout, 'scanout_convert'])]
    outputs = []
    for name, args in cases:
        result = subprocess.run([binary, *args], capture_output=True, timeout=30)
        (out / (name + '.stderr.log')).write_bytes(result.stderr)
        require(result.returncode == 0 and len(result.stdout) < 8 * 1024**2,
                'Shader translation failed: ' + name + '; see per-case log')
        value = json.loads(result.stdout)
        require(value['gpu_execution'] is False and value['profile_is_hardware_observation'] is False,
                'Offline shader probe has an unexpected execution scope')
        (out / (name + '.json')).write_bytes(result.stdout)
        for index, stage in enumerate(value['stages']):
            words = stage['spirv']
            require(len(words) >= 5 and words[0] == 0x07230203 and len(words) * 4 <= 4 * 1024**2,
                    'Invalid translated SPIR-V module')
            path = out / (name + '-' + str(index) + '.spv')
            path.write_bytes(struct.pack('<%dI' % len(words), *words))
            environments = value['validation_envs']
            require(environments, 'The actual translator profile supplies no validation environment')
            for target in environments:
                command = [ROOT / '.toolchains/gpu-host/usr/bin/spirv-val', '--target-env', target,
                           *value['validation_relaxations'], path]
                validation = subprocess.run(command, capture_output=True, text=True, timeout=20)
                (out / (name + '-' + str(index) + '.validation.log')).write_text(validation.stdout + validation.stderr)
                require(validation.returncode == 0, 'SPIR-V validation failed: ' + name)
            outputs.append({'case': name, 'stage': stage['stage'], 'entry_point': stage['entry_point'],
                            'path': str(path.relative_to(ROOT)), 'sha256': sha(path), 'words': len(words),
                            'validation_environments': environments, 'validation_flags': value['validation_relaxations']})
    malformed = out / 'truncated.bc'
    malformed.write_bytes(b'BC\xc0\xde')
    bad_profile = out / 'invalid-profile.json'
    bad_profile.write_text('{}')
    controls = [('truncated-bitcode', ['--list', malformed]),
                ('invalid-profile', [bad_profile, examples, 'scale_and_offset']),
                ('missing-entry', [profile, examples, '__missing__']),
                ('standalone-fragment', [profile, examples, 'colored_fragment']),
                ('wrong-fragment-stage', [profile, examples, 'colored_vertex', examples, 'colored_vertex']),
                ('missing-color-attachment', [profile, examples, 'colored_vertex', examples, 'colored_fragment']),
                ('missing-storage-format-on-floor', [floor_profile, examples, 'invert_texels'])]
    for name, args in controls:
        result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=20)
        require(result.returncode == 2 and not result.stdout.strip() and result.stderr.startswith('REFUSED:'),
                'Real translator did not refuse invalid pipeline: ' + name)
    report = {'result': 'PRODUCTION_METAL_TRANSLATION_HOST_CHECK_PASS',
              'translator_revision': lock['metal2vulkan_reference']['revision'], 'runtime_patches': lock['metal_runtime_patches'],
              'translator_source_tree': source_tree,
              'consumer_source_sha256': sha(consumer), 'cargo_lock_sha256': sha(dependency_lock),
              'original_consumer_source_sha256': sha(original_consumer), 'consumer_api_patch': consumer_patch,
              'host_binary': str(binary.relative_to(ROOT)), 'host_binary_sha256': sha(binary),
              'profile': str(profile.relative_to(ROOT)), 'profile_sha256': sha(profile),
              'profile_scope': 'Vulkan 1.2 floor plus two production Turnip-declared storage-image features; not observed A830 capabilities',
              'base_profile_sha256': sha(floor_profile), 'turnip_feature_source_sha256': sha(turnip_source),
              'air_source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (examples, scanout)},
              'pipelines': len(cases), 'spirv_modules': outputs, 'invalid_pipeline_controls_refused': [name for name, _ in controls],
              'vulkan_loader_linked': False, 'gpu_execution': False, 'hardware_tested': False,
              'scope': 'Actual patched translator compiles public buffer/texture/render and production scanout AIR; validates real SPIR-V. No pixels executed.'}
    (ROOT / 'reports/metal-translation-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(cases)} actual AIR pipelines / {len(outputs)} SPIR-V modules validated; seven real compiler refusal controls')


if __name__ == '__main__':
    main()
