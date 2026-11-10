#!/usr/bin/env python3
"""Build the pinned A830 XNU backend for the native iPhone iOS 16 kernel."""
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

from native_driver_build import (ROOT, NATIVE, archive_imports, build_objects,
                                 inspect_object, pinned_sources, require, sha, symbols)
from check_ios16_graphics import derive, validate_fixture
from optional_gpu_calls import stage_optional_calls
from adreno_display_timeline import stage_display_timeline


def build_accelerator(gpu, out, includes):
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    spec = lock['iphone_graphics_base_fixture']
    fixture_path, header = ROOT / spec['path'], ROOT / spec['header']
    require(sha(fixture_path) == spec['sha256'] and sha(header) == spec['header_sha256'],
            'Original iPhone accelerator fixture/header changed after review')
    fixture = json.loads(fixture_path.read_text())
    actual, _ = derive()
    validate_fixture(actual, fixture)
    stage = out / 'accelerator'
    (stage / 'Adreno740').mkdir(parents=True, exist_ok=True)
    (stage / 'AdrenoMetal').mkdir(exist_ok=True)
    source = stage / 'Adreno740/NativeAdrenoAccelerator.cpp'
    shutil.copyfile(gpu / source.name, source)
    shutil.copyfile(header, stage / 'AdrenoMetal/OriginalAcceleratorABI.h')
    obj, = build_objects([source], stage, includes, ['-Wno-overloaded-virtual'])
    original = obj.read_bytes()
    late = stage / 'NativeAdrenoAccelerator.late.o'
    preferred = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    objcopy = preferred if preferred.exists() else Path('/usr/bin/llvm-objcopy-14')
    init = '__GLOBAL__sub_I_NativeAdrenoAccelerator.cpp'
    with (stage / 'objcopy.log').open('w') as log:
        process = subprocess.run([str(objcopy), '--remove-section=__DATA,__mod_init_func',
                                  '--globalize-symbol=' + init, str(obj), str(late)],
                                 stdout=log, stderr=subprocess.STDOUT)
    require(process.returncode == 0, 'Late accelerator staging failed; see ' + str(stage / 'objcopy.log'))
    transformed = late.read_bytes()
    before, after = inspect_object(original), inspect_object(transformed)

    def text(data, image):
        section, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
        return data[section['fileoff']:section['fileoff'] + section['size']]

    require(text(original, before) == text(transformed, after), 'Staging changed accelerator instructions')
    require(not any(s['name'] == '__mod_init_func' for seg in after['segments'] for s in seg['sections']),
            'Original-parent class initializer is still scheduled for early native startup')
    late_symbols = symbols(transformed)
    require(any(s['name'] == init and s['kind'] & 1 and s['kind'] & 0xe for s in late_symbols),
            'The real late accelerator initializer is not externally callable')
    bindings = {
        '__ZN15IOAcceleratorESC2EPK11OSMetaClass': int(fixture['protected_compatible_constructor_aliases'][0], 16),
        '__ZN15IOAcceleratorESD2Ev': int(fixture['nondeleting_destructor'], 16),
        '__ZN15IOAcceleratorES10gMetaClassE': int(fixture['metaclass'], 16)}
    required = {s['name'] for s in late_symbols if s['kind'] == 1 and 'IOAcceleratorES' in s['name']}
    require(required == set(bindings), 'The accelerator imports differ from the exact reviewed original base')
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    slide = int(profile['kernel']['prelink']['slide'], 0)
    assembly = stage / 'original-bindings.S'
    assembly.write_text(''.join(f'.globl {name}\n.set {name}, {address + slide:#x}\n'
                                 for name, address in sorted(bindings.items())))
    binding_obj = stage / 'original-bindings.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0',
                    '-c', assembly, '-o', binding_obj], check=True)
    inspect_object(binding_obj.read_bytes())
    return [late, binding_obj], {
        'fixture_sha256': sha(fixture_path), 'source_sha256': sha(source), 'header_sha256': sha(header),
        'slide': slide, 'bindings': {name: {'original': hex(address), 'prelinked': hex(address + slide)}
                                    for name, address in bindings.items()},
        'initializer': init, 'initializer_removed_from_early_registration': True,
        'compiled_instructions_unchanged_by_staging': True,
        'requires_original_component': 'com.apple.iokit.IOGPUFamily',
        'requires_original_metaclass_construction_before_late_initializer': True,
        'class_initialized': False, 'runtime_qualified': False}


def main():
    names = ('a830_backend_reference', 'a830_firmware_reference', 'sm8750')
    source = pinned_sources(names)
    gpu, fw = source['a830_backend_reference'], source['a830_firmware_reference']
    gpu, optional_overlay = stage_optional_calls('backend', gpu)
    gpu, timeline_overlay = stage_display_timeline(gpu)
    soc = source['sm8750'] / 'kits/Sm8750Platform'
    kits = ROOT / 'sources/UniXNU/kits'
    support = {}
    for name in ('ArmSmmu4K', 'AdrenoPM4'):
        path = kits / name
        pin = subprocess.check_output(['git', '-C', str(kits.parent), 'ls-tree', 'HEAD', 'kits/' + name], text=True).split()[2]
        head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
        require(pin == head and not subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True),
                'Unexpected GPU support source: ' + name)
        support[name] = head
    files = [gpu / ('NativeAdreno' + name + '.cpp') for name in (
        'A830HwInit', 'CpInit', 'Cpu', 'GmuContext', 'GmuMemory', 'GpuContext', 'Irq', 'Memory',
        'Publish', 'Pwrup', 'Preempt', 'Ring', 'Sha256', 'SmmuContext', 'SmmuMemory', 'Submit',
        'Timer', 'UserClient', 'Vm')]
    files += [soc / name for name in ('Sm8750Gmu.c', 'Sm8750GmuCommandDb.c', 'Sm8750GpuPower.c',
                                     'Sm8750GpuZap.c', 'Sm8750SocInfo.c', 'Sm8750GpuSmmu.c')]
    files += [fw / name for name in ('AdrenoFirmware.c', 'AdrenoHfi.c', 'AdrenoHfiStartup.c', 'AdrenoHfiVotes.c')]
    files += sorted((kits / 'ArmSmmu4K').glob('ArmSmmu4K*.c')) + [kits / 'AdrenoPM4/AdrenoPM4.c']
    includes = (gpu, fw, soc, kits / 'ArmSmmu4K', kits / 'AdrenoPM4')
    out = ROOT / 'build/cph2653-a830-backend'
    objects = build_objects(files, out, includes)
    staged_objects, original_binding = build_accelerator(gpu, out, includes)
    objects += staged_objects
    imports = archive_imports(objects)
    require({'_native_adreno_publish', '_Sm8750GmuColdStart','_dodge_adreno_display_timeline'} <= set(imports['defined']),
            'Required real A830 backend entry points are absent')
    archive = out / 'libAdreno740.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', str(archive), *map(str, objects)], check=True)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    report = {'result': 'NATIVE_A830_BACKEND_ARCHIVE_PASS', 'target': 'arm64-apple-ios16.0','builder_sha256':sha(Path(__file__)),
              'source_revisions': {name: lock[name]['revision'] for name in names},
              'support_revisions': support, 'native_kernel_sha256': sha(NATIVE),
              'optional_call_overlay': optional_overlay,
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
              'object_count': len(objects), 'object_sha256': {obj.name: sha(obj) for obj in objects},
              'source_sha256': {str(file.relative_to(ROOT)): sha(file) for file in files},
              'display_timeline_overlay': timeline_overlay,
              'header_sha256': {str(file.relative_to(ROOT)): sha(file) for directory in includes
                                for pattern in ('*.h', '*.inc') for file in sorted(directory.glob(pattern))},
              'imports': imports, 'default_kernel_changed': False, 'board_startup_included': False,
              'original_accelerator_binding_included': True, 'original_accelerator': original_binding,
              'target_firmware_included': False,
              'metal_frontend_built': False, 'hardware_tested': False,
              'scope': 'All 19 production backend translation units and actual GMU/HFI/SMMU/PM4 dependencies '
                       'compiled for iOS 16, with an exact-original staged accelerator base. '
                       'Board hooks, firmware and original-family initialization remain separate requirements.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/a830-backend.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(objects)} native A830 backend/dependency objects; '
          f'{len(imports["required_board_or_original_imports"])} required board/original imports remain')


if __name__ == '__main__':
    main()
