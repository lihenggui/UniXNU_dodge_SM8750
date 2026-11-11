#!/usr/bin/env python3
"""Build the standalone Gen8 driver with the pinned iPhone Darwin 22 ABI."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

from native_driver_build import (ROOT, NATIVE, archive_imports, build_objects,
                                 inspect_object, pinned_sources, require, sha, symbols)


def apply_overlay(stage, overlay):
    patch = ROOT / overlay['path']
    header = stage / overlay['target']
    require(sha(patch) == overlay['sha256'] and sha(header) == overlay['before_sha256'],
            'Native A830 adapter inputs changed: ' + overlay['path'])
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
                            cwd=stage, capture_output=True, text=True)
    (stage.parent / (patch.stem + '.log')).write_text(result.stdout + result.stderr)
    require(result.returncode == 0 and 'offset' not in result.stdout.lower() and
            sha(header) == overlay['after_sha256'], 'Native A830 adapter did not apply exactly')
    return patch


def stage_source(source, stage, overlay):
    stage.mkdir(parents=True, exist_ok=True)
    inputs = [p for p in source.rglob('*') if p.is_file() and
              p.suffix in ('.h', '.c', '.cpp', '.inc') and
              p.relative_to(source).parts[0] not in ('.git', 'docs', 'tests', 'build')]
    for path in inputs:
        dest = stage / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    apply_overlay(stage, overlay)
    return inputs


def target_firmware():
    """Read every embedded byte and its size back from the existing native object."""
    import struct
    from prepare_native_a830 import FIRMWARE, FILES
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    require(sha(FIRMWARE) == lock['oneplus13_gpu_firmware']['sha256'], 'CPH2653 firmware pins changed')
    pins = json.loads(FIRMWARE.read_text())['firmware']['files']
    out = ROOT / 'build/cph2653-gpu-firmware'
    obj = out / 'firmware.o'
    data = obj.read_bytes()
    image = inspect_object(data)
    section, = [s for segment in image['segments'] for s in segment['sections'] if s['name'] == '__const']
    names = {s['name']: s for s in symbols(data)}
    for symbol, name in zip(('gmu', 'sqe', 'aqe', 'zap'), FILES):
        file = out / name
        pin = pins[name]
        require(file.stat().st_size == pin['bytes'] and sha(file) == pin['sha256'], 'Wrong target firmware: ' + name)
        at = section['fileoff'] + names['_sm8750_gpu_' + symbol]['value']
        size_at = section['fileoff'] + names['_sm8750_gpu_' + symbol + '_size']['value']
        require(data[at:at + pin['bytes']] == file.read_bytes() and
                struct.unpack_from('<Q', data, size_at)[0] == pin['bytes'], 'Target firmware object differs: ' + name)
    return obj, {'files': pins, 'object': str(obj.relative_to(ROOT)), 'object_sha256': sha(obj),
                 'object_readback': 'PASS'}


def link_board(archive, objects, out, firmware):
    import hashlib
    import struct
    from check_gpu_link import native_link_command
    from native_driver_build import OBJDIR, macho
    from native_prelink import backed_offset
    before = sha(NATIVE)
    command, inputs, linker = native_link_command(out)
    partial = out / 'DodgeNativeA830Combined.o'
    partial_command = [str(linker), '-r', '-arch', 'arm64', '-platform_version', 'ios', '16.0', '16.0',
                       '-all_load', str(archive), '-o', str(partial)]
    output = out / 'mach.native-a830'
    full_command = [*command, '-Wl,-force_load,' + str(archive), '-o', str(output)]
    for name, cmd, cwd in (('partial-link', partial_command, ROOT), ('kernel-link', full_command, OBJDIR)):
        with (out / (name + '.log')).open('w') as stream:
            result = subprocess.run(cmd, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
        require(result.returncode == 0, 'Native A830 ' + name + ' failed; see ' + str(out))
    inspect_object(partial.read_bytes())
    imports, merged = archive_imports(objects), archive_imports([partial])
    require(all(merged[key] == imports[key] for key in ('native_public_imports', 'native_static_link_only_imports',
                'required_board_or_original_imports', 'optional_weak_imports')), 'Relocatable link changed native A830 imports')
    linked = output.read_bytes()
    require(struct.unpack_from('<4I', linked) == (0xfeedfacf, 0x100000c, 0, 2), 'Wrong native A830 kernel architecture')
    image = macho(linked)
    table = symbols(linked)
    require(not any(s['kind'] == 1 for s in table), 'Native A830 kernel has unresolved symbols')
    defined = {s['name']: s for s in table if not s['kind'] & 0xe0 and s['kind'] & 14}
    require(set(imports['defined']) <= defined.keys(), 'Native A830 definitions were lost from the kernel')
    aliases = {s['name']: s['value'] for p in objects for s in symbols(p.read_bytes()) if s['kind'] == 3}
    require(len(aliases) == 3 and all(defined[name]['value'] == address for name, address in aliases.items()),
            'Exact iPhone accelerator aliases changed during native A830 link')
    readback = []
    for suffix, name in (('gmu', 'gen80000_gmu.bin'), ('sqe', 'gen80000_sqe.fw'),
                         ('aqe', 'gen80000_aqe.fw'), ('zap', 'gen80000_zap.mbn')):
        pin = firmware['files'][name]
        address = defined['_sm8750_gpu_' + suffix]['value']
        at = backed_offset(image['segments'], address, pin['bytes'], len(linked))
        size_at = backed_offset(image['segments'], defined['_sm8750_gpu_' + suffix + '_size']['value'], 8, len(linked))
        require(address % 4096 == 0 and hashlib.sha256(linked[at:at + pin['bytes']]).hexdigest() == pin['sha256'] and
                struct.unpack_from('<Q', linked, size_at)[0] == pin['bytes'], 'Linked firmware differs: ' + name)
        readback.append({'name': name, 'address': hex(address), **pin})
    inputs.update({archive, NATIVE, linker, ROOT / '.toolchains/xnu-linux/llvm/bin/clang',
                   ROOT / 'scripts/check_gpu_link.py'})
    manifest = out / 'link-inputs.json'
    manifest.write_text(json.dumps({str(p.relative_to(ROOT)): sha(p) for p in sorted(inputs)}, indent=2) + '\n')
    (out / 'link-commands.json').write_text(json.dumps([partial_command, full_command], indent=2) + '\n')
    require(sha(NATIVE) == before, 'The default kernel changed during isolated native A830 link')
    return {'kernel': str(output.relative_to(ROOT)), 'kernel_sha256': sha(output), 'bytes': len(linked),
            'partial_object': str(partial.relative_to(ROOT)), 'partial_object_sha256': sha(partial),
            'strict_no_undefined': True, 'original_accelerator_aliases': {n: hex(a) for n, a in aliases.items()},
            'firmware_readback': readback, 'input_manifest': str(manifest.relative_to(ROOT)),
            'input_manifest_sha256': sha(manifest),
            'default_kernel_unchanged': True, 'original_components_embedded': False, 'crypto_post_sealed': False}


def main():
    from build_a830_backend import build_accelerator
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--board', action='store_true', help='include CPH2653 board startup and local stock firmware')
    parser.add_argument('--link', action='store_true', help='link an isolated native kernel (requires --board)')
    parser.add_argument('--runtime', action='store_true', help='include the iPhone resource and display adapter (requires --board)')
    args = parser.parse_args()
    require(not args.link or args.board, '--link requires the CPH2653 --board variant')
    require(not args.runtime or args.board, '--runtime requires the CPH2653 --board variant')
    require(not (args.runtime and args.link), 'Use build_native_a830_kernel.py to link the complete runtime variant')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    refs = pinned_sources(('native_a830_reference', 'native_a830_smmu_reference', 'sm8750'))
    source = refs['native_a830_reference']
    smmu = refs['native_a830_smmu_reference']
    pm4 = ROOT / 'sources/UniXNU/kits/AdrenoPM4'
    pin = subprocess.check_output(['git', '-C', str(pm4.parent.parent), 'ls-tree',
                                   'HEAD', 'kits/AdrenoPM4'], text=True).split()[2]
    require(subprocess.check_output(['git', '-C', str(pm4), 'rev-parse', 'HEAD'],
                                    text=True).strip() == pin and
            not subprocess.check_output(['git', '-C', str(pm4), 'status', '--porcelain']),
            'AdrenoPM4 differs from the pinned core gitlink')
    spec = importlib.util.spec_from_file_location('native_a830_recipe', source / 'scripts/build-adreno830.py')
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    drivers, platform, _ = recipe.classify(source, [])
    out = ROOT / ('build/cph2653-native-a830-runtime' if args.runtime else
                  'build/cph2653-native-a830-board' if args.board else 'build/cph2653-native-a830')
    stage = out / 'source'
    overlay = lock['native_a830_darwin22_overlay']
    patch = ROOT / overlay['path']
    inputs = stage_source(source, stage, overlay)
    files = [stage / p.relative_to(source) for p in drivers + platform]
    files += sorted(smmu.glob('ArmSmmu4K*.c')) + [pm4 / 'AdrenoPM4.c']
    includes = [stage, stage / 'platform/sm8750', smmu, pm4,
                refs['sm8750'] / 'kits/Sm8750Platform']
    extra = ['-Wno-sign-conversion', '-Wno-shorten-64-to-32']
    board_inputs, firmware = None, None
    generated = []
    if args.board:
        from prepare_native_a830 import INPUTS, FIRMWARE, prepare
        board_inputs, generated = prepare(out / 'generated')
        firmware_obj, firmware = target_firmware()
        board_overlay = apply_overlay(stage, lock['native_a830_firmware_overlay'])
        board_sources = [ROOT / 'drivers/DodgeGpu' / name for name in
                         ('DodgeNativeA830Board.cpp', 'DodgeNativeA830Start.cpp')]
        files += board_sources
        inputs += board_sources + [ROOT / 'drivers/DodgeGpu/DodgeNativeA830Board.h',
                                  INPUTS, FIRMWARE, board_overlay, ROOT / 'scripts/prepare_native_a830.py']
        includes += [out / 'generated', ROOT / 'drivers/DodgeGpu', ROOT / 'build/cph2653-gpu-firmware']
        extra += ['-DNATIVE_ADRENO_FIRMWARE_PINS="DodgeNativeA830FirmwarePins.inc"']
    runtime = None
    if args.runtime:
        from native_a830_runtime import apply_runtime
        runtime = apply_runtime(stage)
        inputs += [ROOT / runtime['path'], ROOT / 'scripts/native_a830_runtime.py']
        inputs += [ROOT / runtime['surface_overlay']['path']]
        inputs += [ROOT / name for name in runtime['support_sha256']]
        boot = ROOT / 'drivers/DodgeGpu/DodgeNativeA830Boot.cpp'
        files += [boot]
        console = ROOT / 'drivers/DodgeGpu/DodgeNativeA830Console.cpp'
        files += [console]
        files += [stage / 'DodgeNativeSurface.cpp']
        inputs += [boot, console]
    objects = build_objects(files, out, includes, extra)
    accelerator, binding = build_accelerator(stage, out, includes)
    objects += accelerator
    if args.board:
        objects += [firmware_obj]
    imports = archive_imports(objects)
    require({'_adreno830_start', '_adreno830_status', '_native_adreno_publish',
             '_native_adreno_accelerator_allocate'} <= set(imports['defined']),
            'Native A830 archive is missing its startup or accelerator implementation')
    if args.board:
        require('_dodge_native_a830_start' in imports['defined'] and
                all('_sm8750_gpu_' + n in imports['defined'] for n in ('gmu', 'sqe', 'aqe', 'zap')),
                'Native A830 board startup or firmware did not reach the archive')
    archive = out / 'libAdreno830.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', str(archive), *map(str, objects)], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 't', str(archive)], text=True).splitlines() ==
            [p.name for p in objects], 'Native A830 archive member list changed')
    kernel = link_board(archive, objects, out, firmware) if args.link else None
    sources = inputs + list(smmu.glob('*.h')) + sorted(smmu.glob('ArmSmmu4K*.c'))
    sources += [pm4 / 'AdrenoPM4.c', pm4 / 'AdrenoPM4.h', patch, Path(__file__),
                ROOT / 'scripts/build_a830_backend.py', ROOT / 'scripts/native_driver_build.py',
                source / 'scripts/build-adreno830.py']
    report = {
        'result': ('NATIVE_A830_IPHONE_RUNTIME_ARCHIVE_PASS' if args.runtime else
                   'NATIVE_A830_CPH2653_KERNEL_LINK_PASS' if args.link else
                   'NATIVE_A830_CPH2653_BOARD_ARCHIVE_PASS' if args.board else 'NATIVE_A830_IPHONE_DARWIN22_ARCHIVE_PASS'),
        'target': 'arm64-apple-ios16.0', 'builder_sha256': sha(Path(__file__)),
        'source_revisions': {name: lock[name]['revision'] for name in refs},
        'adreno_pm4_revision': pin, 'native_kernel_sha256': sha(NATIVE),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'darwin22_overlay': overlay,
        'board_firmware_overlay': lock['native_a830_firmware_overlay'] if args.board else None,
        'runtime_overlay': runtime,
        'generated_sha256': {p.name: sha(p) for p in generated},
        'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
        'object_count': len(objects), 'objects': {p.name: sha(p) for p in objects},
        'original_accelerator': binding, 'imports': imports,
        'frontend_abi': {'version': 2, 'selectors': list(range(1, 17)) + ([19] if args.runtime else []),
                         'optional_unsupported_selectors': [17, 18] if args.runtime else [],
                         'existing_frontend_extensions_to_review': [] if args.runtime else [17, 18]},
        'board_inputs': board_inputs, 'target_firmware': firmware,
        'isolated_link': kernel,
        'board_startup_included': args.board, 'target_firmware_included': args.board,
        'startup_invoked': False,
        'original_surface_producer_connected': args.runtime,
        'full_prelink_qualified': False, 'selected_in_default_kernel': False,
        'hardware_tested': False,
        'scope': ('Native iPhone runtime archive with surface-ID import, original producer grants, whole-VM resource '
                 'leases, deferred fence/reset completion and recovery-aware display snapshots. '
                 'Original owners and bindings are supplied by the complete kernel build.' if args.runtime else
                 'Standalone source archive with Gen8 orchestration, GMU/HFI, SMMU, CP, fences, '
                 'recovery and DCVS, plus the exact iPhone accelerator base. The board variant adds '
                 'CPH2653 declarations, firmware pins and an explicit synchronous entry. '
                 'Metal protocol extensions and complete lifecycle/prelink integration remain separate.')}
    text = json.dumps(report, indent=2) + '\n'
    (out / 'manifest.json').write_text(text)
    report = ROOT / ('reports/native-a830-runtime.json' if args.runtime else
                     'reports/native-a830-board.json' if args.board else 'reports/native-a830.json')
    report.write_text(text)
    print(f'PASS: {len(objects)} native A830/iPhone objects; archive and accelerator bindings checked' +
          ('; strict kernel link and firmware readback' if args.link else ''))


if __name__ == '__main__':
    main()
