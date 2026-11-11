#!/usr/bin/env python3
"""Build the standalone Gen8 driver with the pinned iPhone Darwin 22 ABI."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

from build_a830_backend import build_accelerator
from native_driver_build import (ROOT, NATIVE, archive_imports, build_objects,
                                 pinned_sources, require, sha)


def stage_source(source, stage, overlay):
    stage.mkdir(parents=True, exist_ok=True)
    inputs = [p for p in source.rglob('*') if p.is_file() and
              p.suffix in ('.h', '.c', '.cpp', '.inc') and
              p.relative_to(source).parts[0] not in ('.git', 'docs', 'tests', 'build')]
    for path in inputs:
        dest = stage / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    patch = ROOT / overlay['path']
    header = stage / overlay['target']
    require(sha(patch) == overlay['sha256'] and sha(header) == overlay['before_sha256'],
            'Native A830 Darwin 22 adapter inputs changed')
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
                            cwd=stage, capture_output=True, text=True)
    (stage.parent / 'overlay.log').write_text(result.stdout + result.stderr)
    require(result.returncode == 0 and 'offset' not in result.stdout.lower() and
            sha(header) == overlay['after_sha256'], 'Native A830 adapter did not apply exactly')
    return inputs


def main():
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
    out = ROOT / 'build/cph2653-native-a830'
    stage = out / 'source'
    overlay = lock['native_a830_darwin22_overlay']
    patch = ROOT / overlay['path']
    inputs = stage_source(source, stage, overlay)
    files = [stage / p.relative_to(source) for p in drivers + platform]
    files += sorted(smmu.glob('ArmSmmu4K*.c')) + [pm4 / 'AdrenoPM4.c']
    includes = [stage, stage / 'platform/sm8750', smmu, pm4,
                refs['sm8750'] / 'kits/Sm8750Platform']
    objects = build_objects(files, out, includes, ['-Wno-sign-conversion', '-Wno-shorten-64-to-32'])
    accelerator, binding = build_accelerator(stage, out, includes)
    objects += accelerator
    imports = archive_imports(objects)
    require({'_adreno830_start', '_adreno830_status', '_native_adreno_publish',
             '_native_adreno_accelerator_allocate'} <= set(imports['defined']),
            'Native A830 archive is missing its startup or accelerator implementation')
    archive = out / 'libAdreno830.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', str(archive), *map(str, objects)], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 't', str(archive)], text=True).splitlines() ==
            [p.name for p in objects], 'Native A830 archive member list changed')
    sources = inputs + list(smmu.glob('*.h')) + sorted(smmu.glob('ArmSmmu4K*.c'))
    sources += [pm4 / 'AdrenoPM4.c', pm4 / 'AdrenoPM4.h', patch, Path(__file__),
                ROOT / 'scripts/build_a830_backend.py', ROOT / 'scripts/native_driver_build.py',
                source / 'scripts/build-adreno830.py']
    report = {
        'result': 'NATIVE_A830_IPHONE_DARWIN22_ARCHIVE_PASS',
        'target': 'arm64-apple-ios16.0', 'builder_sha256': sha(Path(__file__)),
        'source_revisions': {name: lock[name]['revision'] for name in refs},
        'adreno_pm4_revision': pin, 'native_kernel_sha256': sha(NATIVE),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'darwin22_overlay': overlay,
        'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
        'object_count': len(objects), 'objects': {p.name: sha(p) for p in objects},
        'original_accelerator': binding, 'imports': imports,
        'frontend_abi': {'version': 2, 'selectors': list(range(1, 17)),
                         'existing_frontend_extensions_to_review': [17, 18]},
        'board_startup_included': False, 'target_firmware_included': False,
        'full_prelink_qualified': False, 'selected_in_default_kernel': False,
        'hardware_tested': False,
        'scope': 'Standalone source archive with Gen8 orchestration, GMU/HFI, SMMU, CP, fences, '
                 'recovery and DCVS, plus the exact iPhone accelerator base. Board inputs, '
                 'Metal protocol extensions and complete lifecycle/prelink integration remain separate.'}
    text = json.dumps(report, indent=2) + '\n'
    (out / 'manifest.json').write_text(text)
    (ROOT / 'reports/native-a830.json').write_text(text)
    print(f'PASS: {len(objects)} native A830/iPhone objects; archive and accelerator bindings checked')


if __name__ == '__main__':
    main()
