#!/usr/bin/env python3
"""Fetch/check pinned local source checkouts and apply reviewed host-port patches.

Default is read-only. --apply creates missing checkouts, retrieves exact
submodules and applies the locked patches; existing source edits are preserved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(list(map(str, args)), check=check, text=True, capture_output=True)


def patch_state(source, specification, apply):
    patch = ROOT / specification['path']
    if hashlib.sha256(patch.read_bytes()).hexdigest() != specification['sha256']:
        raise SystemExit('Patch digest mismatch: ' + str(patch.relative_to(ROOT)))
    command = ['git', '-C', source, 'apply', '--check']
    reverse = run(*command, '--reverse', patch, check=False)
    if reverse.returncode == 0:
        return 'already-applied'
    forward = run(*command, patch, check=False)
    if forward.returncode:
        raise SystemExit(f'Patch does not match {source.name}:\n{forward.stderr}')
    if apply:
        run('git', '-C', source, 'apply', patch)
        return 'applied'
    return 'applicable'


def patch_series_state(source, specifications, apply):
    """Undo/replay overlapping overlays in a private index, preserving user state."""
    patches = []
    for specification in specifications:
        patch = ROOT / specification['path']
        if hashlib.sha256(patch.read_bytes()).hexdigest() != specification['sha256']:
            raise SystemExit('Patch digest mismatch: ' + specification['path'])
        patches.append(patch)
    with tempfile.TemporaryDirectory(prefix='overlay-index-') as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))

        def git(*args, check=True):
            return subprocess.run(['git', '-C', str(source), *map(str, args)], env=env,
                                  capture_output=True, text=True, check=check)

        git('read-tree', 'HEAD')
        git('add', '-u')
        # A source overlay may introduce files not yet tracked in this checkout.
        for patch in patches:
            for line in git('apply', '--numstat', patch).stdout.splitlines():
                name = line.split('\t', 2)[2]
                if (source / name).is_file():
                    git('add', '--', name)
        applied = [False] * len(patches)
        for index in reversed(range(len(patches))):
            patch = patches[index]
            if git('apply', '--cached', '--reverse', '--check', patch, check=False).returncode == 0:
                git('apply', '--cached', '--reverse', patch)
                applied[index] = True
        if any(applied[i] and not all(applied[:i]) for i in range(len(applied))):
            raise SystemExit('Non-prefix overlay state; existing source was preserved: ' + str(source))
        for patch in patches:
            result = git('apply', '--cached', '--check', patch, check=False)
            if result.returncode:
                raise SystemExit(f'Overlay series does not match {source.name} at {patch.name}; source preserved:\n{result.stderr}')
            git('apply', '--cached', patch)
    states = []
    for patch, present in zip(patches, applied):
        if present:
            states.append('already-applied')
        elif apply:
            run('git', '-C', source, 'apply', '--check', patch)
            run('git', '-C', source, 'apply', patch)
            states.append('applied')
        else:
            states.append('applicable')
    return states


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    entries = [('uefi', {'path': 'uefi/Mu-Silicium', 'repository': lock['repository'],
                         'revision': lock['revision'],
                         'patches': [lock['boot_shim_patch'], lock['simplefb_patch']]})]
    entries += [(name, lock[name]) for name in ('unixnu', 'sm8750', 'pagani_reference', 'xnu_ios16', 'unifdef', 'iig_port')]
    if 'oneplus13t_reference' in lock:
        entries.append(('oneplus13t_reference', lock['oneplus13t_reference']))
    entries += [(name, lock[name]) for name in ('native_a830_reference', 'native_a830_smmu_reference', 'a830_backend_reference', 'a830_metal_reference',
                                               'a830_firmware_reference', 'iphoneos_sdk_reference',
                                               'metal2vulkan_reference', 'mesa_reference',
                                               'a830_build_reference', 'erofs_tools', 'glslang_tools', 'apfs_readonly_reference',
                                               'apfs_writer_reference', 'apfs_checker_reference', 'fajita_data_reference', 'ramblock_reference',
                                               'apfs_mount_options_reference',
                                               'iostorage_headers_reference', 'iohid_headers_reference',
                                               'iographics_headers_reference') if name in lock]
    entries.append(('darwinboot', lock['darwinboot']))
    entries.append(('xnuprelink', lock['xnuprelink']))
    entries.append(('lzfse', dict(lock['lzfse'], path='sources/lzfse')))
    result = {}
    for name, spec in entries:
        source = ROOT / spec['path']
        if not (source / '.git').exists():
            if not args.apply:
                raise SystemExit(f'Missing checkout: {source}; run scripts/prepare_sources.py --apply')
            if source.exists() and any(source.iterdir()):
                raise SystemExit('Refusing to replace a nonempty source directory: ' + str(source))
            source.mkdir(parents=True, exist_ok=True)
            run('git', 'init', '--quiet', source)
            run('git', '-C', source, 'remote', 'add', 'origin', spec['repository'])
            fetch = ['git', '-C', source, 'fetch', '--quiet', '--depth', '1']
            if spec.get('sparse_paths'):
                run('git', '-C', source, 'config', 'remote.origin.promisor', 'true')
                run('git', '-C', source, 'config', 'remote.origin.partialclonefilter', 'blob:none')
                fetch.append('--filter=blob:none')
                run('git', '-C', source, 'sparse-checkout', 'init', '--cone')
                run('git', '-C', source, 'sparse-checkout', 'set', *spec['sparse_paths'])
            run(*fetch, 'origin', spec['revision'])
            run('git', '-C', source, 'checkout', '--quiet', '--detach', spec['revision'])
        actual = run('git', '-C', source, 'rev-parse', 'HEAD').stdout.strip()
        if actual != spec['revision']:
            raise SystemExit(f'{name}: unexpected source revision {actual}; existing checkout was not changed')
        if args.apply and not spec.get('reference_only') and (source / '.gitmodules').is_file():
            run('git', '-C', source, 'submodule', 'update', '--init', '--recursive', '--jobs', '4')
        if name in ('uefi', 'unixnu'):
            submodules = run('git', '-C', source, 'submodule', 'status', '--recursive').stdout.splitlines()
            if any(line.startswith(('-', '+', 'U')) for line in submodules):
                raise SystemExit(f'{name}: submodule revision or checkout missing; run with --apply')
        series = spec.get('patches', [])
        states = (patch_series_state(source, series, args.apply) if len(series) > 1
                  else [patch_state(source, patch, args.apply) for patch in series])
        result[name] = {'revision': actual, 'patches': states}
    for script in ('apply_uefi_patch.py', 'apply_unixnu_menu.py'):
        command = ['python3', str(ROOT / 'scripts' / script), '--source', str(ROOT / 'uefi/Mu-Silicium')]
        if args.apply:
            command.append('--apply')
        result[script] = run(*command).stdout.strip()
    print(json.dumps({'source_checks': result, 'phone_operations': 'none'}, indent=2))


if __name__ == '__main__':
    main()
