#!/usr/bin/env python3
"""Check or apply the pinned UniXNU menu and DarwinBoot integration."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from prepare_sources import patch_state, patch_series_state

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'uefi/Mu-Silicium')
    parser.add_argument('--unixnu', type=Path, default=ROOT / 'sources/UniXNU')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    source, core = args.source.resolve(), args.unixnu.resolve()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    boot_source = core / 'drivers/DarwinBoot'
    for directory, expected in [(source, lock['revision']), (core, lock['unixnu']['revision']),
                                (boot_source, lock['darwinboot']['revision'])]:
        actual = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != expected:
            raise SystemExit(f'Unexpected source revision in {directory}: {actual}')
    for specification in lock['darwinboot']['patches']:
        print('DARWINBOOT_PATCH', patch_state(boot_source, specification, args.apply))
    patch = ROOT / lock['menu_patch']['path']
    if hashlib.sha256(patch.read_bytes()).hexdigest() != lock['menu_patch']['sha256']:
        raise SystemExit('Menu patch SHA256 mismatch')
    package = core / 'package/UniXNUPkg'
    if not (package / 'Application/UniXNU/UniXNU.inf').is_file():
        raise SystemExit('The pinned UniXNU package is missing')
    packages = {'UniXNUPkg': package,
                'DarwinBootPkg': core / 'drivers/DarwinBoot/DarwinBootPkg'}
    for name, target in packages.items():
        if not target.is_dir():
            raise SystemExit(f'Missing pinned package: {target}')
        link = source / name
        if link.is_symlink():
            if link.resolve() != target:
                raise SystemExit(f'{name} links to a different checkout')
        elif link.exists():
            raise SystemExit(f'Refusing to overwrite an existing {name} directory')
    series = [lock['menu_patch'], lock['firmware_log_patch']]
    states = patch_series_state(source, series, args.apply)
    for specification, state in zip(series, states):
        print(specification['path'], state)
    if not args.apply:
        for name in packages:
            print(name, 'LINK_PRESENT' if (source / name).is_symlink() else 'LINK_REQUIRED')
        return
    for name, target in packages.items():
        if not (source / name).is_symlink():
            (source / name).symlink_to(target, target_is_directory=True)
    print('FIRMWARE_READY: pinned UniXNU packages and DarwinBoot selected')


if __name__ == '__main__':
    main()
