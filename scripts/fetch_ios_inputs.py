#!/usr/bin/env python3
"""Verify and cache pinned iPhone IPSW inputs; optionally retrieve the OS volumes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tomllib
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unixnu', type=Path, default=ROOT / 'sources/UniXNU')
    parser.add_argument('--lzfse', type=Path, default=ROOT / 'sources/lzfse/build/bin/lzfse')
    parser.add_argument('--target', type=Path, default=ROOT / 'targets/iphone-x-ios16.toml')
    parser.add_argument('--out', type=Path, default=ROOT / 'build/unixnu', help='UniXNU output root, shared with ./unixnu')
    parser.add_argument('--volumes', action='store_true', help='Also cache OS and cryptex images using bounded reads')
    args = parser.parse_args()
    target = tomllib.loads(args.target.read_text())
    if target['os']['family'] != 'ios' or not target['ipsw']['product'].startswith('iPhone'):
        raise SystemExit('This workspace targets an iPhone iOS image.')
    if not args.lzfse.is_file():
        raise SystemExit('Build the reference lzfse decoder first: make -C sources/lzfse -j4')
    sys.path.insert(0, str(args.unixnu.resolve() / 'scripts'))
    from unixnu.ipsw import Ipsw, kernelcache
    from unixnu.util import sha256_file

    spec = target['ipsw']
    ctx = SimpleNamespace(board=target, out_root=args.out.resolve())
    ctx.option_text = lambda *unused: None
    source = Ipsw(ctx)
    raw_manifest = source.zip.read('BuildManifest.plist')
    source.cache.mkdir(parents=True, exist_ok=True)
    (source.cache / 'BuildManifest.plist').write_bytes(raw_manifest)
    report = {'source': spec['url'], 'product_version': source.manifest['ProductVersion'],
              'build': source.manifest['ProductBuildVersion'],
              'products': source.manifest['SupportedProductTypes'],
              'device_class': source.identity['Info']['DeviceClass'],
              'chip_id': source.identity['ApChipID'], 'board_id': source.identity['ApBoardID'],
              'build_manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
              'unixnu_revision': subprocess.check_output(
                  ['git', '-C', str(args.unixnu), 'rev-parse', 'HEAD'], text=True).strip(),
              'components': {}}
    # Record large volume names and sizes without fetching them.
    for component in [*spec['fetch'], 'OS', 'Cryptex1,SystemOS', 'Cryptex1,AppOS']:
        if component not in source.identity['Manifest']:
            continue
        member, size, compressed = source.info(component)
        row = {'member': member, 'bytes': size, 'compressed_bytes': compressed}
        if component in spec['fetch'] or args.volumes:
            path = source.extract(component)
            digest = sha256_file(path)
            if digest != spec['sha256'][path.name]:
                raise SystemExit(f'{component}: cached input SHA256 mismatch')
            row['sha256'] = digest
        report['components'][component] = row
    os.environ['PATH'] = str(args.lzfse.resolve().parent) + os.pathsep + os.environ['PATH']
    data = kernelcache(ctx, source).read_bytes()
    version = re.search(rb'Darwin Kernel Version [^\0\n]+', data)
    if not version or ('xnu-' + target['kernel']['original_xnu']).encode() not in version[0]:
        raise SystemExit('The original kernel version does not match the selected target')
    cpu_type, subtype = struct.unpack_from('<II', data, 4)
    if cpu_type != 0x0100000c or subtype & 0x00ffffff:
        raise SystemExit('Expected a plain arm64 iPhone kernelcache')
    report['kernelcache'] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                            'version_string': version[0].decode(),
                            'architecture': 'arm64', 'macho_header': data[:32].hex()}
    report['scope'] = 'Verified original iPhone inputs only; not a built or booted OnePlus kernel.'
    output = ROOT / 'reports/ios-target.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output), 'product': spec['product'],
                      'build': spec['build'], 'board_id': spec['board_id'],
                      'kernel': report['kernelcache']['version_string']}, indent=2))


if __name__ == '__main__':
    main()
