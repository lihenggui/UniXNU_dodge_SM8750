#!/usr/bin/env python3
"""Compile the dodge hardware tree and read back its iPhone ADT identity."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu.cli import parser
from unixnu.config import Context
from unixnu.devicetree import compile_hardware, generate


def parse_adt(blob):
    nodes = {}

    def read(at, parent='', depth=0):
        if depth > 64 or at + 8 > len(blob):
            raise ValueError('Truncated or excessive ADT')
        count, children = struct.unpack_from('<II', blob, at)
        at += 8
        properties = {}
        for _ in range(count):
            if at + 36 > len(blob):
                raise ValueError('Truncated ADT property header')
            raw, length = struct.unpack_from('<32sI', blob, at)
            length &= 0x7fffffff
            at += 36
            name = raw.split(b'\0', 1)[0].decode()
            if name in properties or at + length > len(blob):
                raise ValueError('Duplicate or truncated ADT property')
            properties[name] = blob[at:at + length]
            at += (length + 3) & ~3
        name = properties['name'].rstrip(b'\0').decode()
        path = parent + '/' + name if parent or name != 'device-tree' else ''
        nodes[path or '/'] = properties
        for _ in range(children):
            at = read(at, path, depth + 1)
        return at

    if read(0) != len(blob):
        raise ValueError('Trailing ADT bytes')
    return nodes


def main():
    ctx = Context(parser().parse_args(['tree', '-D', str(ROOT), '--out', str(ROOT / 'build/unixnu'), '-j', '4']))
    dtb = compile_hardware(ctx)
    private = ROOT / '.cache/platform.json'
    private.parent.mkdir(exist_ok=True)
    if private.exists():
        identity = json.loads(private.read_text())
    else:
        identity = {'unique_chip_id': f'{secrets.randbelow((1 << 64) - 1) + 1:016x}'}
        descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(identity, stream)
    os.chmod(private, 0o600)
    seed = identity['unique_chip_id']
    blob = generate(dtb, ctx.board, unique_chip_id=seed)
    nodes = parse_adt(blob)
    expected = [('/', 'model', b'iPhone10,3\0'), ('/', 'target-type', b'D22\0'),
                ('/product', 'artwork-device-idiom', b'phone\0'),
                ('/product', 'artwork-scale-factor', struct.pack('<I', 3)),
                ('/buttons', 'home-button-type', struct.pack('<I', 2)),
                ('/chosen', 'chip-id', struct.pack('<I', 0x8015)),
                ('/chosen', 'darwinboot-memory-size', struct.pack('<Q', 4 << 30))]
    for path, key, value in expected:
        if nodes[path].get(key) != value:
            raise SystemExit(f'Generated iPhone ADT mismatch: {path}/{key}')
    if nodes['/']['compatible'] != b'D22AP\0iPhone10,3\0AppleARM\0oneplus,dodge\0qcom,sm8750\0':
        raise SystemExit('Original iPhone and native board compatible identities were not preserved')
    cpus = [p for p in nodes if p.startswith('/cpus/cpu')]
    if len(cpus) != 1 or nodes[cpus[0]]['reg'] != bytes(4):
        raise SystemExit('Initial profile must expose only the observed boot CPU')
    output = ctx.work / 'device-tree/dodge-iphone.adt'
    output.write_bytes(blob)
    report = {'result': 'PASS', 'hardware_dtb': str(dtb.relative_to(ROOT)),
              'adt': str(output.relative_to(ROOT)), 'bytes': len(blob),
              'sha256': hashlib.sha256(blob).hexdigest(),
              'model': 'iPhone10,3', 'target_type': 'D22', 'idiom': 'phone', 'display_scale': 3,
              'compatible': ['D22AP', 'iPhone10,3', 'AppleARM', 'oneplus,dodge', 'qcom,sm8750'],
              'enabled_cpu_count': 1, 'owned_memory_bytes': 4 << 30,
              'private_platform_seed_persisted': True, 'private_platform_seed_disclosed': False,
              'random_seed_regenerated': True, 'hardware_tested': False}
    (ROOT / 'reports/device-tree.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: dodge DTS and iPhone ADT readback; one CPU, 4 GiB handoff, phone identity')


if __name__ == '__main__':
    main()
