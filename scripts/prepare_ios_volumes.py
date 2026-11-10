#!/usr/bin/env python3
"""Decode pinned iPhone disk images to local files and inspect APFS identities.

No volumes are mounted and no block devices are opened. APFS field definitions:
https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
This is an image/identity inspection, not a filesystem or root trust verifier.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu.udif import Image

INPUTS = [
    ('OS', '087-86698-044.dmg', '80f426d5b8fca8552f95be427434f1911dbb4c2c6d28aad94f2426ddd0c92483'),
    ('SystemOS', '087-86593-047.dmg', '9cd738f3b0169055549df84ad6d8d13e50a2da39af618ce0522ca4e06df86849'),
]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(8 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def checksum(block):
    first = second = 0
    modulus = 0xffffffff
    for (word,) in struct.iter_unpack('<I', block[8:]):
        first = (first + word) % modulus
        second = (second + first) % modulus
    low = modulus - ((first + second) % modulus)
    high = modulus - ((first + low) % modulus)
    return low | high << 32


def inspect(path):
    containers, volumes = [], {}
    position = 0
    with path.open('rb') as stream:
        while chunk := stream.read(8 << 20):
            for magic in (b'NXSB', b'APSB'):
                start = 0
                while (found := chunk.find(magic, start)) >= 0:
                    start = found + 4
                    offset = found - 32
                    # A GPT partition may begin at sector 34 (not a multiple
                    # of 4096). Validate object checksums without assuming the
                    # whole-disk origin is the APFS block origin.
                    if position + offset < 0:
                        continue
                    block = os.pread(stream.fileno(), 4096, position + offset)
                    if len(block) != 4096:
                        continue
                    stored, = struct.unpack_from('<Q', block)
                    if stored != checksum(block):
                        continue
                    oid, xid, kind = struct.unpack_from('<QQI', block, 8)
                    if magic == b'NXSB' and kind & 0xffff == 1:
                        block_size, count = struct.unpack_from('<IQ', block, 36)
                        if block_size != 4096:
                            raise SystemExit('Unsupported APFS block size')
                        containers.append({'offset': position + offset, 'xid': xid, 'block_bytes': block_size,
                                           'blocks': count, 'uuid': str(uuid.UUID(bytes=block[72:88]))})
                    elif magic == b'APSB' and kind & 0xffff == 13:
                        identity = str(uuid.UUID(bytes=block[240:256]))
                        row = {'uuid': identity, 'oid': oid, 'xid': xid, 'offset': position + offset,
                               'name': block[0x2c0:0x3c0].split(b'\0', 1)[0].decode('utf-8'),
                               'role': struct.unpack_from('<H', block, 0x3c4)[0]}
                        if identity not in volumes or row['xid'] > volumes[identity]['xid']:
                            volumes[identity] = row
            position += len(chunk)
    if not containers or not volumes:
        raise SystemExit(f'No checksum-valid APFS container/volume objects in {path.name}')
    # Embedded ramdisk files may themselves contain checksum-valid objects.
    # Only record volume blocks aligned inside the outermost container.
    outer = min(containers, key=lambda c: c['offset'])
    origin, extent = outer['offset'], outer['blocks'] * outer['block_bytes']
    volumes = [v for v in volumes.values() if origin <= v['offset'] < origin + extent
               and (v['offset'] - origin) % outer['block_bytes'] == 0]
    if not volumes:
        raise SystemExit('No volume objects aligned to the outer APFS container')
    return {'container': outer, 'observed_volumes': volumes,
            'object_checksums_verified': True, 'object_map_traversed': False,
            'filesystem_mount_verified': False, 'root_signature_authenticated': False}


def main():
    os.environ['PATH'] = str(ROOT / 'sources/lzfse/build/bin') + os.pathsep + os.environ['PATH']
    destination = ROOT / 'build/ios16-volumes'
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for label, name, expected in INPUTS:
        source = ROOT / 'build/unixnu/ipsw/20H392' / name
        if sha256(source) != expected:
            raise SystemExit(f'{name}: original disk image SHA256 mismatch')
        image = Image(source)
        output = destination / (label + '.raw')
        saved = output.with_suffix('.json')
        if output.exists():
            if not saved.is_file():
                raise SystemExit(f'Refusing to overwrite an unrecorded output: {output}')
            record = json.loads(saved.read_text())
            if record['source_sha256'] != expected or output.stat().st_size != image.size or sha256(output) != record['raw_sha256']:
                raise SystemExit(f'{label}: existing raw image does not match its record')
        else:
            temporary = output.with_suffix('.partial')
            digest = hashlib.sha256()
            done = 0
            try:
                with temporary.open('xb') as stream:
                    for block in image.blocks():
                        stream.write(block)
                        digest.update(block)
                        done += len(block)
                if done != image.size:
                    raise SystemExit(f'{label}: incomplete disk decoding')
                temporary.rename(output)
            finally:
                temporary.unlink(missing_ok=True)
            record = {'name': label, 'source': name, 'source_sha256': expected,
                      'raw_bytes': done, 'raw_sha256': digest.hexdigest(),
                      'path': str(output.relative_to(ROOT))}
            saved.write_text(json.dumps(record, indent=2) + '\n')
        record['apfs'] = inspect(output)
        saved.write_text(json.dumps(record, indent=2) + '\n')
        rows.append(record)
        print(f'{label}: {image.size} local bytes decoded and inspected', flush=True)
    report = {'product': 'iPhone10,3', 'build': '20H392', 'images': rows,
              'phone_operations': 'none', 'root_authentication_qualified': False}
    (ROOT / 'reports/ios16-volumes.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
