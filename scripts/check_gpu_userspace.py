#!/usr/bin/env python3
"""Read back target, imports and every 4 KiB code-signature hash of own GPU binaries."""
import hashlib
import argparse
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, macho, require, sha


def verify(data, kind):
    image = macho(data)
    require(image['kind'] == kind, 'Unexpected GPU Mach-O file type')
    version, = [at for cmd, at, _ in image['commands'] if cmd == 0x32]
    platform, minimum, sdk = struct.unpack_from('<3I', data, version + 8)
    require(platform == 2 and minimum == 0x100000, 'GPU executable does not target ordinary ARM64 iOS 16')
    signature, = [at for cmd, at, _ in image['commands'] if cmd == 0x1d]
    offset, size = struct.unpack_from('<II', data, signature + 8)
    require(offset + size <= len(data), 'Code signature lies outside the file')
    blob = data[offset:offset + size]
    magic, length, count = struct.unpack_from('>3I', blob)
    require(magic == 0xfade0cc0 and 12 + count * 8 <= length <= size, 'Invalid signature superblob')
    slots = [struct.unpack_from('>II', blob, 12 + i * 8) for i in range(count)]
    directories = [at for slot, at in slots if slot == 0]
    require(len(directories) == 1, 'Expected one primary CodeDirectory')
    start = directories[0]
    require(12 + count * 8 <= start < length - 44, 'CodeDirectory header is out of bounds')
    header = struct.unpack_from('>9I4BI', blob, start)
    magic, cd_length, cd_version, flags, hash_offset, identifier, special, pages, limit, hash_size, hash_type, platform, shift, _ = header
    require(magic == 0xfade0c02 and start + cd_length <= length and cd_version >= 0x20100, 'Invalid CodeDirectory')
    cd = blob[start:start + cd_length]
    require(flags & 2 and platform == 0, 'Expected an own ad-hoc, non-platform signature')
    require((hash_size, hash_type, shift, special) == (32, 2, 12, 0), 'Expected SHA-256 with 4 KiB pages and no special slots')
    require(struct.unpack_from('>I', cd, 44)[0] == 0, 'Unexpected code-signature scatter vector')
    require(limit == offset and pages == (limit + 4095) // 4096, 'CodeDirectory does not cover all executable file bytes')
    require(48 <= identifier < hash_offset and hash_offset + pages * 32 <= cd_length, 'Invalid signature table extent')
    end = cd.index(b'\0', identifier, hash_offset)
    for page in range(pages):
        expected = cd[hash_offset + page * 32:hash_offset + (page + 1) * 32]
        actual = hashlib.sha256(data[page * 4096:min(limit, (page + 1) * 4096)]).digest()
        require(expected == actual, 'Code signature page hash mismatch: ' + str(page))
    libraries = []
    for command, at, size in image['commands']:
        if command in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            name_at, = struct.unpack_from('<I', data, at + 8)
            require(24 <= name_at < size, 'Invalid dylib import name')
            name = data[at + name_at:data.index(b'\0', at + name_at, at + size)].decode()
            require(name.startswith(('/usr/lib/', '/System/Library/')), 'GPU binary imports an unexpected local dependency')
            libraries.append(name)
    return {'filetype': kind, 'minimum_os': '16.0', 'sdk_version_hex': hex(sdk), 'signed_pages': pages,
            'signature_identifier': cd[identifier:end].decode(), 'cdhash': hashlib.sha256(cd).hexdigest()[:40],
            'hash_page_bytes': 4096, 'imports': libraries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-a830', action='store_true')
    args = parser.parse_args()
    out = ROOT / ('build/cph2653-native-a830-metal-plugin' if args.native_a830 else 'build/cph2653-metal-plugin')
    bundle = out / 'NativeAdrenoMetal.bundle'
    files = [(bundle / 'NativeAdrenoMetal', 8), (bundle / 'libvulkan_freedreno.dylib', 6), (out / 'adrenoprobed', 2)]
    results = []
    for path, kind in files:
        data = path.read_bytes()
        result = verify(data, kind)
        # An ordinary code-byte mutation must invalidate the actual directory,
        # without changing the Mach-O load commands or signature structure.
        image = macho(data)
        text, = [s for segment in image['segments'] for s in segment['sections'] if s['name'] == '__text']
        changed = bytearray(data)
        changed[text['fileoff']] ^= 1
        try:
            verify(changed, kind)
        except ValueError as error:
            require('page hash mismatch' in str(error), 'Corruption was rejected for the wrong reason')
        else:
            raise ValueError('Modified GPU instructions passed signature verification')
        results.append({'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': sha(path),
                        **result, 'changed_code_negative_control': 'rejected'})
    report = {'result': 'IOS16_GPU_USERSPACE_BINARY_READBACK_PASS', 'binaries': results,
              'owner_trust_installed': False, 'bundle_resource_seal_created': False,
              'original_metal_discovery_abi_qualified': False, 'hardware_tested': False,
              'scope': 'Own Mach-O target/import and embedded page-integrity checks; no Apple signature or runtime trust claim.'}
    (ROOT / ('reports/native-a830-userspace.json' if args.native_a830 else 'reports/gpu-userspace.json')).write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: three ordinary ARM64/iOS 16 binaries, all 4 KiB code hashes, and code-corruption controls')


if __name__ == '__main__':
    main()
