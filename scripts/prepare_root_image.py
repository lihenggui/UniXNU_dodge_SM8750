#!/usr/bin/env python3
"""Assemble pinned iPhone OS windows in a regular file; no device or GPT writes."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess

from native_driver_build import ROOT, pinned_sources, require

OUT = ROOT / 'build/ios16-root-image'
NAMES = ('OS', 'SystemOS')
MIB = 1 << 20
CHUNK = 8 << 20


def sha(path):
    with path.open('rb') as stream:
        return digest_extent(stream, 0, path.stat().st_size)


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'Expected a regular local file: ' + str(path))


def digest_extent(stream, offset, length):
    stream.seek(offset)
    digest = hashlib.sha256()
    while length:
        block = stream.read(min(CHUNK, length))
        require(block, 'Truncated root-image window')
        digest.update(block)
        length -= len(block)
    return digest.hexdigest()


def make_manifest(rows, total):
    header = bytearray(4096)
    header[:8] = b'SHNGROOT'
    struct.pack_into('<IIQ', header, 8, 1, len(rows), total)
    for i, row in enumerate(rows):
        struct.pack_into('<32sQQII32s40s', header, 24 + 128 * i, row['name'].encode(), row['offset'],
                         row['bytes'], 512, 1, bytes.fromhex(row['sha256']), bytes(40))
    header[4064:] = hashlib.sha256(header[:4064]).digest()
    return bytes(header)


def main():
    volumes_path = ROOT / 'reports/ios16-volumes.json'
    volumes = json.loads(volumes_path.read_text())
    require(volumes['product'] == 'iPhone10,3' and volumes['build'] == '20H392', 'Need the pinned iPhone volumes')
    profile = ROOT / 'targets/iphone-x-ios16.toml'
    import tomllib
    pins = tomllib.loads(profile.read_text())['ipsw']['sha256']
    source = pinned_sources(('pagani_reference',))['pagani_reference'] / 'drivers/NativeUfs'
    rows, cursor = [], MIB
    for name in NAMES:
        row, = [r for r in volumes['images'] if r['name'] == name]
        raw, dmg = ROOT / row['path'], ROOT / 'build/unixnu/ipsw/20H392' / row['source']
        regular(raw); regular(dmg)
        require(row['source_sha256'] == pins[row['source']] == sha(dmg), 'Original IPSW volume pin changed')
        require(raw.stat().st_size == row['raw_bytes'] and sha(raw) == row['raw_sha256'], 'Decoded iPhone volume changed')
        require(row['raw_bytes'] > 0 and not row['raw_bytes'] % 512, 'Unaligned iPhone raw window')
        rows.append({'name': name, 'path': row['path'], 'offset': cursor, 'bytes': row['raw_bytes'], 'sha256': row['raw_sha256']})
        cursor += (row['raw_bytes'] + MIB - 1) // MIB * MIB
    require(cursor % 4096 == 0 and cursor // 4096 < (1 << 32) - 264, 'Root-image READ(10) limit exceeded')
    manifest = make_manifest(rows, cursor)
    OUT.mkdir(parents=True, exist_ok=True)
    image = OUT / 'iphone-root.img'
    saved = OUT / 'manifest.json'
    if image.exists() or image.is_symlink():
        regular(image)
        require(saved.is_file(), 'Refuse an existing root image without its record')
        previous = json.loads(saved.read_text())
        require(previous['image_sha256'] == sha(image), 'Existing root image differs from its record')
    else:
        temporary = OUT / 'iphone-root.partial'
        created = False
        try:
            with temporary.open('xb') as target:
                created = True
                target.truncate(cursor)
                target.write(manifest)
                for row in rows:
                    target.seek(row['offset'])
                    with (ROOT / row['path']).open('rb') as original:
                        while block := original.read(CHUNK):
                            target.write(block)
            # link refuses an existing destination; no previous image is replaced.
            os.link(temporary, image)
        finally:
            if created:
                temporary.unlink()
    require(image.stat().st_size == cursor, 'Root image has a wrong file size')
    with image.open('rb') as stream:
        require(stream.read(4096) == manifest, 'Root manifest differs from the original image contract')
        previous_end = 4096
        for row in rows:
            stream.seek(previous_end)
            require(not any(stream.read(row['offset'] - previous_end)), 'Root-image alignment padding is nonzero')
            require(digest_extent(stream, row['offset'], row['bytes']) == row['sha256'], 'Root-image payload differs: ' + row['name'])
            previous_end = row['offset'] + row['bytes']
        require(not any(stream.read(cursor - previous_end)), 'Root-image final padding is nonzero')
    binary = OUT / 'root-image-host'
    compiler = Path('/usr/bin/clang++-14')
    command = [str(compiler), '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I' + str(source),
               str(ROOT / 'tests/DodgeRootImageTest.cpp'), '-lcrypto', '-o', str(binary)]
    subprocess.run(command, check=True)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    output = subprocess.check_output([binary, image, *(ROOT / r['path'] for r in rows)], env=env, text=True)
    cases = [json.loads(line) for line in output.splitlines()]
    require(len(cases) == 32 and all(c['result'] == 'PASS' for c in cases), 'Actual root-image consumers did not pass')
    case_file = OUT / 'consumer-cases.json'
    case_file.write_text(json.dumps({'result': 'PASS', 'case_count': len(cases), 'cases': cases}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/native_driver_build.py', ROOT / 'tests/DodgeRootImageTest.cpp', profile,
             source / 'RootLayout.h', source / 'RootWindowRead.h', source / 'RootPublication.h', source / 'RootDiagnostics.h',
             ROOT / 'sources/UniXNU/scripts/unixnu/userdata.py']
    result = {'result': 'IOS16_ORIGINAL_READ_ONLY_ROOT_IMAGE_AND_PRODUCTION_CONSUMERS_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392', 'source_revision': json.loads((ROOT / 'upstream.lock.json').read_text())['pagani_reference']['revision'],
              'volume_report_sha256': sha(volumes_path), 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'image': str(image.relative_to(ROOT)), 'image_bytes': cursor, 'image_sha256': sha(image),
              'manifest_sha256': hashlib.sha256(manifest).hexdigest(), 'format': 'SHNGROOT', 'format_version': 1,
              'selected_partition_name': 'unixnu', 'physical_lba_bytes': 4096, 'logical_block_bytes': 512,
              'window_alignment_bytes': MIB, 'windows': rows, 'all_window_bytes_read_back': True,
              'host_consumer': str(binary.relative_to(ROOT)), 'host_consumer_sha256': sha(binary), 'host_compiler_sha256': sha(compiler),
              'host_cases': cases, 'host_case_count': len(cases), 'cpu_cases': str(case_file.relative_to(ROOT)), 'cpu_cases_sha256': sha(case_file),
              'consumer_production_sources_unmodified': True, 'gpt_for_host_tests': 'synthetic in-memory only, not captured hardware geometry',
              'image_contains_gpt': False, 'original_os_windows_included': True, 'writable_data_included': False,
              'root_authentication_qualified': False, 'owner_root_trust_generated': False, 'apple_signature_authentication_verified': False,
              'block_devices_opened': False, 'filesystem_mounted': False, 'phone_operations': 'none', 'physical_partition_modified': False,
              'default_boot_image_replaced': False, 'runtime_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'scope': 'Local regular-file payload of the exact original iPhone OS/SystemOS raw windows, not a phone disk image or GPT. '
                       'Every window byte is hashed back. Actual production manifest, publication ordering and 512-byte/4K window-read algorithms '
                       'execute on the assembled file with synthetic GPT/transport/registry peers and sanitizer checks. '
                       'No physical partition geometry, APFS authenticated root, writable Data, kernel runtime or iOS boot result.'}
    saved.write_text(json.dumps(result, indent=2) + '\n')
    (ROOT / 'reports/ios16-root-image.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: {cursor} original iPhone root-image bytes, {len(cases)} production-consumer cases; regular files only, no GPT or phone writes')


if __name__ == '__main__':
    main()
