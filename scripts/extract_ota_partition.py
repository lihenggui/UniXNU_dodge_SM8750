#!/usr/bin/env python3
"""Read selected full-OTA payload partitions to local files; never access devices.

Wire fields follow Android's system/update_engine/update_metadata.proto. Only
full replacement operations are accepted. Every downloaded operation and final
partition is checked against the manifest's SHA-256 before publishing output.
"""
import argparse
import bz2
import concurrent.futures
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def varint(data, offset):
    value = 0
    for n in range(10):
        require(offset < len(data), 'Truncated protobuf varint')
        byte = data[offset]
        offset += 1
        require(n != 9 or byte <= 1, 'Overflowing protobuf varint')
        value |= (byte & 127) << (7 * n)
        if byte < 128:
            return value, offset
    raise ValueError('Overlong protobuf varint')


def fields(data):
    offset, result = 0, {}
    while offset < len(data):
        key, offset = varint(data, offset)
        number, wire = key >> 3, key & 7
        require(number > 0, 'Invalid protobuf field number')
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, offset = varint(data, offset)
            else:
                size = 8 if wire == 1 else 4
            require(offset + size <= len(data), 'Truncated protobuf field')
            value = data[offset:offset + size]
            offset += size
        else:
            raise ValueError('Unsupported protobuf wire type')
        result.setdefault(number, []).append(value)
    return result


def one(message, number, default=None):
    values = message.get(number, [])
    require(len(values) <= 1, 'Duplicate singular protobuf field')
    if not values:
        require(default is not None, 'Missing required protobuf field: ' + str(number))
        return default
    return values[0]


def read_range(url, offset, size, total):
    require(size > 0 and 0 <= offset < offset + size <= total, 'OTA range is out of bounds')
    request = urllib.request.Request(url, headers={'Range': f'bytes={offset}-{offset + size - 1}',
                                                 'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(request, timeout=120) as response:
        require(response.status == 206, 'OTA server did not honor bounded range request')
        require(response.headers.get('Content-Range') == f'bytes {offset}-{offset + size - 1}/{total}',
                'OTA server returned an unexpected byte range')
        data = response.read(size + 1)
    require(len(data) == size, 'OTA response has an unexpected length')
    return data


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(8 << 20), b''):
            value.update(data)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url-json', type=Path, required=True, help='Local resolver JSON containing url; URL stays private/local')
    parser.add_argument('--layout', type=Path, default=ROOT / 'analysis/oneplus13-payload-layout.json')
    parser.add_argument('--manifest', type=Path, default=ROOT / 'analysis/oneplus13-update-metadata.pb')
    parser.add_argument('--partition', action='append', required=True)
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/stock-cph2653-16.0.1.304')
    args = parser.parse_args()
    url = json.loads(args.url_json.read_text())['url']
    layout = json.loads(args.layout.read_text())
    total = layout['ota_bytes']
    manifest_data = args.manifest.read_bytes()
    # Re-read the header and manifest from this URL. A stale or changed resolver
    # cannot silently mix cached metadata with a different payload.
    header = read_range(url, layout['payload_zip_offset'], 24, total)
    magic, version, size, signature = struct.unpack('>4sQQI', header)
    require((magic, version, size, signature) == (b'CrAU', 2, len(manifest_data), layout['metadata_signature_size']),
            'Payload header differs from the selected manifest/layout')
    actual = read_range(url, layout['payload_zip_offset'] + 24, size, total)
    require(actual == manifest_data, 'Cached manifest differs from the selected public OTA')
    manifest = fields(manifest_data)
    block_size = one(manifest, 3, 4096)
    require(block_size == 4096, 'Unexpected payload block size')
    partitions = {one(p, 1).decode(): p for p in map(fields, manifest[13])}
    args.out.mkdir(parents=True, exist_ok=True)
    reports = []
    for name in args.partition:
        require(re.fullmatch(r'[a-z0-9_]+', name), 'Unsafe output partition name')
        partition = partitions[name]
        require(6 not in partition, 'Delta OTA needs an old image; only full OTA is accepted')
        info = fields(one(partition, 7))
        size, expected = one(info, 1), one(info, 2).hex()
        require(0 < size <= 8 * 1024**3, 'Partition exceeds local extraction limit')
        output = args.out / (name + '.img')
        if output.exists() and output.stat().st_size == size and digest(output) == expected:
            print('Verified existing partition:', name, flush=True)
        else:
            operations = list(map(fields, partition.get(8, [])))
            spans, plans = [], []
            for index, op in enumerate(operations):
                kind = one(op, 1)
                require(kind in (0, 1, 6, 7, 8), 'Unsupported full-OTA operation: ' + str(kind))
                extents = [(one(e, 1) * block_size, one(e, 2) * block_size) for e in map(fields, op.get(6, []))]
                for start, length in extents:
                    require(length > 0 and 0 <= start < start + length <= size, 'Invalid destination extent')
                    spans.append((start, start + length))
                require(extents and sum(length for _, length in extents) <= 16 * 1024**2, 'Operation exceeds extraction limit')
                length, offset = one(op, 3, 0), one(op, 2, 0)
                require(length <= 16 * 1024**2, 'Compressed operation exceeds extraction limit')
                require(offset + length <= layout['payload_size'] - (layout['data_offset'] - layout['payload_zip_offset']),
                        'Operation exceeds payload bounds')
                plans.append((index, kind, offset, length, one(op, 8, b''), extents))
            end = 0
            for start, stop in sorted(spans):
                require(start == end, 'Overlapping or missing destination blocks')
                end = stop
            require(end == size, 'Destination does not cover the whole partition')
            cache = args.out / (name + '-operations')
            cache.mkdir(exist_ok=True)

            def fetch(plan):
                index, kind, offset, length, expected_hash, _ = plan
                if not length:
                    require(kind in (6, 7), 'Replacement operation has no data')
                    return
                require(len(expected_hash) == 32, 'Operation SHA-256 is absent')
                target = cache / str(index)
                if target.exists() and target.stat().st_size == length and digest(target) == expected_hash.hex():
                    return
                data = read_range(url, layout['data_offset'] + offset, length, total)
                require(hashlib.sha256(data).digest() == expected_hash, 'Operation SHA-256 mismatch')
                temporary = target.with_suffix('.download')
                temporary.write_bytes(data)
                temporary.replace(target)

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                for i, _ in enumerate(pool.map(fetch, plans), 1):
                    if i % 32 == 0 or i == len(plans):
                        print(f'{name}: verified {i}/{len(plans)} operations', flush=True)
            temporary = output.with_suffix('.img.partial')
            with temporary.open('wb') as stream:
                stream.truncate(size)
                for index, kind, _, length, _, extents in plans:
                    expected_size = sum(n for _, n in extents)
                    if kind in (6, 7):
                        require(length == 0, 'Zero operation unexpectedly has data')
                        data = bytes(expected_size)
                    else:
                        data = (cache / str(index)).read_bytes()
                        if kind == 1:
                            decoder = bz2.BZ2Decompressor()
                            data = decoder.decompress(data, max_length=expected_size + 1)
                            require(decoder.eof and not decoder.unused_data, 'Invalid bzip2 operation')
                        elif kind == 8:
                            decoder = lzma.LZMADecompressor(memlimit=256 * 1024**2)
                            data = decoder.decompress(data, max_length=expected_size + 1)
                            require(decoder.eof and not decoder.unused_data, 'Invalid XZ operation')
                    require(len(data) == expected_size, 'Operation output size differs from extents')
                    offset = 0
                    for start, length in extents:
                        stream.seek(start)
                        stream.write(data[offset:offset + length])
                        offset += length
            require(digest(temporary) == expected, 'Final partition SHA-256 mismatch')
            temporary.replace(output)
            print('PASS: reconstructed and verified partition:', name, expected, flush=True)
        reports.append({'partition': name, 'path': str(output.relative_to(ROOT)), 'bytes': size, 'sha256': expected})
    report = {'result': 'PUBLIC_OTA_PARTITIONS_EXTRACTED', 'manifest_sha256': hashlib.sha256(manifest_data).hexdigest(),
              'ota_bytes': total, 'partitions': reports, 'full_ota_downloaded': False,
              'operation_and_partition_hashes_verified': True, 'ota_signature_authenticated': False,
              'phone_operations': 'none'}
    (args.out / 'extraction.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
