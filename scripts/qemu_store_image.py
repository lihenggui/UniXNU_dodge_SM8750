#!/usr/bin/env python3
"""Read the pinned RamBlock overlay format from local regular files."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import uuid
import zlib

from native_driver_build import ROOT, require


def open_regular(path):
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb')
    require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Expected a regular local image')
    return stream


def file_sha(path):
    with open_regular(path) as stream:return hashlib.file_digest(stream, 'sha256').hexdigest()


def header_and_bitmap(stream, image_bytes, seed_sha256):
    pages = image_bytes // 4096;bitmap_blocks = (pages + 32767) // 32768
    require(image_bytes > 0 and image_bytes % 4096 == 0 and
        os.fstat(stream.fileno()).st_size == (1 + bitmap_blocks + pages) * 4096, 'Wrong overlay capacity')
    stream.seek(0);header = stream.read(4096)
    require(len(header) == 4096 and header[:8] == b'SHNGDATA' and struct.unpack_from('<IIQ', header, 8) == (1, 64, pages) and
        header[24:56].hex() == seed_sha256 and struct.unpack_from('<I', header, 60)[0] == zlib.crc32(header[:60]),
        'Invalid or foreign RamBlock overlay header')
    bitmap = stream.read(bitmap_blocks * 4096)
    require(len(bitmap) == bitmap_blocks * 4096 and all(not (bitmap[index >> 3] >> (index & 7) & 1)
        for index in range(pages, bitmap_blocks * 32768)), 'Invalid overlay bitmap')
    return header, bitmap, bitmap_blocks, pages


def reconstruct(store, seed, output, image_bytes, seed_sha256):
    require(not output.exists(), 'Snapshot output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with open_regular(store) as source, open_regular(seed) as base:
        header, bitmap, bitmap_blocks, pages = header_and_bitmap(source, image_bytes, seed_sha256)
        require(os.fstat(base.fileno()).st_size == image_bytes, 'Wrong immutable seed capacity')
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as destination:
            digest = hashlib.sha256();zero = bytes(1 << 20)
            while chunk := base.read(len(zero)):
                digest.update(chunk)
                if chunk != zero[:len(chunk)]:destination.write(chunk)
                else:destination.seek(len(chunk), 1)
            destination.truncate(image_bytes)
            require(digest.hexdigest() == seed_sha256, 'Immutable Data seed changed')
            present = 0
            for page in range(pages):
                if not (bitmap[page >> 3] >> (page & 7) & 1):continue
                source.seek((1 + bitmap_blocks + page) * 4096);data = source.read(4096)
                require(len(data) == 4096, 'Short saved Data page')
                destination.seek(page * 4096);destination.write(data);present += 1
    return {'generation': struct.unpack_from('<I', header, 56)[0], 'saved_pages': present,
        'seed_sha256': seed_sha256, 'overlay_sha256': file_sha(store), 'snapshot_sha256': file_sha(output)}


def persona_identifiers(value, depth=0):
    if depth > 10:return set()
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('UserPersonaUniqueString', 'UserPersonaUserODUUID', 'MKBUserSessionUUID') and isinstance(child, str):
                try:identifier = uuid.UUID(child)
                except ValueError:continue
                if identifier.int not in (0, (1 << 128) - 1):found.add(str(identifier))
            found.update(persona_identifiers(child, depth + 1))
    elif isinstance(value, (list, tuple)):
        for child in value:found.update(persona_identifiers(child, depth + 1))
    elif isinstance(value, bytes) and value.startswith(b'bplist00') and len(value) <= 4 << 20:
        try:decoded = plistlib.loads(value)
        except (ValueError, plistlib.InvalidFileException):return found
        found.update(persona_identifiers(decoded, depth + 1))
    return found


def read_persona_marker(image, directory):
    directory.mkdir();blobs = directory / 'blobs';blobs.mkdir()
    reader = ROOT / 'build/ios16-data-apfs-volatile/apfs-data-verify'
    pin = json.loads((ROOT / 'reports/ios16-data-volatile-image.json').read_text())
    require(file_sha(reader) == pin['artifacts'][str(reader.relative_to(ROOT))], 'Read-only APFS reader changed')
    result = subprocess.run([reader, image, blobs], capture_output=True, text=True)
    (directory / 'reader.log').write_text(result.stderr)
    require(not result.returncode, 'Cannot read saved APFS Data: inspect reader.log')
    inventory = directory / 'inventory.jsonl';inventory.write_text(result.stdout)
    markers = []
    for row in map(json.loads, result.stdout.splitlines()):
        if row.get('type') != 'file' or 'persona' not in row['path'].lower() or row['path'].endswith('.writing'):continue
        require(Path(row['blob']).name == row['blob'], 'Unexpected APFS reader blob path')
        content = (blobs / row['blob']).read_bytes()
        if not content.startswith(b'bplist00'):continue
        identifiers = persona_identifiers(plistlib.loads(content))
        if identifiers:
            markers.append({'path': row['path'], 'file_sha256': hashlib.sha256(content).hexdigest(),
                'identifiers': sorted(identifiers)})
    require(markers, 'Original usermanagerd did not leave a readable persona marker')
    return markers, [inventory, directory / 'reader.log']
