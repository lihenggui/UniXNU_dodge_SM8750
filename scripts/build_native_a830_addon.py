#!/usr/bin/env python3
"""Package the native Metal addon and the pinned iPhone trust-cache inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tomllib
import uuid
import zlib

from check_gpu_userspace import verify
from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/cph2653-native-a830-addon'
REPORT = ROOT / 'reports/native-a830-addon.json'


def modules(data):
    require(len(data) >= 8, 'Truncated trust bundle')
    count, = struct.unpack_from('<I', data)
    require(0 < count <= 128 and 4 + count * 4 <= len(data), 'Invalid trust module count')
    starts = list(struct.unpack_from('<' + str(count) + 'I', data, 4)) + [len(data)]
    result = []
    for first, last in zip(starts, starts[1:]):
        require(first >= 4 + count * 4 and first % 4 == 0 and first <= last <= len(data), 'Invalid trust module offset')
        module = data[first:last];require(len(module) >= 24, 'Short trust module')
        version, = struct.unpack_from('<I', module);entries, = struct.unpack_from('<I', module, 20)
        require(version == 2 and len(module) == 24 + 24 * entries, 'Invalid version-2 trust module')
        hashes = [module[24 + i * 24:44 + i * 24] for i in range(entries)]
        require(hashes == sorted(set(hashes)) and all(1 <= module[44 + i * 24] <= 4 for i in range(entries)),
                'Unsorted or invalid trust entries')
        result.append(module)
    return result


def unpack_addon(data):
    require(data[:8] == b'NGPUADD2' and len(data) >= 24, 'Invalid native GPU addon header')
    count, reserved, length = struct.unpack_from('<IIQ', data, 8)
    require(not reserved and length == len(data) and 0 < count < 128, 'Invalid native GPU addon extent')
    at = 24;files = {}
    for _ in range(count):
        require(at + 24 <= len(data), 'Truncated addon record')
        path_bytes, mode, size, packed_size = struct.unpack_from('<IIQQ', data, at);at += 24
        require(1 < path_bytes <= 160 and at + path_bytes <= len(data), 'Invalid addon path extent')
        path = data[at:at + path_bytes];require(path[-1:] == b'\0' and b'\0' not in path[:-1], 'Invalid addon path')
        name = path[:-1].decode();require(not name.startswith('/') and '..' not in name.split('/') and name not in files, 'Unsafe addon path')
        at += (path_bytes + 7) & ~7
        require(at + packed_size <= len(data) and mode in (0o644, 0o755), 'Invalid addon record extent/mode')
        stream = zlib.decompressobj();plain = stream.decompress(data[at:at + packed_size]) + stream.flush()
        require(stream.eof and not stream.unused_data and not stream.unconsumed_tail and len(plain) == size, 'Invalid addon zlib stream')
        files[name] = {'mode': mode, 'bytes': size, 'sha256': hashlib.sha256(plain).hexdigest()}
        at += (packed_size + 7) & ~7
    require(at == len(data), 'Trailing addon data')
    return files


def check_report(report):
    require(report['result'] == 'NATIVE_A830_IPHONE_ADDON_AND_TRUST_INPUTS_PASS' and not report['hardware_tested'], 'Invalid native addon report')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native addon input changed: ' + name)
    require(unpack_addon((ROOT / report['addon']).read_bytes()) == report['files'], 'Native addon readback changed')
    require(len(modules((ROOT / report['trust_bundle']).read_bytes())) == 3, 'Native trust bundle changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native addon and iPhone trust input readback');return
    OUT.mkdir(parents=True, exist_ok=True)
    plugin = ROOT / 'build/cph2653-native-a830-metal-plugin';bundle = plugin / 'NativeAdrenoMetal.bundle'
    binaries = [(bundle / 'NativeAdrenoMetal', 8), (bundle / 'libvulkan_freedreno.dylib', 6), (plugin / 'adrenoprobed', 2)]
    verified = [{'path': str(path.relative_to(ROOT)), 'sha256': sha(path), **verify(path.read_bytes(), kind)} for path, kind in binaries]
    packer = ROOT / 'sources/UniXNU/scripts/make-gpu-addon.py';addon = OUT / 'gpuaddon.bin'
    addon.unlink(missing_ok=True)
    process = subprocess.run([sys.executable, packer, '--publish', addon], env=dict(os.environ, ADRENO_PLUGIN_DIR=str(plugin)),
                             capture_output=True, text=True)
    (OUT / 'pack.log').write_text(process.stdout + process.stderr);require(not process.returncode, 'Native addon packing failed')
    files = unpack_addon(addon.read_bytes());expected = {}
    for path in bundle.rglob('*'):
        if path.is_file():expected['addons/NativeAdrenoMetal.bundle/' + path.relative_to(bundle).as_posix()] = sha(path)
    expected['addons/NativeAdrenoMetal.publish'] = hashlib.sha256(b'1\n').hexdigest()
    expected['bin/adrenoprobed'] = sha(plugin / 'adrenoprobed')
    require({name: row['sha256'] for name, row in files.items()} == expected, 'Native addon file readback differs')
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'));from unixnu.ipsw import im4p_payload
    target = ROOT / 'targets/iphone-x-ios16.toml';pins = tomllib.loads(target.read_text())['ipsw']['sha256']
    originals = [];provenance = []
    for name in ('087-86698-044.dmg.trustcache', '087-86593-047.dmg.trustcache'):
        path = ROOT / 'build/unixnu/ipsw/20H392' / name
        require(sha(path) == pins[name], 'Wrong iPhone trust-cache input: ' + name)
        module = im4p_payload(path.read_bytes());modules(struct.pack('<2I', 1, 8) + module)
        originals.append(module);provenance.append({'input': str(path.relative_to(ROOT)), 'sha256': sha(path),
            'payload_sha256': hashlib.sha256(module).hexdigest(), 'payload_bytes': len(module)})
    hashes = sorted({bytes.fromhex(row['cdhash']) for row in verified});require(len(hashes) == 3, 'Duplicate owner code hash')
    identifier = uuid.uuid5(uuid.NAMESPACE_URL, 'UniXNU/dodge/iPhone10,3/20H392/' + ''.join(h.hex() for h in hashes))
    owner = struct.pack('<I16sI', 2, identifier.bytes, len(hashes)) + b''.join(h + bytes((2, 0, 0, 0)) for h in hashes)
    parts = [owner, *originals];cursor = 4 + 4 * len(parts);offsets = []
    for part in parts:offsets.append(cursor);cursor += len(part)
    trust = struct.pack('<I', len(parts)) + struct.pack('<3I', *offsets) + b''.join(parts)
    require(modules(trust)[1:] == originals, 'Original iPhone trust modules changed')
    trust_path = OUT / 'owner-trust.bundle';trust_path.write_bytes(trust)
    inputs = [Path(__file__), packer, target, ROOT / 'scripts/check_gpu_userspace.py', ROOT / 'sources/UniXNU/scripts/unixnu/ipsw.py']
    artifacts = [addon, trust_path, *(p for p, _ in binaries), bundle / 'Info.plist']
    report = {'result': 'NATIVE_A830_IPHONE_ADDON_AND_TRUST_INPUTS_PASS', 'addon': str(addon.relative_to(ROOT)),
        'trust_bundle': str(trust_path.relative_to(ROOT)), 'files': files, 'binaries': verified, 'original_modules': provenance,
        'owner_cdhashes': [h.hex() for h in hashes],
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in inputs},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'original_iphone_modules_unchanged': True, 'owner_trust_installed': False, 'hardware_tested': False,
        'scope': 'Official NGPUADD2 layout with the native plugin, Turnip and probe; full decompressed file readback. '
                 'One owner hash module precedes the exact two trust-cache payloads from iPhone 20H392. Runtime trust is untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(files)} addon files; three owner hashes and two unchanged iPhone trust modules')


if __name__ == '__main__':main()
