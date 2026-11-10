#!/usr/bin/env python3
"""Extract and build hash-pinned CPH2653 GPU microcode from a local stock vendor image."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, inspect_object, pinned_sources, require, sha, symbols


def validate_image(name, data, pins):
    spec = pins['firmware']['files'][name]
    require(len(data) == spec['bytes'] and hashlib.sha256(data).hexdigest() == spec['sha256'],
            'Target GPU firmware size/hash mismatch: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-image', type=Path, default=ROOT / '.cache/stock-cph2653-16.0.1.304/vendor.img')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    spec = lock['oneplus13_gpu_firmware']
    pins_path = ROOT / spec['path']
    require(sha(pins_path) == spec['sha256'], 'Target firmware pins changed after review')
    pins = json.loads(pins_path.read_text())
    require(args.vendor_image.stat().st_size == pins['vendor']['bytes'] and sha(args.vendor_image) == pins['vendor']['sha256'],
            'The vendor image is not the pinned CPH2653 full-OTA partition')
    vendor_boot = args.vendor_image.parent / 'vendor_boot.img'
    require(vendor_boot.stat().st_size == pins['vendor_boot']['bytes'] and sha(vendor_boot) == pins['vendor_boot']['sha256'],
            'The matching OTA vendor_boot is absent or differs from the pinned captured version')
    capture_manifest = ROOT / 'backups/CPH2653-20261102T030230Z/manifest.json'
    capture_match = None
    if capture_manifest.exists():
        captured = json.loads(capture_manifest.read_text())
        captured_boot, = [row for row in captured['partitions'] if row['name'] == 'vendor_boot_a']
        capture_match = (captured_boot['sha256'] == pins['vendor_boot']['sha256'] and
                         captured_boot['bytes'] == pins['vendor_boot']['bytes'])
        require(capture_match, 'Stock OTA does not match the retained capture manifest')
    sources = pinned_sources(('oneplus13t_reference',))
    original = sources['oneplus13t_reference'] / 'scripts/prepare-gpu-firmware.py'
    module_spec = importlib.util.spec_from_file_location('original_firmware_parser', original)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    dump = ROOT / '.toolchains/gpu-host/bin/dump.erofs'
    require(dump.is_file(), 'Build the pinned offline EROFS reader first')
    out = ROOT / 'build/cph2653-gpu-firmware'
    images, negatives = [], []
    for symbol, name in module.FILES:
        result = subprocess.run([dump, '--path=/firmware/' + name, '--cat', args.vendor_image],
                                capture_output=True, check=True, timeout=30)
        data = result.stdout
        validate_image(name, data, pins)
        # Reuse the exact-byte corruption control for every target file. A
        # similarly named donor or the newer public dump must be refused.
        changed = bytearray(data)
        changed[len(changed) // 2] ^= 1
        try:
            validate_image(name, changed, pins)
        except ValueError:
            negatives.append(name)
        else:
            raise ValueError('Firmware corruption was accepted: ' + name)
        images.append((symbol, name, data))
    metadata, payload = module.zap_parts(images[-1][2])
    require((len(metadata), len(payload)) == (pins['zap_metadata_bytes'], pins['zap_payload_bytes']) == (0xfcc, 0x1000),
            'Target ZAP layout does not match the real SM8750 loader')
    images += [('zap_metadata', 'zap-metadata.bin', metadata), ('zap_payload', 'zap-payload.bin', payload)]
    out.mkdir(parents=True, exist_ok=True)
    assembly = ['.section __DATA_CONST,__const']
    header = ['/* Generated from hash-pinned CPH2653 stock files. */', '#pragma once', '#include <stdint.h>',
              '#ifdef __cplusplus', 'extern "C" {', '#endif']
    for symbol, name, data in images:
        file = out / name
        file.write_bytes(data)
        label = 'sm8750_gpu_' + symbol
        assembly += ['.p2align 12', '.globl _' + label, '_' + label + ':',
                     '.incbin ' + json.dumps(str(file)), '_' + label + '_end:',
                     '.p2align 3', '.globl _' + label + '_size', '_' + label + '_size:',
                     '.quad _' + label + '_end-_' + label]
        header += ['extern const uint8_t ' + label + '[];', 'extern const uint64_t ' + label + '_size;']
    header += ['#ifdef __cplusplus', '}', '#endif']
    source = out / 'firmware.S'
    source.write_text('\n'.join(assembly) + '\n')
    (out / 'Sm8750GpuFirmware.h').write_text('\n'.join(header) + '\n')
    obj = out / 'firmware.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0',
                    '-c', source, '-o', obj], check=True)
    data = obj.read_bytes()
    image = inspect_object(data)
    section, = [s for segment in image['segments'] for s in segment['sections'] if s['name'] == '__const']
    names = {s['name']: s for s in symbols(data)}
    # __const is the only emitted section, with zero object VM base. Read back
    # every file and its real 64-bit size variable from the actual Mach-O.
    for symbol, _, expected in images:
        label = '_sm8750_gpu_' + symbol
        at = section['fileoff'] + names[label]['value']
        size_at = section['fileoff'] + names[label + '_size']['value']
        require(data[at:at + len(expected)] == expected and struct.unpack_from('<Q', data, size_at)[0] == len(expected),
                'Firmware object readback differs: ' + symbol)
    archive = out / 'libSm8750GpuFirmware.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, obj], check=True)
    report = {'result': 'CPH2653_GPU_FIRMWARE_STATIC_BUILD_PASS', 'device_version': pins['captured_version'],
              'ota_id': pins['ota_id'], 'pin_sha256': sha(pins_path), 'vendor_sha256': pins['vendor']['sha256'],
              'captured_vendor_boot_manifest_match': capture_match, 'downloaded_vendor_boot_sha256': sha(vendor_boot),
              'files': pins['firmware']['files'],
              'zap_parser_revision': lock['oneplus13t_reference']['revision'], 'zap_parser_sha256': sha(original),
              'zap_metadata_bytes': len(metadata), 'zap_payload_bytes': len(payload),
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
              'object_readback': 'PASS', 'corrupted_input_negative_controls': negatives,
              'installed_or_executed': False, 'hardware_tested': False,
              'scope': 'Exact stock GPU files parsed and assembled for iOS 16; loading/authentication on the device is untested.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/gpu-firmware.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: four exact CPH2653 microcodes, ZAP extents, corruption controls and native object readback')


if __name__ == '__main__':
    main()
