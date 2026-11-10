#!/usr/bin/env python3
"""Assemble and read back a local native-kernel development payload; no phone I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from prepare_device_tree import parse_adt

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-kernel', action='store_true', help='Compile the source-only kernel before assembling')
    args = parser.parse_args()
    if args.build_kernel:
        subprocess.run([str(ROOT / 'unixnu'), 'kernel', '--skip-prelink'], check=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/validate_kernel_artifacts.py')], check=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/prepare_device_tree.py')], check=True)
    kernel = json.loads((ROOT / 'reports/native-kernel.json').read_text())
    firmware = json.loads((ROOT / 'reports/uefi-build.json').read_text())
    fd = ROOT / 'build/cph2653-uefi-menu/SILICIUM_UEFI.fd'
    if firmware['returncode'] or not firmware['darwinboot_integrated']:
        raise SystemExit('Build and validate the firmware with DarwinBoot first')
    if digest(fd) != next(a['sha256'] for a in firmware['artifacts'] if a['path'].endswith('.fd')):
        raise SystemExit('Firmware changed after its validation')
    native = ROOT / kernel['native']
    if digest(native) != kernel['sha256']:
        raise SystemExit('Native kernel changed after its validation')
    private = json.loads((ROOT / '.cache/platform.json').read_text())
    env = dict(os.environ, UNIXNU_UNIQUE_CHIP_ID=private['unique_chip_id'])
    log = ROOT / 'analysis/native-payload-build.log'
    output = ROOT / 'build/cph2653-native-bringup/boot.img'
    with log.open('w') as stream:
        for command in (
            [str(ROOT / 'unixnu'), 'payload', '--kernel', str(native)],
            [str(ROOT / 'unixnu'), 'bootimg', '--uefi', str(ROOT / 'uefi/Mu-Silicium'),
             '--fd', str(fd), '--dtb', str(ROOT / 'uefi/Mu-Silicium/Resources/DTBs/dodge.dtb'),
             '--output', str(output)],
        ):
            subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
    image = WORK / 'payload/payload.img'
    payload = json.loads((WORK / 'payload/payload.json').read_text())
    boot = json.loads(output.with_name('boot.json').read_text())
    with tempfile.TemporaryDirectory(prefix='payload-readback-') as temporary:
        directory = Path(temporary)
        for name in ('unixnu.toml', 'Payloads/kernel.macho', 'Payloads/kernel.macho.adt'):
            destination = directory / Path(name).name
            subprocess.run(['mcopy', '-i', str(image), '::/EFI/UniXNU/' + name, str(destination)],
                           capture_output=True, text=True, check=True)
        if digest(directory / 'kernel.macho') != kernel['sha256']:
            raise SystemExit('FAT volume contains another kernel')
        config = tomllib.loads((directory / 'unixnu.toml').read_text())
        entry, = [e for e in config['entry'] if e['id'] == 'xnu']
        if entry['args'] != payload['kernel_args'] or len(entry['args'].encode()) >= 608:
            raise SystemExit('Payload command line differs from the Darwin 22 loader contract')
        adt_path = directory / 'kernel.macho.adt'
        if digest(adt_path) != payload['adt_sha256']:
            raise SystemExit('FAT ADT differs from the payload report')
        nodes = parse_adt(adt_path.read_bytes())
        checks = [('/', 'model', b'iPhone10,3\0'), ('/product', 'artwork-device-idiom', b'phone\0'),
                  ('/chosen', 'chip-id', struct.pack('<I', 0x8015)),
                  ('/chosen', 'darwinboot-memory-size', struct.pack('<Q', 4 << 30)),
                  ('/buttons', 'home-button-type', struct.pack('<I', 2))]
        if any(nodes[path].get(key) != value for path, key, value in checks):
            raise SystemExit('FAT ADT lost the selected iPhone/board properties')
    if digest(image) != payload['payload_sha256'] or digest(output) != boot['image_sha256']:
        raise SystemExit('Packaged artifacts differ from their reports')
    report = {'result': 'PASS', 'mode': 'native-source-bringup', 'product_identity': 'iPhone10,3',
              'native_kernel_sha256': kernel['sha256'], 'firmware_sha256': digest(fd),
              'payload': str(image.relative_to(ROOT)), 'payload_sha256': digest(image),
              'boot_image': str(output.relative_to(ROOT)), 'boot_image_bytes': output.stat().st_size,
              'boot_image_sha256': digest(output), 'adt_sha256': payload['adt_sha256'],
              'boot_header_version': boot['header_version'], 'command_line_bytes': len(payload['kernel_args']),
              'fat_readback': 'kernel, ADT and config match', 'android_container_readback': 'shim, FD, firmware DTB and FAT match',
              'private_seed_disclosed': False, 'original_kexts_added': False, 'original_userspace_included': False,
              'phone_operations': 'none', 'hardware_tested': False,
              'scope': 'Local native development artifact only. Original iPhone components, authenticated root, storage, display and input qualification remain pending.'}
    text = json.dumps(report, indent=2) + '\n'
    (ROOT / 'reports/native-payload.json').write_text(text)
    output.with_name('manifest.json').write_text(text)
    print('PASS: native kernel + iPhone ADT + UEFI + FAT/Android v4 readback; no phone operations')


if __name__ == '__main__':
    main()
