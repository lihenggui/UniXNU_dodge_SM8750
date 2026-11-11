#!/usr/bin/env python3
"""Read back the built dodge boot image and publish its local build manifest."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Directory for this firmware variant')
    parser.add_argument('--report', type=Path, default=ROOT / 'reports/uefi-build.json')
    args = parser.parse_args()
    source = ROOT / 'uefi/Mu-Silicium'
    record = json.loads((ROOT / 'analysis/uefi-build-result.json').read_text())
    if record['returncode'] or not record['parallel_jobs_confirmed']:
        raise SystemExit('Need a successful build with the confirmed four-job limit')
    fv = source / 'Build/dodgePkg/DEBUG_CLANGPDB/FV'
    firmware = (fv / 'SILICIUM_UEFI.fd').read_bytes()
    image = (source / 'Mu-dodge.img').read_bytes()
    if len(firmware) != 0x300000 or image[:8] != b'ANDROID!':
        raise SystemExit('Unexpected firmware size or Android header')
    kernel_size, ramdisk_size = struct.unpack_from('<II', image, 8)
    header_size = struct.unpack_from('<I', image, 20)[0]
    header_version = struct.unpack_from('<I', image, 40)[0]
    if (header_version, header_size) != (4, 1584):
        raise SystemExit('Expected the pinned Android boot header v4')
    signature_size = struct.unpack_from('<I', image, 1580)[0]
    align = lambda size: (size + 4095) & ~4095
    expected = 4096 + align(kernel_size) + align(ramdisk_size) + align(signature_size)
    if len(image) != expected:
        raise SystemExit('The boot image length does not match its header')
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = decoder.decompress(image[4096:4096 + kernel_size]) + decoder.flush()
    if not decoder.eof:
        raise SystemExit('Incomplete gzip stream in boot image')
    shim = (source / 'BootShim/BootShim.bin').read_bytes()
    dtb = (source / 'Resources/DTBs/dodge.dtb').read_bytes()
    if raw != shim + firmware or decoder.unused_data != dtb:
        raise SystemExit('Packed shim, FD or firmware DTB differs from the build inputs')
    ramdisk_at = 4096 + align(kernel_size)
    if image[ramdisk_at:ramdisk_at + ramdisk_size] != (source / 'Resources/ramdisk').read_bytes():
        raise SystemExit('Packed ramdisk differs from its input')
    modules = []
    boot_abi = None
    simplefb = None
    firmware_log = None
    if record['menu_integrated']:
        uncompressed = (fv / 'FVMAIN.Fv').read_bytes()
        required = {
                    'UniXNUDxe': '29B950CF-586D-49EA-9D71-F88645CCDAF6',
                    'UniXNURamDiskDxe': '75CA63AD-FBAE-4A06-92A0-F937C671251D'}
        lock = json.loads((ROOT / 'upstream.lock.json').read_text())
        simplefb_pin = lock['simplefb_patch']
        simplefb_source = source / simplefb_pin['target']
        simplefb_test = ROOT / 'reports/simplefb-tests.json'
        simplefb_result = json.loads(simplefb_test.read_text())
        if (digest(simplefb_source.read_bytes()) != simplefb_pin['after_sha256'] or
                simplefb_result['result'] != 'PRODUCTION_SIMPLEFB_HOST_TEST_PASS' or
                simplefb_result['driver_sha256'] != simplefb_pin['after_sha256']):
            raise SystemExit('Need current successful production SimpleFb error/bounds tests')
        required['SimpleFbDxe'] = 'DCFD1E6D-788D-4FFC-8E1B-CA2F75651A92'
        simplefb = {'patch': simplefb_pin, 'host_report': str(simplefb_test.relative_to(ROOT)),
                    'host_report_sha256': digest(simplefb_test.read_bytes()),
                    'runtime_geometry_qualified': False}
        # Read the pinned application GUID rather than assuming its value.
        inf = ROOT / 'sources/UniXNU/package/UniXNUPkg/Application/UniXNU/UniXNU.inf'
        required['UniXNU'] = re.search(r'FILE_GUID\s*=\s*([0-9A-Fa-f-]+)', inf.read_text())[1]
        if record.get('firmware_log_integrated'):
            inf = ROOT / 'sources/UniXNU/package/UniXNUPkg/Driver/AdvancedLogDxe/AdvancedLogDxe.inf'
            required['AdvancedLogDxe'] = re.search(r'FILE_GUID\s*=\s*([0-9A-Fa-f-]+)', inf.read_text())[1]
            producer = source / 'Build/dodgePkg/DEBUG_CLANGPDB/AARCH64/MdeModulePkg/Core/Dxe/DxeMain'
            libraries = (producer / 'OUTPUT/static_library_files.lst').read_text()
            generated = (producer / 'DEBUG/AutoGen.c').read_text()
            if ('/AdvancedLoggerLib/DxeCore/AdvancedLoggerLib/' not in libraries or
                    'Status = DxeCoreAdvancedLoggerLibConstructor (ImageHandle, SystemTable);' not in generated or
                    not re.search(r'#define _PCD_VALUE_PcdAdvancedLoggerPages\s+512U', generated)):
                raise SystemExit('DXE Core is missing the configured 2 MiB Advanced Logger producer')
            firmware_log = {'producer': 'DXE Core', 'buffer_bytes': 512 * 4096,
                            'exporter': 'AdvancedLogDxe', 'format': 'OneSend QR',
                            'sec_log_captured': False, 'hardware_capture_tested': False}
        if record.get('darwinboot_integrated'):
            inf = ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.inf'
            required['DarwinBoot'] = re.search(r'FILE_GUID\s*=\s*([0-9A-Fa-f-]+)', inf.read_text())[1]
            makefile = source / 'Build/dodgePkg/DEBUG_CLANGPDB/AARCH64/DarwinBootPkg/Driver/DarwinBoot/GNUmakefile'
            if '-DDARWIN_BOOT_COMMAND_LINE_LENGTH=608' not in makefile.read_text():
                raise SystemExit('DarwinBoot was not built with the selected Darwin 22 boot_args ABI')
            boot_abi = json.loads((ROOT / 'reports/boot-args-abi.json').read_text())
            if boot_abi.get('result') != 'PASS' or boot_abi.get('command_line_bytes') != 608:
                raise SystemExit('Missing successful boot_args comparison against the selected Apple source')
            header = inf.parent / 'BootArgs.h'
            if boot_abi['loader_header_sha256'] != digest(header.read_bytes()):
                raise SystemExit('Loader header changed after the recorded boot_args ABI check')
        for name, guid in required.items():
            if uuid.UUID(guid).bytes_le not in uncompressed:
                raise SystemExit(f'{name} is missing from the generated firmware volume')
            binary = (source / f'Build/dodgePkg/DEBUG_CLANGPDB/AARCH64/{name}.efi').read_bytes()
            pe = struct.unpack_from('<I', binary, 0x3c)[0]
            if binary[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', binary, pe + 4)[0] != 0xaa64:
                raise SystemExit(f'{name} is not an AArch64 PE image')
            if name == 'SimpleFbDxe' and binary not in uncompressed:
                raise SystemExit('Built SimpleFb executable differs from the embedded firmware input')
            modules.append({'name': name, 'file_guid': guid, 'bytes': len(binary), 'sha256': digest(binary)})
    output = args.output or (ROOT / 'build/cph2653-uefi-menu' if modules else ROOT / 'build/cph2653-uefi-baseline')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for path in [fv / 'SILICIUM_UEFI.fd', source / 'Mu-dodge.img']:
        destination = output / path.name
        shutil.copy2(path, destination)
        artifacts.append({'path': str(destination.relative_to(ROOT)), 'bytes': destination.stat().st_size,
                          'sha256': digest(destination.read_bytes())})
    log = Path(record['log']).read_text(errors='replace')
    verified = re.search(r'(\d+) Images Verified', log)
    record.update(artifacts=artifacts, embedded_modules=modules,
                  efi_images_verified=int(verified[1]) if verified else None,
                  boot_header={'version': header_version, 'kernel_bytes': kernel_size,
                               'ramdisk_bytes': ramdisk_size, 'signature_bytes': signature_size},
                  firmware_dtb_sha256=digest(dtb),
                  darwinboot_abi=boot_abi,
                  simplefb_error_bounds=simplefb,
                  firmware_log=firmware_log,
                  container_readback='PASS: header, sizes, gzip, shim, FD, DTB and ramdisk match',
                  kernel_included=False, hardware_boot='not-tested',
                  variable_writes='UniXNUDxe registers nonvolatile Boot#### and BootOrder variables; platform storage-write review pending.',
                  scope='Host compilation and binary readback only. Donor DXEs differ from the captured phone firmware. Not an iOS boot result.')
    record['log'] = str(Path(record['log']).relative_to(ROOT))
    record['command'] = [part.replace(str(ROOT) + '/', '') for part in record['command']]
    record['planned_commands'] = [[part.replace(str(ROOT) + '/', '') for part in cmd]
                                  for cmd in record['planned_commands']]
    text = json.dumps(record, indent=2) + '\n'
    args.report.write_text(text)
    (output / 'manifest.json').write_text(text)
    print(json.dumps({'result': 'PASS', 'artifacts': artifacts,
                      'embedded_modules': [m['name'] for m in modules],
                      'efi_images_verified': record['efi_images_verified']}, indent=2))


if __name__ == '__main__':
    main()
