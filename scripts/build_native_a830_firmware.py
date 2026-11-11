#!/usr/bin/env python3
"""Build the native GPU development firmware with fresh entropy and DXE log export."""
import argparse
import json
from pathlib import Path

from build_entropy_payload import build_firmware
from build_boot_entropy import reviewed, MU
from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/cph2653-native-a830-firmware'
REPORT = ROOT / 'reports/native-a830-firmware.json'


def check_report(report):
    require(report['result'] == 'CPH2653_ENTROPY_AND_LOGGER_FIRMWARE_PASS' and report['source_efi_count'] == 54 and
            report['logger_exporter_embedded'] and not report['hardware_tested'], 'Incomplete native firmware report')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native firmware source changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native firmware, fresh-entropy loader and DXE exporter');return
    pin, _ = reviewed()
    fd, efi, mapping, readback, artifacts, budget = build_firmware(OUT, expected_images=54)
    # Match the source INF's own GUID rather than a device-specific image name.
    inf = ROOT / 'sources/UniXNU/package/UniXNUPkg/Driver/AdvancedLogDxe/AdvancedLogDxe.inf'
    guid = next(line.split('=', 1)[1].strip().lower() for line in inf.read_text().splitlines() if 'FILE_GUID' in line)
    exporter = [row for row in readback['modules'] if row['guid'] == guid]
    require(len(exporter) == 1 and len(exporter[0]['images']) == 1, 'Native firmware lacks the actual QR log exporter')
    config = MU / 'Platforms/OnePlus/dodgePkg/dodge.dsc'
    require('PcdAdvancedLoggerPages|512' in config.read_text() and 'AdvancedLoggerLib/DxeCore' in config.read_text(),
            'Native firmware lacks the 2 MiB DXE producer configuration')
    files = [Path(__file__), ROOT / 'scripts/build_entropy_payload.py', ROOT / 'scripts/build_boot_entropy.py',
        ROOT / pin['path'], ROOT / pin['header'], inf, config, MU / 'Platforms/OnePlus/dodgePkg/dodge.fdf',
        MU / 'Platforms/OnePlus/dodgePkg/Include/DXE.inc',
        MU / 'Platforms/OnePlus/dodgePkg/Library/MemoryMapLib/MemoryMapLib.c']
    report = {'result': 'CPH2653_ENTROPY_AND_LOGGER_FIRMWARE_PASS',
        'firmware': str(fd.relative_to(ROOT)), 'firmware_sha256': sha(fd),
        'efi': str(efi.relative_to(ROOT)), 'efi_sha256': sha(efi), 'mapping': str(mapping.relative_to(ROOT)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'source_efi_count': readback['source_efi_count'], 'firmware_readback': readback,
        'logger_exporter_embedded': True, 'logger_guid': guid, 'DXE_log_bytes': 2 << 20,
        'fresh_entropy_loader_embedded': True, 'resource_settings': budget, 'jobs': 4,
        'hardware_tested': False, 'scope': 'Separate full-board firmware with the existing memory layout, '
        'a fresh-seed DarwinBoot and the Advanced Logger QR exporter. Embedded loader and exporter identities are read back.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 54 EFI images; exact entropy loader and DXE log exporter in the 3 MiB FD')


if __name__ == '__main__':main()
