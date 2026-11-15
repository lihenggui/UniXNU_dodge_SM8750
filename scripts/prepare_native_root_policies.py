#!/usr/bin/env python3
"""Append authenticated owner policies to a separate root image, keeping boot within captured capacity."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, require, sha
from prepare_qemu_root_policy import REPORT as POLICY_REPORT, check_report as check_policy, file_sha
from prepare_root_image import make_manifest, digest_extent

OUT = ROOT / 'build/cph2653-native-root-policies'
REPORT = ROOT / 'reports/ios16-native-root-policies.json'
ROOT_REPORT = ROOT / 'reports/ios16-root-image.json'
CAPACITY = ROOT / 'hardware/dodge-boot-storage.json'


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_EXTERNAL_ROOT_POLICIES_PASS' and not report['image_contains_gpt'] and
        report['host_cases'] > 4100 and not report['hardware_tested'] and report['boot_partition_bytes'] == 96 << 20,
        'Incomplete external root policies')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'External root-policy input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--write-capacity-contract', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: external owner policies and preserved original root windows');return
    OUT.mkdir(parents=True, exist_ok=True)
    capture_path = ROOT / 'analysis/oneplus13-hardware-info.json';capture = json.loads(capture_path.read_text())
    require(capture['dtb_sha256'] == 'f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11', 'Wrong CPH2653 capture')
    boot = {row['name']: row['bytes'] for row in capture['partitions'] if row['name'] in ('boot_a', 'boot_b')}
    require(boot == {'boot_a': 96 << 20, 'boot_b': 96 << 20}, 'Captured boot capacity changed')
    capacity = {'schema_version': 1, 'device': 'OnePlus 13 CPH2653 / dodge', 'captured_dtb_sha256': capture['dtb_sha256'],
        'boot_partitions': boot, 'root_partition_label': 'unixnu',
        'root_partition_present_in_capture': any(row['name'] == 'unixnu' for row in capture['partitions']),
        'phone_operations': 'none', 'scope': 'Offline captured partition capacity only; no current device or GPT changes.'}
    if args.write_capacity_contract:
        require(not CAPACITY.exists(), 'Refuse to overwrite captured capacity contract')
        CAPACITY.write_text(json.dumps(capacity, indent=2) + '\n')
    require(json.loads(CAPACITY.read_text()) == capacity, 'Captured boot/root capacity contract changed')
    policy = json.loads(POLICY_REPORT.read_text());check_policy(policy)
    parent = json.loads(ROOT_REPORT.read_text());original = ROOT / parent['image']
    require(stat.S_ISREG(original.lstat().st_mode) and file_sha(original) == parent['image_sha256'], 'Original root layout changed')
    records, cursor = [], 4096
    require([row['name'] for row in policy['images']] == ['OS', 'SystemOS'], 'Wrong signed policy order')
    for image in policy['images']:
        path = ROOT / image['manifest'];size = path.stat().st_size
        records.append({'name': image['name'], 'offset': cursor, 'bytes': size, 'image_bytes': image['image_bytes'],
            'manifest': image['manifest'], 'manifest_sha256': file_sha(path)})
        cursor = (cursor + size + 4095) & -4096
    require(8192 <= cursor <= 96 << 20, 'Root policy container exceeds bound')
    header = bytearray(4096);header[:8] = b'DGROOTP1';struct.pack_into('<IIQ', header, 8, 1, 2, cursor)
    for index, row in enumerate(records):struct.pack_into('<4Q', header, 24 + index * 32, row['offset'], row['bytes'], row['image_bytes'], 0)
    container = OUT / 'root-policies.bin'
    with container.open('wb') as stream:
        stream.truncate(cursor);stream.write(header)
        for row in records:stream.seek(row['offset']);stream.write((ROOT / row['manifest']).read_bytes())
    with container.open('rb') as stream:
        require(stream.read(4096) == header, 'Policy header readback differs')
        for row in records:require(digest_extent(stream, row['offset'], row['bytes']) == row['manifest_sha256'], 'Policy envelope readback differs')
    end = max(row['offset'] + row['bytes'] for row in parent['windows']);offset = (end + 0xfffff) & -0x100000
    total = offset + cursor;manifest = make_manifest(parent['windows'], total)
    image = OUT / 'iphone-root.img';saved = OUT / 'manifest.json'
    if image.exists() or image.is_symlink():
        require(stat.S_ISREG(image.lstat().st_mode) and saved.is_file() and
            file_sha(image) == json.loads(saved.read_text())['image_sha256'], 'Refuse an unrelated existing extended root image')
    else:
        pending = OUT / 'root-with-policies.partial'
        require(not pending.exists(), 'Refuse an existing root work file')
        try:
            shutil.copyfile(original, pending)
            with pending.open('r+b') as stream:
                stream.truncate(total);stream.seek(0);stream.write(manifest);stream.seek(offset)
                with container.open('rb') as source:shutil.copyfileobj(source, stream, 8 << 20)
            os.link(pending, image)
        finally:
            if pending.exists():pending.unlink()
    require(image.stat().st_size == total, 'Extended root size changed')
    with image.open('rb') as stream:
        require(stream.read(4096) == manifest, 'Extended root manifest differs')
        for row in parent['windows']:require(digest_extent(stream, row['offset'], row['bytes']) == row['sha256'], 'Original root window changed')
        require(digest_extent(stream, offset, cursor) == file_sha(container), 'Appended policies differ')
    image_digest = file_sha(image);saved.write_text(json.dumps({'image_sha256': image_digest, 'bytes': total,
        'policy_offset': offset, 'policy_bytes': cursor}, indent=2) + '\n')
    compiler = shutil.which('clang++-14') or shutil.which('clang++') or shutil.which('g++')
    require(compiler, 'Need a C++17 compiler with sanitizers')
    binary = OUT / 'root-policy-format-host';test = ROOT / 'tests/DodgeRootPolicyFormatTest.cpp'
    run([compiler, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', ROOT / 'drivers/DodgeStorage', test, '-o', binary], OUT / 'host-compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'External policy bounds checks failed')
    require(file_sha(original) == parent['image_sha256'], 'Preparation changed the original root image')
    files = [Path(__file__), CAPACITY, capture_path, ROOT / 'drivers/DodgeStorage/DodgeRootPolicyFormat.h', test]
    artifacts = [container, image, saved, binary, log]
    report = {'result': 'IOS16_NATIVE_EXTERNAL_ROOT_POLICIES_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (POLICY_REPORT, ROOT_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'image': str(image.relative_to(ROOT)), 'image_bytes': total, 'image_sha256': image_digest, 'windows': parent['windows'],
        'container': str(container.relative_to(ROOT)), 'container_sha256': file_sha(container), 'container_bytes': cursor,
        'container_offset': offset, 'policies': records, 'boot_partition_bytes': min(boot.values()),
        'root_partition_present_in_capture': capacity['root_partition_present_in_capture'],
        'host_cases': int(result.stdout.split()[1]), 'image_contains_gpt': False, 'original_volume_bytes_changed': False,
        'hardware_tested': False, 'physical_storage_written': False, 'phone_operations': 'none',
        'scope': 'Separate regular-file SHNGROOT image with unchanged original iPhone OS/SystemOS windows and appended owner policies. '
        'The kernel pins the entire policy-container digest; existing owner RSA signatures and every-block verification remain required. '
        'Moving hash tables out of the boot kernel permits a smaller FAT within the captured 96 MiB boot slots. '
        'The captured partition table has no unixnu root partition; preparation creates or changes no physical partition.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: external signed policies, unchanged original volumes and', report['host_cases'], 'policy bounds cases')


if __name__ == '__main__':main()
