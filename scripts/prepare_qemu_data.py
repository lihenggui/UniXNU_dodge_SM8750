#!/usr/bin/env python3
"""Prepare a separate volatile APFS Data fixture for the owner VM."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tarfile
import tempfile
import uuid

from native_driver_build import ROOT, require, sha
from prepare_initial_data import validate_inventory, verify_archive
from prepare_data_image import readback, load_packer

OUT = ROOT / 'build/ios16-qemu-data'
REPORT = ROOT / 'reports/ios16-qemu-data-image.json'
BASE = ROOT / 'reports/ios16-data-volatile-image.json'
INITIAL = ROOT / 'reports/ios16-initial-data.json'


def file_sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_VOLATILE_DATA_IMAGE_PASS' and report['original_entries_preserved'] == 198 and
        report['counts']['entries'] == 200 and report['keybag_key_bytes'] == 0 and
        report['reproducible'] and not report['hardware_tested'] and not report['persistent'] and
        not report['data_protection_keys_created'], 'Wrong volatile QEMU Data fixture')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / path) == digest, 'QEMU Data input changed: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: separate volatile QEMU Data image');return
    base = json.loads(BASE.read_text());initial = json.loads(INITIAL.read_text())
    require(base['result'] == 'IOS16_LOCAL_APFS_DATA_IMAGE_PASS' and base['counts']['entries'] == 198 and
        base['archive_report_sha256'] == sha(INITIAL), 'Original Data preparation changed')
    for name, digest in {**base['source_sha256'], **base['tool_dependencies_sha256']}.items():
        require(file_sha(ROOT / name) == digest, 'Data tool input changed: ' + name)
    tools = {'writer': ROOT / 'build/ios16-data-apfs-volatile/apfs-data-build',
        'reader': ROOT / 'build/ios16-data-apfs-volatile/apfs-data-verify',
        'checker': ROOT / 'build/ios16-data-apfs-volatile/apfsprogs-apple-signature/apfsck/apfsck'}
    for tool in tools.values():require(file_sha(tool) == base['artifacts'][str(tool.relative_to(ROOT))], 'Data tool changed')
    archive = ROOT / initial['archive'];metadata = ROOT / initial['metadata']
    require(file_sha(archive) == base['source_archive_sha256'] and sha(metadata) == initial['artifacts'][str(metadata.relative_to(ROOT))],
        'Original Data archive or inventory changed')
    contents = json.loads(metadata.read_text());entries = copy.deepcopy(contents['entries'])
    require(not any(entry['path'].startswith('keybags') for entry in entries), 'Original Data already has keybags')
    OUT.mkdir(parents=True, exist_ok=True)
    profile = json.loads((ROOT / base['profile']).read_text())
    for name in ('container_uuid', 'volume_uuid'):
        profile[name] = str(uuid.uuid5(uuid.NAMESPACE_URL, 'UniXNU.Dodge.QemuData.v1/' + name)).upper()
    with tempfile.TemporaryDirectory(prefix='candidate-', dir=OUT) as temporary:
        work = Path(temporary);blobs = work / 'source-blobs';blobs.mkdir()
        with archive.open('rb') as stream:verify_archive(stream, contents['entries'], metadata.read_bytes())
        with tarfile.open(archive, 'r:') as source:
            for entry in entries:
                if entry['type'] == 'file':
                    data = source.extractfile('Data/' + entry['path']).read();destination = blobs / entry['blob']
                    require(not destination.exists() or destination.read_bytes() == data, 'Original hard-link bytes differ')
                    destination.write_bytes(data)
        timestamp = profile['fixed_time_ns'];inode = max(entry['inode'] for entry in entries) + 1
        common = {'uid': 0, 'gid': 0, 'bsd_flags': 0, 'protection_class': 0, 'xattrs_hex': {},
            **{key: timestamp for key in ('create_time_ns', 'mod_time_ns', 'access_time_ns', 'change_time_ns')}}
        entries.append({**common, 'path': 'keybags', 'inode': inode, 'type': 'directory', 'mode': 0o40700})
        # This explicitly represents an empty, unprotected development state.
        # No Apple bag, passcode, backup key or device secret is generated.
        document = plistlib.dumps({'KeyBagKeys': b''}, fmt=plistlib.FMT_XML, sort_keys=True)
        blob_name = 'inode-' + str(inode + 1);(blobs / blob_name).write_bytes(document)
        entries.append({**common, 'path': 'keybags/systembag.kb', 'inode': inode + 1, 'type': 'file', 'mode': 0o100600,
            'blob': blob_name, 'bytes': len(document), 'decompressed': False, 'sha256': hashlib.sha256(document).hexdigest()})
        counts = validate_inventory(entries, blobs)
        manifest = {**{key: profile[key] for key in ('schema_version', 'product', 'build', 'container_uuid', 'volume_uuid',
            'size_bytes', 'fixed_time_ns')}, 'entries': entries}
        specification = work / 'manifest.json';specification.write_text(json.dumps(manifest, indent=2) + '\n')
        image = work / 'data.apfs';subprocess.run([tools['writer'], specification, blobs, image], check=True)
        checked = subprocess.run([tools['checker'], '-cuw', image], capture_output=True, text=True)
        require(not checked.returncode and not checked.stdout and not checked.stderr, 'QEMU Data APFS integrity check failed')
        volume, observed = readback(tools, image, work / 'readback', entries, profile)
        require(observed == counts, 'QEMU Data inventory differs')
        replica = work / 'replica.apfs';subprocess.run([tools['writer'], specification, blobs, replica], check=True)
        digest = file_sha(image);require(file_sha(replica) == digest, 'QEMU Data image is not reproducible')
        packer, packer_path = load_packer();packed = work / 'data.dbr';packed_info = packer.pack(image, packed)
        logical, extents = packer.regions(packed.read_bytes());require(logical == profile['size_bytes'], 'Wrong packed Data size')
        reconstructed = work / 'reconstructed.apfs'
        with reconstructed.open('xb') as stream:
            stream.truncate(logical)
            for offset, data in extents:stream.seek(offset);stream.write(data)
        require(file_sha(reconstructed) == digest, 'Packed QEMU Data differs')
        for source, destination in ((image, OUT / 'data.apfs'), (packed, OUT / 'data.dbr'),
            (specification, OUT / 'manifest.json'), (work / 'readback/inventory.jsonl', OUT / 'readback.jsonl')):
            shutil.copyfile(source, destination)
    files = [Path(__file__), ROOT / 'scripts/prepare_initial_data.py', ROOT / 'scripts/prepare_data_image.py', packer_path, *tools.values()]
    report = {'result': 'IOS16_QEMU_VOLATILE_DATA_IMAGE_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in files},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (BASE, INITIAL)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in
            (OUT / 'data.apfs', OUT / 'data.dbr', OUT / 'manifest.json', OUT / 'readback.jsonl')},
        'image': str((OUT / 'data.apfs').relative_to(ROOT)), 'packed_image': str((OUT / 'data.dbr').relative_to(ROOT)),
        'image_sha256': digest, 'image_bytes': logical, 'packed_metadata': packed_info, 'volume': volume, 'profile': profile,
        'counts': counts, 'original_entries_preserved': 198, 'keybag_key_bytes': 0, 'reproducible': True,
        'persistent': False, 'data_protection_keys_created': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Separate owner-VM Data seed with the original installation entries plus a root-owned empty KeyBagKeys plist. '
                 'The file describes unprotected development state; it contains no Apple keybag or secret. '
                 'The original seeds and physical storage are unchanged. Runtime acceptance is checked separately.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: reproducible volatile QEMU Data, 198 preserved entries and empty development keybag state')


if __name__ == '__main__':main()
