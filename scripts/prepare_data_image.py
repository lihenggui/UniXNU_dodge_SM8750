#!/usr/bin/env python3
"""Build/read back a local iPhone APFS Data seed on Linux, without mounting it."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
import uuid

from native_driver_build import ROOT, pinned_sources, require
from prepare_initial_data import sha, validate_inventory, verify_archive

OUT = ROOT / 'build/ios16-data-apfs'
REPORT = ROOT / 'reports/ios16-data-image.json'
PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392/data-image.json'
REFERENCES = ('apfs_writer_reference', 'apfs_checker_reference', 'apfs_readonly_reference', 'fajita_data_reference')


def relative(path):
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'Need a local regular file: ' + str(path))


def profile_and_inputs():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pin = 'iphone_volatile_data_image' if PROFILE.name == 'data-volatile-image.json' else 'iphone_data_image'
    require(sha(PROFILE) == lock[pin]['sha256'], 'Data installation profile changed')
    profile = json.loads(PROFILE.read_text())
    require((profile['schema_version'], profile['product'], profile['build'], profile['volume_name'],
             profile['case_sensitive'], profile['role'], profile['encrypted']) ==
            (1, 'iPhone10,3', '20H392', 'Data', True, 0, False), 'Unexpected Data profile')
    require(512 << 20 <= profile['size_bytes'] <= 16 << 30 and profile['size_bytes'] % 4096 == 0,
            'Data capacity exceeds the bounded local build')
    for key in ('container_uuid', 'volume_uuid'):
        require(str(uuid.UUID(profile[key])).upper() == profile[key] and uuid.UUID(profile[key]).int, 'Invalid Data UUID')
    data_path = ROOT / 'reports/ios16-initial-data.json'
    data = json.loads(data_path.read_text())
    require(data['builder_sha256'] == sha(ROOT / 'scripts/prepare_initial_data.py') and
            data['all_archive_files_and_metadata_read_back'] and not data['settings_or_activation_state_changed'],
            'Original Data archive stage is stale')
    for path, digest in {**data['artifacts'], **data['tool_dependencies_sha256'], **data['source_sha256']}.items():
        regular(ROOT / path)
        require(sha(ROOT / path) == digest, 'Original Data input changed: ' + path)
    archive, metadata = ROOT / data['archive'], ROOT / data['metadata']
    require((sha(archive), sha(metadata)) == (profile['source_archive_sha256'], profile['source_metadata_sha256']),
            'Data profile does not match the exact original content archive')
    contents = json.loads(metadata.read_text())
    require((contents['product'], contents['build'], contents['excluded_paths']) ==
            ('iPhone10,3', '20H392', ['staged_system_apps']), 'Original Data identity differs')
    with archive.open('rb') as stream:
        verify_archive(stream, contents['entries'], metadata.read_bytes())
    return lock, profile, contents, archive, data_path


def build_tools(lock, sources):
    specification = lock['apfs_go_toolchain']
    archive = ROOT / specification['path']
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with tempfile.TemporaryDirectory(prefix='go-fetch-', dir=archive.parent) as temporary:
            candidate = Path(temporary) / 'go.tar.gz'
            with urllib.request.urlopen(specification['url'], timeout=90) as source, candidate.open('xb') as destination:
                shutil.copyfileobj(source, destination, 1 << 20)
            require(candidate.stat().st_size == specification['bytes'] and sha(candidate) == specification['sha256'],
                    'Go toolchain download does not match its pin')
            os.link(candidate, archive)
    regular(archive)
    require(archive.stat().st_size == specification['bytes'] and sha(archive) == specification['sha256'], 'Go toolchain changed')
    go = archive.parent / 'go/bin/go'
    if not go.exists():
        with tarfile.open(archive) as package:
            package.extractall(archive.parent, filter='data')
    require(subprocess.check_output([go, 'version'], text=True).strip() == 'go version go1.27.2 linux/amd64', 'Wrong host Go version')
    work = OUT / 'writer-build'
    work.mkdir(exist_ok=True)
    for source, name in (('tools/ApfsDataBuild.go', 'main.go'), ('tools/apfs-data.go.mod', 'go.mod'), ('tools/apfs-data.go.sum', 'go.sum')):
        shutil.copy2(ROOT / source, work / name)
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOMAXPROCS='4',
               GOCACHE=str(OUT / 'go-cache'), GOMODCACHE=str(OUT / 'go-modules'))
    with (OUT / 'writer-build.log').open('w') as log:
        subprocess.run([go, 'build', '-p', '4', '-trimpath', '-buildvcs=false', '-mod=readonly',
                        '-o', OUT / 'apfs-data-build', '.'], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    require((work / 'go.mod').read_bytes() == (ROOT / 'tools/apfs-data.go.mod').read_bytes() and
            (work / 'go.sum').read_bytes() == (ROOT / 'tools/apfs-data.go.sum').read_bytes(), 'Go build changed locked module inputs')
    checker = OUT / 'apfsprogs-build'
    if not checker.exists():
        shutil.copytree(sources['apfs_checker_reference'], checker, ignore=shutil.ignore_patterns('.git'))
    for source in sources['apfs_checker_reference'].rglob('*'):
        if source.is_file() and '.git' not in source.relative_to(sources['apfs_checker_reference']).parts:
            require((checker / source.relative_to(sources['apfs_checker_reference'])).read_bytes() == source.read_bytes(),
                    'APFS checker work-copy source changed')
    with (OUT / 'checker-build.log').open('w') as log:
        subprocess.run(['make', '-j4', 'GIT_COMMIT=1bd1c1c', '-C', checker / 'apfsck'], stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    overlay = lock['apfs_checker_apple_signature_overlay']
    patch = ROOT / overlay['path']
    require(sha(patch) == overlay['sha256'] and sha(sources['apfs_checker_reference'] / 'apfsck/xattr.c') == overlay['base_source_sha256'],
            'APFS checker signature overlay changed')
    compatible = OUT / 'apfsprogs-apple-signature'
    if not compatible.exists():
        shutil.copytree(sources['apfs_checker_reference'], compatible, ignore=shutil.ignore_patterns('.git'))
    changed = compatible / 'apfsck/xattr.c'
    if sha(changed) == overlay['base_source_sha256']:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', patch], cwd=compatible, check=True, capture_output=True)
    require(sha(changed) == overlay['output_source_sha256'], 'APFS checker compatibility source differs')
    for source in sources['apfs_checker_reference'].rglob('*'):
        if source.is_file() and '.git' not in source.relative_to(sources['apfs_checker_reference']).parts:
            destination = compatible / source.relative_to(sources['apfs_checker_reference'])
            require(destination == changed or destination.read_bytes() == source.read_bytes(), 'Unrecorded APFS compatibility checker edit')
    with (OUT / 'strict-checker-build.log').open('w') as log:
        subprocess.run(['make', '-j4', 'GIT_COMMIT=1bd1c1c', '-C', compatible / 'apfsck'], stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    reader = sources['apfs_readonly_reference']
    libraries = [ROOT / '.toolchains/apfs-readonly' / name for name in ('libapfs.a', 'liblzfse.a', 'libcrypto.a')]
    bzip = ROOT / '.toolchains/apfs-deps/usr/lib/x86_64-linux-gnu/libbz2.a'
    compiler = Path('/usr/bin/g++').resolve()
    subprocess.run([compiler, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                    '-I' + str(reader), ROOT / 'tools/ApfsDataVerify.cpp', *libraries, '-lz', bzip,
                    '-o', OUT / 'apfs-data-verify'], check=True)
    return {'writer': OUT / 'apfs-data-build', 'reader': OUT / 'apfs-data-verify',
            'checker': checker / 'apfsck/apfsck', 'strict_checker': compatible / 'apfsck/apfsck'}, [archive, go, compiler, *libraries, bzip]


def readback(tools, image, work, expected, profile):
    work.mkdir()
    blobs = work / 'blobs'
    blobs.mkdir()
    result = subprocess.run([tools['reader'], image, blobs], capture_output=True, text=True, check=True)
    (work / 'inventory.jsonl').write_text(result.stdout)
    (work / 'reader.log').write_text(result.stderr)
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    require(lines[0]['kind'] == 'volume' and lines[0]['bytes'] == profile['size_bytes'] and
            lines[0]['container_uuid_hex'] == uuid.UUID(profile['container_uuid']).hex and
            lines[0]['volume_uuid_hex'] == uuid.UUID(profile['volume_uuid']).hex, 'Data volume identity changed')
    actual = lines[1:]
    for entry in actual:
        require(entry['path'] == 'Data' or entry['path'].startswith('Data/'), 'Unexpected Data inventory prefix')
        entry['path'] = '' if entry['path'] == 'Data' else entry['path'][5:]
    counts = validate_inventory(actual, blobs)
    compare_inventory(actual, blobs, expected)
    return lines[0], counts


def compare_inventory(actual, blobs, expected):
    by_path = {entry['path']: entry for entry in actual}
    require(len(by_path) == len(actual) == len(expected) and set(by_path) == {entry['path'] for entry in expected},
            'Data path set differs')
    fields = ('type', 'mode', 'uid', 'gid', 'bsd_flags', 'protection_class', 'create_time_ns',
              'mod_time_ns', 'access_time_ns', 'change_time_ns', 'xattrs_hex')
    inodes = {}
    for entry in expected:
        observed = by_path[entry['path']]
        for field in fields:
            require(observed[field] == entry[field], 'Data metadata differs: ' + entry['path'] + ' / ' + field)
        if entry['type'] == 'file':
            require(observed['bytes'] == entry['bytes'] and sha(blobs / observed['blob']) == entry['sha256'],
                    'Data content differs: ' + entry['path'])
            if entry['inode'] in inodes:
                require(inodes[entry['inode']] == observed['inode'], 'Data hard-link identity differs')
            inodes[entry['inode']] = observed['inode']
        elif entry['type'] == 'symlink':
            require(observed['target'] == entry['target'], 'Data symlink target differs')
    require(len(set(inodes.values())) == len(inodes), 'Distinct source Data inodes were merged')


def load_packer():
    path = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/packed_ramdisk.py'
    specification = importlib.util.spec_from_file_location('oneplus13_packed_data', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, path


def checksum(block):
    total, weighted, modulus = 0, 0, (1 << 32) - 1
    for value, in struct.iter_unpack('<I', block[8:]):
        total = (total + value) % modulus
        weighted = (weighted + total) % modulus
    low = modulus - ((total + weighted) % modulus)
    high = modulus - ((total + low) % modulus)
    return struct.pack('<II', low, high)


def negative_controls(tools, manifest, blobs, image, packed, work, profile):
    controls = []
    entries = manifest['entries']
    file_index = next(i for i, e in enumerate(entries) if e['type'] == 'file')
    compressed = next(i for i, e in enumerate(entries) if e['bsd_flags'] & 32)
    symlink = next(i for i, e in enumerate(entries) if e['type'] == 'symlink')
    changes = [('parent-traversal', file_index, 'path', '../escape'), ('negative-uid', file_index, 'uid', -1),
               ('owner-overflow', file_index, 'gid', 1 << 32), ('blob-traversal', file_index, 'blob', '../escape'),
               ('file-content-pin', file_index, 'sha256', '00' * 32), ('protection-not-zero', file_index, 'protection_class', 4),
               ('timestamp-overflow', file_index, 'create_time_ns', 1 << 63), ('inode-type-mismatch', file_index, 'mode', 0o120777),
               ('unknown-flags', file_index, 'bsd_flags', 0x10000), ('compressed-without-xattr', compressed, 'xattrs_hex', {}),
               ('symlink-target-mismatch', symlink, 'target', '/different')]
    for name, index, field, value in changes:
        changed = copy.deepcopy(manifest)
        changed['entries'][index][field] = value
        candidate, output = work / (name + '.json'), work / (name + '.apfs')
        candidate.write_text(json.dumps(changed))
        result = subprocess.run([tools['writer'], candidate, blobs, output], capture_output=True, text=True)
        require(result.returncode != 0, 'Invalid Data manifest accepted: ' + name)
        controls.append({'case': name, 'result': 'REJECTED', 'reason': result.stderr.strip()})
    for name in ('existing-output', 'symbolic-output'):
        output = work / name
        sentinel = b'preserve this existing local file\n'
        target = work / (name + '-target')
        target.write_bytes(sentinel)
        if name == 'existing-output':
            os.link(target, output)
        else:
            output.symlink_to(target.name)
        result = subprocess.run([tools['writer'], work / 'manifest.json', blobs, output], capture_output=True, text=True)
        require(result.returncode != 0 and target.read_bytes() == sentinel, 'Existing output was changed')
        controls.append({'case': name, 'result': 'REJECTED', 'existing_bytes_unchanged': True})
    packer, _ = load_packer()
    logical, extents = packer.regions(packed.read_bytes())
    require(logical == profile['size_bytes'], 'Packed Data capacity changed')
    ordinary = next(e for e in entries if e['type'] == 'file' and not e['bsd_flags'] & 32 and e['bytes'] >= 64)
    marker = (blobs / ordinary['blob']).read_bytes()[:64]
    matches = [(base + bytes(data).index(marker)) for base, data in extents if marker in bytes(data)]
    require(len(matches) == 1, 'Cannot identify unique Data payload corruption fixture')
    superblocks = [(base + at) for base, data in extents for at in range(0, len(data), 4096)
                   if bytes(data[at + 32:at + 36]) == b'APSB']
    require(len(superblocks) == 1, 'Expected one newly formatted volume superblock')
    compression_marker = bytes.fromhex(entries[compressed]['xattrs_hex']['com.apple.decmpfs'])
    compression_offsets = [(base + bytes(data).index(compression_marker)) for base, data in extents if compression_marker in bytes(data)]
    require(len(compression_offsets) == 1, 'Cannot identify unique original compression-signature fixture')
    for name in ('container-checksum', 'plain-payload-byte', 'volume-uuid-checksummed', 'invalid-compression-signature-checksummed'):
        output = work / (name + '.apfs')
        subprocess.run(['cp', '--reflink=auto', '--sparse=always', '--', image, output], check=True)
        with output.open('r+b') as stream:
            if name == 'container-checksum':
                byte = stream.read(1); stream.seek(0); stream.write(bytes([byte[0] ^ 1]))
            elif name == 'plain-payload-byte':
                stream.seek(matches[0]); byte = stream.read(1); stream.seek(matches[0]); stream.write(bytes([byte[0] ^ 1]))
            elif name == 'volume-uuid-checksummed':
                # apfs_vol_uuid follows the public apfs_superblock fields at 0xf0.
                stream.seek(superblocks[0]); block = bytearray(stream.read(4096))
                observed = uuid.UUID(profile['volume_uuid']).bytes
                require(block[0xf0:0x100] == observed, 'Volume UUID layout differs from the pinned APFS format')
                block[0xf0] ^= 1
                block[:8] = checksum(block)
                stream.seek(superblocks[0]); stream.write(block)
            else:
                offset = compression_offsets[0]
                stream.seek(offset & ~4095); block = bytearray(stream.read(4096))
                require(block[offset & 4095: (offset & 4095) + 4] == b'fpmc', 'Compression-signature layout changed')
                block[offset & 4095] ^= 1; block[:8] = checksum(block)
                stream.seek(offset & ~4095); stream.write(block)
        if name == 'invalid-compression-signature-checksummed':
            rejected = subprocess.run([tools['strict_checker'], '-cuw', output], capture_output=True, text=True)
            require(rejected.returncode == 1 and rejected.stdout.strip() == 'Compression signature: not supported.' and not rejected.stderr,
                    'Signature compatibility checker accepted an unknown signature or failed another check')
        try:
            readback(tools, output, work / (name + '-readback'), entries, profile)
        except (ValueError, subprocess.CalledProcessError) as error:
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else:
            raise ValueError('Corrupted APFS input accepted: ' + name)
    return controls


def check_current():
    lock, profile, _, _, data_path = profile_and_inputs()
    pinned_sources(REFERENCES)
    report = json.loads(REPORT.read_text())
    require(report['source_references'] == {name: lock[name] for name in REFERENCES}, 'APFS Data source pins changed')
    require(report['result'] == 'IOS16_LOCAL_APFS_DATA_IMAGE_PASS' and report['builder_sha256'] == sha(Path(__file__)), 'Data stage is stale')
    for path, digest in {**report['source_sha256'], **report['tool_dependencies_sha256'], **report['artifacts']}.items():
        regular(ROOT / path)
        require(sha(ROOT / path) == digest, 'APFS Data source/artifact changed: ' + path)
    require(report['archive_report_sha256'] == sha(data_path) and report['volume']['volume_uuid_hex'] == uuid.UUID(profile['volume_uuid']).hex,
            'APFS Data dependency or identity changed')
    require(report['counts']['entries'] == 198 and report['counts']['files'] == 36 and
            report['compressed_files_preserved'] == 17 and report['resource_forks_preserved'] == 5 and
            report['all_contents_and_metadata_read_back'] and report['reproducible_image_verified'] and
            report['packed_entire_logical_image_read_back'] and report['strict_apfsck_unknown_feature_qualification'] and
            len(report['negative_controls']) == 17 and
            all(item['result'] == 'REJECTED' for item in report['negative_controls']), 'APFS Data evidence incomplete')
    require(not any(report[key] for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                                           'block_devices_opened', 'filesystem_mounted', 'settings_or_activation_state_changed',
                                           'data_protection_keys_created', 'writable_data_runtime_qualified')), 'APFS Data scope differs')
    print('PASS: local APFS Data image / 198 entries / 17 compressed files / 5 resource forks / strict compatible checker / 17 negative controls; no writable runtime qualification')


def main():
    global OUT, REPORT, PROFILE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--volatile', action='store_true', help='Build the separate 2 GiB seed for RamBlock without a persistent store')
    args = parser.parse_args()
    if args.volatile:
        OUT = ROOT / 'build/ios16-data-apfs-volatile'
        REPORT = ROOT / 'reports/ios16-data-volatile-image.json'
        PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392/data-volatile-image.json'
    if args.check_only:
        check_current()
        return
    lock, profile, contents, archive, data_path = profile_and_inputs()
    sources = pinned_sources(REFERENCES)
    OUT.mkdir(parents=True, exist_ok=True)
    tools, dependencies = build_tools(lock, sources)
    with tempfile.TemporaryDirectory(prefix='candidate-', dir=OUT) as temporary:
        work = Path(temporary)
        blobs = work / 'source-blobs'
        blobs.mkdir()
        with tarfile.open(archive, 'r:') as source:
            for entry in contents['entries']:
                if entry['type'] == 'file':
                    data = source.extractfile('Data/' + entry['path']).read()
                    blob = blobs / entry['blob']
                    if blob.exists():
                        require(blob.read_bytes() == data, 'Hard-link contents differ')
                    else:
                        blob.write_bytes(data)
        source_counts = validate_inventory(contents['entries'], blobs)
        manifest = {**{k: profile[k] for k in ('schema_version', 'product', 'build', 'container_uuid', 'volume_uuid', 'size_bytes', 'fixed_time_ns')},
                    'entries': contents['entries']}
        manifest_path = work / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        candidate = work / 'data.apfs'
        subprocess.run([tools['writer'], manifest_path, blobs, candidate], check=True)
        result = subprocess.run([tools['checker'], '-cw', candidate], capture_output=True, text=True)
        require(result.returncode == 0 and not result.stdout and not result.stderr, 'Independent APFS integrity check failed: ' + result.stdout + result.stderr)
        strict = subprocess.run([tools['checker'], '-cuw', candidate], capture_output=True, text=True)
        require(strict.returncode == 1 and strict.stdout.strip() == 'Compression signature: not supported.' and not strict.stderr,
                'Unexpected strict APFS checker result')
        compatible = subprocess.run([tools['strict_checker'], '-cuw', candidate], capture_output=True, text=True)
        require(compatible.returncode == 0 and not compatible.stdout and not compatible.stderr, 'Strict compatible APFS checker failed')
        volume, counts = readback(tools, candidate, work / 'readback', contents['entries'], profile)
        require(counts == source_counts, 'APFS read-back inventory counts differ')
        packer, packer_path = load_packer()
        packed = work / 'data.dbr'
        packed_info = packer.pack(candidate, packed)
        digest = sha(candidate)
        logical, extents = packer.regions(packed.read_bytes())
        reconstructed = work / 'reconstructed.apfs'
        with reconstructed.open('xb') as stream:
            stream.truncate(logical)
            for offset, data in extents:
                stream.seek(offset); stream.write(data)
        require(sha(reconstructed) == digest, 'Packed reconstruction differs from complete raw Data image')
        replica = work / 'replica.apfs'
        subprocess.run([tools['writer'], manifest_path, blobs, replica], check=True)
        require(sha(replica) == digest, 'APFS Data build is not reproducible')
        controls = negative_controls(tools, manifest, blobs, candidate, packed, work, profile)
        final, encoded = OUT / 'data.apfs', OUT / 'data.dbr'
        for source, destination in ((candidate, final), (packed, encoded)):
            if destination.exists() or destination.is_symlink():
                regular(destination)
                require(sha(destination) == sha(source), 'Refuse to replace a different Data installation: ' + str(destination))
            else:
                os.link(source, destination)
        shutil.copy2(work / 'readback/inventory.jsonl', OUT / 'readback.jsonl')
        (OUT / 'data-volume.config').write_text('# Offline Data seed identity; not selected in the default kernel.\n'
                                               'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="' + profile['volume_uuid'] + '"\n')
        (OUT / 'checker.json').write_text(json.dumps({'integrity_flags': '-cw', 'integrity_exit_code': 0,
            'strict_unknown_feature_flags': '-cuw', 'strict_exit_code': strict.returncode, 'strict_message': strict.stdout.strip(),
            'strict_unknown_features_qualified_by_unmodified_checker': False, 'compatible_checker_flags': '-cuw', 'compatible_checker_exit_code': 0,
            'compatible_checker_overlay': lock['apfs_checker_apple_signature_overlay'],
            'limitation': 'Unmodified apfsck expects a zero compression signature. The separate locked work-copy recognizes exactly Apple fpmc as well; all unknown signatures and other strict checks remain enabled.'}, indent=2) + '\n')
        artifacts = [final, encoded, OUT / 'readback.jsonl', OUT / 'data-volume.config', OUT / 'checker.json', *tools.values()]
        source_files = [Path(__file__), ROOT / 'scripts/prepare_initial_data.py', ROOT / 'tools/ApfsDataBuild.go',
                        ROOT / 'tools/ApfsDataVerify.cpp', ROOT / 'tools/ApfsDataInventory.cpp', ROOT / 'tools/apfs-data.go.mod',
                        ROOT / 'tools/apfs-data.go.sum', ROOT / lock['apfs_checker_apple_signature_overlay']['path'], PROFILE, packer_path]
        report = {'result': 'IOS16_LOCAL_APFS_DATA_IMAGE_PASS', 'builder_sha256': sha(Path(__file__)),
                  'product': 'iPhone10,3', 'build': '20H392', 'profile': relative(PROFILE),
                  'source_sha256': {relative(p): sha(p) for p in source_files},
                  'source_references': {name: lock[name] for name in REFERENCES},
                  'archive_report_sha256': sha(data_path), 'source_archive_sha256': sha(archive),
                  'tool_dependencies_sha256': {relative(p): sha(p) for p in dependencies},
                  'artifacts': {relative(p): sha(p) for p in artifacts}, 'image': relative(final),
                  'image_bytes': final.stat().st_size, 'image_sha256': digest, 'packed_image': relative(encoded),
                  'packed_bytes': encoded.stat().st_size, 'packed_metadata': packed_info, 'packed_extents': len(extents),
                  'volume': volume, 'counts': counts, 'compressed_files_preserved': 17, 'resource_forks_preserved': 5,
                  'volatile_sparse_ramblock_compatible_capacity': profile['size_bytes'] <= 2 << 30,
                  'persistent_store_required_for_ramblock_writes': profile['size_bytes'] > 2 << 30,
                  'new_installation_uuid_profile_retained': True, 'original_inode_numbers_reassigned': True,
                  'original_file_contents_uid_gid_modes_four_timestamps_flags_protection_classes_xattrs_and_symlinks_preserved': True,
                  'all_contents_and_metadata_read_back': True, 'independent_apfsck_cw_passed': True,
                  'strict_apfsck_unknown_feature_qualification': True,
                  'strict_unmodified_apfsck_unknown_feature_qualification': False,
                  'strict_checker_overlay': lock['apfs_checker_apple_signature_overlay'],
                  'strict_checker_scope': 'Pinned checker plus the locked exact fpmc signature compatibility edit, checked with -cuw and an unknown-signature refusal. The original unmodified checker passes -cw but reports fpmc as unknown with -u; no original file bytes were changed.',
                  'reproducible_image_verified': True, 'packed_entire_logical_image_read_back': True,
                  'negative_controls': controls, 'data_protection_keys_created': False,
                  'settings_or_activation_state_changed': False, 'source_symlinks_followed': False,
                  'host_ownership_or_xattrs_changed': False, 'original_os_modified': False,
                  'image_contains_gpt': False, 'physical_partition_created_or_modified': False,
                  'block_devices_opened': False, 'filesystem_mounted': False, 'phone_operations': 'none',
                  'default_boot_image_replaced': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
                  'all_ios_port_code_complete': False, 'writable_data_runtime_qualified': False,
                  'scope': 'Linux user-space creation of a fresh reproducible APFS v2 regular-file Data container and DBRDISK1 seed. '
                           'Exact original initial Data payloads, metadata, compressed representations and resource forks are read back by the independent pinned apfs-fuse implementation. '
                           'One case-sensitive, unencrypted volume with no role and newly fixed installation UUIDs; this is a local seed, not a phone partition or authenticated/writable iOS runtime.'}
        REPORT.write_text(json.dumps(report, indent=2) + '\n')
    check_current()


if __name__ == '__main__':
    main()
