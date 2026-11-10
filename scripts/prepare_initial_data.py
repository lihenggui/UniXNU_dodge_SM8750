#!/usr/bin/env python3
"""Prepare stock iPhone initial Data contents and metadata, without formatting APFS."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile

from native_driver_build import ROOT, pinned_sources, require

OUT = ROOT / 'build/ios16-initial-data'
MAX_FILE = 256 << 20
MAX_TOTAL = 512 << 20


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(8 << 20):
            digest.update(block)
    return digest.hexdigest()


def validate_inventory(entries, blobs):
    require(0 < len(entries) <= 100000, 'Data inventory exceeds entry bound')
    by_path, seen_blobs, attributes, total = {}, {}, 0, 0
    integer_fields = ('inode', 'uid', 'gid', 'mode', 'bsd_flags', 'protection_class', 'create_time_ns',
                      'mod_time_ns', 'access_time_ns', 'change_time_ns')
    for entry in entries:
        path = entry['path']
        require(isinstance(path, str) and '\0' not in path and len(path.encode()) < 4096, 'Invalid Data path')
        parts = path.split('/') if path else []
        require(len(parts) <= 64 and all(p and p not in ('.', '..') for p in parts) and not PurePosixPath(path).is_absolute(), 'Data path traversal')
        require(not parts or parts[0] != 'staged_system_apps', 'Staged system apps must remain outside initial Data')
        require(path not in by_path, 'Duplicate Data path')
        for field in integer_fields:
            value = entry[field]
            require(type(value) is int and 0 <= value <= (1 << (16 if field == 'mode' else 32 if field in ('uid', 'gid', 'bsd_flags', 'protection_class') else 64)) - 1,
                    'Invalid Data metadata integer: ' + field)
        expected = {'directory': stat.S_IFDIR, 'file': stat.S_IFREG, 'symlink': stat.S_IFLNK}.get(entry['type'])
        require(expected is not None and stat.S_IFMT(entry['mode']) == expected, 'Data inode mode/type mismatch')
        attrs = entry['xattrs_hex']
        require(type(attrs) is dict and len(attrs) <= 128, 'Invalid Data extended attribute list')
        for name, value in attrs.items():
            require(isinstance(name, str) and name and len(name.encode()) < 1024 and '\0' not in name and isinstance(value, str), 'Invalid Data extended attribute')
            data = bytes.fromhex(value)
            require(data.hex() == value and len(data) <= 4 << 20, 'Invalid Data extended attribute encoding')
            attributes += len(data)
            require(attributes <= 64 << 20, 'Data extended attributes exceed total bound')
        if expected == stat.S_IFREG:
            require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= MAX_FILE and type(entry['decompressed']) is bool, 'Data stream size/encoding invalid')
            name = entry['blob']
            require(name == 'inode-' + str(entry['inode']), 'Invalid Data blob path')
            blob = blobs / name
            require(stat.S_ISREG(blob.lstat().st_mode) and blob.stat().st_size == entry['bytes'], 'Data blob is not the expected regular file')
            digest = sha(blob)
            require(not entry.get('sha256') or digest == entry['sha256'], 'Data blob content changed')
            entry['sha256'] = digest
            signature = (entry['bytes'], digest, entry['mode'], entry['uid'], entry['gid'], entry['bsd_flags'], entry['xattrs_hex'])
            if name in seen_blobs:
                require(seen_blobs[name] == signature, 'Hard-linked Data inode metadata differs')
            else:
                seen_blobs[name] = signature
                total += entry['bytes']
                require(total <= MAX_TOTAL, 'Initial Data streams exceed total bound')
        elif expected == stat.S_IFLNK:
            target = entry['target']
            require(isinstance(target, str) and target and '\0' not in target and len(target.encode()) < 4096, 'Invalid Data symbolic link')
            original = bytes.fromhex(attrs.get('com.apple.fs.symlink', ''))
            require(original.rstrip(b'\0') == target.encode(), 'Data symbolic link differs from its original attribute')
        by_path[path] = entry
    require('' in by_path and by_path['']['type'] == 'directory', 'Initial Data root directory missing')
    for path in by_path:
        if path:
            parent = path.rpartition('/')[0]
            require(parent in by_path and by_path[parent]['type'] == 'directory', 'Data parent missing or symbolic')
    require({p.name for p in blobs.iterdir()} == set(seen_blobs), 'Unexpected initial Data blob')
    return {'entries': len(entries), 'directories': sum(e['type'] == 'directory' for e in entries),
            'files': sum(e['type'] == 'file' for e in entries), 'symlinks': sum(e['type'] == 'symlink' for e in entries),
            'unique_file_streams': len(seen_blobs), 'unique_file_bytes': total, 'extended_attribute_bytes': attributes}


def seconds(nanoseconds):
    return f'{nanoseconds // 1000000000}.{nanoseconds % 1000000000:09d}'


def pax(entry):
    result = {'mtime': seconds(entry['mod_time_ns']), 'atime': seconds(entry['access_time_ns']),
              'LIBARCHIVE.creationtime': seconds(entry['create_time_ns'])}
    for name in ('inode', 'bsd_flags', 'protection_class', 'create_time_ns', 'mod_time_ns', 'access_time_ns', 'change_time_ns'):
        result['UNIXNU.apfs.' + name] = str(entry[name])
    # These are retained metadata, not a request to set the host's xattrs or data-protection keys.
    for name, value in entry['xattrs_hex'].items():
        result['UNIXNU.xattr.' + name.encode().hex()] = value
    if entry['type'] == 'file':
        result['UNIXNU.payload.sha256'] = entry['sha256']
        result['UNIXNU.payload.decompressed'] = '1' if entry['decompressed'] else '0'
    return result


def archive_name(entry):
    return 'Data' + ('/' + entry['path'] if entry['path'] else '')


def write_archive(path, entries, blobs, metadata):
    hardlinks = {}
    with tarfile.open(path, 'x', format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            info = tarfile.TarInfo(archive_name(entry))
            info.mode, info.uid, info.gid = entry['mode'] & 0o7777, entry['uid'], entry['gid']
            info.mtime = entry['mod_time_ns'] // 1000000000
            info.pax_headers = pax(entry)
            if entry['type'] == 'directory':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry['type'] == 'symlink':
                info.type, info.linkname = tarfile.SYMTYPE, entry['target']
                archive.addfile(info)
            elif entry['inode'] in hardlinks:
                info.type, info.linkname = tarfile.LNKTYPE, hardlinks[entry['inode']]
                archive.addfile(info)
            else:
                info.size = entry['bytes']
                with (blobs / entry['blob']).open('rb') as stream:
                    archive.addfile(info, stream)
                hardlinks[entry['inode']] = info.name
        info = tarfile.TarInfo('InitialDataMetadata.json')
        info.mode, info.uid, info.gid, info.size = 0o600, 0, 0, len(metadata)
        archive.addfile(info, io.BytesIO(metadata))


def verify_archive(fileobj, entries, metadata):
    with tarfile.open(fileobj=fileobj, mode='r:') as archive:
        members = archive.getmembers()
        require(len(members) == len(entries) + 1, 'Data archive member count differs')
        seen, first = set(), {}
        for member, entry in zip(members, entries):
            require(member.name == archive_name(entry) and member.name not in seen, 'Data archive paths differ')
            seen.add(member.name)
            require((member.mode, member.uid, member.gid) == (entry['mode'] & 0o7777, entry['uid'], entry['gid']), 'Data archive mode/owner differs')
            require(all(member.pax_headers.get(k) == v for k, v in pax(entry).items()), 'Data archive original metadata differs')
            if entry['type'] == 'directory':
                require(member.isdir(), 'Data directory type differs')
            elif entry['type'] == 'symlink':
                require(member.issym() and member.linkname == entry['target'], 'Data symbolic link differs')
            else:
                if entry['inode'] in first:
                    require(member.islnk() and member.linkname == first[entry['inode']], 'Data hard link differs')
                else:
                    require(member.isfile() and member.size == entry['bytes'], 'Data regular file differs')
                    first[entry['inode']] = member.name
                stream = archive.extractfile(member)
                require(stream is not None and hashlib.file_digest(stream, 'sha256').hexdigest() == entry['sha256'], 'Data archive content digest differs')
        require(members[-1].name == 'InitialDataMetadata.json' and archive.extractfile(members[-1]).read() == metadata,
                'Data archive metadata document differs')


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reader = pinned_sources(('apfs_readonly_reference',))['apfs_readonly_reference']
    revision = subprocess.check_output(['git', '-C', reader / '3rdparty/lzfse', 'rev-parse', 'HEAD'], text=True).strip()
    require(revision == lock['apfs_readonly_reference']['lzfse_submodule'], 'APFS decompressor revision changed')
    volume_path = ROOT / 'reports/ios16-volumes.json'
    volumes = json.loads(volume_path.read_text())
    require(volumes['product'] == 'iPhone10,3' and volumes['build'] == '20H392', 'Need exact original iPhone volume identity')
    os_image, = [v for v in volumes['images'] if v['name'] == 'OS']
    image = ROOT / os_image['path']
    require(stat.S_ISREG(image.lstat().st_mode) and sha(image) == os_image['raw_sha256'], 'Original iPhone OS raw image changed')
    OUT.mkdir(parents=True, exist_ok=True)
    libraries = ROOT / '.toolchains/apfs-readonly'
    bzip = ROOT / '.toolchains/apfs-deps/usr/lib/x86_64-linux-gnu/libbz2.a'
    if not all((libraries / name).is_file() for name in ('libapfs.a', 'liblzfse.a', 'libcrypto.a')) or not bzip.is_file():
        from prepare_ios16_display_cache import build_extractor
        build_extractor(lock)
    compiler = Path('/usr/bin/g++')
    binary = OUT / 'apfs-data-inventory'
    command = [str(compiler), '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               '-I' + str(reader), str(ROOT / 'tools/ApfsDataInventory.cpp'), str(libraries / 'libapfs.a'),
               str(libraries / 'liblzfse.a'), str(libraries / 'libcrypto.a'), '-lz', str(bzip), '-o', str(binary)]
    subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix='read-only-', dir=OUT) as temporary:
        work = Path(temporary)
        blobs = work / 'blobs'
        blobs.mkdir()
        process = subprocess.run([binary, image, blobs], check=True, capture_output=True, text=True)
        entries = [json.loads(line) for line in process.stdout.splitlines()]
        entries.sort(key=lambda e: e['path'].encode())
        counts = validate_inventory(entries, blobs)
        for name in ('mobile', 'root', 'tmp', 'run'):
            require(any(e['path'] == name and e['type'] == 'directory' for e in entries), 'Original Data runtime directory missing: ' + name)
        metadata = json.dumps({'product': 'iPhone10,3', 'build': '20H392', 'source_path': '/private/var',
                               'source_image_sha256': os_image['raw_sha256'], 'excluded_paths': ['staged_system_apps'],
                               'entries': entries}, ensure_ascii=False, indent=2).encode() + b'\n'
        candidate = work / 'initial-data.tar'
        write_archive(candidate, entries, blobs, metadata)
        with candidate.open('rb') as stream:
            verify_archive(stream, entries, metadata)
        controls = []
        file_index = next(i for i, e in enumerate(entries) if e['type'] == 'file')
        link_index = next((i for i, e in enumerate(entries) if e['type'] == 'symlink'), None)
        changes = [('parent-traversal', file_index, 'path', '../escape'), ('blob-traversal', file_index, 'blob', '../escape'),
                   ('negative-owner', file_index, 'uid', -1), ('wrong-inode-type', file_index, 'mode', stat.S_IFLNK | 0o777),
                   ('file-content-pin', file_index, 'sha256', '00' * 32), ('invalid-xattr', file_index, 'xattrs_hex', {'invalid': 'q0'})]
        if link_index is not None:
            changes.append(('embedded-NUL-link', link_index, 'target', 'bad\0target'))
        for name, index, field, value in changes:
            changed = copy.deepcopy(entries)
            changed[index][field] = value
            try:
                validate_inventory(changed, blobs)
            except ValueError:
                controls.append({'case': name, 'result': 'REJECTED'})
            else:
                raise ValueError('Invalid Data metadata was accepted: ' + name)
        with candidate.open('rb') as stream, tarfile.open(fileobj=stream, mode='r:') as archive:
            member = next(m for m in archive.getmembers() if m.isfile() and m.name != 'InitialDataMetadata.json' and m.size)
            mutation = member.offset_data
        altered = bytearray(candidate.read_bytes())
        altered[mutation] ^= 1
        try:
            verify_archive(io.BytesIO(altered), entries, metadata)
        except ValueError as error:
            require('content digest' in str(error), 'Archive corruption failed for an unrelated reason')
            controls.append({'case': 'archive-file-byte', 'result': 'REJECTED'})
        else:
            raise ValueError('Changed Data archive content was accepted')
        final = OUT / 'initial-data.tar'
        if final.exists() or final.is_symlink():
            require(stat.S_ISREG(final.lstat().st_mode) and sha(final) == sha(candidate), 'Refuse to replace a differing initial Data archive')
        else:
            os.link(candidate, final)
        (OUT / 'initial-data-metadata.json').write_bytes(metadata)
        (OUT / 'reader-output.jsonl').write_text(process.stdout)
    files = [Path(__file__), ROOT / 'scripts/native_driver_build.py', ROOT / 'tools/ApfsDataInventory.cpp',
             ROOT / 'scripts/prepare_ios16_display_cache.py', ROOT / 'targets/iphone-x-ios16.toml',
             reader / 'ApfsLib/DeviceLinux.cpp', reader / 'ApfsLib/ApfsDir.cpp', reader / 'ApfsLib/Decmpfs.cpp']
    artifacts = [final, OUT / 'initial-data-metadata.json', OUT / 'reader-output.jsonl', binary]
    result = {'result': 'IOS16_ORIGINAL_INITIAL_DATA_CONTENT_AND_METADATA_ARCHIVE_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392', 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'reader_source': lock['apfs_readonly_reference'], 'source_image': str(image.relative_to(ROOT)), 'source_image_sha256': os_image['raw_sha256'],
              'volume_report_sha256': sha(volume_path), 'source_path': '/private/var', 'excluded_paths': ['staged_system_apps'],
              'archive': str(final.relative_to(ROOT)), 'archive_sha256': sha(final), 'archive_bytes': final.stat().st_size,
              'metadata': str((OUT / 'initial-data-metadata.json').relative_to(ROOT)), 'metadata_sha256': sha(OUT / 'initial-data-metadata.json'),
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'counts': counts,
              'tool_dependencies_sha256': {str(p.relative_to(ROOT)): sha(p) for p in [libraries / n for n in ('libapfs.a', 'liblzfse.a', 'libcrypto.a')] + [bzip]},
              'compiler_sha256': sha(compiler), 'negative_controls': controls, 'all_archive_files_and_metadata_read_back': True,
              'source_uid_gid_mode_times_xattrs_and_hardlinks_preserved_as_metadata': True,
              'host_ownership_or_xattrs_changed': False, 'source_symlinks_followed': False, 'data_protection_keys_created': False,
              'settings_or_activation_state_changed': False, 'original_os_modified': False,
              'apfs_data_image_formatted': False, 'archive_ready_as_apfs_restore_input': True, 'writable_data_runtime_qualified': False,
              'phone_operations': 'none', 'block_devices_opened': False, 'filesystem_mounted': False,
              'hardware_tested': False, 'ready_for_ios_boot': False,
              'scope': 'Deterministic archive of the exact original iPhone initial /private/var, excluding staged_system_apps as in the upstream seed tool. '
                       'Regular payloads, links, numeric ownership/permissions, nanosecond timestamps, protection-class/flags and all xattr bytes are read back. '
                       'The full JSON and UNIXNU PAX records preserve APFS metadata for a later formatter; they do not apply data-protection or compression state. '
                       'No APFS container is formatted, no settings or keybags are generated, no host symlink/ownership operations, no phone or writable-Data runtime result.'}
    (ROOT / 'reports/ios16-initial-data.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: original initial Data {counts}, {len(controls)} corruption/bounds refusals; archive read back, APFS formatting still pending')


if __name__ == '__main__':
    main()
