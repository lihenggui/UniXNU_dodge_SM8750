#!/usr/bin/env python3
"""Derive a bounded Data-mount ABI from the exact original iPhone program and APFS."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import tempfile

from native_driver_build import ROOT, macho, require, symbols
from native_prelink import backed_offset, exports, unserialize_xml
from prepare_initial_data import sha

OUT = ROOT / 'build/ios16-apfs-mount-abi'
PROGRAM = OUT / 'mount_apfs-filesystem'
PROGRAM_PATH = '/System/Library/Filesystems/apfs.fs/mount_apfs'
PROGRAM_SHA = 'ccac6fa5b10c74ac9458212044bdc4115831c7a01be04d61d04e86bdec52dc27'
PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392/apfs-mount.json'
KERNEL = ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed'


def program_inputs(extract=False):
    report_path = ROOT / 'reports/ios16-volumes.json'
    volumes = json.loads(report_path.read_text())
    require(volumes['product'] == 'iPhone10,3' and volumes['build'] == '20H392', 'Wrong iPhone OS identity')
    os_image, = [row for row in volumes['images'] if row['name'] == 'OS']
    require(os_image['raw_sha256'] == '6e87bfcaa8eca952e00b719f333d1f1060715a63566112267ad8730e1ed98906', 'Wrong original OS image')
    image = ROOT / os_image['path']
    require(stat.S_ISREG(image.lstat().st_mode) and image.stat().st_size == os_image['raw_bytes'], 'Original OS image geometry changed')
    OUT.mkdir(parents=True, exist_ok=True)
    if extract or not PROGRAM.exists():
        require(sha(image) == os_image['raw_sha256'], 'Original iPhone OS image changed')
        tool = ROOT / '.toolchains/apfs-readonly/apfs-extract'
        require(sha(tool) == 'a64fd2535cc4bbe93f128948dad4c25a9940b75b7d4643146a9a83895c599cb3', 'Read-only extractor changed')
        with tempfile.TemporaryDirectory(prefix='mount-program-', dir=OUT) as directory:
            output = Path(directory) / 'mount_apfs'
            subprocess.run([tool, image, '0', PROGRAM_PATH, output], check=True, capture_output=True)
            require(output.stat().st_size == 72960 and sha(output) == PROGRAM_SHA, 'Original mount program identity differs')
            if PROGRAM.exists():
                require(sha(PROGRAM) == PROGRAM_SHA, 'Refuse to overwrite an unrecorded original program')
            else:
                PROGRAM.write_bytes(output.read_bytes())
    require(stat.S_ISREG(PROGRAM.lstat().st_mode) and PROGRAM.stat().st_size == 72960 and sha(PROGRAM) == PROGRAM_SHA,
            'Original iPhone mount_apfs bytes changed')
    return volumes, os_image


def imports(raw, image):
    table = symbols(raw)
    command, = [at for cmd, at, size in image['commands'] if cmd == 11]
    indirect, count = struct.unpack_from('<II', raw, command + 56)
    require(indirect + count * 4 <= len(raw), 'Original program indirect symbols exceed file')
    stubs, pointers = {}, {}
    for section in (s for seg in image['segments'] for s in seg['sections']):
        flags, first, width = struct.unpack_from('<III', raw, section['command_offset'] + 64)
        kind = flags & 255
        if kind not in (6, 7, 8):
            continue
        width = width if kind == 8 else 8
        require(width == (12 if kind == 8 else 8) and section['size'] % width == 0 and
                first + section['size'] // width <= count, 'Original import section geometry changed')
        for index in range(section['size'] // width):
            slot, = struct.unpack_from('<I', raw, indirect + 4 * (first + index))
            require(not slot & 0xc0000000 and slot < len(table), 'Unsupported original indirect symbol')
            (stubs if kind == 8 else pointers)[section['va'] + index * width] = table[slot]['name']
    require(len(stubs) == 67 and len(pointers) == 76, 'Original mount program import counts changed')
    return stubs, pointers


def derive(program=None, kernel=None):
    program = PROGRAM.read_bytes() if program is None else program
    kernel = KERNEL.read_bytes() if kernel is None else kernel
    require(hashlib.sha256(program).hexdigest() == PROGRAM_SHA, 'Original mount program hash differs')
    identity = json.loads((ROOT / 'reports/ios16-original-components.json').read_text())
    require(hashlib.sha256(kernel).hexdigest() == identity['original_sha256'], 'Original kernelcache hash differs')
    user = macho(program)
    require(struct.unpack_from('<4I', program) == (0xfeedfacf, 0x100000c, 0, 2), 'Need ordinary ARM64 iPhone executable')
    native = macho(kernel)
    stubs, pointers = imports(program, user)
    def user_read(address, size):
        offset = backed_offset(user['segments'], address, size, len(program))
        return program[offset:offset + size]
    def read(address, size):
        offset = backed_offset(native['segments'], address, size, len(kernel))
        return kernel[offset:offset + size]
    def words(address, count):
        return struct.unpack('<' + str(count) + 'I', read(address, count * 4))
    def address(pc, a, b, reg, load=False):
        require(a & 0x9f00001f == 0x90000000 | reg, 'Original APFS ADRP changed')
        delta = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
        delta -= (1 << 21) if delta & (1 << 20) else 0
        require(b & 0xffc003ff == (0xf9400000 if load else 0x91000000) | reg << 5 | reg,
                'Original APFS address/load pair changed')
        return (pc & -4096) + (delta << 12) + ((b >> 10) & 4095) * (8 if load else 1)
    def branch(pc):
        word, = words(pc, 1)
        require(word & 0xfc000000 == 0x94000000, 'Original APFS call changed')
        delta = word & 0x3ffffff
        return pc + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
    names = {name: at for at, group in exports(kernel, native).items() for name in group}
    def imported(stub):
        a, b, c = words(stub, 3)
        require(c == 0xd61f0200, 'Original APFS import branch changed')
        return struct.unpack('<Q', read(address(stub, a, b, 16, True), 8))[0]
    info, = [s for s in native['segments'] if s['name'] == '__PRELINK_INFO']
    entry, = [e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']
              if e['CFBundleIdentifier'] == 'com.apple.filesystems.apfs']
    require(entry['CFBundleVersion'] == '2142.140.9', 'Wrong original APFS version')
    # The original registration constructs vfs_fsentry on its stack. Its first
    # pointer identifies vfsops; the separately copied fsname is checked too.
    registration = 0xfffffff0061735b4
    ops = address(registration, *words(registration, 2), 8)
    require(ops == 0xfffffff006eb1540 and words(registration + 8, 1) == (0xf90013e8,), 'Original vfsops registration differs')
    require(imported(branch(0xfffffff006173604)) == names['_vfs_fsadd'], 'Original APFS registration is not vfs_fsadd')
    name_a, name_b = words(0xfffffff0061735d8, 2)
    # This pair uses x1 as the destination and the same x1 base.
    fsname = address(0xfffffff0061735d8, name_a, name_b, 1)
    require(read(fsname, 5) == b'apfs\0', 'Original VFS entry name differs')
    mount_entry, = struct.unpack('<Q', read(ops, 8))
    require(mount_entry == 0xfffffff0061d1258 and words(mount_entry + 32, 2) == (0xaa0303f4, 0xaa0203f7),
            'Original APFS mount data/context register flow differs')
    require(words(0xfffffff0061d133c, 3) == (0x910d03e1, 0xaa1703e0, 0x52802882) and
            imported(branch(0xfffffff0061d1348)) == names['_copyin'], 'Original APFS copyin source, destination or 0x144 bound changed')
    require(words(0xfffffff0061d134c, 3) == (0xb900d7e0, 0x34000220, 0xaa0003f9), 'Original APFS copyin failure path changed')
    main, = [at for cmd, at, size in user['commands'] if cmd == 0x80000028]
    entry_offset, stack = struct.unpack_from('<QQ', program, main + 8)
    require(entry_offset == 0x1a34 and stack == 0 and stubs[0x100003654] == '_mount', 'Original main/mount entry differs')
    require(user_read(0x1000025c4, 28) == struct.pack('<7I', 0xb9411be2, 0x3000a880, 0xd503201f,
                0x912523e1, 0x914007e3, 0x911c0063, 0x9400041e), 'Original mount syscall argument flow changed')
    blocks = {}
    for label, pc, size in (('vfs_registration', 0xfffffff00617355c, 172), ('mount_to_copyin', mount_entry, 260),
                            ('copyin_to_normal_path', 0xfffffff0061d133c, 88)):
        blocks[label] = {'address': hex(pc), 'bytes': size, 'sha256': hashlib.sha256(read(pc, size)).hexdigest()}
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
            'original_program_path': PROGRAM_PATH, 'original_program_sha256': PROGRAM_SHA, 'original_program_bytes': 72960,
            'original_kernelcache_sha256': identity['original_sha256'], 'original_apfs_version': entry['CFBundleVersion'],
            'program_entry': hex(0x100000000 + entry_offset), 'mount_stub': '0x100003654', 'mount_call': '0x1000025dc',
            'program_stubs': 67, 'program_pointer_imports': len(pointers),
            'user_buffer_bytes': 0x150, 'user_semantic_extent_bytes': 0x14c, 'vfs_device_pointer_bytes': 8,
            'apfs_copyin_bytes_after_vfs_pointer': 0x144, 'apfs_copyin_call': '0xfffffff0061d1348',
            'vfs_registration': '0xfffffff006173604', 'vfsops': hex(ops), 'apfs_mount_entry': hex(mount_entry),
            'copyin_stub': '0xfffffff00625e700', 'statfs_stub': '0xfffffff00625f354',
            'normal_after_copyin': '0xfffffff0061d1394', 'error_after_copyin': '0xfffffff0061d1354',
            'offsets': {'fspec': 0, 'flags': 8, 'mode': 16, 'volume_word': 24, 'snapshot_name': 28,
                        'owner_uid': 0x144, 'owner_gid': 0x148, 'tail_padding': 0x14c},
            'bounded_ordinary_volume_mode': 1, 'ordinary_owner_policy': 'mountpoint uid/gid, or 99 with MNT_UNKNOWNPERMISSIONS',
            'kernel_blocks': blocks, 'full_apfs_mount_qualified': False, 'hardware_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--extract', action='store_true', help='Re-extract and compare the exact original program read-only')
    args = parser.parse_args()
    volumes, image = program_inputs(args.extract)
    contract = derive()
    if args.write:
        require(not PROFILE.exists(), 'Refuse to replace the reviewed APFS mount contract')
        PROFILE.write_text(json.dumps(contract, indent=2) + '\n')
    require(PROFILE.exists() and json.loads(PROFILE.read_text()) == contract, 'Reviewed original APFS mount contract differs')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    if not args.write:
        pin = lock['iphone_apfs_mount_abi']
        require(pin['path'] == str(PROFILE.relative_to(ROOT)) and pin['sha256'] == sha(PROFILE) and
                sha(ROOT / pin['header']) == pin['header_sha256'], 'APFS ABI/header pin differs')
    controls = []
    for name, path, offset in [('program-mount-call', PROGRAM, 0x25dc), ('APFS-copyin-bound', KERNEL, None)]:
        raw = bytearray(path.read_bytes())
        if offset is None:
            offset = backed_offset(macho(raw)['segments'], 0xfffffff0061d1344, 4, len(raw))
        raw[offset] ^= 1
        try:
            derive(program=raw) if path == PROGRAM else derive(kernel=raw)
        except ValueError as error:
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else:
            raise ValueError('Altered original APFS input was accepted')
    sources = [Path(__file__), PROFILE, ROOT / 'scripts/native_driver_build.py',
               ROOT / lock['iphone_apfs_mount_abi']['header']]
    report = {'result': 'IOS16_EXACT_ORIGINAL_APFS_MOUNT_ABI_STATIC_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'dependency_report_sha256': {'reports/ios16-volumes.json': sha(ROOT / 'reports/ios16-volumes.json'),
                                         'reports/ios16-original-components.json': sha(ROOT / 'reports/ios16-original-components.json')},
              'artifacts': {str(PROGRAM.relative_to(ROOT)): sha(PROGRAM)}, 'contract': str(PROFILE.relative_to(ROOT)),
              'contract_sha256': sha(PROFILE), 'original_program_path': PROGRAM_PATH,
              'original_os_image_sha256': image['raw_sha256'], 'user_buffer_bytes': 336, 'apfs_copyin_bytes': 324,
              'original_program_or_kernel_executed': False, 'full_apfs_mount_qualified': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'negative_controls': controls,
              'scope': 'Exact iPhone ordinary-arm64 mount_apfs and original APFS registration, vfsops and bounded copyin are derived. '
                       'The user buffer includes an 8-byte device pointer removed by VFS, 324 bytes consumed by APFS and 4 bytes tail padding. '
                       'Ordinary volume mode/owner semantics still require separate CPU/source checks; no original APFS filesystem is mounted.'}
    (ROOT / 'reports/ios16-apfs-mount-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact original iPhone APFS mount contract, 336-byte user buffer / 8-byte VFS pointer / 324-byte APFS copyin')


if __name__ == '__main__':
    main()
