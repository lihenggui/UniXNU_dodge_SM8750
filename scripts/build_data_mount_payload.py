#!/usr/bin/env python3
"""Package the isolated init-context Data mount candidate with exact packed seed/ADT readback."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace

from native_driver_build import ROOT, require
from prepare_initial_data import sha
from prepare_device_tree import parse_adt
from build_data_payload import reserve_packed_data, loader_parser, from_fat

sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu import bootimg
from unixnu.payload import EPOCH, write_volume, check_args

OUT = ROOT / 'build/ios16-apfs-mount-bringup'


def main():
    dependencies = [ROOT / 'reports' / (name + '.json') for name in
                    ('ios16-data-mount-prelink', 'ios16-data-mount-kernel', 'ios16-data-volatile-image', 'native-payload', 'uefi-build')]
    prelink, cpu, data, baseline, firmware = [json.loads(path.read_text()) for path in dependencies]
    for report in (prelink, cpu, data):
        for name, digest in report['source_sha256'].items(): require(sha(ROOT / name) == digest, 'Data payload stage source changed: ' + name)
    require(prelink['combined_source_objects'] == 87 and cpu['case_count'] == 80 and cpu['candidate_sha256'] == prelink['candidate_sha256'], 'Need current startup/original prelink and CPU checks')
    candidate, seed, original_fat = ROOT / prelink['candidate'], ROOT / data['packed_image'], ROOT / baseline['payload']
    require(sha(candidate) == prelink['candidate_sha256'] and sha(seed) == data['artifacts'][data['packed_image']] and
            data['image_bytes'] == 2 << 30 and sha(original_fat) == baseline['payload_sha256'], 'Data payload input changed')
    fd = ROOT / 'build/cph2653-uefi-menu/SILICIUM_UEFI.fd'
    require(not firmware['returncode'] and firmware['darwinboot_integrated'] and sha(fd) == baseline['firmware_sha256'], 'Need the existing checked menu firmware')
    board = tomllib.loads((ROOT / 'board.toml').read_text())
    config_profile = ROOT / 'profiles/os/ios-16.7.16-20H392/gpu-prelink.json'
    args = check_args(json.loads(config_profile.read_text())['boot_arguments'], board['payload']['command_line_length'])
    require('dodge-data=' not in args and 'dodge-data-mount=' not in args, 'Data argument must remain default-off in this development container')
    OUT.mkdir(exist_ok=True)
    tools = {'clang': Path('/usr/bin/clang-14'), 'llvm-objcopy': Path('/usr/bin/llvm-objcopy-14'), 'llvm-nm': Path('/usr/bin/llvm-nm-14')}
    tool_dir = OUT / 'tools'; tool_dir.mkdir(exist_ok=True)
    for name, path in tools.items():
        link = tool_dir / name
        if link.exists(): require(link.is_symlink() and link.resolve() == path.resolve(), 'Unexpected Data container tool')
        else: link.symlink_to(path)
    library, check, parser_artifacts, parser_sources = loader_parser(OUT)
    encoded = seed.read_bytes(); controls = []
    uefi = ROOT / 'uefi/Mu-Silicium'; dtb = uefi / 'Resources/DTBs/dodge.dtb'
    with tempfile.TemporaryDirectory(prefix='checked-', dir=OUT) as temporary:
        work = Path(temporary); stage = work / 'stage'; stage.mkdir()
        subprocess.run(['mcopy', '-s', '-i', original_fat, '::/EFI', stage], capture_output=True, check=True)
        directory = stage / 'EFI/UniXNU'; configuration = directory / 'unixnu.toml'
        config = tomllib.loads(configuration.read_text()); entry, = [item for item in config['entry'] if item['id'] == 'xnu']
        require(entry['args'] == args and entry['path'] == 'Payloads/kernel.macho' and 'initrd' not in entry, 'Original FAT entry differs')
        text = configuration.read_text(); anchor = 'path = "Payloads/kernel.macho"\n'
        require(text.count(anchor) == 1, 'Data menu kernel path is ambiguous')
        text = text.replace(anchor, anchor + 'initrd = "Payloads/scratch-data.img"\n')
        title = 'title = "' + board['payload']['title'] + '"'
        require(text.count(title) == 1, 'Data menu title is ambiguous')
        configuration.write_text(text.replace(title, 'title = "OnePlus 13: experimental iPhone init Data mount development"'))
        shutil.copyfile(candidate, directory / 'Payloads/kernel.macho'); shutil.copyfile(seed, directory / 'Payloads/scratch-data.img')
        adt = directory / 'Payloads/kernel.macho.adt'
        require(sha(adt) == baseline['adt_sha256'], 'Original iPhone ADT changed')
        old_adt = adt.read_bytes(); new_adt, prop, node = reserve_packed_data(old_adt); adt.write_bytes(new_adt)
        accepted, offset, logical = check(new_adt, encoded)
        require(accepted == 1 and offset == prop + 36 and logical == 2 << 30, 'Actual DarwinBoot parser refused packed Data handoff')
        nodes = parse_adt(new_adt)
        for path, key, value in (('/', 'model', b'iPhone10,3\0'), ('/product', 'artwork-device-idiom', b'phone\0'),
                                 ('/chosen', 'chip-id', struct.pack('<I', 0x8015)), ('/chosen', 'darwinboot-memory-size', struct.pack('<Q', 4 << 30))):
            require(nodes[path][key] == value, 'Data ADT lost the iPhone identity or memory window')
        copied = ctypes.create_string_buffer(len(encoded))
        require(library.copy_encoded(copied, len(encoded), ctypes.create_string_buffer(encoded), len(encoded)) == 1 and copied.raw == encoded,
                'Actual loader copy primitive changed encoded seed bytes')
        mutations = [('seed-short-header', encoded[:31]), ('seed-short-payload', encoded[:-1]), ('seed-trailing-data', encoded + b'x')]
        for name, position, form, value in (('seed-version', 8, '<I', 2), ('seed-page-size', 12, '<I', 16384),
                ('seed-zero-logical', 16, '<Q', 0), ('seed-wrong-capacity', 16, '<Q', 3 << 30), ('seed-count', 24, '<Q', 65537),
                ('seed-offset-alignment', 32, '<Q', 1), ('seed-empty-extent', 40, '<Q', 0)):
            bad = bytearray(encoded); struct.pack_into(form, bad, position, value); mutations.append((name, bytes(bad)))
        for name, bad in mutations:
            require(check(new_adt, bad)[0] == 0, 'Malformed packed Data accepted: ' + name)
            controls.append({'case': name, 'result': 'REJECTED'})
        for name, bad in [('adt-truncated', new_adt[:-1])]:
            require(check(bad, encoded)[0] == 0, 'Malformed Data ADT accepted: ' + name); controls.append({'case': name, 'result': 'REJECTED'})
        for name, at, value in (('adt-placeholder-length', prop + 32, struct.pack('<I', 8)),
                                ('adt-nonzero-placeholder', offset, struct.pack('<Q', 1))):
            bad = bytearray(new_adt); bad[at:at + len(value)] = value
            require(check(bytes(bad), encoded)[0] == 0, 'Malformed Data placeholder accepted'); controls.append({'case': name, 'result': 'REJECTED'})
        try: reserve_packed_data(new_adt)
        except ValueError: controls.append({'case': 'adt-duplicate-reservation', 'result': 'REJECTED'})
        else: raise ValueError('Duplicate Data reservation accepted')
        # Add the conflicting raw placeholder after the packed one; the actual
        # production parser must reject two possible handoff destinations.
        end = prop + 52; conflicting = bytearray(new_adt[:end] + struct.pack('<32sI', b'RAMDisk', 16) + bytes(16) + new_adt[end:])
        count, = struct.unpack_from('<I', conflicting, node); struct.pack_into('<I', conflicting, node, count + 1)
        require(check(bytes(conflicting), encoded)[0] == 0, 'Actual loader accepted conflicting raw/packed Data')
        controls.append({'case': 'adt-raw-packed-conflict', 'result': 'REJECTED'})
        for path in [*stage.rglob('*'), stage]: os.utime(path, (EPOCH, EPOCH))
        fat = work / 'payload.img'; write_volume(stage, fat, board['payload']['volume'], board['payload']['size_mib'])
        readback = work / 'readback'; readback.mkdir()
        for name in ('unixnu.toml', 'Payloads/kernel.macho', 'Payloads/kernel.macho.adt', 'Payloads/scratch-data.img'):
            output = readback / Path(name).name; from_fat(fat, name, output)
            require(sha(output) == sha(directory / name), 'Data FAT file readback differs: ' + name)
        require(check((readback / 'kernel.macho.adt').read_bytes(), (readback / 'scratch-data.img').read_bytes())[0] == 1,
                'Actual loader refused the read-back FAT handoff')
        boot = work / 'boot.img'; previous_path = os.environ['PATH']; os.environ['PATH'] = str(tool_dir) + os.pathsep + previous_path
        try: bootimg.build(SimpleNamespace(board=board, work=work), uefi, fd, dtb, ramdisk=fat, output=boot)
        finally: os.environ['PATH'] = previous_path
        record = json.loads((work / 'boot.json').read_text())
        require(record['header_version'] == 4 and record['ramdisk_bytes'] == fat.stat().st_size and record['image_sha256'] == sha(boot), 'Android Data container readback differs')
        adt_sha, menu_sha = sha(adt), sha(configuration)
        shutil.copy2(adt, OUT / 'kernel.macho.adt')
        for name in ('payload.img', 'boot.img', 'boot.json'): (work / name).replace(OUT / name)
    files = [Path(__file__), ROOT / 'scripts/build_data_payload.py', ROOT / 'scripts/prepare_device_tree.py', ROOT / 'scripts/prepare_data_image.py', ROOT / 'board.toml', config_profile,
             ROOT / 'sources/UniXNU/scripts/unixnu/bootimg.py', ROOT / 'sources/UniXNU/scripts/unixnu/payload.py', *parser_sources,
             uefi / 'BootShim/BootShim.S', uefi / 'Resources/Configs/dodge.toml', uefi / 'Resources/Scripts/mkbootimg.py', dtb]
    artifacts = [OUT / name for name in ('payload.img', 'boot.img', 'boot.json', 'kernel.macho.adt')] + parser_artifacts
    report = {'result': 'IOS16_INIT_DATA_MOUNT_PACKED_SEED_AND_CONTAINER_READBACK_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': prelink['candidate'], 'candidate_sha256': prelink['candidate_sha256'],
              'boot_image': str((OUT / 'boot.img').relative_to(ROOT)), 'boot_image_sha256': sha(OUT / 'boot.img'), 'boot_image_bytes': (OUT / 'boot.img').stat().st_size,
              'payload': str((OUT / 'payload.img').relative_to(ROOT)), 'payload_sha256': sha(OUT / 'payload.img'),
              'packed_seed': data['packed_image'], 'packed_seed_bytes': len(encoded), 'logical_data_bytes': 2 << 30,
              'adt_sha256': adt_sha, 'menu_sha256': menu_sha, 'kernel_args': args, 'linked_source_objects': 87,
              'native_source_entries': prelink['native_source_entries_preserved'], 'original_components': 28, 'original_interfaces': 7,
              'actual_loader_adt_and_packed_parsers_passed': True, 'loader_keeps_packed_input': True, 'loader_dense_2GiB_allocation_required': False,
              'all_original_adt_values_preserved': True, 'negative_controls': controls, 'boot_header_version': 4,
              'source_data_default_enabled': False, 'source_data_mount_default_enabled': False, 'init_boot_call_site_wired': True, 'source_data_startup_and_payload_wired': True, 'original_userspace_included': False,
              'original_root_windows_included': False, 'private_platform_seed_disclosed': False, 'original_apfs_data_mount_qualified': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'scope': 'Separate 87-object Data startup/original-component kernel, exact packed 2 GiB seed, preserved iPhone ADT plus zero PackedRAMDisk placeholder, existing firmware, FAT and Android v4 development container. '
                       'Actual production C ADT/packed parsers and encoded copy primitive, FAT file reads and complete Android container readback pass. '
                       'Data startup and init-context mounting remain default-off; original Data mount, userspace/root boot, physical loader allocation, IOKit registry and phone runtime are not qualified.'}
    (ROOT / 'reports/ios16-data-mount-payload.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: separate 87-object FAT/Android v4 Data development container, actual loader handoff parsers,', len(controls), 'rejection controls; defaults retained')


if __name__ == '__main__':
    main()
