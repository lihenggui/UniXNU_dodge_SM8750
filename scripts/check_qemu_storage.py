#!/usr/bin/env python3
"""Exercise the iPhone VirtIO storage candidate with local read-only disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import time

from build_qemu_storage import REPORT as SOURCE_REPORT, check_report as check_source
from check_native_a830_entry import (REPORT as ENTRY_REPORT, check_report as check_entry, MENU, Remote,
    virtual_tree, registered_policies, checked_contract)
from image4_boot_policy import prepare_policy, encode_tree
from native_driver_build import ROOT, require, symbols
from prepare_device_tree import parse_adt
from unixnu.devicetree import read_fdt, registers

OUT = ROOT / 'build/cph2653-qemu-storage-entry'
REPORT = ROOT / 'reports/ios16-qemu-storage-entry.json'


def file_sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream, 'sha256').hexdigest()


def virtual_resources(tree, fdt, root_uuid):
    nodes = parse_adt(virtual_tree(tree))
    for path in ('/', '/arm-io'):
        nodes[path]['#address-cells'] = struct.pack('<I', 2)
        nodes[path]['#size-cells'] = struct.pack('<I', 2)
    resources = []
    for entry in read_fdt(fdt).walk():
        if 'virtio,mmio' not in entry.strings('compatible'):continue
        require((entry.parent.scalar('#address-cells'), entry.parent.scalar('#size-cells')) == (2, 2),
                'Unexpected QEMU resource parent')
        regions = registers(entry)
        require(len(regions) == 1 and 'dma-coherent' in entry.properties, 'Unqualified VirtIO resources')
        address, size = regions[0]
        require(0x08000000 <= address < address + size <= 0x0c000000 and size >= 0x108,
                'VirtIO window outside the QEMU bus')
        resources.append((address, size))
    require(0 < len(resources) <= 32 and len(set(resources)) == len(resources), 'Missing or repeated QEMU windows')
    for index, (address, size) in enumerate(sorted(resources)):
        name = 'virtio-mmio-' + str(index)
        nodes['/arm-io/' + name] = {'name': name.encode() + b'\0', 'compatible': b'virtio,mmio\0',
            'reg': struct.pack('<QQ', address - 0x08000000, size), 'dma-coherent': b''}
    nodes['/chosen']['root-matching'] = ('<dict><key>IOProviderClass</key><string>IOMedia</string>'
        '<key>IOPropertyMatch</key><dict><key>UUID</key><string>' + root_uuid.upper() + '</string></dict></dict>\0').encode()
    return encode_tree(nodes), [{'address': hex(address), 'bytes': size} for address, size in sorted(resources)]


def run_case(case, paths, environment, kernel, names, images, board_tree, timeout, *, directory_root=OUT, remote_factory=Remote,
             resource_factory=virtual_resources, packed_data=None, extra_boot_args=()):
    qemu, firmware, variables, roms = paths
    directory = directory_root / case;esp = directory / 'esp'
    payloads = esp / 'EFI/UniXNU/Payloads'
    for path in (payloads, esp / 'EFI/BOOT', esp / 'EFI/UniXNU/Drivers'):
        path.mkdir(parents=True, exist_ok=True)
    original = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads'
    for source, dest in ((MENU, esp / 'EFI/BOOT/BOOTAA64.EFI'),
        (ROOT / 'build/cph2653-native-a830-firmware/DarwinBoot.efi', esp / 'EFI/UniXNU/Drivers/DarwinBoot.efi'),
        (kernel, payloads / 'kernel.macho'), (original / 'kernel.macho.trustcache', payloads / 'kernel.macho.trustcache')):
        shutil.copyfile(source, dest)
    if packed_data is not None:
        require(stat.S_ISREG(packed_data.lstat().st_mode) and 64 <= packed_data.stat().st_size <= 16 << 20,
            'Expected a bounded regular packed Data input')
        shutil.copyfile(packed_data, payloads / 'scratch-data.img')
    require(all(value and set(value) <= set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-=:')
        for value in extra_boot_args), 'Invalid fixture boot argument')
    machine = 'virt,virtualization=off,secure=off,gic-version=3'
    base_command = [qemu, '-L', roms, '-M', machine, '-accel', 'tcg', '-cpu', 'max', '-m', '2048', '-smp', '1',
                    '-global', 'virtio-mmio.force-legacy=false']
    disks = []
    for index, image in enumerate(images):
        path = ROOT / image['path']
        if case == 'writable-backend':
            path = directory / ('writable-' + str(index) + '.raw')
            with path.open('wb') as stream:stream.truncate(1 << 20)
        disks += ['-drive', f'if=none,id=root{index},format=raw,readonly={"off" if case == "writable-backend" else "on"},file={path}',
                  '-device', f'virtio-blk-device,drive=root{index}']
    fdt_path = directory / 'qemu.dtb'
    dump = [*base_command, '-M', machine + ',dumpdtb=' + str(fdt_path), *disks, '-nographic', '-nodefaults']
    process = subprocess.run(list(map(str, dump)), env=environment, capture_output=True, timeout=20)
    require(not process.returncode and fdt_path.is_file(), 'QEMU did not provide its actual FDT')
    root_uuid = images[0]['apfs']['observed_volumes'][0]['uuid']
    tree, resources = resource_factory(board_tree, fdt_path.read_bytes(), root_uuid)
    component_names = ('kernel.macho', 'kernel.macho.trustcache') + (('scratch-data.img',) if packed_data is not None else ())
    components = {name: (payloads / name).read_bytes() for name in component_names}
    tree, policy = prepare_policy(tree, components)
    (payloads / 'kernel.macho.adt').write_bytes(tree)
    policy_path = directory / 'image4-boot-policy.json';policy_path.write_text(json.dumps(policy, indent=2) + '\n')
    enabled = ' dodge-qemu-root=1' if case != 'disabled' else ''
    if extra_boot_args:enabled += ' ' + ' '.join(extra_boot_args)
    initrd = 'initrd = "Payloads/scratch-data.img"\n' if packed_data is not None else ''
    (esp / 'EFI/UniXNU/unixnu.toml').write_text('version = 1\n[boot]\ntimeout = 0\ndefault = "xnu"\n'
        '[kits]\nautoload = false\n[[driver]]\npath = "Drivers/DarwinBoot.efi"\n[[entry]]\nid = "xnu"\n'
        'type = "xnu"\npath = "Payloads/kernel.macho"\n' + initrd + 'args = "-v serial=3 debug=0x14e cpus=1' + enabled + '"\n')
    require(len([path for path in esp.rglob('*') if path.is_file()]) == 6 + int(packed_data is not None), 'Unexpected QEMU payload files')
    shutil.copyfile(variables, directory / 'vars.fd')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0));port = reservation.getsockname()[1]
    serial = directory / 'serial.log'
    command = [*base_command, *disks, '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}',
        '-drive', f'if=pflash,format=raw,file={directory}/vars.fd',
        '-drive', f'if=none,id=esp,format=raw,readonly=on,file=fat:{esp}', '-device', 'virtio-blk-pci,drive=esp',
        '-device', 'virtio-rng-pci', '-device', 'ramfb', '-nic', 'none', '-display', 'none', '-monitor', 'none',
        '-no-reboot', '-serial', f'file:{serial}', '-gdb', f'tcp:127.0.0.1:{port}', '-S']
    targets = ('_arm_init', '_bsd_init', '_native_virtio_read_checkpoint', '_dodge_qemu_storage_checkpoint', '_IOFindBSDRoot', '_panic')
    observation = {'case': case, 'checkpoints': [], 'reads': [], 'storage': {}, 'resources': resources}
    deadline = time.monotonic() + timeout
    with (directory / 'qemu.log').open('w') as log:
        process = subprocess.Popen(list(map(str, command)), env=environment, stdout=log, stderr=log)
        try:
            stream = None
            for _ in range(100):
                require(process.poll() is None, 'QEMU stopped before GDB attached')
                try:
                    stream = socket.create_connection(('127.0.0.1', port), timeout=0.5)
                    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    break
                except OSError:time.sleep(0.05)
            require(stream is not None, 'QEMU GDB did not start')
            with stream:
                def idle():require(process.poll() is None, 'QEMU exited before storage observation')
                remote = remote_factory(stream, deadline, idle)
                remote.packet('qSupported');require(remote.packet('?').startswith('T'), 'QEMU did not stop')
                for name in targets:require(remote.packet(f'Z1,{names[name]:x},4') == 'OK', 'QEMU refused checkpoint')
                while True:
                    require(remote.packet('c').startswith('T05'), 'Unexpected QEMU stop')
                    registers_raw = bytes.fromhex(remote.packet('g'));values = struct.unpack_from('<33Q', registers_raw)
                    pc = values[32];name, = [name for name in targets if names[name] == pc]
                    observation['registers'] = {f'x{index}': hex(value) for index, value in enumerate(values[:31])}
                    observation['registers'].update(sp=hex(values[31]), pc=hex(pc))
                    def integer(symbol, count=4):return int.from_bytes(remote.memory(names[symbol], count), 'little')
                    if name == '_panic':
                        observation['next_stop'] = {'format': remote.memory(values[0], 256).split(b'\0')[0].decode(errors='replace'),
                            'arguments': [hex(value) for value in struct.unpack('<4Q', remote.memory(values[31], 32))],
                            'lr': hex(values[30])}
                        observation['storage'] = {key: integer('_dodge_qemu_storage_' + key) for key in ('phase', 'attempted', 'started', 'result')}
                        observation['total_read_requests'] = integer('_native_virtio_read_requests')
                        observation['read_failures'] = integer('_native_virtio_read_failures')
                        observation['root_vnode'] = hex(integer('_rootvnode', 8))
                        break
                    if name == '_native_virtio_read_checkpoint':
                        observation['reads'].append({'device': hex(values[0]), 'physical': hex(integer('_native_virtio_mmio_physical', 8)),
                            'sectors': integer('_native_virtio_sectors', 8), 'first_sector_sha256': remote.memory(names['_native_virtio_first_sector_sha256'], 32).hex(),
                            'requests': integer('_native_virtio_read_requests'), 'failures': integer('_native_virtio_read_failures')})
                        require(len(observation['reads']) <= 2, 'Unexpected extra block device')
                        # A hardware breakpoint remains at this entry for the second device.
                        require(remote.packet(f'z1,{pc:x},4') == 'OK', 'Cannot step transport checkpoint')
                        require(remote.packet('s').startswith('T05'), 'Cannot step transport checkpoint')
                        require(remote.packet(f'Z1,{pc:x},4') == 'OK', 'Cannot restore transport checkpoint')
                        print('QEMU: completed first-sector DMA read', len(observation['reads']), flush=True)
                        continue
                    if name == '_bsd_init':
                        observation['policies'] = registered_policies(remote, names, checked_contract()['mac_policy_layout'])
                        observation['translation_registers'] = {key: hex(value) for key, value in remote.system_registers().items()}
                    if name == '_IOFindBSDRoot' and case != 'enabled':
                        observation['storage'] = {key: integer('_dodge_qemu_storage_' + key) for key in ('phase', 'attempted', 'started', 'result')}
                        observation['total_read_requests'] = integer('_native_virtio_read_requests')
                        observation['read_failures'] = integer('_native_virtio_read_failures')
                        observation['next_stop'] = {'symbol': name, 'root_selection_entered': False}
                        break
                    if name == '_dodge_qemu_storage_checkpoint':
                        observation['storage'] = {key: integer('_dodge_qemu_storage_' + key) for key in ('phase', 'attempted', 'started', 'result')}
                        observation['platform_device_count'] = integer('_armdt_platform_device_count')
                        require(case != 'enabled' or observation['storage']['started'] == 2,
                                'QEMU storage startup failed; inspect observation.json')
                    observation['checkpoints'].append(name)
                    require(remote.packet(f'z1,{pc:x},4') == 'OK', 'Cannot release checkpoint')
                    print('QEMU:', name, flush=True)
        finally:
            (directory / 'observation.json').write_text(json.dumps(observation, indent=2) + '\n')
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
    require('DARWINBOOT: inputs validated; exiting boot services' in serial.read_text(errors='replace'), 'Incomplete actual EFI handoff')
    return observation, [serial, directory / 'qemu.log', directory / 'observation.json', fdt_path, policy_path,
                         *sorted(path for path in esp.rglob('*') if path.is_file())]


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_VIRTIO_READ_ONLY_TRANSPORT_PASS' and not report['hardware_tested'] and
            not report['system_booted'] and report['APFS_root_mounted'] and not report['root_authenticated'], 'Invalid QEMU storage report')
    execution = report['execution']
    require(execution['storage']['phase'] == 2 and execution['storage']['started'] == 2 and
            execution['storage']['attempted'] == len(execution['resources']) == 32 and
            execution['platform_device_count'] == 33 and execution['storage']['result'] == 0 and
            len(execution['reads']) == 2 and execution['total_read_requests'] > 2 and execution['read_failures'] == 0 and
            int(execution['root_vnode'], 0) and execution['next_stop']['format'] == 'rootvp not authenticated after mounting @%s:%d' and
            {row['name'] for row in execution['policies']} == {'AppleImage4', 'AMFI', 'Sandbox'} and
            all(row['registered'] for row in execution['policies']) and
            set(report['negative_controls']) == {'disabled', 'writable-backend'} and
            all(not row['reads'] and row['storage']['started'] == 0 and row['total_read_requests'] == row['read_failures'] == 0
                for row in report['negative_controls'].values()), 'Incomplete actual QEMU storage observations')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'QEMU storage entry input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=180);args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: recorded QEMU read-only storage execution');return
    require(10 <= args.timeout <= 600, 'Choose 10..600 seconds per QEMU case')
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    entry = json.loads(ENTRY_REPORT.read_text());check_entry(entry)
    emulator = [ROOT / name for name in entry['emulator_sha256']]
    qemu, firmware, variables, rom = emulator
    paths = (qemu, firmware, variables, rom.parent)
    environment = dict(os.environ)
    libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():environment['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + environment['LD_LIBRARY_PATH'] if environment.get('LD_LIBRARY_PATH') else '')
    volume_path = ROOT / 'reports/ios16-volumes.json';volumes = json.loads(volume_path.read_text())
    require((volumes['product'], volumes['build']) == ('iPhone10,3', '20H392') and
            [image['name'] for image in volumes['images']] == ['OS', 'SystemOS'], 'Wrong local root inputs')
    for image in volumes['images']:
        path = ROOT / image['path']
        require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size == image['raw_bytes'] and
                file_sha(path) == image['raw_sha256'], 'Original root input changed: ' + image['name'])
        with path.open('rb') as stream:image['first_sector_sha256'] = hashlib.sha256(stream.read(512)).hexdigest()
    kernel = ROOT / source['candidate'];names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 0xe}
    board = (ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads/kernel.macho.adt').read_bytes()
    enabled, artifacts = run_case('enabled', paths, environment, kernel, names, volumes['images'], board, args.timeout)
    require(enabled['storage']['started'] == 2 and enabled['storage']['result'] == 0 and len(enabled['reads']) == 2 and
            all(row['failures'] == 0 for row in enabled['reads']) and enabled['read_failures'] == 0 and
            enabled['total_read_requests'] > 2 and int(enabled['root_vnode'], 0) and
            enabled['next_stop']['format'] == 'rootvp not authenticated after mounting @%s:%d',
            'Original storage reads, root mount or expected authentication refusal differ; inspect observation.json')
    expected = {(image['raw_bytes'] // 512, image['first_sector_sha256']) for image in volumes['images']}
    require({(row['sectors'], row['first_sector_sha256']) for row in enabled['reads']} == expected,
            'Actual QEMU DMA returned different original disk bytes')
    controls = {}
    for case in ('disabled', 'writable-backend'):
        observation, extra = run_case(case, paths, environment, kernel, names, volumes['images'], board, args.timeout)
        require(not observation['reads'] and not observation['storage']['started'] and
                observation['total_read_requests'] == observation['read_failures'] == 0 and
                observation['storage']['phase'] == (0 if case == 'disabled' else 3),
                'Refused storage path performed DMA or entered the wrong state')
        controls[case] = observation;artifacts += extra
    report = {'result': 'IOS16_QEMU_VIRTIO_READ_ONLY_TRANSPORT_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): file_sha(p) for p in (Path(__file__), ROOT / 'scripts/check_native_a830_entry.py',
            ROOT / 'scripts/image4_boot_policy.py', ROOT / 'sources/UniXNU/scripts/unixnu/devicetree.py')},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): file_sha(p) for p in (SOURCE_REPORT, ENTRY_REPORT, volume_path)},
        'artifacts': {str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p): file_sha(p) for p in
            [*artifacts, *emulator, kernel, *(ROOT / image['path'] for image in volumes['images'])]},
        'product': 'iPhone10,3', 'build': '20H392', 'execution': enabled, 'negative_controls': controls,
        'hardware_tested': False, 'system_booted': False, 'APFS_root_mounted': True, 'root_authenticated': False, 'phone_operations': 'none',
        'scope': 'Actual EFI and the separate Darwin 22 iPhone kernel execute the original storage class and '
                 'read-only modern VirtIO transport in QEMU. Both original OS/SystemOS first-sector DMA reads '
                 'match their local files. Original APFS mounts the root; its root-authentication ioctl fails '
                 'and XNU preserves the resulting panic. Root authentication and iOS userspace remain separate.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original iPhone storage class, two real VirtIO DMA reads and disabled/writable-backend controls')


if __name__ == '__main__':main()
