#!/usr/bin/env python3
"""Run the built iPhone kernel through DarwinBoot and XNU entry in QEMU TCG."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
import xml.etree.ElementTree as ET

from build_native_a830_payload import REPORT as PAYLOAD_REPORT, check_report as check_payload
from build_native_a830_firmware import REPORT as FIRMWARE_REPORT, check_report as check_firmware
from native_driver_build import ROOT, require, sha, symbols
from prepare_device_tree import parse_adt
from unixnu.devicetree import node

OUT = ROOT / 'build/cph2653-native-a830-entry'
REPORT = ROOT / 'reports/native-a830-entry.json'
CHECKPOINTS = ('_arm_init', '_kernel_bootstrap', '_InitIOKit')
POLICY_PANIC = 'failed to get mix-n-match policy: %d'
MENU = ROOT / 'build/cph2653-native-a830-firmware/tree/Build/dodgePkg/DEBUG_CLANGPDB/AARCH64/UniXNU.efi'


def check_report(report):
    require(report['result'] == 'NATIVE_A830_QEMU_ENTRY_TO_INITIOKIT_PASS' and
            [row['symbol'] for row in report['checkpoints']] == list(CHECKPOINTS) and
            report['next_stop']['format'] == POLICY_PANIC and report['negative_control']['result'] == 'REJECTED' and
            not report['hardware_tested'] and not report['system_booted'], 'Incomplete native QEMU entry report')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts'],
                         **report['emulator_sha256']}.items():
        require(sha(ROOT / name) == digest, 'Native QEMU entry input changed: ' + name)


def virtual_tree(board, missing_seed=False):
    """Retain the target identity; replace board resources with QEMU resources."""
    original = parse_adt(board)
    require(original['/']['model'] == b'iPhone10,3\0' and
            original['/chosen']['chip-id'] == struct.pack('<I', 0x8015), 'Entry fixture needs the pinned iPhone target')
    chosen = dict(original['/chosen'])
    chosen.update({'dram-base': struct.pack('<Q', 0x40000000), 'dram-size': struct.pack('<Q', 2 << 30),
                   'darwinboot-memory-size': struct.pack('<Q', 1 << 30), 'unique-chip-id': bytes(8)})
    if missing_seed:
        chosen.pop('random-seed')
    else:
        chosen['random-seed'] = os.urandom(256)
    # No Image4 policy or fuse values are invented to pass the next startup
    # dependency. In particular, do not copy the static IPSW's zero placeholders.
    require('mix-n-match-prevention-status' not in chosen, 'Review the newly supplied boot policy before changing this fixture')

    def properties(values):
        return [(key, value) for key, value in values.items() if key != 'name']

    return node('device-tree', properties(original['/']), [
        node('chosen', properties(chosen), [node('memory-map', [('TrustCache', bytes(16))]), node('manifest-properties')]),
        node('cpus', children=[node('cpu0', [('state', b'running\0'), ('reg', bytes(4)),
            ('device_type', b'cpu\0'), ('compatible', b'arm,armv8\0'),
            ('timebase-frequency', struct.pack('<I', 62500000)), ('clock-frequency', struct.pack('<I', 1000000000))])]),
        node('defaults', [('vmm-present', struct.pack('<I', 1))]), node('options'),
        node('product', properties(original['/product'])), node('buttons', properties(original['/buttons'])),
        node('arm-io', [('device_type', b'qemu-virt\0'), ('ranges', struct.pack('<QQQ', 0, 0x08000000, 0x04000000))],
             [node('intc', [('compatible', b'arm,gic-v3\0'), ('reg', struct.pack('<4Q', 0, 0x10000, 0xa0000, 0xf60000))])])])


class Refused(Exception):
    pass


class Remote:
    """The read/continue subset of GDB RSP; never writes kernel registers or RAM."""
    def __init__(self, stream, deadline, idle):
        self.stream, self.deadline, self.idle = stream, deadline, idle
        stream.settimeout(0.5)

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            require(time.monotonic() < self.deadline, 'QEMU entry timed out')
            try:
                part = self.stream.recv(count - len(result))
            except socket.timeout:
                self.idle()
                continue
            require(part, 'QEMU GDB disconnected')
            result.extend(part)
        return bytes(result)

    def packet(self, message):
        data = message.encode()
        self.stream.sendall(b'$' + data + b'#' + f'{sum(data) % 256:02x}'.encode())
        while self.read(1) != b'$':
            pass
        data = bytearray()
        while True:
            value = self.read(1)
            if value == b'#':
                break
            data.extend(value)
        require(int(self.read(2), 16) == sum(data) % 256, 'Invalid QEMU GDB checksum')
        self.stream.sendall(b'+')
        return data.decode()

    def memory(self, address, size):
        reply = self.packet(f'm{address:x},{size:x}')
        require(not reply.startswith('E'), 'QEMU refused a bounded memory read')
        data = bytes.fromhex(reply)
        require(len(data) == size, 'Short QEMU memory read')
        return data

    def xml(self, filename):
        result = ''
        while True:
            reply = self.packet(f'qXfer:features:read:{filename}:{len(result):x},fff')
            require(reply[:1] in ('m', 'l'), 'QEMU omitted register metadata')
            result += reply[1:]
            if reply[0] == 'l':
                # QEMU 6.2 uses xi:include without declaring the xi prefix.
                return ET.fromstring(result.replace('xi:include', 'include'))

    def system_registers(self):
        result = {}
        for include in self.xml('target.xml').iter():
            if not include.tag.endswith('include'):
                continue
            for register in self.xml(include.attrib['href']).iter('reg'):
                name = register.attrib['name']
                if name == 'SCTLR':
                    name = 'SCTLR_EL1'
                if name in ('SCTLR_EL1', 'TCR_EL1', 'TTBR0_EL1', 'TTBR1_EL1'):
                    raw = bytes.fromhex(self.packet('p' + format(int(register.attrib['regnum']), 'x')))
                    result[name] = int.from_bytes(raw, 'little')
        require(len(result) == 4, 'QEMU omitted the actual EL1 translation registers')
        return result


def run_case(case, qemu, firmware, variables, roms, env, names, timeout, missing_seed):
    directory = OUT / case
    esp = directory / 'esp'
    payloads = esp / 'EFI/UniXNU/Payloads'
    for path in (payloads, esp / 'EFI/BOOT', esp / 'EFI/UniXNU/Drivers'):
        path.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'build/cph2653-native-a830-bringup/readback/EFI/UniXNU/Payloads'
    tree = virtual_tree((source / 'kernel.macho.adt').read_bytes(), missing_seed)
    (payloads / 'kernel.macho.adt').write_bytes(tree)
    for src, dest in ((MENU, esp / 'EFI/BOOT/BOOTAA64.EFI'),
                      (ROOT / 'build/cph2653-native-a830-firmware/DarwinBoot.efi', esp / 'EFI/UniXNU/Drivers/DarwinBoot.efi'),
                      (source / 'kernel.macho', payloads / 'kernel.macho'),
                      (source / 'kernel.macho.trustcache', payloads / 'kernel.macho.trustcache')):
        shutil.copyfile(src, dest)
    configuration = esp / 'EFI/UniXNU/unixnu.toml'
    configuration.write_text('version = 1\n[boot]\ntimeout = 0\ndefault = "xnu"\n[kits]\nautoload = false\n'
        '[[driver]]\npath = "Drivers/DarwinBoot.efi"\n[[entry]]\nid = "xnu"\ntype = "xnu"\n'
        'path = "Payloads/kernel.macho"\nargs = "-v serial=3 debug=0x14e cpus=1"\n')
    shutil.copyfile(variables, directory / 'vars.fd')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    serial = directory / 'serial.log'
    command = [qemu, '-L', roms, '-M', 'virt,virtualization=off,secure=off,gic-version=3', '-accel', 'tcg',
        '-cpu', 'max', '-m', '2048', '-smp', '1',
        '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}',
        '-drive', f'if=pflash,format=raw,file={directory}/vars.fd',
        '-drive', f'if=none,id=esp,format=raw,readonly=on,file=fat:{esp}', '-device', 'virtio-blk-pci,drive=esp',
        '-device', 'virtio-rng-pci', '-device', 'ramfb', '-nic', 'none', '-display', 'none', '-monitor', 'none',
        '-no-reboot', '-serial', f'file:{serial}', '-gdb', f'tcp:127.0.0.1:{port}', '-S']
    stopped, registers = [], {}
    deadline = time.monotonic() + timeout
    with (directory / 'qemu.log').open('w') as log:
        process = subprocess.Popen(list(map(str, command)), env=env, stdout=log, stderr=log)
        try:
            stream = None
            connect_deadline = min(deadline, time.monotonic() + 10)
            while time.monotonic() < connect_deadline:
                require(process.poll() is None, 'QEMU exited before GDB attached')
                try:
                    stream = socket.create_connection(('127.0.0.1', port), timeout=0.5)
                    break
                except OSError:
                    time.sleep(0.05)
            require(stream is not None, 'QEMU GDB did not start')

            def idle():
                require(process.poll() is None, 'QEMU exited before the expected kernel stop')
                if missing_seed and serial.exists():
                    text = serial.read_text(errors='replace')
                    if 'UNIXNU: menu: entry 0 returned Compromised Data' in text:
                        raise Refused()

            with stream:
                remote = Remote(stream, deadline, idle)
                remote.packet('qSupported')
                require(remote.packet('?').startswith('T'), 'QEMU did not stop for GDB')
                targets = (*CHECKPOINTS, '_bsd_init', '_panic')
                for name in targets:
                    require(remote.packet(f'Z1,{names[name]:x},4') == 'OK', 'QEMU refused an execution breakpoint')
                try:
                    while True:
                        require(remote.packet('c').startswith('T05'), 'QEMU stopped outside an execution breakpoint')
                        raw = bytes.fromhex(remote.packet('g'))
                        values = struct.unpack_from('<33Q', raw)
                        pc, lr, pstate = values[32], values[30], struct.unpack_from('<I', raw, 264)[0]
                        name, = [name for name in targets if pc == names[name]]
                        require(not missing_seed, 'Kernel entry accepted an ADT without an entropy reservation')
                        if name == '_panic':
                            message = remote.memory(values[0], 128).split(b'\0')[0].decode()
                            require(message == POLICY_PANIC and values[1] == 0x30003, 'Unexpected startup panic: ' + message)
                            stop = {'symbol': name, 'pc': hex(pc), 'lr': hex(lr), 'format': message, 'error': hex(values[1])}
                            break
                        require(len(stopped) < len(CHECKPOINTS) and name == CHECKPOINTS[len(stopped)],
                                'Unexpected kernel checkpoint: ' + name)
                        registers = remote.system_registers()
                        require(pstate & 0xf in (4, 5) and registers['SCTLR_EL1'] & 1 and
                                registers['TCR_EL1'] & (3 << 14) == 0 and
                                (registers['TCR_EL1'] >> 30) & 3 == 2, 'XNU did not enter EL1 with 4 KiB translation tables')
                        stopped.append({'symbol': name, 'pc': hex(pc), 'lr': hex(lr), 'pstate': hex(pstate),
                                        'translation_registers': {key: hex(value) for key, value in registers.items()}})
                        print('QEMU:', name, 'EL1, MMU enabled, 4 KiB tables', flush=True)
                        require(remote.packet(f'z1,{pc:x},4') == 'OK', 'QEMU could not release a reached checkpoint')
                except Refused:
                    require(missing_seed and not stopped, 'Unexpected EFI refusal')
                    stop = {'result': 'REJECTED', 'case': 'missing-entropy-reservation', 'kernel_entered': False}
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    text = serial.read_text(errors='replace')
    require('DARWINBOOT: loader v2 installed EL1' in text, 'Actual DarwinBoot did not run')
    if not missing_seed:
        require(len(stopped) == len(CHECKPOINTS) and 'DARWINBOOT: inputs validated; exiting boot services' in text,
                'Actual EFI handoff or XNU checkpoints are incomplete')
    else:
        require('exiting boot services' not in text, 'Entropy refusal crossed ExitBootServices')
    return stopped, stop, [serial, directory / 'qemu.log', *sorted(path for path in esp.rglob('*') if path.is_file())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--qemu', type=Path)
    parser.add_argument('--firmware', type=Path)
    parser.add_argument('--firmware-vars', type=Path)
    parser.add_argument('--rom-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()))
        print('PASS: recorded QEMU iPhone entry through InitIOKit; startup policy remains unresolved')
        return
    require(10 <= args.timeout <= 300, 'Choose a 10..300 second timeout per QEMU case')
    payload = json.loads(PAYLOAD_REPORT.read_text())
    check_payload(payload)
    firmware_report = json.loads(FIRMWARE_REPORT.read_text())
    check_firmware(firmware_report)
    menus = [row for row in firmware_report['firmware_readback']['modules'] if row['ui'] == 'UniXNU']
    require(len(menus) == 1 and len(menus[0]['images']) == 1 and
            sha(MENU) == menus[0]['images'][0]['sha256'], 'QEMU menu differs from the embedded board firmware')
    readback = ROOT / 'build/cph2653-native-a830-bringup/readback'
    for name in ('kernel.macho', 'kernel.macho.adt', 'kernel.macho.trustcache'):
        path = 'EFI/UniXNU/Payloads/' + name
        require(sha(readback / path) == payload['fat_files'][path], 'QEMU input differs from the packaged FAT: ' + name)
    prefix = ROOT / '.toolchains/qemu/usr'
    qemu = args.qemu or (prefix / 'bin/qemu-system-aarch64' if (prefix / 'bin/qemu-system-aarch64').is_file()
                         else Path(shutil.which('qemu-system-aarch64') or 'qemu-system-aarch64'))
    firmware = args.firmware or next((path for path in (prefix / 'share/AAVMF/AAVMF_CODE.fd',
        Path('/usr/share/AAVMF/AAVMF_CODE.fd')) if path.is_file()), None)
    variables = args.firmware_vars or (firmware.with_name('AAVMF_VARS.fd') if firmware else None)
    roms = args.rom_dir or next((path for path in (prefix / 'share/seabios', Path('/usr/share/seabios'))
                                if (path / 'vgabios-ramfb.bin').is_file()), None)
    require(qemu.is_file() and firmware and variables and variables.is_file() and roms,
            'Install qemu-system-arm, qemu-efi-aarch64 and seabios, or provide the QEMU paths')
    qemu, firmware, variables, roms = [path.resolve() for path in (qemu, firmware, variables, roms)]
    env = dict(os.environ)
    libraries = qemu.parent.parent / 'lib/x86_64-linux-gnu'
    if libraries.is_dir():
        env['LD_LIBRARY_PATH'] = str(libraries) + (os.pathsep + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    version = subprocess.check_output([qemu, '--version'], env=env, text=True).splitlines()[0]
    kernel = ROOT / 'build/cph2653-native-a830-prelink/kernel.macho'
    require(sha(kernel) == payload['fat_files']['EFI/UniXNU/Payloads/kernel.macho'], 'QEMU and packaged kernels differ')
    names = {row['name']: row['value'] for row in symbols(kernel.read_bytes()) if row['kind'] & 0xe}
    checkpoints, stop, artifacts = run_case('entry', qemu, firmware, variables, roms, env, names, args.timeout, False)
    _, control, extra = run_case('missing-seed', qemu, firmware, variables, roms, env, names, args.timeout, True)
    artifacts += extra + [kernel, MENU, ROOT / 'build/cph2653-native-a830-firmware/DarwinBoot.efi']
    report = {'result': 'NATIVE_A830_QEMU_ENTRY_TO_INITIOKIT_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (Path(__file__), ROOT / 'scripts/prepare_device_tree.py',
            ROOT / 'scripts/native_driver_build.py', ROOT / 'sources/UniXNU/scripts/unixnu/devicetree.py')},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (PAYLOAD_REPORT, FIRMWARE_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'emulator_sha256': {str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p): sha(p)
            for p in (qemu, firmware, variables, roms / 'vgabios-ramfb.bin')},
        'qemu_version': version, 'acceleration': 'TCG', 'CPU': 'max', 'CPUs': 1, 'RAM_bytes': 2 << 30,
        'DarwinBoot_owned_bytes': 1 << 30, 'product': 'iPhone10,3', 'build': '20H392',
        'candidate_sha256': sha(kernel), 'checkpoints': checkpoints, 'next_stop': stop, 'negative_control': control,
        'kernel_or_register_patches': False, 'synthetic_boot_policy_supplied': False,
        'system_booted': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Actual UniXNU.efi, fresh-entropy DarwinBoot and the packaged ordinary-arm64 iPhone kernel execute '
                 'in QEMU TCG through three function-entry checkpoints. The fixture replaces board resources with '
                 'QEMU RAM, CPU and GICv3 while retaining iPhone identity. Original Image4 then refuses the missing '
                 'mix-n-match policy. Missing entropy is refused before ExitBootServices. Board firmware, GPU MMIO '
                 'and original user space are not executed.'}
    check_report(report)
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: actual QEMU entry through InitIOKit, EL1/4 KiB MMU and missing-entropy refusal; Image4 policy is the next dependency')


if __name__ == '__main__':
    main()
