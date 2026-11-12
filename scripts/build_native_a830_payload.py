#!/usr/bin/env python3
"""Build and read back the native GPU development FAT and Android container."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib
from types import SimpleNamespace

from build_native_a830_prelink import REPORT as PRELINK_REPORT, check_report as check_prelink
from build_native_a830_firmware import REPORT as FIRMWARE_REPORT, check_report as check_firmware
from build_native_a830_addon import REPORT as ADDON_REPORT, check_report as check_addon
from build_mapped_lease_payload import extract_fat
from boot_entropy_execution import Firmware
from check_boot_entropy_kernel import execute_efi, seed_case, CRYPTO_REPORT
from native_driver_build import ROOT, require, sha
from prepare_device_tree import parse_adt
from prepare_crypto_execution import FIXTURE as POST_FIXTURE
from prepare_ios16_crypto import FIXTURE as OWNER_FIXTURE
from image4_boot_policy import CONTRACT as IMAGE4_CONTRACT, prepare_policy, check_policy

OUT = ROOT / 'build/cph2653-native-a830-bringup'
REPORT = ROOT / 'reports/native-a830-payload.json'


def reserve_handoff(blob, name):
    before = parse_adt(blob);target = '/chosen/memory-map'
    require(target in before and name not in before[target] and name in ('TrustCache', 'GpuAddon'), 'Duplicate or invalid handoff')
    found = []
    def scan(at, parent='', depth=0):
        require(depth <= 64 and at + 8 <= len(blob), 'ADT node bounds')
        start = at;count, children = struct.unpack_from('<II', blob, at);at += 8;props = {}
        for _ in range(count):
            require(at + 36 <= len(blob), 'ADT property bounds')
            key, length = struct.unpack_from('<32sI', blob, at);length &= 0x7fffffff;at += 36
            require(at + length <= len(blob), 'ADT value bounds')
            props[key.split(b'\0', 1)[0].decode()] = blob[at:at + length];at += (length + 3) & ~3
        node = props['name'].rstrip(b'\0').decode();path = parent + '/' + node if parent or node != 'device-tree' else ''
        if path == target:found.append((start, at, count))
        for _ in range(children):at = scan(at, path, depth + 1)
        return at
    require(scan(0) == len(blob) and len(found) == 1, 'Ambiguous ADT handoff node')
    start, at, count = found[0];record = struct.pack('<32sI', name.encode(), 16) + bytes(16)
    result = bytearray(blob[:at] + record + blob[at:]);struct.pack_into('<I', result, start, count + 1)
    after = parse_adt(result)
    require(after == {key: dict(value, **{name: bytes(16)}) if key == target else value for key, value in before.items()},
            'Adding a handoff changed an original ADT value')
    return bytes(result)


def check_report(report):
    require(report['result'] == 'NATIVE_A830_COMPLETE_LOCAL_PAYLOAD_PASS' and report['linked_source_objects'] == 111 and
            report['boot_header_version'] == 4 and not report['hardware_tested'] and not report['original_userspace_included'],
            'Incomplete native payload report')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native payload input changed: ' + name)
    check_policy((ROOT / report['image4_adt']).read_bytes(), report['image4_boot_policy'],
                 {name: (ROOT / path).read_bytes() for name, path in report['image4_boot_inputs'].items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native A830 FAT, addon/trust handoff and Android v4 container');return
    prelink, firmware, addon = [json.loads(p.read_text()) for p in (PRELINK_REPORT, FIRMWARE_REPORT, ADDON_REPORT)]
    check_prelink(prelink);check_firmware(firmware);check_addon(addon)
    baseline_path = ROOT / 'reports/ios16-crypto-payload.json';baseline = json.loads(baseline_path.read_text())
    old_fat = ROOT / baseline['payload'];require(sha(old_fat) == baseline['payload_sha256'], 'Baseline FAT changed')
    OUT.mkdir(parents=True, exist_ok=True)
    tests = subprocess.run([sys.executable, ROOT / 'scripts/test_image4_boot_policy.py'], capture_output=True, text=True)
    test_log = OUT / 'boot-policy-tests.log';test_log.write_text(tests.stdout + tests.stderr)
    require(not tests.returncode, 'Owner boot-policy tests failed; inspect boot-policy-tests.log')
    policy_tests = json.loads(tests.stdout)
    require(policy_tests['result'] == 'PASS' and policy_tests['test_cases'] >= 12, 'Owner boot-policy coverage is incomplete')
    fat = OUT / 'payload.img';shutil.copyfile(old_fat, fat)
    old_files = extract_fat(old_fat, OUT / 'old-readback')
    directory = OUT / 'stage';directory.mkdir(exist_ok=True)
    original_adt = OUT / 'old-readback/EFI/UniXNU/Payloads/kernel.macho.adt'
    adt = directory / 'kernel.macho.adt'
    adt.write_bytes(reserve_handoff(reserve_handoff(original_adt.read_bytes(), 'TrustCache'), 'GpuAddon'))
    nodes = parse_adt(adt.read_bytes())
    require(nodes['/']['model'] == b'iPhone10,3\0' and nodes['/product']['artwork-device-idiom'] == b'phone\0' and
            nodes['/chosen']['chip-id'] == struct.pack('<I', 0x8015) and
            nodes['/chosen']['darwinboot-memory-size'] == struct.pack('<Q', 4 << 30), 'Native payload identity differs')
    old_menu = OUT / 'old-readback/EFI/UniXNU/unixnu.toml';menu = tomllib.loads(old_menu.read_text())
    entry, = [e for e in menu['entry'] if e['id'] == 'xnu']
    require(entry['args'] == baseline['kernel_args'] == '-v serial=0 debug=0x14e cpus=1' and
            entry['initrd'] == 'Payloads/scratch-data.img', 'Baseline entry differs')
    text = old_menu.read_text();title = 'title = ' + json.dumps(entry['title'])
    require(text.count(title) == 1, 'Ambiguous native menu title')
    text = text.replace(title, 'title = "OnePlus 13: native A830 / iPhone iOS 16"')
    if not any(e.get('action') == 'tools' for e in menu['entry']):
        text += '[[entry]]\nid = "tools"\ntitle = "Tools"\ntype = "action"\naction = "tools"\n'
    configuration = directory / 'unixnu.toml';configuration.write_text(text)
    candidate = ROOT / prelink['candidate'];trust = ROOT / addon['trust_bundle'];gpu_addon = ROOT / addon['addon']
    policy_inputs = {'kernel.macho': candidate, 'kernel.macho.trustcache': trust, 'kernel.macho.gpuaddon': gpu_addon,
                     'scratch-data.img': OUT / 'old-readback/EFI/UniXNU/Payloads/scratch-data.img'}
    policy_components = {name: path.read_bytes() for name, path in policy_inputs.items()}
    policy_adt, policy = prepare_policy(adt.read_bytes(), policy_components)
    adt.write_bytes(policy_adt)
    policy_path = directory / 'image4-boot-policy.json';policy_path.write_text(json.dumps(policy, indent=2) + '\n')
    copies = [(candidate, 'Payloads/kernel.macho'), (adt, 'Payloads/kernel.macho.adt'),
              (trust, 'Payloads/kernel.macho.trustcache'), (gpu_addon, 'Payloads/kernel.macho.gpuaddon'), (configuration, 'unixnu.toml')]
    expected = dict(old_files)
    for path, name in copies:
        subprocess.run(['mcopy', '-o', '-i', fat, path, '::/EFI/UniXNU/' + name], capture_output=True, check=True)
        expected['EFI/UniXNU/' + name] = sha(path)
    actual = extract_fat(fat, OUT / 'readback');require(actual == expected, 'Native FAT readback differs')
    readback = OUT / 'readback/EFI/UniXNU/Payloads';disk = readback / 'scratch-data.img'
    efi, mapping = ROOT / firmware['efi'], ROOT / firmware['mapping']
    facts_report = ROOT / 'reports/ios16-boot-entropy-kernel.json'
    facts = json.loads(facts_report.read_text())['compiler_firmware_layout']
    # Run the unchanged packed-Data handoff's failure/control suite against
    # this exact EFI and kernel before adding the optional handoff records.
    print('EXECUTE: actual entropy EFI, native seed consumption and original crypto POST', flush=True)
    rows = execute_efi(efi, mapping, facts, candidate, original_adt, disk)
    files = {'\\kernel.macho': candidate.read_bytes(), '\\kernel.macho.adt': adt.read_bytes(),
             '\\kernel.macho.trustcache': trust.read_bytes(), '\\kernel.macho.gpuaddon': gpu_addon.read_bytes()}
    model = Firmware(efi.read_bytes(), mapping, facts, files, disk.read_bytes(), 'normal')
    handoff, tree, seed = model.run();properties = parse_adt(tree)['/chosen/memory-map'];handoff_files = {}
    check_policy(tree, policy, policy_components)
    for name, path in (('TrustCache', trust), ('GpuAddon', gpu_addon)):
        address, length = struct.unpack('<QQ', properties[name])
        require(length == path.stat().st_size and model.read(address, length) == path.read_bytes(), 'Actual EFI handoff differs: ' + name)
        handoff_files[name] = {'bytes': length, 'sha256': sha(path)}
    final_seed = seed_case(candidate, tree, seed, 'normal')
    cpu = OUT / 'cpu-cases.json';cpu.write_text(json.dumps({'entropy_success': rows[0], 'entropy_failures': rows[1],
        'instruction_controls': rows[2], 'native_seed_to_crypto': rows[3], 'native_seed_failures': rows[4],
        'addon_handoff': handoff, 'handoff_files': handoff_files, 'final_native_seed_to_crypto': final_seed}, indent=2) + '\n')
    sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'));from unixnu import bootimg
    board = tomllib.loads((ROOT / 'board.toml').read_text());mu = ROOT / 'uefi/Mu-Silicium';fd = ROOT / firmware['firmware']
    boot = OUT / 'boot.img';old_path = os.environ.get('PATH', '');os.environ['PATH'] = '/usr/lib/llvm-14/bin' + os.pathsep + old_path
    try:bootimg.build(SimpleNamespace(board=board, work=OUT), mu, fd, mu / 'Resources/DTBs/dodge.dtb', ramdisk=fat, output=boot)
    finally:os.environ['PATH'] = old_path
    container = json.loads((OUT / 'boot.json').read_text())
    require(container['header_version'] == 4 and container['image_sha256'] == sha(boot) and container['fd_sha256'] == sha(fd) and
            container['ramdisk_bytes'] == fat.stat().st_size and sha(old_fat) == baseline['payload_sha256'], 'Native Android container differs')
    sources = [Path(__file__), ROOT / 'scripts/boot_entropy_execution.py', ROOT / 'scripts/check_boot_entropy_kernel.py',
        ROOT / 'scripts/build_mapped_lease_payload.py', ROOT / 'sources/UniXNU/scripts/unixnu/bootimg.py',
        ROOT / 'scripts/prepare_device_tree.py', ROOT / 'scripts/original_crypto_execution.py',
        ROOT / 'scripts/image4_boot_policy.py', ROOT / 'scripts/test_image4_boot_policy.py', IMAGE4_CONTRACT,
        ROOT / 'scripts/prepare_crypto_execution.py', POST_FIXTURE, OWNER_FIXTURE,
        ROOT / 'board.toml', mu / 'BootShim/BootShim.S', mu / 'Resources/Configs/dodge.toml']
    artifacts = [fat, boot, OUT / 'boot.json', cpu, adt, configuration, policy_path, test_log]
    report = {'result': 'NATIVE_A830_COMPLETE_LOCAL_PAYLOAD_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in
            (PRELINK_REPORT, FIRMWARE_REPORT, ADDON_REPORT, baseline_path, facts_report, CRYPTO_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'payload': str(fat.relative_to(ROOT)), 'payload_sha256': sha(fat), 'payload_bytes': fat.stat().st_size,
        'boot_image': str(boot.relative_to(ROOT)), 'boot_image_sha256': sha(boot), 'boot_image_bytes': boot.stat().st_size,
        'firmware': firmware['firmware'], 'firmware_sha256': sha(fd), 'linked_source_objects': prelink['combined_source_objects'],
        'kernel_args': entry['args'], 'boot_header_version': 4, 'fat_files': actual, 'handoff_files': handoff_files,
        'image4_boot_policy': policy, 'image4_adt': str(adt.relative_to(ROOT)),
        'boot_policy_host_tests': policy_tests,
        'image4_boot_inputs': {name: str(path.relative_to(ROOT)) for name, path in policy_inputs.items()},
        'Apple_personalization_supplied': False, 'owner_nonce_lifetime': 'payload-build',
        'actual_EFI_handoff_model': 'PASS', 'original_POST_tests_in_model': len(final_seed['actual_post_tests']),
        'original_userspace_included': False, 'default_kernel_selected': False, 'hardware_tested': False,
        'phone_operations': 'none', 'scope': 'Separate native A830 kernel, entropy/logger firmware, runtime addon and exact iPhone trust inputs. '
        'All FAT files, the actual EFI addon/trust memory handoff, native seed/POST model and Android v4 container are checked. '
        'An owner development boot-set manifest binds kernel, trust cache, addon, Data seed and normalized ADT, with mixing disabled '
        'and a nonce generated for this payload build. It is not an Apple personalized manifest or a hardware fuse report. '
        'The packed Data seed and original boot arguments are retained. System boot and hardware remain untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native A830 development FAT/Android v4 container; actual EFI addon/trust handoff and original 18-test POST model')


if __name__ == '__main__':main()
