#!/usr/bin/env python3
"""Build an isolated saved-seed VM fixture from the checked persistent kernel inputs."""
import argparse
import json
from pathlib import Path
import subprocess

import build_qemu_store as store
import build_seed_sync as seed
from check_gpu_link import run
from native_driver_build import ROOT, OBJDIR, build_objects, require, sha, symbols

OUT = ROOT / 'build/cph2653-qemu-seed-sync'
REPORT = ROOT / 'reports/ios16-qemu-seed-sync-kernel.json'


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_SEED_SYNC_KERNEL_PASS' and not report['hardware_tested'] and
        not report['physical_storage_enabled'] and report['root_transports_readonly'] and
        report['native_owner_guard_preserved'], 'Incomplete saved-seed VM fixture')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Saved-seed VM source/artifact changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: isolated VM seed-sync kernel; native owner guard retained');return
    parent = json.loads(store.REPORT.read_text());store.check_report(parent)
    sync = json.loads(seed.REPORT.read_text());seed.check_report(sync)
    require(not parent['old_percpu_control'], 'Saved-seed fixture requires the current mbuf consumer')
    baseline = json.loads(store.data_kernel.BASE_REPORT.read_text());OUT.mkdir(parents=True, exist_ok=True)
    command = json.loads((ROOT / baseline['link_command']).read_text())[:-2]
    old_list, = [value for value in command if value.startswith('-Wl,-filelist,')]
    lines = (store.OUT / 'native.percpu.filelist').read_text().splitlines()
    original_vfs = str(OBJDIR / 'bsd/DEVELOPMENT/vfs_vnops.o')
    require(lines.count(original_vfs) == 1, 'Ambiguous saved-seed VFS consumer')
    filelist = OUT / 'native.filelist';filelist.write_text(''.join(
        (str(ROOT / sync['vfs_object']) if row == original_vfs else row) + '\n' for row in lines))
    command[command.index(old_list)] = '-Wl,-filelist,' + str(filelist)
    original_observers = str(ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o')
    require(command.count(original_observers) == 1, 'Ambiguous observer input')
    command[command.index(original_observers)] = str(store.data_kernel.SYSTEM_OUT / 'absent-observers.o')
    for before, after in (
        (ROOT / 'build/cph2653-data-source/libDodgeRamBlock.a', store.OUT / 'ramblock/libDodgeRamBlock.a'),
        (ROOT / 'build/ios16-apfs-mount-native/libDodgeDataMount.a', store.OUT / 'mount/libDodgeDataMount.a')):
        argument = '-Wl,-force_load,' + str(before);require(command.count(argument) == 1, 'Ambiguous VM storage archive')
        command[command.index(argument)] = '-Wl,-force_load,' + str(after)
    driver = ROOT / 'drivers/DodgeStorage/DodgeSeedSync.cpp';guard = ROOT / 'drivers/DodgeSecurity/DodgeQemuSeedPolicy.cpp'
    objects = build_objects([driver, guard], OUT / 'driver', [driver.parent, guard.parent],
        ['-Ddodge_owner_security_ready=dodge_qemu_seed_security_ready'])
    require('_dodge_owner_security_ready' not in {row['name'] for obj in objects for row in symbols(obj.read_bytes())},
        'VM seed fixture can call the native owner guard')
    archive = OUT / 'libDodgeQemuSeedSync.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, *objects], check=True)
    dependencies = (store.OUT / 'root/libDodgeQemuOwnerRoot.a', store.data_kernel.AES_OUT / 'libDodgeQemuAES.a',
        store.data_kernel.keystore.OUT / 'libDodgeQemuKeyStore.a', store.OUT / 'libDodgeQemuStore.a', archive)
    for path in dependencies:command.append('-Wl,-force_load,' + str(path))
    native = OUT / 'mach.qemu-seed-sync';command += ['-o', str(native)];run(command, OUT / 'link.log', OBJDIR)
    candidate, emission, security, readback, checked = store.data_kernel.prelink(native, parent, baseline, OUT,
        additional_entries=(*parent['store_callbacks'], '_dodge_qemu_persistent_volume_seed', '_dodge_qemu_store_checkpoint',
            '_dodge_seed_close_sync', '_dodge_qemu_seed_security_ready'))
    record = OUT / 'link-command.json';record.write_text(json.dumps(command, indent=2) + '\n')
    artifacts = [filelist, *objects, archive, native, candidate, emission, security, record, OUT / 'driver/compile-commands.json']
    store.check_report(parent)  # The fixture must not replace any baseline artifact.
    report = {'result': 'IOS16_QEMU_SEED_SYNC_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (Path(__file__), driver, guard,
            ROOT / 'scripts/build_qemu_data.py', ROOT / 'scripts/native_driver_build.py')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in
            (store.REPORT, seed.REPORT, store.data_kernel.BASE_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'native_owner_guard_preserved': True, 'root_transports_readonly': True,
        'physical_storage_enabled': False, 'hardware_tested': False, 'phone_operations': 'none',
        'security_start_readback': readback, **checked,
        'scope': 'Separate VM fixture reuses the checked persistent Data transport and exact pinned VFS close hook. '
        'The selected guard requires real QEMU AES/KeyStore readiness and the existing virtual-bus/development-identity '
        'check. Native source, owner guard, both native packages and baseline VM artifacts stay unchanged. '
        'Actual filesystem behavior is checked separately; no physical storage or hardware security is supplied.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: separate seed-sync VM kernel with original iPhone closure and preserved native/baseline artifacts')


if __name__ == '__main__':main()
