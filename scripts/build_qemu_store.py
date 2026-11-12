#!/usr/bin/env python3
"""Build the separate iPhone QEMU kernel with a persistent Data backend."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import build_qemu_data as data_kernel
from build_data_source import INIT, concrete_methods, check_table
from check_gpu_link import run
from native_driver_build import ROOT, OBJDIR, build_objects, require, sha, symbols, inspect_object

OUT = ROOT / 'build/cph2653-qemu-store'
REPORT = ROOT / 'reports/ios16-qemu-store-kernel.json'
CALLBACKS = ('mode', 'open', 'read', 'write', 'sync', 'gpt_check')


def compile_like(record, source, output):
    command = list(record['arguments'])
    require(command.count(record['source']) == 1 and command.count('-o') == 1, 'Ambiguous native recipe')
    command[command.index(record['source'])] = str(source);command[command.index('-o') + 1] = str(output)
    run(command, output.with_suffix('.log'), record['directory']);inspect_object(output.read_bytes())
    return command


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_PERSISTENT_DATA_KERNEL_PASS' and not report['hardware_tested'] and
        not report['physical_storage_enabled'] and report['root_transports_readonly'] and
        report['store_callbacks'] == ['_dodge_qemu_store_' + name for name in CALLBACKS], 'Wrong persistent Data kernel')
    for path, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / path) == digest, 'QEMU store kernel input changed: ' + path)
    raw = (ROOT / report['candidate']).read_bytes()
    require(check_table(raw, report['ramblock_methods']) == 352, 'Persistent RamBlock layout changed')
    data_kernel.keystore.readback(raw, report['class_tables'], report['layout'])


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: separate QEMU persistent Data kernel');return
    parent = json.loads(data_kernel.REPORT.read_text());data_kernel.check_report(parent)
    require(not parent['wrong_seed_control'], 'Wrong-seed kernel cannot supply persistence')
    baseline = json.loads(data_kernel.BASE_REPORT.read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / 'host-test.log').open('w') as log:
        subprocess.run([sys.executable, ROOT / 'scripts/check_qemu_store_host.py'], stdout=log, stderr=log, check=True)
    backend, = build_objects([ROOT / 'drivers/DodgeStorage/DodgeQemuStore.cpp'], OUT / 'backend')
    require(not any(section['name'] == '__mod_init_func' and section['size'] for segment in inspect_object(backend.read_bytes())['segments']
        for section in segment['sections']), 'Store backend has an early initializer')

    ramdir = OUT / 'ramblock';ramdir.mkdir(exist_ok=True)
    wrapper = ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp';ram_source = ramdir / wrapper.name
    defines = ''.join('#define native_ufs_store_' + name + ' dodge_qemu_store_' + name + '\n' for name in CALLBACKS)
    ram_source.write_text(defines + wrapper.read_text())
    ram_recipe = ROOT / 'build/cph2653-data-source/compile-commands.json'
    record = json.loads(ram_recipe.read_text())[0];ram_obj = ramdir / 'DodgeRamBlock.o'
    commands = [compile_like(record, ram_source, ram_obj)]
    methods = concrete_methods(ram_obj)
    original_ram_obj = ROOT / 'build/cph2653-data-source/DodgeRamBlock.o'
    require(methods == concrete_methods(original_ram_obj), 'Persistence changed the native RamBlock interface')
    imports = {row['name'] for row in symbols(ram_obj.read_bytes()) if row['kind'] == 1}
    callbacks = ['_dodge_qemu_store_' + name for name in CALLBACKS]
    require(all(name in imports for name in callbacks) and not any(name.startswith('_native_ufs_store_') for name in imports),
        'RamBlock can reach a physical store callback')
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    late = ramdir / 'DodgeRamBlock.late.o'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, ram_obj, late], check=True)
    original_ram_archive = ROOT / 'build/cph2653-data-source/libDodgeRamBlock.a'
    lifecycle = ramdir / 'DodgeRamBlockLifecycle.o'
    lifecycle.write_bytes(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', original_ram_archive, lifecycle.name]))
    ram_archive = ramdir / original_ram_archive.name;ram_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', ram_archive, late, lifecycle], check=True)

    rootdir = OUT / 'root';rootdir.mkdir(exist_ok=True)
    original_root_archive = data_kernel.OWNER_OUT / 'libDodgeQemuOwnerRoot.a'
    members = subprocess.check_output(['/usr/bin/llvm-ar-14', 't', original_root_archive], text=True).splitlines()
    require(members == ['DodgeVirtioBlock.late.o', 'DodgeQemuStorage.o', 'verified_root.o', 'xnu_crypto.o', 'root-policies.o',
        'absent-verified-ufs.o'], 'Owner-root archive changed')
    subprocess.run(['/usr/bin/llvm-ar-14', 'x', original_root_archive], cwd=rootdir, check=True)
    root_source = rootdir / 'DodgeQemuStorage.cpp';shutil.copyfile(ROOT / 'drivers/DodgeStorage/DodgeQemuStorage.cpp', root_source)
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_qemu_store_reservation_overlay'];patch = ROOT / pin['path']
    require(sha(root_source) == pin['base_source_sha256'] and sha(patch) == pin['sha256'], 'Store reservation input changed')
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch], cwd=rootdir, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(root_source) == pin['output_source_sha256'],
        'Store reservation overlay is not exact')
    root_recipe = data_kernel.OWNER_OUT / 'driver/compile-commands.json'
    root_record, = [row for row in json.loads(root_recipe.read_text()) if Path(row['source']).name == 'DodgeQemuStorage.cpp']
    commands.append(compile_like(root_record, root_source, rootdir / 'DodgeQemuStorage.o'))
    root_archive = rootdir / original_root_archive.name;root_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', root_archive, *(rootdir / name for name in members)], check=True)
    preserved = {name: sha(rootdir / name) for name in members if name != 'DodgeQemuStorage.o'}
    for name, digest in preserved.items():
        require(hashlib.sha256(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', original_root_archive, name])).hexdigest() == digest,
            'Original root verification or read-only transport changed')

    mountdir = OUT / 'mount';mountdir.mkdir(exist_ok=True)
    header = mountdir / 'DodgeDataMountSeed.h';shutil.copyfile(data_kernel.OUT / header.name, header)
    mount_obj, = build_objects([ROOT / 'drivers/DodgeStorage/DodgeQemuData.cpp'], mountdir,
        [mountdir, ROOT / 'drivers/DodgeStorage'], ['-Dnative_ram_block_volume_seed=dodge_qemu_persistent_volume_seed'])
    mount_archive = mountdir / 'libDodgeDataMount.a';mount_archive.unlink(missing_ok=True)
    ordinary = ROOT / 'build/ios16-apfs-mount-native'
    for name in ('DodgeApfsMountArgs.o', 'DodgeDataMountSyscall.o'):
        (mountdir / name).write_bytes(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', ordinary / mount_archive.name, name]))
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', mount_archive, mountdir / 'DodgeApfsMountArgs.o', mount_obj,
        mountdir / 'DodgeDataMountSyscall.o'], check=True)
    backend_archive = OUT / 'libDodgeQemuStore.a';backend_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', backend_archive, backend], check=True)
    command = json.loads((ROOT / baseline['link_command']).read_text())[:-2]
    filelist, = [value for value in command if value.startswith('-Wl,-filelist,')]
    command[command.index(filelist)] = '-Wl,-filelist,' + str(data_kernel.keystore.OUT / 'native.filelist')
    original_observers = str(ROOT / 'build/cph2653-native-a830-kernel/absent-observers.o')
    require(command.count(original_observers) == 1, 'Ambiguous observer input')
    command[command.index(original_observers)] = str(data_kernel.SYSTEM_OUT / 'absent-observers.o')
    for old, new in ((original_ram_archive, ram_archive), (ordinary / mount_archive.name, mount_archive)):
        argument = '-Wl,-force_load,' + str(old);require(command.count(argument) == 1, 'Ambiguous archive input')
        command[command.index(argument)] = '-Wl,-force_load,' + str(new)
    for archive in (root_archive, data_kernel.AES_OUT / 'libDodgeQemuAES.a', data_kernel.keystore.OUT / 'libDodgeQemuKeyStore.a', backend_archive):
        command += ['-Wl,-force_load,' + str(archive)]
    native = OUT / 'mach.qemu-store';command += ['-o', str(native)];run(command, OUT / 'link.log', OBJDIR)
    require(check_table(native.read_bytes(), methods) == 352, 'Persistent RamBlock class layout changed')
    candidate, emission, security, security_readback, checked = data_kernel.prelink(native, parent, baseline, OUT,
        additional_entries=(*callbacks, '_dodge_qemu_persistent_volume_seed', '_dodge_qemu_store_checkpoint'))
    require(check_table(candidate.read_bytes(), methods) == 352, 'Persistent RamBlock prelink changed')
    compile_record = OUT / 'adapted-compile-commands.json';compile_record.write_text(json.dumps(commands, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/build_qemu_data.py', ROOT / 'scripts/check_qemu_store_host.py',
        ROOT / 'tests/DodgeQemuStoreTest.cpp', ROOT / 'drivers/DodgeStorage/DodgeQemuStore.cpp',
        ROOT / 'drivers/DodgeStorage/DodgeQemuStoreTransport.h', wrapper, ram_source, root_source, patch, ram_recipe, root_recipe]
    artifacts = [backend, late, lifecycle, ram_archive, root_archive, mount_obj, mount_archive, backend_archive,
        header, native, candidate, emission, security, compile_record, OUT / 'host-test.log']
    report = {'result': 'IOS16_QEMU_PERSISTENT_DATA_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(data_kernel.REPORT.relative_to(ROOT)): sha(data_kernel.REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'class_tables': parent['class_tables'], 'layout': parent['layout'], 'ramblock_methods': methods,
        'store_callbacks': callbacks, 'root_archive_preserved_members': preserved,
        'root_transports_readonly': True, 'physical_storage_enabled': False, 'hardware_tested': False,
        'security_start_readback': security_readback, **checked,
        'scope': 'QEMU-only persistent backend uses a separately marked VirtIO flat file and verifies its identifier, exact capacity and FLUSH support. '
                 'RamBlock store references are redirected to that backend; physical UFS callbacks remain outside its call graph. '
                 'The 352-byte/190-slot class, original iPhone closure and both read-only verified root transports are retained. '
                 'No GPT operations are performed; cross-boot durability is tested separately.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: QEMU persistent Data kernel, original class ABI and read-only root isolation')


if __name__ == '__main__':main()
