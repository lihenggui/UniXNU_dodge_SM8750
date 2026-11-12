#!/usr/bin/env python3
"""Build a separate iPhone kernel with deferred read-only QEMU block storage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_native_a830_kernel import REPORT as BASE_REPORT, check_report as check_base, check_firmware
from build_crypto_prelink import validate
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import run
from check_qemu_storage_host import check as check_host
from image4_boot_policy import CONTRACT, security_plan, check_security_starts
from native_driver_build import (ROOT, TREE, OBJDIR, archive_imports, build_objects, inspect_object,
                                 pinned_sources, require, sha, symbols, macho)
from native_prelink import backed_offset
from prepare_storage_abi import FIXTURE, HEADER, stage_headers
from prepare_surface_backing import checked as backing_checked, apply_hooks, hook_readbacks as surface_readbacks

OUT = ROOT / 'build/cph2653-qemu-storage'
REPORT = ROOT / 'reports/ios16-qemu-storage.json'
INIT = '__GLOBAL__sub_I_DodgeVirtioBlock.cpp'
VTABLE = '__ZTV17NativeVirtioBlock'


def concrete_methods(path):
    raw = path.read_bytes();image, names = inspect_object(raw), symbols(raw)
    table, = [row for row in names if row['name'] == VTABLE]
    section, = [section for segment in image['segments'] for section in segment['sections']
                if section['va'] <= table['value'] < section['va'] + section['size']]
    offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
    slots = {}
    for index in range(count):
        address, bits = struct.unpack_from('<2I', raw, offset + index * 8)
        slot = section['va'] + address - table['value'] - 16
        if 0 <= slot < 190 * 8:
            require(bits >> 24 == 14 and slot % 8 == 0, 'Unexpected VirtIO table relocation')
            slots[slot // 8] = names[bits & 0xffffff]['name']
    require(set(slots) == set(range(190)) and '___cxa_pure_virtual' not in slots.values(), 'Incomplete VirtIO class table')
    return [slots[index] for index in range(190)]


def readback(raw, methods):
    image = macho(raw)
    names = {row['name']: row for row in symbols(raw) if not row['kind'] & 0xe0}
    require(image['kind'] == 2 and not any(row['kind'] == 1 for row in names.values()), 'QEMU storage link has undefined symbols')
    def read(address, count):
        offset = backed_offset(image['segments'], address, count, len(raw))
        return raw[offset:offset + count]
    require(struct.unpack('<190Q', read(names[VTABLE]['value'] + 16, 190 * 8)) ==
            tuple(names[name]['value'] for name in methods), 'VirtIO iPhone class pointers changed')
    size, = struct.unpack('<I', read(names['_dodge_virtio_driver_bytes']['value'], 4))
    require(144 < size < 1024, 'Wrong VirtIO storage instance size')
    for segment in image['segments']:
        for section in segment['sections']:
            if section['name'] == '__mod_init_func' and section['size']:
                initializers = struct.unpack('<' + str(section['size'] // 8) + 'Q', read(section['va'], section['size']))
                require(names[INIT]['value'] not in initializers, 'VirtIO class initializes before its original parent')
    address = names['_IOKitBSDInit']['value']
    calls = []
    for index, word in enumerate(struct.unpack('<20I', read(address, 80))):
        if word & 0xfc000000 == 0x94000000:
            delta = word & 0x3ffffff
            calls.append(address + index * 4 + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta))
    expected = [names[name]['value'] for name in ('__ZN9IOService15publishResourceEPKcP8OSObject',
        '_dodge_system_schedule', '_dodge_data_schedule', '_dodge_input_schedule', '_dodge_qemu_storage_start')]
    require(calls[:5] == expected, 'QEMU storage is not called after existing IOBSD schedulers')
    return {'storage_base_bytes': 144, 'driver_bytes': size, 'vtable_entries': 190,
            'deferred_constructor': hex(names[INIT]['value']), 'IOBSD_calls': [hex(value) for value in expected]}


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_READ_ONLY_STORAGE_SOURCE_AND_PRELINK_PASS' and
            report['source_objects'] == 113 and len(report['concrete_methods']) == 190 and
            report['coordinator_host_tests']['case_count'] == 27 and
            report['source_reference'] == json.loads((ROOT / 'upstream.lock.json').read_text())['virtio_block_reference'] and
            not report['hardware_tested'] and not report['default_kernel_selected'], 'Incomplete QEMU storage build')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'QEMU storage input changed: ' + name)
    require(readback((ROOT / report['candidate']).read_bytes(), report['concrete_methods']) == report['class_readback'],
            'QEMU storage readback changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: deferred iPhone QEMU storage build and strict prelink');return
    base = json.loads(BASE_REPORT.read_text());check_base(base)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reference = pinned_sources(('virtio_block_reference',))['virtio_block_reference']
    fixture = json.loads(FIXTURE.read_text())
    require(sha(FIXTURE) == lock['iphone_storage_abi']['sha256'] and
            sha(HEADER) == lock['iphone_storage_abi']['header_sha256'] and
            (fixture['product'], fixture['build'], fixture['instance_bytes'], fixture['vtable_entries']) ==
            ('iPhone10,3', '20H392', 144, 190), 'Wrong original iPhone storage ABI')
    OUT.mkdir(parents=True, exist_ok=True)
    host = check_host(OUT / 'host')
    _, include, target = stage_headers(OUT / 'abi')
    sources = [ROOT / 'drivers/DodgeStorage/DodgeVirtioBlock.cpp', ROOT / 'drivers/DodgeStorage/DodgeQemuStorage.cpp']
    obj, lifecycle = build_objects(sources, OUT, [include, reference, HEADER.parent],
        ['-Wno-deprecated-declarations', '-Wno-macro-redefined', '-include', str(target), '-DNATIVE_VERIFIED_BLOCK=0'])
    methods = concrete_methods(obj)
    all_names = list(dict.fromkeys([*methods, *(row['name'] for row in fixture['methods'])]))
    readable = dict(zip(all_names, subprocess.check_output(['/usr/bin/llvm-cxxfilt-14'],
        input='\n'.join(name[1:] for name in all_names) + '\n', text=True).splitlines()))
    for row, actual in zip(fixture['methods'], methods):
        own = actual.startswith(('__ZN17NativeVirtioBlock', '__ZNK17NativeVirtioBlock'))
        require((own if row['name'] == '___cxa_pure_virtual' else actual == row['name'] or
                 own and (row['slot'] in (0, 1) or readable[actual].split('::', 1)[1] == readable[row['name']].split('::', 1)[1])),
                'VirtIO override differs from the original prototype at slot ' + str(row['slot']))
    late = OUT / 'DodgeVirtioBlock.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, obj, late], check=True)
    def text(path):
        raw = path.read_bytes()
        section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(text(obj) == text(late), 'Class deferral changed transport instructions')
    require(not any(section['size'] for path in (late, lifecycle)
        for segment in inspect_object(path.read_bytes())['segments'] for section in segment['sections']
        if section['name'] == '__mod_init_func'), 'QEMU storage has an early constructor')
    imports = archive_imports([late, lifecycle])
    require(set(imports['required_board_or_original_imports']) <= base['combined_original_bindings'].keys() and
            not imports['optional_weak_imports'], 'Unclassified VirtIO dependency: ' + repr(imports))
    archive = OUT / 'libDodgeQemuStorage.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, late, lifecycle], check=True)
    old_bsd = ROOT / 'build/cph2653-data-startup/IOKitBSDInit.cpp'
    pin = lock['dodge_qemu_storage_overlay'];patch = ROOT / pin['path']
    require(sha(old_bsd) == pin['base_source_sha256'] and sha(patch) == pin['sha256'], 'QEMU storage source overlay changed')
    bsd = OUT / 'IOKitBSDInit.cpp';bsd.write_bytes(old_bsd.read_bytes())
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)], cwd=OUT, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(bsd) == pin['output_source_sha256'],
            'QEMU storage source hook does not apply exactly')
    recipe = json.loads((OBJDIR / 'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json').read_text().strip().rstrip(','))
    args, index = [], 0
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value == recipe['file']:args.append(str(bsd))
        elif value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):args.append(value)
        index += 1
    bsd_obj = OUT / 'IOKitBSDInit.qemu.cpo';args += ['-o', str(bsd_obj)]
    run(args, OUT / 'bsd-compile.log', recipe['directory'])
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = Path(old_arg.split(',', 2)[2]).read_text().splitlines()
    old_obj = str(ROOT / 'build/cph2653-data-startup/IOKitBSDInit.data.cpo')
    require(rows.count(old_obj) == 1, 'Ambiguous original IOBSD object')
    filelist = OUT / 'native.filelist'
    filelist.write_text(''.join((str(bsd_obj) if row == old_obj else row) + '\n' for row in rows))
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(filelist)
    native = OUT / 'mach.qemu-storage';command += ['-Wl,-force_load,' + str(archive), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    data = native.read_bytes();facts = readback(data, methods)
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    source = {**base, 'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data),
              'actual_init_hook': init_hook_readback(data),
              'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'],
                  '_dodge_qemu_storage_start', '_dodge_qemu_storage_checkpoint', '_dodge_virtio_allocate',
                  '_dodge_virtio_driver_meta', '_native_virtio_read_checkpoint']}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    security_path = OUT / 'security-init.json';security_path.write_text(json.dumps(security, indent=2) + '\n')
    context = original_context(ORIGINAL.read_bytes(), profile['kernel']['prelink']['roots'] + config['additional_roots'], config)
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL,
                   '--slide=' + config['slide'], '--output', pending]
        for name in profile['kernel']['prelink']['roots'] + config['additional_roots']:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', security_path]
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'QEMU storage prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and
            record['native_sha256'] == sha(native) and record['original_sha256'] == sha(ORIGINAL),
            'QEMU storage emission identities changed')
    checked = validate(raw, record, data, ORIGINAL.read_bytes(), context, config, source, security)
    checked.update(native_source_entries_preserved=len(source['combined_native_entries']),
                   original_aliases_preserved=len(source['combined_original_bindings']))
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    require(readback(candidate.read_bytes(), methods) == facts, 'Prelink changed the VirtIO source class')
    firmware = check_firmware(candidate.read_bytes(), base['firmware_pins'])
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    files = [Path(__file__), *sources, patch, old_bsd, FIXTURE, HEADER, CONTRACT,
        ROOT / 'scripts/check_qemu_storage_host.py', ROOT / 'tests/DodgeQemuStorageTest.cpp',
        ROOT / 'scripts/image4_boot_policy.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_storage_abi.py',
        ROOT / 'scripts/build_crypto_prelink.py', ROOT / 'scripts/build_data_startup.py', emitter,
        reference / 'NativeVirtioBlock.cpp', reference / 'LICENSE', target]
    artifacts = [obj, late, lifecycle, archive, bsd, bsd_obj, filelist, native, candidate, emission, security_path,
                 OUT / 'compile-commands.json', ROOT / host['binary'], OUT / 'host/qemu-storage-host.log',
                 OUT / 'host/DodgeQemuStorage.extracted.h']
    report = {'result': 'IOS16_QEMU_READ_ONLY_STORAGE_SOURCE_AND_PRELINK_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(BASE_REPORT.relative_to(ROOT)): sha(BASE_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'source_reference': lock['virtio_block_reference'], 'source_objects': base['combined_source_objects'] + 2,
        'class_readback': facts, 'concrete_methods': methods, 'security_start_readback': security_readback,
        'coordinator_host_tests': host,
        'firmware_readback': firmware, 'original_surface_hooks': surface_readbacks(candidate.read_bytes(), backing), **checked,
        'read_only': True, 'owner_verified_blocks': False, 'default_kernel_selected': False, 'hardware_tested': False,
        'scope': 'Separate iPhone Darwin 22 kernel with the unchanged pinned modern VirtIO MMIO read-only transport. '
                 'The measured 144-byte/190-slot storage ABI and deferred original-parent registration are used. '
                 'IOBSD invokes startup only for the opt-in QEMU bus. Root authentication and userspace remain separate.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 113-object QEMU storage kernel, 190 class slots and 63889 original pointer readbacks')


if __name__ == '__main__':main()
