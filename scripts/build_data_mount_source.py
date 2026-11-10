#!/usr/bin/env python3
"""Build a separate init-context Data mount interface; retain the 84-object startup candidate."""
import difflib
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from build_data_startup import hook_readback
from build_data_source import check_table, concrete_methods
from check_gpu_link import run
from native_driver_build import ROOT, OBJDIR, build_objects, require, symbols, macho
from native_prelink import backed_offset
from prepare_initial_data import sha

OUT = ROOT / 'build/ios16-apfs-mount-native'
ENTRIES = ('_dodge_apfs_ordinary_mount_args', '_dodge_apfs_default_mount_owner', '_dodge_data_mount_for_init',
           '_dodge_data_mount_status', '_dodge_apfs_mount_syscall', '_dodge_data_mount_boot')


def init_hook_readback(raw):
    image = macho(raw); table = [s for s in symbols(raw) if not s['kind'] & 0xe0]
    names = {s['name']: s['value'] for s in table}
    start = names['_load_init_program']
    section = next(s['section'] for s in table if s['name'] == '_load_init_program')
    end = min(s['value'] for s in table if s['section'] == section and s['kind'] & 0x0e == 14 and
              not s['name'].startswith(('ltmp', 'L')) and s['value'] > start)
    require(0 < end - start < 4096, 'Unexpected actual init function extent')
    offset = backed_offset(image['segments'], start, end - start, len(raw)); code = raw[offset:offset + end - start]
    calls = {}
    for index, (word,) in enumerate(struct.iter_unpack('<I', code)):
        if word & 0xfc000000 == 0x94000000:
            delta = word & 0x3ffffff
            target = start + index * 4 + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
            calls.setdefault(target, []).append(start + index * 4)
    wanted = [names[name] for name in ('_mach_vm_allocate_kernel', '_dodge_data_mount_boot', '_load_init_program_at_path')]
    require(all(target in calls for target in wanted) and len(calls[wanted[1]]) == 1 and
            max(calls[wanted[0]]) < calls[wanted[1]][0] < min(calls[wanted[2]]), 'Init scratch/Data/launchd call order differs')
    return {'address': hex(start), 'bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(),
            'scratch_allocate_calls': [hex(at) for at in calls[wanted[0]]], 'data_boot_call': hex(calls[wanted[1]][0]),
            'load_init_path_calls': [hex(at) for at in calls[wanted[2]]], 'default_mount_enabled': False}


def main():
    dependencies = {}
    for name, builder in [('ios16-data-startup', 'build_data_startup.py'), ('ios16-apfs-mount-source', 'build_apfs_mount_args.py')]:
        path = ROOT / 'reports' / (name + '.json')
        report = json.loads(path.read_text())
        require(report['builder_sha256'] == sha(ROOT / 'scripts' / builder), 'Data mount dependency is stale: ' + name)
        for filename, value in {**report['source_sha256'], **report['artifacts'], **report['dependency_report_sha256']}.items():
            require(sha(ROOT / filename) == value, 'Data mount source input changed: ' + filename)
        dependencies[name] = report
    base = dependencies['ios16-data-startup']
    require(base['combined_source_objects'] == 84 and len(base['combined_native_entries']) == 85, 'Wrong Data startup base')
    seed_path = ROOT / 'profiles/os/ios-16.7.16-20H392/data-volatile-image.json'
    seed = json.loads(seed_path.read_text())
    seed_report_path = ROOT / 'reports/ios16-data-volatile-image.json'
    seed_report = json.loads(seed_report_path.read_text())
    require(seed['volume_uuid'] == 'DAF0DD2B-1D90-5A73-A426-9306E1F967B5' and seed['size_bytes'] == 1 << 31 and
            seed_report['image_sha256'] == '8bbc59292a215c08fc40698dfe4c9b132633ae055afc956cf560626905c7a856', 'Selected mount seed differs')
    seed_header = ROOT / 'profiles/os/ios-16.7.16-20H392/storage/DodgeDataMountSeed.h'
    expected = ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n// Exact independently verified volatile APFS installation; not a phone identity.\n'
                '#pragma once\n#include <stdint.h>\nstatic const char dodgeDataMountVolumeUUID[] = "' + seed['volume_uuid'] + '";\n'
                'static const uint64_t dodgeDataMountSeedBytes = UINT64_C(2147483648);\nstatic const uint8_t dodgeDataMountSeedSHA256[32] = {' +
                ', '.join('0x' + seed_report['image_sha256'][i:i + 2] for i in range(0, 64, 2)) + '};\n')
    require(seed_header.read_text() == expected, 'Compiled Data identity does not match exact verified seed')
    sources = [ROOT / 'drivers/DodgeStorage/DodgeDataMount.cpp', ROOT / 'drivers/DodgeStorage/DodgeDataMountSyscall.c']
    objects = build_objects(sources, OUT, [ROOT / 'drivers/DodgeStorage', seed_header.parent])
    recipe = json.loads((OBJDIR / 'bsd/DEVELOPMENT/kern_exec.o.json').read_text().strip().rstrip(','))
    old_exec = Path(recipe['file']); before = old_exec.read_text()
    anchor = '\t(void) mach_vm_allocate_kernel(map, &scratch_addr, map_page_size, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_NONE);\n'
    addition = ('\t/* The separately gated Data path needs PID 1\'s live user map. */\n'
                '\textern int dodge_data_mount_boot(proc_t, user_addr_t, size_t);\n'
                '\tint dodge_data_error = dodge_data_mount_boot(p, (user_addr_t)scratch_addr, map_page_size);\n'
                '\tif (dodge_data_error) panic("dodge Data preparation before init failed: %d", dodge_data_error);\n')
    require(before.count(anchor) == 1, 'Original init scratch allocation anchor differs')
    after = before.replace(anchor, anchor + addition)
    patch = ROOT / 'patches/oneplus13/0010-ios16-init-data-mount.patch'
    overlay = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_data_mount_init_overlay']
    require(patch.read_text() == ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                fromfile='a/kern_exec.c', tofile='b/kern_exec.c')) and sha(patch) == overlay['sha256'] and
            sha(old_exec) == overlay['base_source_sha256'], 'Reviewed init Data overlay differs')
    exec_source = OUT / 'kern_exec.data.c'; exec_source.write_text(after)
    require(sha(exec_source) == overlay['output_source_sha256'], 'Init Data overlay output hash differs')
    exec_object = OUT / 'kern_exec.data.o'
    args, index = [], 0
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value == recipe['file']: args.append(str(exec_source))
        elif value in ('-o', '-MF', '-MJ'): index += 1
        elif value not in ('-MD', '-MP'): args.append(value)
        index += 1
    run([*args, '-iquote', str(old_exec.parent), '-o', str(exec_object)], OUT / 'init-compile.log', recipe['directory'])
    args_object = ROOT / dependencies['ios16-apfs-mount-source']['native_object']
    archive = OUT / 'libDodgeDataMount.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, args_object, *objects], check=True)
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    filelist_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    filelist = OUT / 'combined-native.filelist'
    rows = Path(filelist_arg.removeprefix('-Wl,-filelist,')).read_text().splitlines()
    old_exec_object = str(OBJDIR / 'bsd/DEVELOPMENT/kern_exec.o')
    require(rows.count(old_exec_object) == 1, 'Base init object in filelist is ambiguous')
    filelist.write_text(''.join((str(exec_object) if row == old_exec_object else row) + '\n' for row in rows))
    command[command.index(filelist_arg)] = '-Wl,-filelist,' + str(filelist)
    candidate = OUT / 'mach.data-mount'
    command += ['-Wl,-force_load,' + str(archive), '-o', str(candidate)]
    run(command, OUT / 'link.log', OBJDIR)
    raw = candidate.read_bytes(); names = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Data mount source has unresolved imports')
    for name, value in base['combined_original_bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Data mount original binding changed: ' + name)
    data_base = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
    require(check_table(raw, concrete_methods(ROOT / data_base['late_object'])) == 352, 'Data mount changed RamBlock ABI')
    hook = hook_readback(raw)
    init_hook = init_hook_readback(raw)
    broken = bytearray(raw)
    offset = backed_offset(macho(raw)['segments'], int(init_hook['data_boot_call'], 16), 4, len(raw))
    struct.pack_into('<I', broken, offset, 0xd503201f)
    try:
        init_hook_readback(broken)
    except ValueError as error:
        controls = [{'case': 'init-Data-call-NOP', 'result': 'REJECTED', 'reason': str(error)}]
    else:
        raise ValueError('Missing init Data call was accepted')
    entries = [*base['combined_native_entries'], *ENTRIES]
    require(all(name in names and names[name]['kind'] & 0x0e == 14 for name in entries), 'Data mount source entry is missing')
    link_path = OUT / 'link-command.json'; link_path.write_text(json.dumps(command, indent=2) + '\n')
    source_files = [Path(__file__), *sources, ROOT / 'drivers/DodgeStorage/DodgeDataMount.h',
                    ROOT / 'drivers/DodgeStorage/DodgeApfsMountArgs.h', ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.h',
                    seed_header, seed_path, patch, old_exec, ROOT / 'scripts/build_data_startup.py', ROOT / 'scripts/build_data_source.py']
    artifacts = [*objects, archive, candidate, link_path, OUT / 'compile-commands.json', exec_source, exec_object, filelist]
    report = {'result': 'IOS16_SEPARATE_INIT_CONTEXT_DATA_MOUNT_SOURCE_LINK_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {**{'reports/' + name + '.json': sha(ROOT / 'reports' / (name + '.json')) for name in dependencies},
                                         str(seed_report_path.relative_to(ROOT)): sha(seed_report_path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(candidate.relative_to(ROOT)),
              'candidate_sha256': sha(candidate), 'link_command': str(link_path.relative_to(ROOT)),
              'combined_source_objects': 87, 'combined_original_aliases': 332,
              'combined_original_bindings': base['combined_original_bindings'],
              'combined_native_entries': {name: hex(names[name]['value']) for name in entries}, 'actual_iobsd_hook': hook,
              'actual_init_hook': init_hook, 'init_overlay': overlay,
              'init_context_mount_api_prepared': True, 'init_boot_call_site_wired': True,
              'source_data_default_enabled': False, 'source_data_mount_default_enabled': False,
              'original_root_authentication_qualified': False, 'original_apfs_data_mount_qualified': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'negative_controls': controls, 'phone_operations': 'none',
              'scope': 'Separate 87-object/91-entry candidate adds actual ordinary-volume serialization, a bounded PID-1 process-context mount coordinator '
                       'and a C bridge using the real generated syscall structure. A separate kern_exec overlay calls the bounded gate after init scratch allocation and before launchd loading. '
                       'Default-off API checks selected seed identity, owners, original root identity and post-mount device/flags; it never claims root authentication '
                       'or invokes mounting from the Data worker. The actual original-root boot and the full APFS runtime remain unqualified.'}
    (ROOT / 'reports/ios16-data-mount-native.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: separate 87-object / 91-entry Data mount candidate, strict link, actual init hook and 332 original aliases preserved')


if __name__ == '__main__':
    main()
