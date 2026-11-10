#!/usr/bin/env python3
"""Build a deferred RamBlock class against iPhone storage and link a separate candidate."""
import json
from pathlib import Path
import struct
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, pinned_sources, require, symbols, macho
from prepare_initial_data import sha
from prepare_storage_abi import FIXTURE, HEADER, stage_headers
from check_data_lifecycle import check as check_lifecycle
from native_prelink import backed_offset

OUT = ROOT / 'build/cph2653-data-source'
INIT = '__GLOBAL__sub_I_DodgeRamBlock.cpp'


def concrete_methods(path):
    raw = path.read_bytes()
    image, names = inspect_object(raw), symbols(raw)
    symbol, = [s for s in names if s['name'] == '__ZTV14NativeRamBlock']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
    slots = {}
    for i in range(count):
        at, bits = struct.unpack_from('<2I', raw, offset + 8 * i)
        at += section['va']
        if symbol['value'] + 16 <= at < symbol['value'] + 16 + 190 * 8:
            require(bits >> 24 == 14 and (at - symbol['value'] - 16) % 8 == 0, 'Unexpected RamBlock table relocation')
            slots[(at - symbol['value'] - 16) // 8] = names[bits & 0xffffff]['name']
    require(set(slots) == set(range(190)) and '___cxa_pure_virtual' not in slots.values(), 'Incomplete RamBlock concrete table')
    return [slots[i] for i in range(190)]


def check_table(data, methods):
    image = macho(data)
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    at = backed_offset(image['segments'], names['__ZTV14NativeRamBlock']['value'] + 16, 190 * 8, len(data))
    require(list(struct.unpack_from('<190Q', data, at)) == [names[n]['value'] for n in methods], 'RamBlock concrete pointers changed')
    address = names['_dodge_ramblock_driver_bytes']['value']
    at = backed_offset(image['segments'], address, 8, len(data))
    move, ret = struct.unpack_from('<2I', data, at)
    require(move & 0xffe0001f == 0x52800000 and ret == 0xd65f03c0, 'RamBlock size leaf changed')
    size = (move >> 5) & 65535
    require(size > 144, 'RamBlock lost source state')
    for section in (s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__mod_init_func'):
        at = backed_offset(image['segments'], section['va'], section['size'], len(data))
        initializers = struct.unpack_from('<' + str(section['size'] // 8) + 'Q', data, at)
        require(names[INIT]['value'] not in initializers, 'RamBlock initializes its unloaded original parent early')
    return size


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reference = pinned_sources(('ramblock_reference',))['ramblock_reference']
    storage_path = ROOT / 'reports/ios16-storage-abi.json'
    storage = json.loads(storage_path.read_text())
    require(storage['builder_sha256'] == sha(ROOT / 'scripts/prepare_storage_abi.py') and
            sha(FIXTURE) == lock['iphone_storage_abi']['sha256'] and sha(HEADER) == lock['iphone_storage_abi']['header_sha256'],
            'Need the measured original iPhone storage contract')
    fixture = json.loads(FIXTURE.read_text())
    require((fixture['product'], fixture['build'], fixture['instance_bytes'], fixture['vtable_entries']) ==
            ('iPhone10,3', '20H392', 144, 190), 'Wrong storage ABI identity')
    for name, digest in storage['source_sha256'].items():
        require(sha(ROOT / name) == digest, 'Storage ABI source changed: ' + name)
    base_path = ROOT / 'reports/ios16-input-native.json'
    base = json.loads(base_path.read_text())
    for name, digest in json.loads((ROOT / base['link_manifest']).read_text()).items():
        require(sha(ROOT / name) == digest, 'Combined input source link input changed: ' + name)
    require(base['combined_source_objects'] == 81, 'Unexpected base source candidate')
    OUT.mkdir(exist_ok=True)
    _, include, target = stage_headers(OUT / 'abi')
    host = check_lifecycle(OUT)
    obj, lifecycle = build_objects([ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp', ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.cpp'], OUT, [include, reference, HEADER.parent],
                        ['-Wno-deprecated-declarations', '-Wno-macro-redefined', '-include', str(target)])
    methods = concrete_methods(obj)
    all_names = list(dict.fromkeys([*methods, *[row['name'] for row in fixture['methods']]]))
    readable = dict(zip(all_names, subprocess.check_output(['/usr/bin/llvm-cxxfilt-14'],
                       input='\n'.join(name[1:] for name in all_names) + '\n', text=True).splitlines()))
    overrides = []
    for row, actual in zip(fixture['methods'], methods):
        own = actual.startswith(('__ZN14NativeRamBlock', '__ZNK14NativeRamBlock'))
        if row['name'] == '___cxa_pure_virtual':
            require(own, 'RamBlock failed to implement a required transport operation')
        elif actual != row['name']:
            require(own and (row['slot'] in (0, 1) or readable[actual].split('::', 1)[1] == readable[row['name']].split('::', 1)[1]),
                    'RamBlock override differs from the original prototype at ' + str(row['slot']))
        if own:
            overrides.append(row['slot'])
    late = OUT / 'DodgeRamBlock.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, obj, late], check=True)
    def text(path):
        raw = path.read_bytes()
        section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(text(late) == text(obj) and not any(s['size'] for seg in inspect_object(late.read_bytes())['segments']
            for s in seg['sections'] if s['name'] == '__mod_init_func'), 'RamBlock deferral changed implementation text')
    archive = OUT / 'libDodgeRamBlock.a'
    # Ar replaces the single member in place; no previous candidate is selected.
    require(not any(s['size'] for seg in inspect_object(lifecycle.read_bytes())['segments'] for s in seg['sections'] if s['name'] == '__mod_init_func'),
            'Data lifecycle has an early dynamic initializer')
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, late, lifecycle], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 't', archive], text=True).splitlines() == [late.name, lifecycle.name] and
            subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, late.name]) == late.read_bytes(), 'RamBlock archive content differs')
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    candidate = OUT / 'mach.data'
    command += ['-Wl,-force_load,' + str(archive), '-o', str(candidate)]
    run(command, OUT / 'link.log', OBJDIR)
    data = candidate.read_bytes()
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    require(macho(data)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Combined Data candidate has undefined symbols')
    for name, address in base['combined_original_bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(address, 16), 'Original iPhone binding changed: ' + name)
    size = check_table(data, methods)
    controls = []
    image = macho(data)
    at = backed_offset(image['segments'], names['__ZTV14NativeRamBlock']['value'] + 16 + 171 * 8, 8, len(data))
    corrupt = bytearray(data); corrupt[at] ^= 1
    try:
        check_table(corrupt, methods)
    except ValueError as error:
        controls.append({'case': 'concrete-RamBlock-vtable', 'result': 'REJECTED', 'reason': str(error)})
    else:
        raise ValueError('Corrupt RamBlock table was accepted')
    link_command = OUT / 'link-command.json'
    link_command.write_text(json.dumps(command, indent=2) + '\n')
    source_files = [Path(__file__), ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp', ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.cpp',
                    ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.h', ROOT / 'scripts/check_data_lifecycle.py', ROOT / 'tests/DodgeRamBlockLifecycleTest.cpp',
                    *[p for folder in ('ufs_lifecycle_include', 'graphics_lifecycle_include') for p in (ROOT / 'tests' / folder).rglob('*.h')], ROOT / 'scripts/native_driver_build.py',
                    ROOT / 'scripts/prepare_storage_abi.py', FIXTURE, HEADER, target, *[reference / name for name in
                    ('NativeRamBlock.cpp', 'SparseDisk.h', 'SeedDisk.h', 'DirectDisk.h', 'PersistOverlay.h', 'LICENSE')]]
    artifacts = [obj, late, lifecycle, archive, candidate, OUT / 'compile-commands.json', link_command, ROOT / host['binary']]
    report = {'result': 'IOS16_SOURCE_RAMBLOCK_IPHONE_ABI_AND_STRICT_NATIVE_LINK_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392', 'source_reference': lock['ramblock_reference'],
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (storage_path, base_path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
              'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
              'late_object': str(late.relative_to(ROOT)), 'initializer': INIT, 'initializer_removed_from_early_registration': True,
              'initializer_implementation_text_unchanged': True, 'compiled_instance_bytes': size,
              'original_storage_base_bytes': 144, 'concrete_vtable_entries': 190, 'concrete_override_slots': overrides,
              'combined_source_objects': 83, 'combined_original_aliases': len(base['combined_original_bindings']), 'lifecycle_host_tests': host,
              'combined_original_bindings': base['combined_original_bindings'],
              'combined_native_entries': {name: hex(names[name]['value']) for name in
                                          [*base['combined_native_entries'], '_dodge_ramblock_driver_bytes', '_dodge_ramblock_driver_meta',
                                           '_dodge_ramblock_allocate', '_dodge_ramblock_prepare', '_dodge_ramblock_start', '_dodge_ramblock_status']},
              'negative_controls': controls, 'strict_no_undefined': True, 'new_original_bindings_invented': False,
              'ramblock_metadata_registered_or_started': False, 'default_kernel_selected': False,
              'original_parent_aware_deferred_registration_implemented': True, 'source_instance_and_provider_pinned_before_original_init': True,
              'source_init_attach_start_failure_latched_without_release': True, 'default_data_boot_argument_enabled': False,
              'original_components_embedded': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'remaining': ['Original parent init/start and disk-matching/completion lifecycle qualification.',
                            'Original APFS Data mount and iPhone-specific crypto/security lifecycle qualification.'],
              'scope': 'Exact pinned RamBlock class compiled with measured iPhone 144-byte/190-slot storage ABI. '
                       'Separate 83-object strict native link retains the existing source input/storage/display classes and 332 original aliases. '
                       'Deferred exact-parent registration and a default-off one-shot starter are implemented; the first instance/provider are pinned before original init, and failures are latched. '
                       'Thirty source lifecycle sanitizer cases use explicit peers; no original metadata registration, device start, original-component prelink or runtime result is claimed.'}
    (ROOT / 'reports/ios16-data-source.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: RamBlock {size} bytes / 190 slots, separate 83-object strict source link / {len(base["combined_original_bindings"])} original aliases; 30 lifecycle cases, constructor deferred')


if __name__ == '__main__':
    main()
