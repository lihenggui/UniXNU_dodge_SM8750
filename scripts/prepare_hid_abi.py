#!/usr/bin/env python3
"""Audit the exact original iPhone HID base; reject an incomplete public ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

from check_ios16_swap import original_input
from native_driver_build import ROOT, NATIVE, build_objects, compile_command, inspect_object, pinned_sources, require, sha, symbols
from native_prelink import backed_offset, exports, macho, unserialize_xml

OUT = ROOT / 'build/ios16-hid-abi'
FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/hid-device-abi.json'
FACTS = FIXTURE.parent / 'input/OriginalHidDeviceFacts.h'


def stage_reference():
    refs = pinned_sources(('iohid_headers_reference', 'iographics_headers_reference', 'iphoneos_sdk_reference'))
    public, graphics = refs['iohid_headers_reference'], refs['iographics_headers_reference']
    sdk = refs['iphoneos_sdk_reference'] / 'iPhoneOS16.5.sdk'
    include = OUT / 'include'
    staged_sources = []
    for source, destination in ((public / 'IOHIDFamily', include / 'IOKit/hid'),
                                (public / 'IOHIDSystem/IOKit/hidsystem', include / 'IOKit/hidsystem')):
        destination.mkdir(parents=True, exist_ok=True)
        for path in sorted(source.glob('*.h')):
            shutil.copyfile(path, destination / path.name)
            staged_sources.append(path)
    hid = include / 'HIDDriverKit'
    hid.mkdir(exist_ok=True)
    for path in (public / 'IOHIDFamily/IOHIDDeviceTypes.h', public / 'HIDDriverKit/IOHIDDevice.iig'):
        shutil.copyfile(path, hid / path.name)
        staged_sources.append(path)
    destination = include / 'IOKit/graphics'
    destination.mkdir(exist_ok=True)
    for name in ('IOGraphicsTypes.h', 'IOGraphicsTypesPrivate.h'):
        path = graphics / 'IOGraphicsFamily/IOKit/graphics' / name
        shutil.copyfile(path, destination / name)
        staged_sources.append(path)
    target = sdk / 'usr/include/TargetConditionals.h'
    shutil.copyfile(target, include / target.name)
    probe = OUT / 'HidHeaderReference.cpp'
    probe.write_text('#include <IOKit/hid/IOHIDDevice.h>\n'
                     'OSDefineMetaClassAndAbstractStructors(IOHIDDevice,IOService)\n'
                     'static_assert(sizeof(IOHIDDevice)==208,"Original iPhone instance size");\n'
                     'static_assert(sizeof(IOHIDReportType)==4,"Public report-type width");\n'
                     'static_assert(TARGET_OS_IOS && !TARGET_OS_OSX && !TARGET_OS_SIMULATOR,"Actual iPhone target");\n')
    recipe = compile_command(probe, OUT / 'HidHeaderReference.o', [include],
                             ['-include', str(target), '-Wno-macro-redefined', '-Wno-deprecated-declarations'])
    # IIG parses the .iig declarations, then the real kernel compiler consumes
    # its header. It never needs a fabricated DriverKit SDK or type definitions.
    native = recipe['arguments']
    directories = []
    i = 0
    while i < len(native):
        arg = native[i]
        if arg in ('-I', '-iquote', '-isystem'):
            i += 1
            directories += [arg, str((Path(recipe['directory']) / native[i]).resolve())]
        elif arg.startswith('-I') and len(arg) > 2:
            directories += ['-I' + str((Path(recipe['directory']) / arg[2:]).resolve())]
        i += 1
    tool = ROOT / '.toolchains/host/bin/iig'
    host = json.loads((ROOT / 'reports/host-tools.json').read_text())
    require(sha(tool) == host['iig_executable_sha256'], 'Pinned real IIG tool changed')
    command = [str(tool), '--def', str(hid / 'IOHIDDevice.iig'), '--header', str(hid / 'IOHIDDevice.h'),
               '--impl', str(OUT / 'IOHIDDevice.iig.cpp'), '--framework-name', 'HIDDriverKit', '--deployment-target', '16.0', '--',
               '-x', 'c++', '-std=gnu++17', '--target=arm64-apple-ios16.0', '-D__IIG=1', '-DDRIVERKIT_PRIVATE=1',
               '-DXNU_TARGET_OS_IOS=1', '-stdlib=libc++', '-isysroot', str(sdk), '-I' + str(include), *directories,
               '-include', str(hid / 'IOHIDDeviceTypes.h')]
    # Types precede OSObject.iig's KERNEL annotation macro, as required when
    # Apple's HID declarations are parsed together with the XNU .iig files.
    with (OUT / 'iig.log').open('w') as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    (OUT / 'iig-command.json').write_text(json.dumps(command, indent=2) + '\n')
    objects = build_objects([probe], OUT, [include], ['-include', str(target), '-Wno-macro-redefined', '-Wno-deprecated-declarations'])
    return refs, objects[0], [*staged_sources, target], hid / 'IOHIDDevice.h', tool


def public_methods(path):
    raw = path.read_bytes()
    image, table = inspect_object(raw), symbols(raw)
    vtable, = [s['value'] for s in table if s['name'] == '__ZTV11IOHIDDevice']
    section = next(s for seg in image['segments'] for s in seg['sections'] if s['va'] <= vtable < s['va'] + s['size'])
    offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
    references = {}
    for i in range(count):
        at, bits = struct.unpack_from('<2I', raw, offset + i * 8)
        if bits >> 24 == 14:
            references[section['va'] + at] = table[bits & 0xffffff]['name']
    result, at = [], vtable + 16
    while at in references:
        result.append(references[at])
        at += 8
    require(len(result) == 205 and [i for i, n in enumerate(result) if n == '___cxa_pure_virtual'] == [180],
            'Public HID annotation shape changed')
    return result


def derive(reference, mutation=None):
    identity, raw, image, original_read = original_input()
    names = {n: a for a, group in exports(raw, image).items() for n in group}
    info = next(s for s in image['segments'] if s['name'] == '__PRELINK_INFO')
    component = next(e for e in unserialize_xml(original_read(info['va'], info['filesize']))['_PrelinkInfoDictionary']
                     if e['CFBundleIdentifier'] == 'com.apple.iokit.IOHIDFamily')
    module = macho(raw, backed_offset(image['segments'], component['_PrelinkExecutableLoadAddr'], 32, len(raw)))

    def read(a, n):
        data = bytearray(original_read(a, n))
        if mutation and a <= mutation[0] < a + n:
            data[mutation[0] - a] ^= mutation[1]
        return bytes(data)

    def inside(a, executable=False):
        return any(s['va'] <= a < s['va'] + s['size'] and (not executable or s['initprot'] & 4) for s in module['segments'])

    def words(a, n):
        return struct.unpack('<' + str(n) + 'I', read(a, n * 4))

    def adrp(a, word):
        require(word & 0x9f000000 == 0x90000000, 'HID ADRP changed')
        value = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (a & ~4095) + ((value - (1 << 21) if value & (1 << 20) else value) << 12)

    def branch(a, call=True):
        word, = words(a, 1)
        require(word & 0xfc000000 == (0x94000000 if call else 0x14000000), 'HID branch shape changed')
        value = word & 0x3ffffff
        return a + 4 * (value - (1 << 26) if value & (1 << 25) else value)

    def stub(a):
        x, y, z = words(a, 3)
        require(x & 0x9f00001f == 0x90000010 and y & 0xffc003ff == 0xf9400210 and z == 0xd61f0200, 'HID import stub changed')
        return struct.unpack('<Q', read(adrp(a, x) + ((y >> 10) & 4095) * 8, 8))[0]

    constructor = 0xfffffff005726b9c
    code = words(constructor, 8)
    require(code[:2] == (0xa9bf7bfd, 0x910003fd) and code[5:] == (0xf9000008, 0xa8c17bfd, 0xd65f03c0) and
            stub(branch(constructor + 8)) == names['__ZN9IOServiceC2EPK11OSMetaClass'], 'HID actual protected constructor differs')
    vptr = adrp(constructor + 12, code[3]) + ((code[4] >> 10) & 4095)
    methods = struct.unpack('<207Q', read(vptr, 207 * 8))
    native = struct.unpack('<168Q', read(names['__ZTV9IOService'] + 16, 168 * 8))
    require(read(vptr + 207 * 8, 24) == bytes(24) and all(methods), 'Original HID 207-slot extent changed')
    overrides = [i for i in range(168) if methods[i] != native[i]]
    require(overrides == [0, 1, 7, 12, 14, 21, 23, 76, 81, 82, 86, 87, 91, 92, 93, 101, 132, 140], 'HID native override set changed')
    require([i for i, a in enumerate(methods) if a == names['___cxa_pure_virtual']] == [180], 'HID descriptor pure slot changed')
    destructor = 0xfffffff005726bbc
    require(stub(branch(destructor, False)) == names['__ZN9IOServiceD2Ev'] and
            words(methods[0], 1) == words(methods[1], 1) == (0xd4200020,), 'HID abstract/protected destructor changed')
    getmeta = methods[7]
    a, b, c = words(getmeta, 3)
    require(a & 0x9f00001f == 0x90000000 and b & 0xffc003ff == 0x91000000 and c == 0xd65f03c0, 'HID class identity shape changed')
    meta = adrp(getmeta, a) + ((b >> 10) & 4095)
    setup = 0xfffffff005726bd4
    code = words(setup, 13)
    require(code[:2] == (0xa9bf7bfd, 0x910003fd) and code[6] == 0x52801a03 and
            stub(branch(setup + 28)) == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'HID metadata constructor/208-byte size changed')
    label = adrp(setup + 8, code[2]) + ((code[3] >> 10) & 4095)
    parent, = struct.unpack('<Q', read(adrp(setup + 16, code[4]) + ((code[5] >> 10) & 4095) * 8, 8))
    require(read(label, 12) == b'IOHIDDevice\0' and parent == names['__ZN9IOService10gMetaClassE'], 'HID actual name or parent changed')
    require(inside(vptr) and inside(meta) and inside(constructor, True), 'HID class identity escaped its original component')
    rows, mismatches = [], []
    for i, address in enumerate(methods):
        native_slot = i < 168 and i not in overrides
        if native_slot:
            require(reference[i] in names and names[reference[i]] == address, 'HID inherited native method mismatch')
        elif i != 180:
            require(inside(address, True), 'HID owned virtual entry escaped executable text')
        counterpart = reference[i] if i < len(reference) else None
        if counterpart in names and names[counterpart] != address:
            mismatches.append(i)
        rows.append({'slot': i, 'address': hex(address), 'native_inherited_exact': native_slot,
                     'public_reference_declaration': counterpart, 'original_owned_prototype_qualified': False})
    require(mismatches == [76, 81, 82], 'Public HID/native override difference changed')
    blocks = {name: {'address': hex(a), 'bytes': n, 'sha256': hashlib.sha256(read(a, n)).hexdigest()} for name, a, n in
              (('protected_constructor', constructor, 32), ('protected_destructor', destructor, 4),
               ('get_meta_class', getmeta, 12), ('metadata_constructor', setup, 52))}
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392', 'module': 'com.apple.iokit.IOHIDFamily',
            'original_kernelcache_sha256': identity['original_kernelcache_sha256'], 'class': 'IOHIDDevice', 'instance_bytes': 208,
            'parent': 'IOService', 'parent_instance_bytes': 136, 'vptr': hex(vptr), 'metaclass': hex(meta),
            'protected_constructor': hex(constructor), 'protected_destructor': hex(destructor), 'vtable_entries': 207,
            'vtable_sha256': hashlib.sha256(read(vptr, 207 * 8)).hexdigest(), 'pure_virtual_slots': [180],
            'overridden_native_slots': overrides, 'public_reference_entries': 205, 'public_reference_native_mismatches': mismatches,
            'unmatched_tail_slots': [205, 206], 'public_header_is_exact_driver_abi': False, 'methods': rows, 'blocks': blocks,
            'full_hid_prototypes_qualified': False, 'source_driver_installed': False, 'hardware_tested': False}


def facts(contract):
    return ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n'
            '// Original iPhone facts only. This deliberately does not declare a C++ HID driver class.\n'
            '#pragma once\nconstexpr unsigned DodgeOriginalHidDeviceBytes=208;\n'
            'constexpr unsigned DodgeOriginalHidDeviceSlots=207;\n'
            'constexpr unsigned DodgePublicHidReferenceSlots=205;\n'
            'constexpr bool DodgePublicHidHeaderIsExactDriverABI=false;\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    refs, obj, public_files, generated, tool = stage_reference()
    reference = public_methods(obj)
    contract = derive(reference)
    if args.write:
        require(not FIXTURE.exists() and not FACTS.exists(), 'Refuse to replace reviewed HID inputs')
        FACTS.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps(contract, indent=2) + '\n')
        FACTS.write_text(facts(contract))
    require(json.loads(FIXTURE.read_text()) == contract and FACTS.read_text() == facts(contract), 'Reviewed original HID contract changed')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    if not args.write:
        require(lock['iphone_hid_abi']['sha256'] == sha(FIXTURE) and lock['iphone_hid_abi']['header_sha256'] == sha(FACTS), 'HID contract pin changed')
    controls = []
    for name, at, bit in (('inherited-slot-pointer', int(contract['vptr'], 16) + 2 * 8, 1),
                          ('metadata-instance-size', 0xfffffff005726bd4 + 24, 0x20)):
        try:
            derive(reference, (at, bit))
        except ValueError as error:
            controls.append({'case': name, 'result': 'REJECTED', 'check': str(error)})
        else:
            raise ValueError('Corrupt HID class was accepted: ' + name)
    files = [Path(__file__), ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/check_ios16_swap.py', FIXTURE, FACTS, *public_files]
    manifest = OUT / 'compile-commands.json'
    result = {'result': 'IOS16_ORIGINAL_HID_CLASS_FACTS_AND_PUBLIC_ABI_DIFFERENCE_AUDIT_PASS', 'builder_sha256': sha(Path(__file__)),
              'native_kernel_sha256': sha(NATIVE), 'original_kernelcache_sha256': contract['original_kernelcache_sha256'],
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'public_references': {n: lock[n] for n in ('iohid_headers_reference', 'iographics_headers_reference', 'iphoneos_sdk_reference')},
              'contract': str(FIXTURE.relative_to(ROOT)), 'contract_sha256': sha(FIXTURE), 'facts_header': str(FACTS.relative_to(ROOT)),
              'facts_header_sha256': sha(FACTS), 'reference_object': str(obj.relative_to(ROOT)), 'reference_object_sha256': sha(obj),
              'generated_iig_header': str(generated.relative_to(ROOT)), 'generated_iig_header_sha256': sha(generated), 'iig_tool_sha256': sha(tool),
              'iig_command': str((OUT / 'iig-command.json').relative_to(ROOT)), 'iig_command_sha256': sha(OUT / 'iig-command.json'),
              'compile_manifest': str(manifest.relative_to(ROOT)), 'compile_manifest_sha256': sha(manifest),
              'instance_bytes': 208, 'original_vtable_entries': 207, 'public_reference_vtable_entries': 205,
              'pure_descriptor_slot': 180, 'exact_native_inherited_slots': 150, 'public_reference_native_mismatches': [76, 81, 82],
              'negative_controls': controls, 'uses_actual_pinned_iphone_sdk_conditionals': True,
              'public_header_is_exact_driver_abi': False, 'full_hid_prototypes_qualified': False, 'complete_typed_hid_driver_header_generated': False,
              'reference_implementation_linked_or_executed': False, 'target_touch_rail_policy_implemented': False,
              'input_driver_archive_built': False, 'default_kernel_selected': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'scope': 'The real native iOS16 compiler consumes unchanged pinned Apple HID/graphics type headers and an actual IIG-generated header. '
                       'The exact original iPhone has 208 bytes/207 virtual entries; the public reference emits 205, with additional native override differences at 76/81/82. '
                       'Actual original metadata, protected C2/D2, native inherited entries and complete vtable identity are pinned and corruptions rejected. '
                       'Public declarations are reference candidates, not proof of every original owned prototype. No invented signatures, HID class installation, '
                       'original HID runtime, touch rail sequence or hardware result.'}
    (ROOT / 'reports/ios16-hid-abi.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: exact original HID 208 bytes / 207 slots; public 205-slot header mismatch and three overrides recorded; no guessed driver interface')


if __name__ == '__main__':
    main()
