#!/usr/bin/env python3
"""Derive the iPhone 20H392 accelerator base from unchanged original code."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tomllib

from native_driver_build import ROOT, NATIVE, compile_command, inspect_object, require, sha
from native_prelink import backed_offset, exports, macho, unique_kernel_binding, unserialize_xml

PROFILE = ROOT / 'profiles/os/ios-16.7.16-20H392'
FIXTURE = PROFILE / 'graphics-abi.json'


def validate_fixture(actual, fixture):
    require(actual == fixture, 'The exact iPhone accelerator identity differs from the reviewed fixture')


def derive():
    profile = tomllib.loads((PROFILE / 'profile.toml').read_text())
    raw = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    original_sha = hashlib.sha256(raw).hexdigest()
    require(original_sha == profile['kernel']['prelink']['kernelcache_sha256'], 'Original iPhone kernelcache changed')
    image = macho(raw)

    def read(address, count):
        offset = backed_offset(image['segments'], address, count, len(raw))
        return raw[offset:offset + count]

    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    entries = {e['CFBundleIdentifier']: e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']}
    entry = entries['com.apple.iokit.IOGPUFamily']
    module = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
    text, = [s for s in module['segments'] if s['name'] == '__TEXT_EXEC']
    code = read(text['va'], text['filesize'])
    original_exports = exports(raw, image)
    names = {name: address for address, group in original_exports.items() for name in group}

    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Expected an actual ADRP instruction')
        imm = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & ~4095) + ((imm - (1 << 21) if imm & (1 << 20) else imm) << 12)

    def branch(pc):
        word, = struct.unpack('<I', read(pc, 4))
        require(word & 0x7c000000 == 0x14000000, 'Expected an actual direct branch')
        imm = word & 0x3ffffff
        return pc + 4 * (imm - (1 << 26) if imm & (1 << 25) else imm)

    def imported(stub):
        a, b, c = struct.unpack('<3I', read(stub, 12))
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200,
                'Expected an unchanged original ARM64 import stub')
        return struct.unpack('<Q', read(adrp(stub, a) + ((b >> 10) & 4095) * 8, 8))[0]

    # The actual class setup keeps its metadata in x19 across OSMetaClass C2.
    # Match every instruction that supplies this/name/parent/size and installs
    # the resulting metadata vptr. No runtime observation from another OS is used.
    setups = []
    for index in range(0, len(code) - 48, 4):
        pc = text['va'] + index
        a, b, c, d, e, f, g, h, j, k, l, m = struct.unpack_from('<12I', code, index)
        if not (a & 0x9f00001f == 0x90000013 and b & 0xffc003ff == 0x91000273 and
                c & 0x9f00001f == 0x90000001 and d & 0xffc003ff == 0x91000021 and
                e & 0x9f00001f == 0x90000002 and f & 0xffc003ff == 0xf9400042 and
                g == 0xaa1303e0 and h & 0xffe0001f == 0x52800003 and
                j & 0xfc000000 == 0x94000000 and k & 0x9f00001f == 0x90000008 and
                l & 0xffc003ff == 0x91000108 and m == 0xf9000268):
            continue
        name = read(adrp(pc + 8, c) + ((d >> 10) & 4095), 16)
        if name != b'IOAcceleratorES\0':
            continue
        parent, = struct.unpack('<Q', read(adrp(pc + 16, e) + ((f >> 10) & 4095) * 8, 8))
        require(parent == names['__ZN9IOService10gMetaClassE'], 'Original accelerator parent is not IOService')
        require(imported(branch(pc + 32)) == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'Original metadata constructor differs')
        require((h >> 5) & 65535 == 136, 'Original accelerator has a different instance extent')
        setups.append((pc, adrp(pc, a) + ((b >> 10) & 4095)))
    setup, = setups
    setup_pc, meta = setup
    require(any(s['initprot'] & 2 and s['va'] <= meta < s['va'] + s['size'] for s in module['segments']),
            'Class metadata is outside its original writable component')
    getters = []
    for index in range(0, len(code) - 12, 4):
        pc = text['va'] + index
        a, b, c = struct.unpack_from('<3I', code, index)
        if (a & 0x9f00001f == 0x90000000 and b & 0xffc003ff == 0x91000000 and
                c == 0xd65f03c0 and adrp(pc, a) + ((b >> 10) & 4095) == meta):
            getters.append(pc)
    getter, = getters
    base_vptr = names['__ZTV9IOService'] + 16
    base = struct.unpack('<168Q', read(base_vptr, 168 * 8))
    tables = []
    for segment in module['segments']:
        if segment['name'] in ('__TEXT_EXEC', '__LINKEDIT') or not segment['filesize']:
            continue
        data, index = read(segment['va'], segment['filesize']), 0
        while True:
            found = data.find(struct.pack('<Q', getter), index)
            if found < 0:
                break
            index = found + 1
            vp = segment['va'] + found - 7 * 8
            if vp % 8:
                continue
            values = struct.unpack('<168Q', read(vp, 168 * 8))
            changed = [i for i, (a, b) in enumerate(zip(base, values)) if a != b]
            if changed == [0, 1, 7] and read(vp + 168 * 8, 24) == bytes(24):
                tables.append((vp, values))
    vp, values = tables[0] if len(tables) == 1 else (None, None)
    require(vp is not None, 'Original 168-entry accelerator table is not uniquely identified')
    constructors = []
    for index in range(12, len(code) - 12, 4):
        pc = text['va'] + index
        a, b, c = struct.unpack_from('<3I', code, index)
        if not (a & 0x9f00001f == 0x90000008 and b & 0xffc003ff == 0x91000108 and c == 0xf9000008 and
                adrp(pc, a) + ((b >> 10) & 4095) == vp):
            continue
        start = pc - 12
        words = struct.unpack('<8I', read(start, 32))
        require(words[0:2] == (0xa9bf7bfd, 0x910003fd) and words[6:8] == (0xa8c17bfd, 0xd65f03c0),
                'Original constructor has additional instructions')
        require(imported(branch(start + 8)) == names['__ZN9IOServiceC2EPK11OSMetaClass'],
                'Original constructor does not delegate to the true IOService constructor')
        constructors.append(start)
    require(len(constructors) == 2, 'Expected the two actual compatible constructor aliases')
    require(imported(branch(values[0])) == names['__ZN9IOServiceD2Ev'], 'Original destructor chain differs')

    blocks = [(address, 32, 'constructor') for address in constructors]
    blocks += [(values[0], 4, 'nondeleting_destructor'), (getter, 12, 'get_meta_class'),
               (setup_pc, 48, 'class_metadata_setup')]
    fixture = {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
               'original_sha256': original_sha, 'component': 'com.apple.iokit.IOGPUFamily',
               'component_version': entry['CFBundleVersion'],
               'original_iogpu_text_sha256': hashlib.sha256(code).hexdigest(),
               'metaclass': hex(meta), 'instance_bytes': 136, 'vptr': hex(vp), 'virtual_entries': 168,
               'operational_overrides': [], 'metadata_overrides': [0, 1, 7],
               'protected_compatible_constructor_aliases': [hex(a) for a in constructors],
               'nondeleting_destructor': hex(values[0]), 'get_meta_class': hex(getter),
               'class_metadata_setup': hex(setup_pc),
               'original_vtable_sha256': hashlib.sha256(read(vp, 168 * 8)).hexdigest(),
               'original_ioservice_vtable_sha256': hashlib.sha256(read(base_vptr, 168 * 8)).hexdigest(),
               'code_blocks': [{'address': hex(a), 'bytes': size, 'purpose': purpose,
                                'sha256': hashlib.sha256(read(a, size)).hexdigest()} for a, size, purpose in blocks]}

    native = NATIVE.read_bytes()
    native_image = macho(native)
    native_exports = exports(native, native_image)
    native_names = {}
    for address, group in native_exports.items():
        for name in group:
            native_names.setdefault(name, set()).add(address)
    native_vptr = next(iter(native_names['__ZTV9IOService'])) + 16

    def native_read(address, count):
        offset = backed_offset(native_image['segments'], address, count, len(native))
        return native[offset:offset + count]

    native_base = struct.unpack('<168Q', native_read(native_vptr, 168 * 8))
    # The original complete-object destructor is stripped from its symbol table.
    # Clang may outline the empty base destructors as pure tail branches. Follow
    # only unconditional B instructions; the final entire body must be identical.
    trivial = struct.pack('<3I', 0x92800008, 0xf9000008, 0xd65f03c0)
    native_destructor = native_base[0]
    tail_aliases = []
    for _ in range(8):
        word, = struct.unpack('<I', native_read(native_destructor, 4))
        if word & 0xfc000000 != 0x14000000:
            break
        imm = word & 0x3ffffff
        destination = native_destructor + 4 * (imm - (1 << 26) if imm & (1 << 25) else imm)
        tail_aliases.append({'address': hex(native_destructor), 'target': hex(destination),
                             'target_names': native_exports.get(destination, [])})
        native_destructor = destination
    require(read(base[0], 12) == trivial == native_read(native_destructor, 12),
            'The complete-object destructor chain has different instructions or effects')
    require(native_base[0] in native_names['__ZN9IOServiceD1Ev'], 'Native complete-object destructor identity changed')
    for index in range(1, 168):
        require(unique_kernel_binding(base[index], original_exports, native_names) == native_base[index],
                f'Native IOService virtual slot differs from the original: {index}')
    native_evidence = {'native_kernel_sha256': hashlib.sha256(native).hexdigest(),
                       'ioservice_named_virtual_slots_matched': 167,
                       'ioservice_complete_destructor_bytes_matched': 12,
                       'native_complete_destructor_tail_aliases': tail_aliases,
                       'complete_destructor_sha256': hashlib.sha256(trivial).hexdigest()}
    return fixture, native_evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-fixture', action='store_true', help='Create a missing exact-original fixture; never replace a different one')
    args = parser.parse_args()
    actual, evidence = derive()
    if args.write_fixture and not FIXTURE.exists():
        FIXTURE.write_text(json.dumps(actual, indent=2) + '\n')
    fixture = json.loads(FIXTURE.read_text())
    validate_fixture(actual, fixture)
    controls = []
    for field, value in (('original_sha256', '0' * 64), ('metaclass', '0x1'), ('instance_bytes', 144)):
        wrong = copy.deepcopy(fixture)
        wrong[field] = value
        try:
            validate_fixture(actual, wrong)
        except ValueError:
            controls.append(field)
        else:
            raise ValueError('Incorrect graphics fixture was accepted: ' + field)
    out = ROOT / 'build/cph2653-graphics-abi'
    out.mkdir(parents=True, exist_ok=True)
    shape = out / 'shape.cpp'
    shape.write_text('#include "OriginalAcceleratorABI.h"\n')
    command = compile_command(shape, out / 'shape.o', [PROFILE / 'graphics'])
    with (out / 'compile.log').open('w') as log:
        process = subprocess.run(command['arguments'], cwd=command['directory'], stdout=log, stderr=subprocess.STDOUT)
    require(process.returncode == 0, 'Native graphics class assertions failed; see build/cph2653-graphics-abi/compile.log')
    inspect_object((out / 'shape.o').read_bytes())
    report = {'result': 'IOACCELERATOR_BASE_STATIC_AUDIT_PASS', 'fixture': str(FIXTURE.relative_to(ROOT)),
              'fixture_sha256': sha(FIXTURE), 'identity': fixture, 'native_comparison': evidence,
              'native_header_assertions': ['sizeof(IOService)==136', 'sizeof(IOAcceleratorES)==136', 'sizeof(OSMetaClass)==40'],
              'header_sha256': sha(PROFILE / 'graphics/OriginalAcceleratorABI.h'),
              'compiler_recipe_sha256': command['recipe_sha256'], 'negative_fixtures_rejected': controls,
              'base_shape_statically_qualified': True, 'all_graphics_abi_qualified': False,
              'original_code_modified': False, 'class_initialized': False, 'hardware_tested': False,
              'scope': 'Exact iPhone base-class ancestry, whole virtual table, full constructor/destructor/getter bodies, '
                       'metadata setup and source IOService prefix. No original IOGPU runtime or full graphics ABI qualification.'}
    (ROOT / 'reports/ios16-graphics-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact iPhone IOAcceleratorES base, 168 native IOService slots, class extents and three wrong-fixture refusals')


if __name__ == '__main__':
    main()
