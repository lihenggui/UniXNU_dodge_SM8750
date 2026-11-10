#!/usr/bin/env python3
"""Derive exact iPhone framebuffer metadata/vtables before adapting private display code."""
import argparse
import copy
import hashlib
import json
import struct
import tomllib

from native_driver_build import ROOT, macho, require, sha
from native_prelink import backed_offset, exports, unserialize_xml

FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/display-abi.json'


def validate_fixture(actual, fixture):
    require(actual == fixture, 'Exact iPhone display metadata/vtables differ from the reviewed fixture')


def derive():
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    raw = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == profile['kernel']['prelink']['kernelcache_sha256'], 'Original iPhone KC changed')
    image = macho(raw)

    def read(address, count):
        offset = backed_offset(image['segments'], address, count, len(raw))
        return raw[offset:offset + count]

    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    entry, = [e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']
              if e['CFBundleIdentifier'] == 'com.apple.iokit.IOMobileGraphicsFamily']
    module = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
    text, = [s for s in module['segments'] if s['name'] == '__TEXT_EXEC']
    code = read(text['va'], text['filesize'])
    names = {name: address for address, group in exports(raw, image).items() for name in group}

    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Expected ADRP')
        value = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & ~4095) + ((value - (1 << 21) if value & (1 << 20) else value) << 12)

    def executable(address):
        return any(s['initprot'] & 4 and s['va'] <= address < s['va'] + s['filesize'] for s in image['segments'])

    classes = {}
    for index in range(40, len(code) - 48, 4):
        pc = text['va'] + index
        a, b = struct.unpack_from('<2I', code, index)
        if a & 0x9f00001f != 0x90000001 or b & 0xffc003ff != 0x91000021:
            continue
        name_address = adrp(pc, a) + ((b >> 10) & 4095)
        name = read(name_address, 32).split(b'\0', 1)[0].decode(errors='replace')
        if name not in ('IOMobileFramebuffer', 'IOMobileFramebufferService', 'IOMobileFramebufferLegacy'):
            continue
        setup = pc - 40
        words = struct.unpack('<22I', read(setup, 88))
        # Verify this's complete stack path, argument registers and final vptr
        # store in the actual unoptimized original OSMetaClass constructor.
        require(words[:3] == (0xd100c3ff, 0xa9027bfd, 0x910083fd) and
                words[5:10] == (0x91004108, 0xf9000be8, 0xf81f83a0, 0xf85f83a0, 0xf90007e0) and
                words[16:] == (0xf94007e0, 0xf9400be8, 0xf9000008, 0xa9427bfd, 0x9100c3ff, 0xd65f03c0),
                'Original metadata constructor stack/this flow differs')
        require(words[3] & 0x9f00001f == 0x90000008 and words[4] & 0xffc003ff == 0x91000108 and
                words[12] & 0x9f00001f == 0x90000002 and words[14] & 0xffe0001f == 0x52800003 and
                words[15] & 0xfc000000 == 0x94000000, 'Original metadata arguments differ')
        parent_address = adrp(setup + 48, words[12])
        if words[13] & 0xffc003ff == 0xf9400042:
            parent_address, = struct.unpack('<Q', read(parent_address + ((words[13] >> 10) & 4095) * 8, 8))
        else:
            require(words[13] & 0xffc003ff == 0x91000042, 'Original parent metadata is not ADRP/ADD or ADRP/LDR')
            parent_address += (words[13] >> 10) & 4095
        immediate = words[15] & 0x3ffffff
        stub = setup + 60 + 4 * (immediate - (1 << 26) if immediate & (1 << 25) else immediate)
        x, y, z = struct.unpack('<3I', read(stub, 12))
        require(x & 0x9f00001f == 0x90000010 and y & 0xffc003ff == 0xf9400210 and z == 0xd61f0200,
                'Original constructor call is not the expected import stub')
        target, = struct.unpack('<Q', read(adrp(stub, x) + ((y >> 10) & 4095) * 8, 8))
        require(target == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'Original class setup calls a different constructor')
        getter = setup - 24
        g = struct.unpack('<6I', read(getter, 24))
        require(g[:2] == (0xd10043ff, 0xf90007e0) and g[2] & 0x9f00001f == 0x90000000 and
                g[3] & 0xffc003ff == 0x91000000 and g[4:] == (0x910043ff, 0xd65f03c0),
                'Original getMetaClass getter flow differs')
        metadata = adrp(getter + 8, g[2]) + ((g[3] >> 10) & 4095)
        candidates = []
        for segment in module['segments']:
            if segment['name'] in ('__TEXT_EXEC', '__LINKEDIT') or not segment['filesize']:
                continue
            data, start = read(segment['va'], segment['filesize']), 0
            while True:
                found = data.find(struct.pack('<Q', getter), start)
                if found < 0:
                    break
                start = found + 1
                vp = segment['va'] + found - 56
                if vp % 8:
                    continue
                methods = []
                for slot in range(512):
                    address, = struct.unpack('<Q', read(vp + slot * 8, 8))
                    if not executable(address):
                        break
                    methods.append(address)
                if len(methods) >= 168:
                    require(read(vp - 16, 16) == bytes(16) and read(vp + len(methods) * 8, 24) == bytes(24),
                            'Original vtable has unexpected RTTI or trailing extent')
                    candidates.append((vp, methods))
        vp, methods = candidates[0] if len(candidates) == 1 else (None, None)
        require(vp is not None and name not in classes, 'Ambiguous original framebuffer class/table')
        classes[name] = {'metadata': hex(metadata), 'parent_metadata': hex(parent_address),
            'instance_bytes': (words[14] >> 5) & 65535, 'metadata_setup': hex(setup),
            'metadata_setup_sha256': hashlib.sha256(read(setup, 88)).hexdigest(), 'metadata_getter': hex(getter),
            'metadata_getter_sha256': hashlib.sha256(read(getter, 24)).hexdigest(), 'vptr': hex(vp),
            'virtual_entries': len(methods), 'vtable_sha256': hashlib.sha256(read(vp, len(methods) * 8)).hexdigest(),
            'abstract_slots': [i for i, address in enumerate(methods) if address == names['___cxa_pure_virtual']]}
    require(len(classes) == 3, 'Missing exact original framebuffer classes')
    require(classes['IOMobileFramebuffer']['parent_metadata'] == hex(names['__ZN9IOService10gMetaClassE']) and
            classes['IOMobileFramebufferService']['parent_metadata'] == classes['IOMobileFramebuffer']['metadata'] and
            classes['IOMobileFramebufferLegacy']['parent_metadata'] == classes['IOMobileFramebufferService']['metadata'],
            'Original framebuffer class hierarchy differs')
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392', 'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(),
            'family_version': entry['CFBundleVersion'], 'family_text_sha256': hashlib.sha256(code).hexdigest(), 'classes': classes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record-fixture', action='store_true')
    args = parser.parse_args()
    actual = derive()
    if args.record_fixture:
        require(not FIXTURE.exists(), 'A reviewed display fixture already exists')
        FIXTURE.write_text(json.dumps(actual, indent=2) + '\n')
        print('Derived new exact-original display fixture for review')
        return
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_display_fixture']
    require(sha(FIXTURE) == lock['sha256'], 'Reviewed iPhone display fixture changed')
    fixture = json.loads(FIXTURE.read_text())
    validate_fixture(actual, fixture)
    negatives = []
    for field, wrong in (('instance_bytes', 6304), ('virtual_entries', 358)):
        changed = copy.deepcopy(fixture)
        changed['classes']['IOMobileFramebufferLegacy'][field] = wrong
        try:
            validate_fixture(actual, changed)
        except ValueError:
            negatives.append(field)
        else:
            raise ValueError('iPadOS 17 Legacy layout was incorrectly accepted')
    report = {'result': 'IOS16_ORIGINAL_DISPLAY_STATIC_AUDIT_PASS', **actual,
              'fixture_sha256': sha(FIXTURE), 'ipad17_legacy_size_and_vtable_controls_rejected': negatives,
              'private_method_prototypes_qualified': False, 'swap_request_layout_qualified': False,
              'iosurface_field_layout_qualified': False, 'display_provider_implemented': False, 'hardware_tested': False,
              'scope': 'Exact original class hierarchy, instance extents and complete vtable boundaries; not a display backend or runtime qualification.'}
    (ROOT / 'reports/ios16-display-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact iPhone display hierarchy; Legacy is 5728 bytes / 338 slots, rejecting the 17 reference layout')


if __name__ == '__main__':
    main()
