#!/usr/bin/env python3
"""Derive the exact iPhone AMFI/PMGR boundary; no substitute power or latch implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, require, macho
from native_prelink import backed_offset, exports, unserialize_xml
from prepare_initial_data import sha

OUT = ROOT / 'build/ios16-pmgr-abi'
FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/pmgr-contract.json'
KERNEL = ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed'


def reviewed():
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_pmgr_contract']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and pin['sha256'] == sha(FIXTURE) and
            (pin['product'], pin['build']) == ('iPhone10,3', '20H392'), 'Reviewed iPhone PMGR pin changed')
    return json.loads(FIXTURE.read_text()), pin


def original():
    raw = KERNEL.read_bytes(); image = macho(raw)
    pin = json.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/security-init.json').read_text())['original_sha256']
    require(hashlib.sha256(raw).hexdigest() == pin, 'Need the exact pinned iPhone kernelcache')
    def read(address, count):
        offset = backed_offset(image['segments'], address, count, len(raw)); return raw[offset:offset + count]
    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    entries = {e['CFBundleIdentifier']: e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']}
    names = {name: address for address, group in exports(raw, image).items() for name in group}
    return raw, image, read, entries, names


def derive(mutation=None):
    raw, image, original_read, entries, names = original()
    def read(address, count):
        data = bytearray(original_read(address, count))
        if mutation and address <= mutation[0] < address + count:
            at = mutation[0] - address; value, = struct.unpack_from('<I', data, at)
            struct.pack_into('<I', data, at, value ^ mutation[1])
        return bytes(data)
    def words(address, count): return struct.unpack('<' + str(count) + 'I', read(address, count * 4))
    def pointer(address): return struct.unpack('<Q', read(address, 8))[0]
    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'PMGR ADRP changed')
        delta = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & -4096) + ((delta - (1 << 21) if delta & (1 << 20) else delta) << 12)
    def branch(pc, call=True):
        word, = words(pc, 1)
        require(word & 0xfc000000 == (0x94000000 if call else 0x14000000), 'PMGR direct branch changed')
        delta = word & 0x3ffffff
        return pc + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
    def imported(pc):
        a, b, c = words(pc, 3)
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200, 'PMGR import stub changed')
        slot = adrp(pc, a) + ((b >> 10) & 4095) * 8
        return slot, pointer(slot)
    def executable(address):
        return any(s['initprot'] & 4 and s['va'] <= address < s['va'] + s['filesize'] for s in image['segments'])
    classes = {}
    module_rows = {}
    for module, name, setup, vptr, size, count in (
        ('ApplePMGR', 'ApplePMGR', 0xfffffff00565717c, 0xfffffff006c9faf8, 0x36968, 325),
        ('ApplePMGR', 'ApplePMGRNub', 0xfffffff0056831b4, 0xfffffff006ca5058, 1856, 168),
        ('AppleT8015PMGR', 'AppleT8015PMGR', 0xfffffff00626a0f8, 0xfffffff006ebb2a8, 0x37d88, 336)):
        entry = entries['com.apple.driver.' + module]
        child = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
        require(any(s['initprot'] & 4 and s['va'] <= setup < s['va'] + s['filesize'] for s in child['segments']), 'PMGR class left its module')
        w = words(setup, 8)
        require(w[:2] == (0xa9bf7bfd, 0x910003fd) and w[2] & 0x9f00001f == 0x90000001 and
                w[3] & 0xffc003ff == 0x91000021 and w[4] & 0x9f00001f == 0x90000002 and
                w[5] & 0xffc003ff == 0xf9400042 and w[6] & 0xffe0001f == 0x52800003, 'PMGR metadata arguments changed')
        label = adrp(setup + 8, w[2]) + ((w[3] >> 10) & 4095)
        require(read(label, len(name) + 1) == name.encode() + b'\0', 'PMGR class name changed')
        actual_size = (w[6] >> 5) & 65535; call = setup + 28
        if w[7] & 0xffe0001f == 0x72a00003:
            actual_size |= ((w[7] >> 5) & 65535) << 16; call += 4
        require(actual_size == size and imported(branch(call))[1] == names['__ZN11OSMetaClassC2EPKcPKS_j'],
                'PMGR class size or metadata constructor changed')
        parent = pointer(adrp(setup + 16, w[4]) + ((w[5] >> 10) & 4095) * 8)
        getter = setup - 12; a, b, c = words(getter, 3)
        require(a & 0x9f00001f == 0x90000000 and b & 0xffc003ff == 0x91000000 and c == 0xd65f03c0, 'PMGR metadata getter changed')
        metadata = adrp(getter, a) + ((b >> 10) & 4095)
        methods = struct.unpack('<' + str(count) + 'Q', read(vptr, count * 8))
        require(methods[7] == getter and all(executable(value) for value in methods) and
                read(vptr - 16, 16) == bytes(16) and read(vptr + count * 8, 8) == bytes(8), 'PMGR vtable identity or extent changed')
        classes[name] = {'module': entry['CFBundleIdentifier'], 'instance_bytes': size, 'metaclass': hex(metadata),
            'parent_metaclass': hex(parent), 'metadata_constructor': hex(setup), 'metadata_constructor_bytes': call - setup + 24,
            'metadata_constructor_sha256': hashlib.sha256(read(setup, call - setup + 24)).hexdigest(),
            'vptr': hex(vptr), 'vtable_entries': count, 'vtable_sha256': hashlib.sha256(read(vptr, count * 8)).hexdigest()}
        module_rows[entry['CFBundleIdentifier']] = {'version': entry['CFBundleVersion'],
            'executable_sha256': {s['name']: hashlib.sha256(read(s['va'], s['filesize'])).hexdigest()
                                   for s in child['segments'] if s['initprot'] & 4}}
    require(int(classes['ApplePMGR']['parent_metaclass'], 16) == names['__ZN6IOPMGR10gMetaClassE'] and
            int(classes['ApplePMGRNub']['parent_metaclass'], 16) == names['__ZN9IOService10gMetaClassE'] and
            classes['AppleT8015PMGR']['parent_metaclass'] == classes['ApplePMGR']['metaclass'], 'PMGR hierarchy changed')
    read_stub, write_stub = branch(0xfffffff0056fe790), branch(0xfffffff0056fe7a0)
    read_slot, reader = imported(read_stub); write_slot, writer = imported(write_stub)
    r, w = words(reader, 7), words(writer, 6)
    require(r[:3] == (0xf9404400, 0xb4000080, 0xf9400008) and r[3] & 0xffc003ff == 0xf9400101 and
            r[4:] == (0xd61f0020, 0x12800000, 0xd65f03c0) and
            w[:3] == (0xf9404400, 0xb4000080, 0xf9400008) and w[3] & 0xffc003ff == 0xf9400102 and
            w[4:] == (0xd61f0040, 0xd65f03c0), 'PMGR nub provider dispatch changed')
    require((r[3] >> 10) & 4095 == 312 and (w[3] >> 10) & 4095 == 313,
            'iPhone PMGR provider slots differ; do not use the iPad slots')
    base_table, target_table = int(classes['ApplePMGR']['vptr'], 16), int(classes['AppleT8015PMGR']['vptr'], 16)
    base_read, base_write = pointer(base_table + 312 * 8), pointer(base_table + 313 * 8)
    target_read, target_write = pointer(target_table + 312 * 8), pointer(target_table + 313 * 8)
    require(words(base_read, 2) == (0x12800000, 0xd65f03c0) and words(base_write, 1) == (0xd65f03c0,), 'PMGR abstract fallback changed')
    require(words(target_read, 3) == (0x52800601, 0x72a001a1, 0x52800002) and
            words(target_write, 4) == (0xaa0103e2, 0x52800601, 0x72a001a1, 0x52800003), 'T8015 security register arguments changed')
    _, read_wrapper = imported(branch(target_read + 12, False))
    _, write_wrapper = imported(branch(target_write + 16, False))
    require(words(read_wrapper, 6) == (0xaa0203e3, 0xaa0103e2, 0xf9400008, 0xf944ed04, 0x52800021, 0xd61f0080) and
            words(write_wrapper, 7) == (0xaa0303e4, 0xaa0203e3, 0xaa0103e2, 0xf9400008, 0xf944f105, 0x52800021, 0xd61f00a0),
            'T8015 register-region dispatch changed')
    require(words(0xfffffff0056fe794, 3) == (0x321e0015, 0xaa1403e0, 0xaa1503e1), 'AMFI read/OR/write arguments changed')
    matching = imported(branch(0xfffffff0056fe75c))[1]; waiting = imported(branch(0xfffffff0056fe770))[1]
    require(matching == names['__ZN9IOService15serviceMatchingEPKcP12OSDictionary'] and
            waiting == names['__ZN9IOService22waitForMatchingServiceEP12OSDictionaryy'], 'AMFI PMGR matching imports changed')
    require(words(0xfffffff0056fe764, 3) == (0xd2958001, 0xf2bf8461, 0xf2c000c1), 'AMFI PMGR timeout changed')
    require(pointer(pointer(0xfffffff006cb56c8)) == int(classes['ApplePMGRNub']['metaclass'], 16), 'AMFI PMGR class import changed')
    blocks = [('amfi_matching_gate', 0xfffffff0056fe750, 136), ('nub_read', reader, 28), ('nub_write', writer, 24),
              ('target_read', target_read, 16), ('target_write', target_write, 20),
              ('read_wrapper', read_wrapper, 24), ('write_wrapper', write_wrapper, 28),
              ('resource_lookup', 0xfffffff005666074, 52), ('region_size', 0xfffffff005670194, 44),
              ('generic_read', 0xfffffff0056703ac, 96), ('generic_write', 0xfffffff005670424, 96),
              ('target_write_override', 0xfffffff00626e1bc, 616)]
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(), 'classes': classes, 'modules': module_rows,
        'amfi': {'entry': '0xfffffff0056fe750', 'success_boundary': '0xfffffff0056fe7d8', 'missing_nub_boundary': '0xfffffff0056fe90c',
                 'service_class': 'ApplePMGRNub', 'matching_timeout_ns': 30000000000, 'value_update_mask': 4,
                 'read_stub': hex(read_stub), 'write_stub': hex(write_stub), 'read_import_slot': hex(read_slot), 'write_import_slot': hex(write_slot)},
        'dispatch': {'provider_field_offset': 136, 'read_slot': 312, 'write_slot': 313,
                     'read_entry': hex(reader), 'write_entry': hex(writer), 'null_provider_read': 0xffffffff,
                     'null_provider_write_has_no_operation': True, 'null_provider_fallback_is_not_hardware_success': True},
        'target_register': {'read_entry': hex(target_read), 'write_entry': hex(target_write),
            'read_wrapper': hex(read_wrapper), 'write_wrapper': hex(write_wrapper), 'region': 1, 'bank': 0, 'byte_offset': 0xd0030,
            'bank_count_field': 0x2a64, 'resource_table_field': 0xb20, 'region_stride': 0x50, 'bank_stride': 0x28,
            'resource_pointer_field': 24, 'resource_length_field': 32, 'value_bits': 32,
            'read_bank_slot': 315, 'write_bank_slot': 316, 'actual_target_performs_register_access': True},
        'blocks': {name: {'address': hex(address), 'bytes': size, 'sha256': hashlib.sha256(read(address, size)).hexdigest()}
                   for name, address, size in blocks},
        'sm8750_security_latch_mapping_derived': False, 'power_provider_implemented': False,
        'original_policy_registration_qualified': False, 'hardware_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    actual = derive()
    if args.write:
        require(not FIXTURE.exists(), 'Refuse to replace the reviewed iPhone PMGR contract')
        FIXTURE.write_text(json.dumps(actual, indent=2) + '\n')
    fixture, pin = reviewed()
    require(fixture == actual, 'Exact iPhone PMGR contract differs')
    controls = []
    for name, mutation in (('wrong-nub-size', (0xfffffff0056831cc, 1 << 5)),
                           ('ipad-provider-slot', (int(actual['dispatch']['read_entry'], 16) + 12, (312 ^ 320) << 10)),
                           ('wrong-register-offset', (int(actual['target_register']['read_entry'], 16) + 4, 1 << 5))):
        try:
            require(derive(mutation) == actual, 'PMGR input mutation changed the measured contract')
        except ValueError as error:
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Corrupt PMGR contract input was accepted: ' + name)
    sources = [Path(__file__), FIXTURE, ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_initial_data.py',
               ROOT / 'profiles/os/ios-16.7.16-20H392/security-init.json']
    report = {'result': 'IOS16_EXACT_IPHONE_PMGR_DEPENDENCY_CONTRACT_STATIC_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'dependency_report_sha256': {}, 'artifacts': {}, 'contract': str(FIXTURE.relative_to(ROOT)),
              'contract_sha256': sha(FIXTURE), 'contract_facts': actual, 'negative_controls': controls,
              'source_pin': pin,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'scope': 'Exact original iPhone AMFI matching/read-OR-write and PMGR class/dispatch/resource contracts. '
                       'The T8015 provider performs real register access at region 1, bank 0, offset 0xd0030. '
                       'Base/null fallbacks are not a replacement for that behavior. No Qualcomm security mapping, '
                       'replacement power provider, original policy initialization or hardware operation is supplied.'}
    (ROOT / 'reports/ios16-pmgr-contract.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact iPhone PMGR classes, slots 312/313 and real T8015 register path; three altered-input controls rejected')


if __name__ == '__main__': main()
