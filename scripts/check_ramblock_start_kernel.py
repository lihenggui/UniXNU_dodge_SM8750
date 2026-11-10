#!/usr/bin/env python3
"""Execute the compiled RamBlock start path using exact packed Data seeds and explicit platform peers."""
import hashlib
import json
import argparse
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, inspect_object, require, symbols
from prepare_initial_data import sha
from check_data_mount_kernel import Model

OUT = ROOT / 'build/ios16-ramblock-start-kernel'


def layout():
    directory = OUT / 'abi'; directory.mkdir(parents=True, exist_ok=True)
    original = ROOT / 'sources/UniXNU/drivers/RamBlock/NativeRamBlock.cpp'
    before = original.read_text(); anchor = '  OSDeclareDefaultStructors(NativeRamBlock)\n'
    require(before.count(anchor) == 1, 'RamBlock layout annotation anchor differs')
    (directory / 'NativeRamBlock.cpp').write_text(before.replace(anchor, anchor + 'public: // layout annotation only\n'))
    source = directory / 'DodgeRamBlock.cpp'
    pairs = [('instance_bytes', 'sizeof(NativeRamBlock)'), ('seed_hash', 'offsetof(NativeRamBlock,seedHash)'),
             ('data_bytes', 'sizeof(OSData)'), ('data_length', 'DodgeDataLayout::lengthOffset()'),
             ('data_pointer', 'DodgeDataLayout::dataOffset()'), ('string_bytes', 'sizeof(OSString)'),
             ('string_pointer', 'DodgeStringLayout::pointerOffset()'), ('number_bytes', 'sizeof(OSNumber)'),
             ('number_size', 'DodgeNumberLayout::sizeOffset()'), ('number_value', 'DodgeNumberLayout::valueOffset()')]
    source.write_text((ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp').read_text() + '''
struct DodgeDataLayout : OSData {
    static constexpr unsigned lengthOffset() { return offsetof(DodgeDataLayout, length); }
    static constexpr unsigned dataOffset() { return offsetof(DodgeDataLayout, data); }
};
struct DodgeStringLayout : OSString {
    static constexpr unsigned pointerOffset() { return offsetof(DodgeStringLayout, string); }
};
struct DodgeNumberLayout : OSNumber {
    static constexpr unsigned sizeOffset() { return offsetof(DodgeNumberLayout, size); }
    static constexpr unsigned valueOffset() { return offsetof(DodgeNumberLayout, value); }
};
extern "C" const unsigned dodge_ramblock_start_layout[]={''' + ','.join('unsigned(' + value + ')' for _, value in pairs) + '};\n')
    recipes = json.loads((ROOT / 'build/cph2653-data-source/compile-commands.json').read_text())
    recipe, = [row for row in recipes if row['source'] == str(ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp')]
    command = recipe['arguments'][:]; obj = directory / 'DodgeRamBlock.o'
    command[command.index(recipe['source'])] = str(source); command[command.index('-o') + 1] = str(obj)
    command += ['-Wno-invalid-' 'offsetof', '-I', str(original.parent)]
    with (directory / 'compile.log').open('w') as log:
        process = subprocess.run(command, cwd=recipe['directory'], stdout=log, stderr=subprocess.STDOUT)
    require(not process.returncode, 'RamBlock start layout failed; inspect ' + str(directory / 'compile.log'))
    def text(path):
        raw = path.read_bytes()
        section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(text(obj) == text(ROOT / 'build/cph2653-data-source/DodgeRamBlock.o'), 'Start layout annotation changed production text')
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_ramblock_start_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(pairs)) + 'I', raw, section['fileoff'] + symbol['value'] - section['va'])
    facts = json.loads((ROOT / 'reports/ios16-data-kernel.json').read_text())['instance_layout']
    require(values[0] == facts['instance_bytes'] == 352, 'Actual source start object size differs')
    return {**facts, **dict(zip((name for name, _ in pairs), values))}, obj


def packed_pages(encoded):
    magic, version, block, logical, count = struct.unpack_from('<8sIIQQ', encoded)
    require((magic, version, block) == (b'DBRDISK1', 1, 4096) and count <= 65536, 'Need valid exact Data packed seed')
    cursor, pages = 32 + count * 16, {}
    for index in range(count):
        offset, size = struct.unpack_from('<QQ', encoded, 32 + index * 16)
        require(not (offset | size) & 4095 and size and offset + size <= logical and cursor + size <= len(encoded), 'Packed fixture extent differs')
        for delta in range(0, size, 4096):
            page = encoded[cursor + delta:cursor + delta + 4096]
            if any(page): pages[(offset + delta) // 4096] = page
        cursor += size
    require(cursor == len(encoded), 'Packed fixture has trailing data')
    return logical, pages


CASES = ('parent-start-failed', 'missing-map', 'missing-property', 'wrong-property-type', 'wrong-range-length',
         'both-range-properties', 'zero-bytes', 'oversize-input', 'unaligned-physical', 'raw-unaligned-size',
         'physical-before-window', 'physical-after-window', 'input-larger-than-window', 'physical-address-overflow',
         'mapping-failed', 'lock-failed', 'bad-magic', 'bad-version', 'bad-page-size', 'bad-count', 'trailing-data',
         'unaligned-logical-size', 'pointer-array-failed', 'first-page-failed', 'later-page-failed',
         'dense-small-fixture', 'actual-packed-2GiB', 'actual-packed-3GiB')


def emulate(path, case, facts, control=False, live_io=False, live_media=False):
    raw = path.read_bytes(); model = Model(raw)
    root = ROOT / 'reports'
    image = json.loads((root / ('ios16-data-image.json' if case == 'actual-packed-3GiB' else 'ios16-data-volatile-image.json')).read_text())
    encoded = (ROOT / image['packed_image']).read_bytes()
    require(sha(ROOT / image['packed_image']) == image['artifacts'][image['packed_image']], 'Actual startup seed changed')
    logical, pages = packed_pages(encoded)
    dense = case in ('dense-small-fixture', 'raw-unaligned-size')
    seed = pages[0] if dense else encoded
    if dense: logical = len(seed)
    if case.startswith('bad-') or case in ('trailing-data', 'unaligned-logical-size'):
        changed = bytearray(encoded)
        if case == 'bad-magic': changed[0] ^= 1
        if case == 'bad-version': struct.pack_into('<I', changed, 8, 2)
        if case == 'bad-page-size': struct.pack_into('<I', changed, 12, 16384)
        if case == 'bad-count': struct.pack_into('<Q', changed, 24, 65537)
        if case == 'unaligned-logical-size': struct.pack_into('<Q', changed, 16, logical + 1)
        seed = bytes(changed) + (b'x' if case == 'trailing-data' else b'')
    obj, provider, registry, packed, plain, range_value, gate = [model.heap + offset for offset in
            (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000)]
    registry_table = model.heap + 0x10000
    loaded = model.heap + 0x200000
    model.map(loaded - 64, len(seed) + 128)
    model.put(loaded - 64, bytes([0xa5]) * (len(seed) + 128)); model.put(loaded, seed)
    model.put(obj - 64, bytes([0xa5]) * (facts['instance_bytes'] + 128)); model.put(obj, bytes(facts['instance_bytes']))
    model.put(registry, struct.pack('<Q', registry_table))
    model.put(registry_table, bytes(512))
    counters = {'map_refs': 0, 'map_releases': 0, 'allocations': 0, 'lock_allocations': 0, 'publications': 0,
                'hash_updates': 0, 'hash_bytes': 0, 'length_calls': 0, 'bytes_calls': 0, 'parent_start_calls': 0}
    accounting, allocations = [], []
    physical_base, physical_size, physical = 0x80000000, 4 << 30, 0x80200000
    count = len(seed)
    if case == 'zero-bytes': count = 0
    if case == 'oversize-input': count = (1 << 31) + 1
    if case == 'unaligned-physical': physical += 1
    if case == 'raw-unaligned-size': count -= 1
    if case == 'physical-before-window': physical = physical_base - 4096
    if case == 'physical-after-window': physical = physical_base + physical_size - 4096
    if case == 'input-larger-than-window': physical_size = count - 1
    if case == 'physical-address-overflow': physical = (1 << 64) - 4096
    model.put(model.names['_gPhysBase'], struct.pack('<Q', physical_base))
    model.put(model.names['_gPhysSize'], struct.pack('<Q', physical_size))
    plane = model.heap + 0x8000
    model.put(model.names['_gIODTPlane'], struct.pack('<Q', plane))
    model.put(range_value, struct.pack('<QQ', physical, count))
    for address in (packed, plain):
        model.put(address, bytes(facts['data_bytes']))
        model.put(address, struct.pack('<Q', model.names['__ZTV6OSData'] + 16))
        model.put(address + facts['data_length'], struct.pack('<I', 8 if case == 'wrong-range-length' else 16))
        model.put(address + facts['data_pointer'], struct.pack('<Q', range_value))
    def account(args):
        require(args[0] == model.names['__ZN14NativeRamBlock10gMetaClassE'], 'Source constructor used another metaclass')
        accounting.append(args[0]); model.returned()
    model.bind('__ZNK11OSMetaClass19instanceConstructedEv', account)
    parent_init, = struct.unpack('<Q', model.read(model.names['__ZTV9IOService'] + 16 + 21 * 8, 8))
    model.names['_native_parent_init_peer'] = parent_init
    model.bind('_native_parent_init_peer', lambda args: model.returned(1))
    def set_property(args):
        require(args[0] == obj and model.string(args[1]) == 'device-type' and model.string(args[2]) == 'Generic', 'Original init set a different property')
        model.returned(1)
    model.bind('__ZN15IORegistryEntry11setPropertyEPKcS1_', set_property)
    def from_path(args):
        require(model.string(args[0]) == '/chosen/memory-map' and args[1] == plane and not any(args[2:5]), 'Start read a different memory-map path')
        if case == 'missing-map': model.returned(); return
        counters['map_refs'] += 1; model.returned(registry)
    model.bind('__ZN15IORegistryEntry8fromPathEPKcPK15IORegistryPlanePcPiPS_', from_path)
    property_peer, release_peer = model.stop + 0x100, model.stop + 0x200
    model.names['_range_property_peer'] = property_peer; model.names['_range_release_peer'] = release_peer
    model.put(registry_table + 35 * 8, struct.pack('<Q', property_peer))
    model.put(registry_table + 5 * 8, struct.pack('<Q', release_peer))
    def property_peer_fn(args):
        require(args[0] == registry and counters['map_refs'] == 1, 'Property lookup lost its registry ownership')
        key = model.string(args[1]); require(key in ('RAMDisk', 'PackedRAMDisk'), 'Unexpected start range property')
        present = case != 'missing-property' and ((key == 'RAMDisk') if dense else (key == 'PackedRAMDisk'))
        if case == 'both-range-properties': present = True
        model.returned((plain if key == 'RAMDisk' else packed) if present else 0)
    model.bind('_range_property_peer', property_peer_fn)
    def release(args):
        require(args[0] == registry and counters['map_refs'] == 1, 'Source released a borrowed registry object')
        counters['map_refs'] -= 1; counters['map_releases'] += 1; model.returned()
    model.bind('_range_release_peer', release)
    def cast(args):
        require(args[1] == model.names['__ZN6OSData10gMetaClassE'] and args[0] in (0, packed, plain), 'Wrong typed range metadata')
        model.returned(0 if case == 'wrong-property-type' else args[0])
    model.bind('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass', cast)
    def mapped(args):
        require(args[0] == physical, 'Static mapping changed the physical range')
        model.returned(0 if case == 'mapping-failed' else loaded)
    model.bind('_ml_static_ptovirt', mapped)
    def lock(args):
        counters['lock_allocations'] += 1; model.returned(0 if case == 'lock-failed' else gate)
    model.bind('_IOLockAlloc', lock)
    cursor = model.heap + 0x400000
    def allocate(args):
        nonlocal cursor
        require(args[0] == model.names['_KHEAP_DEFAULT'] and args[2] == facts['zero_alloc_flags'] and 0 < args[1] <= 4 << 20,
                'Start allocator heap/zero flag/size differs')
        counters['allocations'] += 1
        limit = 0 if case == 'pointer-array-failed' else 1 if case == 'first-page-failed' else 4 if case == 'later-page-failed' else 1000
        if len(allocations) >= limit: model.returned(); return
        address = (cursor + 4095) & -4096; cursor = address + args[1] + 128
        model.map(address - 64, args[1] + 128)
        model.put(address - 64, bytes([0xa5]) * (args[1] + 128)); model.put(address, bytes(args[1]))
        allocations.append((address, args[1])); model.returned(address)
    model.bind('_IOMalloc_internal', allocate)
    model.bind('_bzero', lambda args: (model.put(args[0], bytes(args[1])), model.returned()))
    model.bind('_memcpy', lambda args: (model.put(args[0], model.read(args[1], args[2])), model.returned(args[0])))
    def compare(args):
        require(args[2] <= 4096, 'Start memcmp exceeds bound')
        a, b = model.read(args[0], args[2]), model.read(args[1], args[2]); model.returned((a > b) - (a < b))
    model.bind('_memcmp', compare)
    contexts, digests = {}, []
    def hash_init(args):
        contexts[args[0]] = hashlib.sha256(); model.returned()
    def hash_update(args):
        require(args[0] in contexts and 0 < args[2] <= 4096, 'Start hash context or chunk bound differs')
        chunk = model.read(args[1], args[2])
        if case == 'actual-packed-2GiB':
            require(args[2] == 4096 and chunk == pages.get(counters['hash_bytes'] // 4096, bytes(4096)),
                    'Start hashed a different logical seed page')
        contexts[args[0]].update(chunk)
        counters['hash_updates'] += 1; counters['hash_bytes'] += args[2]
        if case == 'actual-packed-2GiB' and counters['hash_bytes'] % (512 << 20) == 0:
            print('Actual 2 GiB start hash:', counters['hash_bytes'] >> 20, 'MiB checked', flush=True)
        model.returned()
    def hash_final(args):
        require(args[1] in contexts, 'Start finalized an unknown hash context')
        digest = contexts.pop(args[1]).digest(); digests.append(digest)
        if control == 'hash-peer-poison': digest = bytes([digest[0] ^ 1]) + digest[1:]
        model.put(args[0], digest); model.returned()
    model.bind('_SHA256_Init', hash_init); model.bind('_SHA256_Update', hash_update); model.bind('_SHA256_Final', hash_final)
    expected_digest = hashlib.sha256(seed).digest() if dense else bytes.fromhex(image['packed_metadata']['sha256'])
    def publish(args):
        require(args[0] == obj and args[1] == 0, 'Source start used different registration flags')
        require(model.read(obj + facts['online'], 1) == b'\1' and
                model.read(model.names['_native_ram_block_ready'], 4) == struct.pack('<I', 1) and
                model.read(obj + facts['seed_hash'], 32) == expected_digest, 'Source published before complete ready/hash state')
        counters['publications'] += 1; model.returned()
    model.bind('__ZN9IOService15registerServiceEj', publish)
    def forbidden(args): raise ValueError('Start reached a native panic/stack failure')
    model.bind('_panic', forbidden); model.bind('___stack_chk_fail', forbidden)
    native_start = model.names['__ZN9IOService5startEPS_']
    require(model.read(native_start, 8) == struct.pack('<2I', 0x52800020, 0xd65f03c0), 'Actual inherited parent start body changed')
    parent_slot, = struct.unpack('<Q', model.read(model.names['__ZTV20IOBlockStorageDevice'] + 16 + 86 * 8, 8))
    require(parent_slot == native_start, 'Original storage parent start no longer identifies the native inherited method')
    length_load = 0xb9400000 | ((facts['data_length'] // 4) << 10)
    pointer_load = 0xf9400009 | ((facts['data_pointer'] // 8) << 10)
    getters = [('length_calls', '__ZNK6OSData9getLengthEv', (length_load, 0xd65f03c0)),
               ('bytes_calls', '__ZNK6OSData14getBytesNoCopyEv',
                (length_load | 8, pointer_load, 0x7100011f, 0x9a8903e0, 0xd65f03c0))]
    for label, name, words in getters:
        require(model.read(model.names[name], len(words) * 4) == struct.pack('<' + str(len(words)) + 'I', *words),
                'Actual OSData getter differs from compiler layout or its empty-data guard')
        def observed_getter(cpu, pc, size, ignored, key=label):
            require(counters['map_refs'] == 1 and model.register(0) in (packed, plain), 'Native property getter ran outside its owner lifetime')
            counters[key] += 1
        model.cpu.hook_add(model.u.UC_HOOK_CODE, observed_getter, begin=model.names[name], end=model.names[name])
    def observed_parent(cpu, pc, size, ignored): counters['parent_start_calls'] += 1
    model.cpu.hook_add(model.u.UC_HOOK_CODE, observed_parent, begin=native_start, end=native_start)
    if case == 'parent-start-failed':
        model.bind('__ZN9IOService5startEPS_', lambda args: model.returned())
    model.call('__ZN14NativeRamBlockC1Ev', [obj])
    require(accounting == [model.names['__ZN14NativeRamBlock10gMetaClassE']], 'Full source constructor did not account exactly once')
    require(model.call('__ZN20IOBlockStorageDevice4initEP12OSDictionary', [obj, 0]) == 1, 'Original storage init did not complete')
    if control == 'start-RET':
        model.put(model.names['__ZN14NativeRamBlock5startEP9IOService'], struct.pack('<I', 0xd65f03c0))
    result = model.call('__ZN14NativeRamBlock5startEP9IOService', [obj, provider], limit=50000000)
    success = case in ('dense-small-fixture', 'actual-packed-2GiB', 'actual-packed-3GiB')
    require(result == int(success) and counters['publications'] == int(success), 'Source start accepted/refused or published incorrectly: ' + case)
    require(counters['parent_start_calls'] == 1 and not counters['map_refs'] and counters['map_releases'] ==
            (0 if case in ('parent-start-failed', 'missing-map') else 1), 'Start parent/map ownership is unbalanced')
    require(model.read(obj - 64, 64) == model.read(obj + facts['instance_bytes'], 64) == bytes([0xa5]) * 64, 'Start escaped driver bounds')
    require(model.read(loaded, len(seed)) == seed and model.read(loaded - 64, 64) == model.read(loaded + len(seed), 64) == bytes([0xa5]) * 64,
            'Start changed loader-owned input or its canaries')
    for address, size in allocations:
        require(model.read(address - 64, 64) == model.read(address + size, 64) == bytes([0xa5]) * 64, 'Start escaped an allocator buffer')
    if success:
        require(not contexts and digests == [expected_digest] and model.read(obj + facts['seed_hash'], 32) == expected_digest and
                model.read(model.names['_native_ram_block_seed_sha256'], 32) == expected_digest, 'Complete source start hash differs from exact seed')
        capacity, = struct.unpack('<Q', model.read(obj + facts['capacity'], 8))
        require(capacity == logical // 512 and model.read(obj + facts['online'], 1) == b'\1', 'Source start published a wrong capacity')
        resident = logical if dense else len(pages) * 4096
        require(model.read(model.names['_native_ram_block_bytes'], 8) == struct.pack('<Q', logical) and
                model.read(model.names['_native_ram_block_resident_bytes'], 8) == struct.pack('<Q', resident) and
                model.read(model.names['_native_ram_block_sparse'], 4) == struct.pack('<I', not dense),
                'Source start diagnostics lost actual logical/resident geometry')
        if not dense:
            require(counters['allocations'] == len(pages) + (2 if logical > 1 << 31 else 1), 'Start allocation count differs from actual nonzero pages')
            if logical <= 1 << 31:
                require(counters['hash_bytes'] == logical and counters['hash_updates'] == logical // 4096 and
                        model.read(obj + facts['memory'], 8) == bytes(8), 'Actual 2 GiB sparse start did not hash every logical page')
                table, = struct.unpack('<Q', model.read(obj + facts['sparse'] + facts['sparse_pages'], 8))
                imported = {index: struct.unpack('<Q', model.read(table + index * 8, 8))[0] for index in pages}
            else:
                index_array, = struct.unpack('<Q', model.read(obj + facts['big'] + facts['big_index'], 8))
                pointer_array, = struct.unpack('<Q', model.read(obj + facts['big'] + facts['big_page'], 8))
                imported = {struct.unpack('<Q', model.read(index_array + index * 8, 8))[0]: struct.unpack('<Q', model.read(pointer_array + index * 8, 8))[0]
                            for index in range(len(pages))}
            require(set(imported) == set(pages) and all(model.read(imported[index], 4096) == page for index, page in pages.items()), 'Actual start imported different seed pages')
    else:
        require(not counters['hash_updates'] and not counters['publications'] and model.read(obj + facts['online'], 1) == b'\0', 'Failed source start exposed a partial disk')
        require(model.read(model.names['_native_ram_block_ready'], 4) == bytes(4) and
                model.read(model.names['_native_ram_block_seed_sha256'], 32) == bytes(32), 'Failed start exposed ready/hash globals')
    row = {'case': case, 'result': 'PASS', 'source_start_return': result, **counters,
            'allocated_bytes': sum(size for _, size in allocations), 'logical_bytes': logical if success else None,
            'nonzero_pages': len(pages) if success and not dense else None, 'seed_sha256': expected_digest.hex() if success else None,
            'native_parent_start_body_executed': case != 'parent-start-failed',
            'source_constructor_and_original_storage_init_executed': True,
            'allocation_mapping_metadata_registry_hash_and_registration_are_explicit_peers': True,
            'explicit_peers': sorted(model.visited), 'phone_or_firmware_execution': False}
    if live_io:
        from ramblock_live_io import exercise
        require(success and not dense, 'Live I/O requires a successfully started exact packed Data disk')
        row['post_start_io'] = exercise(model, obj, facts, logical, pages, allocations, control == 'io-RET')
        require(model.read(loaded, len(seed)) == seed, 'Live I/O changed the immutable packed loader input')
        for address, size in allocations:
            require(model.read(address - 64, 64) == model.read(address + size, 64) == bytes([0xa5]) * 64,
                    'Live I/O escaped a start or I/O allocation')
    if live_media:
        from ramblock_live_media import exercise
        require(success and not dense, 'Media selection requires a successfully started exact packed Data disk')
        row['post_start_media'] = exercise(model, obj, facts, logical, expected_digest, control == 'selector-RET')
        require(model.read(loaded, len(seed)) == seed and
                model.read(obj - 64, 64) == model.read(obj + facts['instance_bytes'], 64) == bytes([0xa5]) * 64,
                'Media selection changed its immutable loader input or escaped the driver')
    return row


def check_report(report):
    require(report['result'] == 'IOS16_RAMBLOCK_ACTUAL_START_IO_AND_MEDIA_ARM64_PASS' and
            report['builder_sha256'] == sha(Path(__file__)), 'RamBlock live report is stale')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'RamBlock live input/artifact changed: ' + name)
    require(sha(ROOT / report['candidate']) == report['candidate_sha256'], 'RamBlock live candidate changed')
    require(len(report['start_cases']) == report['start_case_count'] == 28 and
            sum(row.get('post_start_io', {}).get('case_count', 0) for row in report['start_cases']) == report['post_start_io_case_count'] == 26 and
            sum(row.get('post_start_media', {}).get('case_count', 0) for row in report['start_cases']) == report['post_start_media_case_count'] == 68,
            'RamBlock actual start/live case counts differ')
    require(all(row['result'] == 'PASS' for row in report['start_cases']) and len(report['negative_controls']) == 4 and
            all(row['result'] == 'REJECTED' for row in report['negative_controls']), 'RamBlock positive/rejection evidence differs')
    require({row['case'] for row in report['start_cases']} == set(CASES) and
            all(item['result'] == 'PASS' for row in report['start_cases'] for key in ('post_start_io', 'post_start_media')
                for item in row.get(key, {}).get('cases', [])), 'RamBlock nested paths are incomplete')
    evidence = json.loads((OUT / 'cpu-cases.json').read_text())
    require(evidence == {'layout': report['instance_layout'], 'start_cases': report['start_cases'],
                         'negative_controls': report['negative_controls']}, 'RamBlock report and raw CPU evidence differ')
    two = next(row for row in report['start_cases'] if row['case'] == 'actual-packed-2GiB')
    three = next(row for row in report['start_cases'] if row['case'] == 'actual-packed-3GiB')
    require(two['hash_updates'] == 524288 and two['hash_bytes'] == 1 << 31 and two['nonzero_pages'] == three['nonzero_pages'] == 176 and
            three['hash_bytes'] == 17 + 176 * (8 + 4096), 'RamBlock full logical/large-seed hash evidence differs')
    require(not any(report[key] for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
            'original_iomedia_matching_qualified', 'original_apfs_data_mount_qualified', 'persistent_data_writes_qualified')),
            'RamBlock live report overstates qualification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true', help='Check current source/dependencies and artifact hashes')
    args = parser.parse_args()
    subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_data_mount_stack.py', '--check-only'], check=True)
    report_path = ROOT / 'reports/ios16-ramblock-start-kernel.json'
    if args.check_only:
        check_report(json.loads(report_path.read_text()))
        print('PASS: preserved RamBlock startup/live evidence (28 start / 26 I/O / 68 selector paths; 4 rejection controls)')
        return
    candidate = ROOT / 'build/ios16-apfs-mount-prelink/kernel.macho'
    facts, obj = layout()
    rows = []
    for case in CASES:
        live = case in ('actual-packed-2GiB', 'actual-packed-3GiB')
        row = emulate(candidate, case, facts, live_io=live, live_media=live)
        rows.append(row); print('PASS: actual RamBlock start:', case, flush=True)
    controls = []
    for case, mutation, io, media in (('dense-small-fixture', 'start-RET', False, False),
                                    ('actual-packed-3GiB', 'hash-peer-poison', False, False),
                                    ('actual-packed-3GiB', 'io-RET', True, False),
                                    ('actual-packed-3GiB', 'selector-RET', False, True)):
        try:
            emulate(candidate, case, facts, control=mutation, live_io=io, live_media=media)
        except ValueError as error:
            controls.append({'case': mutation, 'result': 'REJECTED', 'reason': str(error)})
        else:
            raise ValueError('Corrupted RamBlock startup/live code or hash peer was accepted: ' + mutation)
    evidence = OUT / 'cpu-cases.json'
    evidence.write_text(json.dumps({'layout': facts, 'start_cases': rows, 'negative_controls': controls}, indent=2) + '\n')
    source_files = [Path(__file__), *[ROOT / 'scripts' / name for name in ('ramblock_live_io.py', 'ramblock_live_media.py',
                    'check_data_mount_kernel.py', 'native_driver_build.py', 'prepare_initial_data.py')],
                    ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp', *[ROOT / 'sources/UniXNU/drivers/RamBlock' / name for name in
                    ('NativeRamBlock.cpp', 'SparseDisk.h', 'SeedDisk.h', 'DirectDisk.h', 'PersistOverlay.h')]]
    dependencies = [ROOT / 'reports' / (name + '.json') for name in ('ios16-data-source', 'ios16-data-kernel',
                    'ios16-data-mount-prelink', 'data-mount-stack', 'ios16-data-image', 'ios16-data-volatile-image', 'ios16-storage-abi')]
    report = {'result': 'IOS16_RAMBLOCK_ACTUAL_START_IO_AND_MEDIA_ARM64_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392',
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in dependencies},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, evidence)},
              'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
              'source_reference': json.loads((ROOT / 'upstream.lock.json').read_text())['ramblock_reference'],
              'instance_layout': facts, 'annotation_text_identical_to_production': True,
              'start_case_count': len(rows), 'post_start_io_case_count': 26, 'post_start_media_case_count': 68,
              'start_cases': rows, 'negative_controls': controls,
              'actual_start_object_reused_without_field_reconstruction': True,
              'full_logical_2GiB_hash_loop_executed': True, 'large_seed_identity_scheme': 'SHNGSEED2',
              'native_osdata_string_number_getters_executed': True,
              'constructor_original_storage_init_and_inherited_start_executed': True,
              'source_selector_attach_store_and_seed_info_executed': True,
              'original_iomedia_matching_qualified': False, 'original_apfs_data_mount_qualified': False,
              'persistent_data_writes_qualified': False, 'source_data_default_enabled': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'scope': 'The unchanged pinned source constructor, original storage init and inherited native parent start execute. '
                       'Twenty-eight start paths include exact packed 2/3 GiB APFS seeds, full 2 GiB logical hashing and failure admission. '
                       'Those actual objects then execute 26 I/O and 68 source volume-selector paths without reconstructing driver state. '
                       'Native OSData/OSString/OSNumber getters execute using measured layouts. Allocation, mapping, class membership, '
                       'registry collections/provider edges, SHA primitives, descriptor/completion/lock and registration/library calls '
                       'remain explicit peers. SHA peers hash actual source-selected bytes. Store mode is explicitly zero. '
                       'The 4 KiB dense fixture is a superblock diagnostic, not a complete APFS volume. Failed starts are retained by '
                       'the separately checked lifecycle; no rollback/free qualification, actual IOMedia publication, original APFS mount, '
                       'persistent writes, MMIO or phone operation is claimed.'}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    check_report(report)
    print('PASS: 122 actual startup/live paths (28 start / 26 I/O / 68 selector), 4 rejection controls')


if __name__ == '__main__':
    main()
