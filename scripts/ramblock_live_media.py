#!/usr/bin/env python3
"""Run the pinned volume selector against an actually started RamBlock object."""
import struct

from native_driver_build import require


CASES = ('ordinary', 'foreign-object-skipped', 'no-media', 'duplicate-media', 'matching-allocation-failed',
         'properties-allocation-failed', 'string-allocation-failed', 'uuid-filter-failed', 'property-filter-failed',
         'missing-iterator', 'missing-uuid', 'wrong-uuid-type', 'wrong-uuid', 'missing-name', 'empty-name', 'long-name',
         'short-path-buffer', 'missing-major', 'major-overflow', 'missing-minor', 'minor-overflow', 'no-ram-ancestor',
         'provider-cycle', 'ancestor-at-depth-64', 'ancestor-at-depth-65', 'offline-disk', 'short-uuid', 'null-uuid',
         'null-device', 'null-path', 'tiny-path-buffer', 'null-base', 'null-bytes', 'null-digest')


def exercise(model, obj, facts, logical, digest, control=False):
    base = model.heap + 0x40000
    matching, properties, wanted, iterator, media, foreign, identity, name, major, minor = [base + delta for delta in
        (0, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900)]
    nodes = [base + 0x1000 + 0x100 * index for index in range(64)]
    table, strings, output, uuid_address = base + 0x6000, base + 0x7000, base + 0x8000, base + 0x9000
    rows, active, refs, held = [], {}, {}, {}
    for address, symbol in ((matching, '__ZTV12OSDictionary'), (properties, '__ZTV12OSDictionary'),
                            (wanted, '__ZTV8OSString'), (iterator, '__ZTV10OSIterator'), (media, '__ZTV9IOService'),
                            (identity, '__ZTV8OSString'), (name, '__ZTV8OSString'),
                            (major, '__ZTV8OSNumber'), (minor, '__ZTV8OSNumber'),
                            *[(node, '__ZTV9IOService') for node in nodes]):
        model.put(address, bytes(128)); model.put(address, struct.pack('<Q', model.names[symbol] + 16))
    # Only the iterator's abstract next-object slot is supplied by the collection peer.
    model.put(table, model.read(model.names['__ZTV10OSIterator'] + 16, 18 * 8))
    next_address = model.stop + 0x400
    model.put(table + 17 * 8, struct.pack('<Q', next_address)); model.put(iterator, struct.pack('<Q', table))
    native_string_length = model.names['__ZNK8OSString9getLengthEv']
    # In this pinned ordinary-arm64 kernel OSString has an 18-bit length including NUL.
    require(model.read(native_string_length, 16) == struct.pack('<4I', 0xb9400c08, 0x530e7d08, 0x51000500, 0xd65f03c0),
            'Native OSString packed length getter changed')
    require(facts['string_bytes'] == facts['number_bytes'] == 24 and facts['string_pointer'] == facts['number_value'] == 16 and
            facts['number_size'] == 12, 'Compiler metadata layouts changed')
    def put_string(address, value, pointer):
        model.put(pointer, value.encode() + b'\0')
        model.put(address + 12, struct.pack('<I', (len(value) + 1) << 14))
        model.put(address + facts['string_pointer'], struct.pack('<Q', pointer))
    def create(args, kind, address):
        if kind == 'matching': require(model.string(args[0]) == 'IOMedia' and not args[1], 'Selector matched another service')
        elif kind == 'properties': require(args[0] == 1, 'Selector changed UUID dictionary capacity')
        else: require(model.string(args[0]) == active['uuid'], 'Selector copied another UUID')
        active['factories'].append(kind)
        failed = active['case'] == {'matching': 'matching-allocation-failed', 'properties': 'properties-allocation-failed',
                                    'wanted': 'string-allocation-failed'}[kind]
        if failed: model.returned(); return
        refs[address] = 1; model.returned(address)
    model.bind('__ZN9IOService15serviceMatchingEPKcP12OSDictionary', lambda args: create(args, 'matching', matching))
    model.bind('__ZN12OSDictionary12withCapacityEj', lambda args: create(args, 'properties', properties))
    model.bind('__ZN8OSString11withCStringEPKc', lambda args: create(args, 'wanted', wanted))
    def set_object(args):
        address, key, value = args[0], model.string(args[1]), args[2]
        require((address, key, value) in ((properties, 'UUID', wanted), (matching, 'IOPropertyMatch', properties)) and
                refs.get(address) and refs.get(value), 'Selector built another matching dictionary')
        failed = active['case'] == ('uuid-filter-failed' if address == properties else 'property-filter-failed')
        active['setters'].append(key)
        if not failed: refs[value] += 1; held.setdefault(address, []).append(value)
        model.returned(not failed)
    model.bind('__ZN12OSDictionary9setObjectEPKcPK15OSMetaClassBase', set_object)
    def drop(address):
        require(refs.get(address, 0) > 0, 'Selector released a borrowed/dead registry object')
        refs[address] -= 1
        if not refs[address]:
            for child in held.pop(address, []): drop(child)
    model.bind('__ZNK8OSObject7releaseEv', lambda args: (drop(args[0]), model.returned()))
    def get_services(args):
        require(args[0] == matching and refs.get(matching) == 1 and held.get(matching) == [properties] and
                held.get(properties) == [wanted], 'Selector queried an incomplete/dead UUID filter')
        active['queries'] += 1
        if active['case'] == 'missing-iterator': model.returned(); return
        refs[iterator] = 1; model.returned(iterator)
    model.bind('__ZN9IOService19getMatchingServicesEP12OSDictionary', get_services)
    def next_object(args):
        require(args[0] == iterator and refs.get(iterator) == 1, 'Selector advanced an unowned iterator')
        active['next_calls'] += 1
        require(active['next_calls'] <= 4, 'Selector iteration escaped its bounded fixture')
        sequence = active['sequence']; model.returned(sequence.pop(0) if sequence else 0)
    model.names['_live_media_next'] = next_address; model.bind('_live_media_next', next_object)
    def cast(args):
        pointer, metadata = args[:2]
        allowed = {model.names['__ZN9IOService10gMetaClassE']: [media],
                   model.names['__ZN8OSString10gMetaClassE']: [identity, name],
                   model.names['__ZN8OSNumber10gMetaClassE']: [major, minor],
                   model.names['__ZN14NativeRamBlock10gMetaClassE']: [obj]}
        require(metadata in allowed, 'Selector requested another class')
        model.returned(pointer if pointer in allowed[metadata] else 0)
    model.bind('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass', cast)
    def property_value(args):
        require(args[0] == media and refs.get(iterator) == 1, 'Selector accessed unowned media properties')
        key = model.string(args[1]); values = {'UUID': identity, 'BSD Name': name, 'BSD Major': major, 'BSD Minor': minor}
        require(key in values, 'Selector accessed another media property')
        missing = {'missing-uuid': 'UUID', 'missing-name': 'BSD Name', 'missing-major': 'BSD Major', 'missing-minor': 'BSD Minor'}
        value = 0 if key == missing.get(active['case']) else foreign if key == 'UUID' and active['case'] == 'wrong-uuid-type' else values[key]
        model.returned(value)
    model.bind('__ZNK15IORegistryEntry11getPropertyEPKc', property_value)
    def provider(args):
        active['provider_calls'] += 1
        require(active['provider_calls'] <= 64 and args[0] in active['edges'],
                'Selector provider walk escaped fixture: ' + active['case'] + ' at ' + hex(args[0]))
        model.returned(active['edges'][args[0]])
    model.bind('__ZNK9IOService11getProviderEv', provider)
    locks = [0, 0]
    gate, = struct.unpack('<Q', model.read(obj + facts['gate'], 8))
    def lock(args):
        require(args[0] == gate and locks[0] == locks[1], 'Selector locked another disk or retained its gate')
        locks[0] += 1; model.returned()
    def unlock(args):
        require(args[0] == gate and locks[0] == locks[1] + 1, 'Selector unlocked another disk')
        locks[1] += 1; model.returned()
    model.bind('_lck_mtx_lock', lock); model.bind('_lck_mtx_unlock', unlock)
    model.bind('_native_ufs_store_mode', lambda args: model.returned())
    def no_storage(args): raise ValueError('Read-only selector fixture reached a physical persistence operation')
    for symbol in ('_native_ufs_store_open', '_native_ufs_store_read', '_native_ufs_store_write',
                   '_native_ufs_store_sync', '_native_ufs_store_gpt_check'):
        model.bind(symbol, no_storage)
    model.bind('_strlen', lambda args: model.returned(len(model.string(args[0]))))
    model.bind('_strcmp', lambda args: model.returned((model.string(args[0]) > model.string(args[1])) - (model.string(args[0]) < model.string(args[1]))))
    def snprintf(args):
        require(args[1] == 64 and model.string(args[2]) == '/dev/%s', 'Selector changed its bounded BSD path format')
        sp = model.cpu.reg_read(model.arm.UC_ARM64_REG_SP)
        pointer, = struct.unpack('<Q', model.read(sp, 8))
        data = ('/dev/' + model.string(pointer)).encode()
        model.put(args[0], data[:63] + b'\0'); model.returned(len(data))
    model.bind('_snprintf', snprintf)
    def strlcpy(args):
        data = model.string(args[1]).encode(); require(0 < args[2] <= 64, 'Selector path copy escaped bound')
        model.put(args[0], data[:args[2] - 1] + b'\0'); model.returned(len(data))
    model.bind('_strlcpy', strlcpy)
    entry = '_native_ram_block_volume_seed'
    if control: model.put(model.names[entry], struct.pack('<I', 0xd65f03c0))
    for case in CASES:
        refs.clear(); held.clear()
        uuid = 'DAF0DD2B-1D90-5A73-A426-9306E1F967B5' if logical == 1 << 31 else 'C5A60047-CB25-5EF4-9FE8-44C65A1F0E63'
        if case == 'short-uuid': uuid = uuid[:-1]
        model.put(uuid_address, uuid.encode() + b'\0')
        put_string(identity, uuid if case != 'wrong-uuid' else '00000000-0000-0000-0000-000000000000', strings)
        put_string(name, '' if case == 'empty-name' else 'x' * 58 if case == 'long-name' else 'disk2s1', strings + 0x100)
        put_string(wanted, uuid, strings + 0x200)
        for address, value in ((major, 256 if case == 'major-overflow' else 14), (minor, 1 << 24 if case == 'minor-overflow' else 7)):
            model.put(address + facts['number_size'], struct.pack('<I', 64))
            model.put(address + facts['number_value'], struct.pack('<Q', value))
        chain = [media, nodes[0], obj]
        if case == 'no-ram-ancestor': chain = [media, nodes[0], 0]
        if case == 'ancestor-at-depth-64': chain = [media, *nodes[:62], obj]
        if case == 'ancestor-at-depth-65': chain = [media, *nodes[:63], obj]
        edges = dict(zip(chain, chain[1:]))
        edges[obj] = 0
        if case == 'provider-cycle': edges = {media: nodes[0], nodes[0]: nodes[1], nodes[1]: nodes[0]}
        sequence = [] if case == 'no-media' else [foreign, media] if case == 'foreign-object-skipped' else [media, media] if case == 'duplicate-media' else [media]
        active.update(case=case, uuid=uuid, sequence=sequence, edges=edges, factories=[], setters=[], queries=0, next_calls=0, provider_calls=0)
        model.put(output - 64, bytes([0xa5]) * 384)
        dev, path, seed_base, seed_bytes, seed_hash = output, output + 16, output + 96, output + 104, output + 112
        arguments = [0 if case == 'null-uuid' else uuid_address, 0 if case == 'null-device' else dev,
                     0 if case == 'null-path' else path, 5 if case == 'tiny-path-buffer' else 6 if case == 'short-path-buffer' else 64,
                     0 if case == 'null-base' else seed_base, 0 if case == 'null-bytes' else seed_bytes, 0 if case == 'null-digest' else seed_hash]
        was_online = model.read(obj + facts['online'], 1)
        if case == 'offline-disk': model.put(obj + facts['online'], b'\0')
        before_locks = locks[0]
        result = model.call(entry, arguments, limit=1000000)
        model.put(obj + facts['online'], was_online)
        success = case in ('ordinary', 'foreign-object-skipped', 'ancestor-at-depth-64')
        require(result == int(success) and not any(refs.values()) and not held and locks[0] == locks[1],
                'Selector result, owned metadata lifetime or gate is incorrect: ' + case)
        require(model.read(output - 64, 64) == bytes([0xa5]) * 64 and model.read(output + 160, 160) == bytes([0xa5]) * 160,
                'Selector escaped output buffer')
        if success:
            require(model.read(dev, 4) == struct.pack('<I', (14 << 24) | 7) and model.string(path) == '/dev/disk2s1' and
                    model.read(seed_base, 8) == bytes(8) and model.read(seed_bytes, 8) == struct.pack('<Q', logical) and
                    model.read(seed_hash, 32) == digest, 'Selector lost actual start capacity/hash/device identity')
        else:
            expected = bytes([0xa5]) * 48 if case in ('null-base', 'null-bytes', 'null-digest') else bytes(48)
            require(model.read(seed_base, 48) == expected, 'Selector failed-output seed contract differs')
        rows.append({'case': case, 'result': 'PASS', 'return': result, 'provider_edges_visited': active['provider_calls'],
                     'balanced_lock_pairs': locks[0] - before_locks, 'owned_metadata_references_remaining': sum(refs.values()),
                     'actual_started_disk_seed_info': success})
    return {'result': 'PASS', 'case_count': len(rows), 'cases': rows,
            'source_selector_attach_store_and_seed_info_executed': True,
            'native_string_and_number_getters_executed': True,
            'registry_collection_allocation_class_membership_and_provider_edges_are_explicit_peers': True,
            'persistent_store_mode_peer': 0, 'actual_iomedia_registration_or_matching_qualified': False}
