#!/usr/bin/env python3
"""Original iPhone security startup and owner development boot-set inputs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct

from native_driver_build import ROOT, require, sha, macho, symbols, build_objects
from native_prelink import backed_offset, unserialize_xml
from prepare_device_tree import parse_adt
from unixnu.devicetree import node

CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/image4-boot.json'
DOMAIN = 'UniXNU.Dodge.Image4BootSet.v1'
MARKER = DOMAIN.encode() + b'\0'
AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
SANDBOX = 'com.apple.security.sandbox'
POLICY_KEYS = ('owner-image4-policy', 'mix-n-match-prevention-status', 'boot-manifest-hash')


def compile_policy_layout():
    fields = [('list_bytes', 'sizeof(mac_policy_list_t)'),
        *[(name, '__builtin_offsetof(mac_policy_list_t,' + name + ')') for name in ('numloaded', 'max', 'maxindex', 'entries')],
        ('element_bytes', 'sizeof(struct mac_policy_list_element)'), ('conf_bytes', 'sizeof(struct mac_policy_conf)'),
        *[(name, '__builtin_offsetof(struct mac_policy_conf,' + name + ')') for name in ('mpc_name', 'mpc_ops', 'mpc_runtime_flags')],
        ('registered_flag', 'MPC_RUNTIME_FLAG_REGISTERED')]
    out = ROOT / 'build/cph2653-image4-abi';out.mkdir(parents=True, exist_ok=True)
    source = out / 'PolicyLayout.c'
    source.write_text('#include <security/mac_internal.h>\nconst unsigned dodge_policy_layout[]={' +
                      ','.join('(unsigned)(' + expression + ')' for _, expression in fields) + '};\n')
    obj, = build_objects([source], out)
    data = obj.read_bytes();image = macho(data)
    address, = [s['value'] for s in symbols(data) if s['name'] == '_dodge_policy_layout']
    at = backed_offset(image['segments'], address, len(fields) * 4, len(data))
    values = struct.unpack_from('<' + str(len(fields)) + 'I', data, at)
    facts = dict(zip((name for name, _ in fields), values))
    return facts, [source, obj, out / 'compile-commands.json']


def derive_contract():
    from prepare_ios16_pmgr import original
    raw, image, read, entries, _ = original()

    def block(address, size):
        return {'address': hex(address), 'bytes': size, 'sha256': hashlib.sha256(read(address, size)).hexdigest()}

    starts = {}
    for module, initializer, expected_slot, expected_target in (
            (AMFI, 0xfffffff005704320, 0xfffffff007a11a60, 0),
            (SANDBOX, 0xfffffff0064bcd80, 0xfffffff007ae8dc8, 0xfffffff0064bcd80)):
        record = entries[module]['_PrelinkKmodInfo']
        start, = struct.unpack('<Q', read(record + 180, 8))
        a, b, *tail = struct.unpack('<7I', read(start, 28))
        require(a & 0x9f00001f == 0x90000008 and b & 0xffc003ff == 0x91000108 and
                tail == [0xf9400102, 0xb4000042, 0xd61f0040, 0x52800000, 0xd65f03c0],
                'Original security start is not the measured pointer trampoline')
        delta = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
        if delta & (1 << 20):
            delta -= 1 << 21
        slot = (start & -4096) + (delta << 12) + ((b >> 10) & 4095)
        target, = struct.unpack('<Q', read(slot, 8))
        require(slot == expected_slot and target == expected_target, 'Original security start target changed')
        starts[module] = {'kmod_record': hex(record), 'start': hex(start), 'slot': hex(slot),
            'slot_value': hex(target), 'initializer': hex(initializer), 'wrapper': block(start, 28),
            'normal_start_runs_initializer': target == initializer}

    # These entries were located at the actual QEMU panic and callback. All
    # addresses and code are from this iPhone's Darwin 22 collection.
    strings = {'mix-n-match-prevention-status': 0xfffffff004e204c8,
               'BNCH': 0xfffffff004e202c5, '/chosen/manifest-properties': 0xfffffff004e20287}
    for name, address in strings.items():
        require(read(address, len(name) + 1) == name.encode() + b'\0', 'Original Image4 property identity changed')
    # Identifier 12 maps to this property, then the boolean getter inverts
    # prevention into allow-mix-n-match. A value of one keeps mixing disabled.
    table = read(0xfffffff004e18b60, 12)
    require(table[12 - 5] == 17 and
            struct.unpack('<5I', read(0xfffffff0056eff8c, 20)) ==
            (0xf10032bf, 0x540000c1, 0xb9400fe8, 0x7100011f, 0x1a9f17e8),
            'Original Image4 AMNM mapping or boolean inversion changed')
    layout, _ = compile_policy_layout()
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(),
        'Image4_module': entries['com.apple.security.AppleImage4']['CFBundleIdentifier'],
        'Image4_version': entries['com.apple.security.AppleImage4']['CFBundleVersion'],
        'properties': {name: {'address': hex(address), 'value_bytes': 4 if name.startswith('mix-') else 48 if name == 'BNCH' else None}
                       for name, address in strings.items()},
        'allow_mix_identifier': 12, 'prevention_value_for_disabled_mixing': 1,
        'Image4_startup': block(0xfffffff0056e98cc, 1744),
        'Image4_boolean_getter': block(0xfffffff0056efe7c, 384), 'security_starts': starts, 'mac_policy_layout': layout}


def checked_contract(derive=False):
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_image4_boot_contract']
    require(pin['path'] == str(CONTRACT.relative_to(ROOT)) and pin['sha256'] == sha(CONTRACT),
            'Reviewed iPhone Image4 startup contract changed')
    contract = json.loads(CONTRACT.read_text())
    require((contract['product'], contract['build']) == ('iPhone10,3', '20H392'), 'Wrong Image4 target')
    if derive:
        require(derive_contract() == contract, 'Original iPhone Image4 or security start bytes changed')
    return contract


def security_plan(profile, fixture):
    contract = checked_contract(derive=True)
    require(fixture['original_sha256'] == contract['original_kernelcache_sha256'] and
            set(fixture['initializers']) == {AMFI, SANDBOX}, 'Wrong original security fixture')
    planned = copy.deepcopy(fixture)
    normal, requests = {}, []
    for request in profile['kernel']['prelink']['early_security_init']:
        name, text = request.split('=', 1)
        start = contract['security_starts'][name]
        require(int(text, 0) == int(start['initializer'], 0) == int(fixture['initializers'][name]['address'], 0),
                'Security initializer differs from the measured module start')
        if start['normal_start_runs_initializer']:
            normal[name] = start
            del planned['initializers'][name]
        else:
            requests.append(request)
    require(set(normal) == {SANDBOX} and set(planned['initializers']) == {AMFI}, 'Unexpected security startup coverage')
    return planned, requests, normal


def check_security_starts(data, record, normal):
    contract = checked_contract()
    image = macho(data)
    slide = record['slide']

    def read(address, count):
        at = backed_offset(image['segments'], address + slide, count, len(data))
        return data[at:at + count]

    info, = [seg for seg in image['segments'] if seg['name'] == '__PRELINK_INFO']
    at = backed_offset(image['segments'], info['va'], info['filesize'], len(data))
    entries = {entry['CFBundleIdentifier']: entry for entry in unserialize_xml(data[at:at + info['filesize']])['_PrelinkInfoDictionary']}
    require(normal == {SANDBOX: contract['security_starts'][SANDBOX]} and
            set(record['early_security_initializers']) == {AMFI} and
            '_NativePrelinkEarlySecurityInit' not in entries[SANDBOX], 'Sandbox has a duplicate early initializer')
    for name, start in contract['security_starts'].items():
        require(struct.unpack('<Q', read(int(start['kmod_record'], 0) + 180, 8))[0] == int(start['start'], 0) + slide,
                'Original security kmod start changed')
        wrapper = start['wrapper']
        require(hashlib.sha256(read(int(wrapper['address'], 0), wrapper['bytes'])).hexdigest() == wrapper['sha256'],
                'Original security start wrapper changed')
        target = int(start['slot_value'], 0)
        require(struct.unpack('<Q', read(int(start['slot'], 0), 8))[0] == (target + slide if target else 0),
                'Original security start target changed')
    return {'normal_starts': [SANDBOX], 'explicit_initializers': [AMFI], 'original_wrappers_preserved': True}


def encode_tree(nodes):
    def encode(path):
        children = [key for key in nodes if key != path and key.rsplit('/', 1)[0] == ('' if path == '/' else path)]
        properties = nodes[path]
        return node(properties['name'].rstrip(b'\0').decode(), [(k, v) for k, v in properties.items() if k != 'name'],
                    [encode(child) for child in children])
    return encode('/')


def strip_policy(nodes):
    nodes = copy.deepcopy(nodes)
    chosen = nodes['/chosen']
    manifest = nodes.get('/chosen/manifest-properties', {})
    if any(key in chosen for key in POLICY_KEYS) or 'BNCH' in manifest:
        require(chosen.get('owner-image4-policy') == MARKER, 'Refuse to replace existing firmware or Apple boot policy')
    for key in POLICY_KEYS:
        chosen.pop(key, None)
    manifest.pop('BNCH', None)
    return nodes


def canonical_tree(nodes):
    nodes = strip_policy(nodes)
    chosen = nodes['/chosen']
    chosen['owner-image4-policy'] = MARKER
    chosen['mix-n-match-prevention-status'] = struct.pack('<I', 1)
    require(len(chosen.get('random-seed', b'')) == 256, 'Owner policy requires the entropy reservation')
    chosen['random-seed'] = bytes(256)
    for key in ('TrustCache', 'GpuAddon', 'RAMDisk', 'PackedRAMDisk'):
        value = nodes.get('/chosen/memory-map', {}).get(key)
        if value is not None:
            require(len(value) == 16, 'Malformed loader memory-map placeholder')
            nodes['/chosen/memory-map'][key] = bytes(16)
    nodes.setdefault('/chosen/manifest-properties', {'name': b'manifest-properties\0'})
    return encode_tree(nodes)


def component_records(components):
    require({'kernel.macho', 'kernel.macho.trustcache'} <= components.keys() <=
            {'kernel.macho', 'kernel.macho.trustcache', 'kernel.macho.gpuaddon', 'scratch-data.img'},
            'Unexpected owner boot components')
    require(all(isinstance(data, bytes) and data for data in components.values()), 'Empty owner boot component')
    return {name: {'bytes': len(data), 'sha384': hashlib.sha384(data).hexdigest()} for name, data in sorted(components.items())}


def manifest_hash(manifest):
    return hashlib.sha384(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).digest()


def check_policy(adt, manifest, components):
    nodes = parse_adt(adt)
    chosen = nodes['/chosen']
    require(nodes['/']['model'] == b'iPhone10,3\0' and chosen['chip-id'] == struct.pack('<I', 0x8015), 'Wrong owner boot identity')
    require(set(manifest) == {'schema_version', 'domain', 'scope', 'product', 'build', 'mix_n_match_prevention',
                             'nonce_hash', 'device_tree_sha384', 'components'} and
            manifest['schema_version'] == 1 and manifest['domain'] == DOMAIN and manifest['scope'] == 'owner-development' and
            (manifest['product'], manifest['build']) == ('iPhone10,3', '20H392') and manifest['mix_n_match_prevention'] is True,
            'Wrong owner development policy')
    nonce = bytes.fromhex(manifest['nonce_hash'])
    require(len(nonce) == 48 and any(nonce) and chosen.get('owner-image4-policy') == MARKER and
            chosen.get('mix-n-match-prevention-status') == struct.pack('<I', 1) and
            chosen.get('boot-manifest-hash') == manifest_hash(manifest) and
            nodes.get('/chosen/manifest-properties', {}).get('BNCH') == nonce, 'Owner Image4 handoff fields differ')
    require(manifest['components'] == component_records(components) and
            manifest['device_tree_sha384'] == hashlib.sha384(canonical_tree(nodes)).hexdigest(),
            'Owner boot manifest does not bind the selected files and device tree')
    return True


def prepare_policy(adt, components, nonce=None):
    nodes = strip_policy(parse_adt(adt))
    require(nodes['/']['model'] == b'iPhone10,3\0' and nodes['/chosen']['chip-id'] == struct.pack('<I', 0x8015),
            'Owner boot policy needs the pinned iPhone identity')
    nonce = os.urandom(48) if nonce is None else nonce
    require(isinstance(nonce, bytes) and len(nonce) == 48 and any(nonce), 'Invalid private owner boot-set nonce')
    nonce_hash = hashlib.sha384(b'UniXNU.Dodge.OwnerNonce.v1\0' + nonce).digest()
    manifest = {'schema_version': 1, 'domain': DOMAIN, 'scope': 'owner-development', 'product': 'iPhone10,3', 'build': '20H392',
        'mix_n_match_prevention': True, 'nonce_hash': nonce_hash.hex(),
        'device_tree_sha384': hashlib.sha384(canonical_tree(nodes)).hexdigest(), 'components': component_records(components)}
    chosen = nodes['/chosen']
    chosen['owner-image4-policy'] = MARKER
    chosen['mix-n-match-prevention-status'] = struct.pack('<I', 1)
    chosen['boot-manifest-hash'] = manifest_hash(manifest)
    nodes.setdefault('/chosen/manifest-properties', {'name': b'manifest-properties\0'})['BNCH'] = nonce_hash
    result = encode_tree(nodes)
    check_policy(result, manifest, components)
    return result, manifest
