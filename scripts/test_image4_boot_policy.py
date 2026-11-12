#!/usr/bin/env python3
"""Test owner boot-set binding and preservation of existing firmware inputs."""
import copy
import hashlib
import json
import struct
import unittest

from image4_boot_policy import (AMFI, SANDBOX, MARKER, canonical_tree, checked_contract, check_policy,
                               encode_tree, manifest_hash, prepare_policy, strip_policy)
from prepare_device_tree import parse_adt
from unixnu.devicetree import node


class BootPolicyTest(unittest.TestCase):
    def setUp(self):
        self.source = node('device-tree', [('model', b'iPhone10,3\0'), ('compatible', b'D22AP\0AppleARM\0')], [
            node('chosen', [('chip-id', struct.pack('<I', 0x8015)), ('random-seed', bytes([17]) * 256)],
                 [node('memory-map', [('TrustCache', bytes(16))])]), node('product', [('artwork-device-idiom', b'phone\0')])])
        self.components = {'kernel.macho': b'host kernel input', 'kernel.macho.trustcache': b'host trust input'}
        self.nonce = bytes(range(48))
        self.adt, self.manifest = prepare_policy(self.source, self.components, self.nonce)

    def test_original_start_contract(self):
        contract = checked_contract()
        self.assertTrue(contract['security_starts'][SANDBOX]['normal_start_runs_initializer'])
        self.assertFalse(contract['security_starts'][AMFI]['normal_start_runs_initializer'])
        self.assertEqual(contract['prevention_value_for_disabled_mixing'], 1)

    def test_bound_inputs(self):
        self.assertTrue(check_policy(self.adt, self.manifest, self.components))
        self.assertEqual(prepare_policy(self.source, self.components, self.nonce), (self.adt, self.manifest))
        original = parse_adt(self.source)
        actual = strip_policy(parse_adt(self.adt))
        del actual['/chosen/manifest-properties']
        self.assertEqual(actual, original)

    def test_nonce_rotation(self):
        adt, manifest = prepare_policy(self.source, self.components, bytes([42]) * 48)
        self.assertNotEqual(manifest['nonce_hash'], self.manifest['nonce_hash'])
        self.assertNotEqual(manifest_hash(manifest), manifest_hash(self.manifest))
        self.assertTrue(check_policy(adt, manifest, self.components))

    def test_bad_private_nonce(self):
        for nonce in (bytes(48), bytes(47), bytes(49), 'not nonce bytes'):
            with self.subTest(size=len(nonce)), self.assertRaises(ValueError):
                prepare_policy(self.source, self.components, nonce)

    def test_changed_components(self):
        for name in self.components:
            changed = {**self.components, name: self.components[name] + b'changed'}
            with self.subTest(component=name), self.assertRaises(ValueError):
                check_policy(self.adt, self.manifest, changed)

    def test_component_inventory(self):
        for components in ({}, {'kernel.macho': b'kernel'}, {**self.components, '../other': b'bad'},
                           {**self.components, 'kernel.macho': b''}):
            with self.subTest(components=list(components)), self.assertRaises(ValueError):
                prepare_policy(self.source, components, self.nonce)
        components = {**self.components, 'kernel.macho.gpuaddon': b'addon'}
        adt, manifest = prepare_policy(self.source, components, self.nonce)
        self.assertTrue(check_policy(adt, manifest, components))
        components['scratch-data.img'] = b'packed Data input'
        adt, manifest = prepare_policy(self.source, components, self.nonce)
        with self.assertRaises(ValueError):
            check_policy(adt, manifest, {**components, 'scratch-data.img': b'changed Data input'})

    def test_policy_values(self):
        for key, value in (('scope', 'apple-personalized'), ('build', 'other'), ('mix_n_match_prevention', False),
                           ('schema_version', 2), ('nonce_hash', '00' * 48)):
            bad = copy.deepcopy(self.manifest);bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_policy(self.adt, bad, self.components)

    def test_changed_handoff(self):
        for path, key, value in (('/chosen', 'mix-n-match-prevention-status', bytes(4)),
                                ('/chosen', 'boot-manifest-hash', bytes(48)),
                                ('/chosen', 'owner-image4-policy', b'other\0'),
                                ('/chosen/manifest-properties', 'BNCH', bytes(48))):
            nodes = parse_adt(self.adt);nodes[path][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_policy(encode_tree(nodes), self.manifest, self.components)

    def test_wrong_identity(self):
        for path, key, value in (('/', 'model', b'iPad7,3\0'), ('/chosen', 'chip-id', struct.pack('<I', 0x8011))):
            nodes = parse_adt(self.source);nodes[path][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                prepare_policy(encode_tree(nodes), self.components, self.nonce)

    def test_changed_board_resources(self):
        nodes = parse_adt(self.adt);nodes['/chosen']['dram-size'] = struct.pack('<Q', 2 << 30)
        with self.assertRaises(ValueError):
            check_policy(encode_tree(nodes), self.manifest, self.components)
        rebound, manifest = prepare_policy(encode_tree(nodes), self.components, self.nonce)
        self.assertNotEqual(manifest_hash(manifest), manifest_hash(self.manifest))
        self.assertTrue(check_policy(rebound, manifest, self.components))

    def test_loader_entropy_and_addresses(self):
        nodes = parse_adt(self.adt)
        nodes['/chosen']['random-seed'] = bytes([99]) * 256
        nodes['/chosen/memory-map']['TrustCache'] = struct.pack('<QQ', 0x12345000, 4096)
        self.assertTrue(check_policy(encode_tree(nodes), self.manifest, self.components))
        self.assertEqual(hashlib.sha384(canonical_tree(nodes)).hexdigest(), self.manifest['device_tree_sha384'])
        nodes['/chosen/memory-map']['PackedRAMDisk'] = bytes(16)
        adt, manifest = prepare_policy(encode_tree(nodes), self.components, self.nonce)
        nodes = parse_adt(adt);nodes['/chosen/memory-map']['PackedRAMDisk'] = struct.pack('<QQ', 0x20000000, 721024)
        self.assertTrue(check_policy(encode_tree(nodes), manifest, self.components))

    def test_existing_firmware_policy_is_preserved(self):
        for path, key, value in (('/chosen', 'boot-manifest-hash', b'a' * 48),
                                ('/chosen', 'mix-n-match-prevention-status', struct.pack('<I', 1))):
            nodes = parse_adt(self.source);nodes[path][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                prepare_policy(encode_tree(nodes), self.components, self.nonce)
        nodes = parse_adt(self.source)
        nodes['/chosen/manifest-properties'] = {'name': b'manifest-properties\0', 'BNCH': b'a' * 48}
        with self.assertRaises(ValueError):
            prepare_policy(encode_tree(nodes), self.components, self.nonce)


if __name__ == '__main__':
    program = unittest.main(exit=False)
    print(json.dumps({'result': 'PASS' if program.result.wasSuccessful() else 'FAIL', 'test_cases': program.result.testsRun}))
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
