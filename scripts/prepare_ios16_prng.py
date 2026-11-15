#!/usr/bin/env python3
"""Derive the original iPhone PRNG sysctl tree without private PRNG structure guesses."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, require, sha
from prepare_ios16_pmgr import original

CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/prng-sysctl.json'
NODE = 0xfffffff007a0b910
CHILDREN = 0xfffffff007a10da0
COUNT = 4 + 32 * 4
SLIDE = -0x1000000


def derive():
    raw, _, read, _, names = original()
    rows = []
    for index in range(COUNT):
        address = NODE + 80 * index
        data = read(address, 80)
        parent, link, number, kind, arg1, arg2 = struct.unpack_from('<QQiiQi', data)
        name, handler, fmt, description, version, refcount = struct.unpack_from('<QQQQii', data, 40)
        def text(pointer):return read(pointer, 128).split(b'\0', 1)[0].decode() if pointer else None
        label = text(name)
        node = index == 0 or index >= 4 and (index - 4) % 4 == 0
        pool = (index - 4) // 4
        expected_name = (('prng', 'scheduled_reseed_count', 'scheduled_reseed_max_sample_count', 'entropy_max_sample_count')[index]
            if index < 4 else ('pool_' + str(pool), 'sample_count', 'drain_count', 'max_sample_count')[(index - 4) % 4])
        expected_parent = names['_sysctl__kern_children'] if not index else CHILDREN if index < 4 or node else CHILDREN + 8 * (pool + 1)
        require(label == expected_name and parent == expected_parent and not link and number == -1 and
            kind & 0xffffffff == (0x80400001 if node else 0x80400004) and not arg2 and not description and
            version == 1 and not refcount and text(fmt) == ('N' if node else 'Q') and
            handler == (0 if node else names['_sysctl_handle_quad']), 'Original iPhone PRNG node changed: ' + str(index))
        require(not node or arg1 == CHILDREN + (8 * (pool + 1) if index else 0), 'Original PRNG child list changed')
        rows.append({'address': hex(address), 'name': label, 'parent': hex(parent), 'kind': hex(kind & 0xffffffff),
            'arg1': hex(arg1), 'handler': hex(handler), 'format': text(fmt)})
    require(read(CHILDREN, 33 * 8) == bytes(33 * 8), 'Original PRNG child lists are not initially empty')
    consumer = ROOT / 'build/cph2653-native-entropy/prng_seedctl.original'
    entropy = json.loads((ROOT / 'hardware/dodge-entropy.json').read_text())['iPhone_consumer']
    require(sha(consumer) == entropy['sha256'] and consumer.read_bytes().count(b'kern.prng.pool%zu.%s\0') == 1,
        'Need the exact original iPhone pool-name consumer')
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(), 'slide': hex(SLIDE),
        'node_bytes': 80, 'node_count': COUNT, 'counter_count': 99, 'pools': 32, 'counter_bytes': 8,
        'node_block_sha256': hashlib.sha256(read(NODE, COUNT * 80)).hexdigest(),
        'original_children': hex(CHILDREN), 'linked_children': hex(CHILDREN + SLIDE),
        'linked_binding': {'_sysctl__kern_prng_children': hex(CHILDREN + SLIDE),
            '_dodge_original_prng_pool_children': hex(CHILDREN + SLIDE + 8)}, 'nodes': rows,
        'consumer_sha256': entropy['sha256'], 'consumer_pool_format': 'kern.prng.pool%zu.%s',
        'counter_owner': 'unchanged original iPhone corecrypto', 'hardware_tested': False}


def reviewed():
    facts = derive()
    require(json.loads(CONTRACT.read_text()) == facts, 'Original iPhone PRNG contract changed')
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--write', action='store_true');args = parser.parse_args()
    facts = derive()
    if args.write:
        require(not CONTRACT.exists(), 'Refuse to replace reviewed PRNG inputs')
        CONTRACT.write_text(json.dumps(facts, indent=2) + '\n')
    reviewed()
    print('PASS: original iPhone PRNG tree, 32 pools, 99 real 64-bit observations and shared child list')


if __name__ == '__main__':main()
