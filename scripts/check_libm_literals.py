#!/usr/bin/env python3
"""Check the pinned iPhone Libm constant range and an altered-byte refusal."""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import backed_offset, macho, unserialize_xml
from emit_prelink import MATH_LITERAL_POOLS, instruction_inventory, pc_relative_target


def main():
    spec = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_libm_literal_pool']
    data = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    if hashlib.sha256(data).hexdigest() != spec['original_sha256']:
        raise SystemExit('Unqualified original iPhone input')
    parent = macho(data)
    info, = [s for s in parent['segments'] if s['name'] == '__PRELINK_INFO']
    at = backed_offset(parent['segments'], info['va'], info['filesize'], len(data))
    entry, = [e for e in unserialize_xml(data[at:at + info['filesize']])['_PrelinkInfoDictionary']
              if e['CFBundleIdentifier'] == 'com.apple.kec.Libm']
    module = macho(data, backed_offset(parent['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(data)))
    code, = [s for s in module['segments'] if s['name'] == '__TEXT_EXEC']
    code_at = backed_offset(parent['segments'], code['va'], code['filesize'], len(data))
    blob = data[code_at:code_at + code['filesize']]
    address, length = int(spec['va'], 16), spec['size']
    at = backed_offset(parent['segments'], address, length, len(data))
    if hashlib.sha256(data[at:at + length]).hexdigest() != spec['sha256']:
        raise SystemExit('Complete Libm constant range does not match')
    if data[at-4:at] != bytes.fromhex('c0035fd6') or data[at+length:at+length+8] != bytes.fromhex('fd7bbfa9fd030091'):
        raise SystemExit('Reviewed return / following function boundary changed')
    ranges = []
    for prefix, size, digest in MATH_LITERAL_POOLS:
        search = 0
        while (search := blob.find(bytes.fromhex(prefix), search)) >= 0:
            if hashlib.sha256(blob[search:search + size]).hexdigest() == digest:
                ranges.append((code['va'] + search, code['va'] + search + size))
            search += 4
    references = []
    for offset in range(0, len(blob) - 3, 4):
        pc = code['va'] + offset
        if any(start <= pc < end for start, end in ranges):
            continue
        word, = struct.unpack_from('<I', blob, offset)
        decoded = pc_relative_target(word, pc)
        if not decoded or not address <= decoded[0] < address + length:
            continue
        branch = (word & 0x7c000000 == 0x14000000 or word & 0xff000010 == 0x54000000
                  or word & 0x7e000000 in (0x34000000, 0x36000000))
        if branch:
            raise SystemExit('A direct branch enters the reviewed constant range')
        references.append({'site': hex(pc), 'target': hex(decoded[0]), 'word': hex(word)})
    if len(references) != len(spec['code_data_references']):
        raise SystemExit('Reviewed data-reference set changed')
    inventory = instruction_inventory(data, parent['segments'], {'com.apple.kec.Libm': module})
    altered = bytearray(data)
    altered[at] ^= 1
    try:
        instruction_inventory(altered, parent['segments'], {'com.apple.kec.Libm': module})
    except ValueError as error:
        if 'External PC-relative encoding' not in str(error):
            raise
    else:
        raise SystemExit('Changed constants were accepted by the production inventory')
    report = {'result': 'PASS', 'original_sha256': spec['original_sha256'],
              'address': spec['va'], 'bytes': length, 'sha256': spec['sha256'],
              'previous_return_and_following_function': 'matched',
              'direct_branches_into_pool': 0, 'data_reference_count': len(references),
              'actual_libm_instruction_inventory': 'PASS', 'altered_byte_negative_control': 'rejected',
              'recognized_libm_pools': len(ranges),
              'scope': 'Static classification of unchanged pinned bytes only; full register dataflow, ABI and runtime remain unqualified.'}
    (ROOT / 'reports/libm-literals.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: complete iPhone Libm pool, 30 data references, no direct entries; changed bytes rejected')


if __name__ == '__main__':
    main()
