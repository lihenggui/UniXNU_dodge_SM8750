#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check the actual UEFI memory table against the captured boot-time FDT."""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


def read_tree(data):
    h = struct.unpack_from('>10I', data)
    if h[0] != 0xd00dfeed or h[1] != len(data):
        raise ValueError('Invalid FDT header or total size')
    names = data[h[3]:h[3] + h[8]]
    pos, end, stack, nodes = h[2], h[2] + h[9], [], {}
    while pos < end:
        token, = struct.unpack_from('>I', data, pos)
        pos += 4
        if token == 1:
            stop = data.index(0, pos)
            stack.append(data[pos:stop].decode())
            nodes['/' + '/'.join(stack[1:])] = {}
            pos = (stop + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            size, name_offset = struct.unpack_from('>II', data, pos)
            pos += 8
            if pos + size > end or name_offset >= len(names):
                raise ValueError('FDT property outside structure block')
            key = names[name_offset:names.index(0, name_offset)].decode()
            nodes['/' + '/'.join(stack[1:])][key] = data[pos:pos + size]
            pos = (pos + size + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack:
                raise ValueError('Unbalanced FDT nodes')
            return nodes
        else:
            raise ValueError(f'Unknown FDT token {token}')
    raise ValueError('Missing FDT end token')


def ranges(nodes, path):
    parent = nodes[path.rsplit('/', 1)[0] or '/']
    ac = int.from_bytes(parent.get('#address-cells', b'\0\0\0\2'), 'big')
    sc = int.from_bytes(parent.get('#size-cells', b'\0\0\0\1'), 'big')
    raw = nodes[path].get('reg', b'')
    step = (ac + sc) * 4
    if not step or len(raw) % step:
        raise ValueError(f'Invalid reg encoding: {path}')
    return [(int.from_bytes(raw[i:i + ac * 4], 'big'),
             int.from_bytes(raw[i + ac * 4:i + step], 'big'))
            for i in range(0, len(raw), step)]


def uncovered(start, length, allowed):
    current, stop, missing = start, start + length, []
    for base, size in sorted(allowed):
        end = base + size
        if end <= current or base >= stop:
            continue
        if base > current:
            missing.append((current, min(base, stop) - current))
        current = max(current, min(end, stop))
    if current < stop:
        missing.append((current, stop - current))
    return missing


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--map', type=Path, required=True)
    parser.add_argument('--dtb', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    data = args.dtb.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != args.expected_sha256.lower():
        raise ValueError('Device tree hash does not match the selected device')
    nodes = read_tree(data)
    memory = [r for p, v in nodes.items() if v.get('device_type') == b'memory\0' for r in ranges(nodes, p) if r[1]]
    reserved = [(p, base, size) for p, v in nodes.items()
                if p.startswith('/reserved-memory/') and p.count('/') == 2
                and v.get('status', b'okay\0') in (b'okay\0', b'ok\0')
                for base, size in ranges(nodes, p) if size]
    source = args.map.read_text()
    rows = []
    for match in re.finditer(r'\{\s*"([^"]+)"\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,([^}]+)\}', source):
        fields = [x.strip() for x in match[4].split(',')]
        if len(fields) != 5:
            raise ValueError('Unexpected memory descriptor fields')
        rows.append({'name': match[1], 'base': int(match[2], 16), 'size': int(match[3], 16),
                     'hob': fields[0], 'resource': fields[1], 'type': fields[3],
                     'line': source[:match.start()].count('\n') + 1})
    if not rows or len([r for r in rows if r['name'] == 'DXE_Heap']) != 1:
        raise ValueError('Missing memory table or unique primary DXE_Heap')
    problems = []
    for row in rows:
        if row['hob'] != 'AddMem' or row['resource'] != 'SYS_MEM' or row['type'] != 'Conv':
            continue
        start, size = row['base'], row['size']
        if not size or start % 4096 or size % 4096:
            problems.append({'kind': 'unaligned_or_empty', 'region': row['name']})
        for base, count in uncovered(start, size, memory):
            problems.append({'kind': 'outside_device_memory', 'region': row['name'],
                             'start': hex(base), 'size': hex(count)})
        for name, base, count in reserved:
            overlap = min(start + size, base + count) - max(start, base)
            if overlap > 0:
                problems.append({'kind': 'reserved_overlap', 'region': row['name'],
                                 'reserved_node': name, 'overlap_bytes': overlap})
    ram_rows = sorted((r for r in rows if r['base'] >= 0x80000000), key=lambda r: r['base'])
    for left, right in zip(ram_rows, ram_rows[1:]):
        if left['base'] + left['size'] > right['base']:
            problems.append({'kind': 'descriptor_overlap', 'left': left['name'], 'right': right['name']})
    report = {'map': str(args.map.resolve()), 'dtb_sha256': digest,
              'allocatable_regions': [r for r in rows if r['hob'] == 'AddMem' and r['resource'] == 'SYS_MEM' and r['type'] == 'Conv'],
              'problems': problems, 'result': 'FAIL' if problems else 'PASS',
              'scope': 'Static initial table versus captured FDT; not proof of a successful or safe hardware boot.'}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(bool(problems))


if __name__ == '__main__':
    main()
