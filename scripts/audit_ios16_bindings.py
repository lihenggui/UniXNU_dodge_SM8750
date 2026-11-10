#!/usr/bin/env python3
"""Inventory all selected iPhone kernel imports without supplying substitute addresses."""
import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge'
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import backed_offset, exports, macho, unserialize_xml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--try-prelink', action='store_true', help='Also run strict local emission and retain its failure log')
    args = parser.parse_args()
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    native_path = WORK / 'tree' / profile['kernel']['prelink']['kernel']
    original_path = ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed'
    native_data, original_data = native_path.read_bytes(), original_path.read_bytes()
    original_hash = hashlib.sha256(original_data).hexdigest()
    if original_hash != profile['kernel']['prelink']['kernelcache_sha256']:
        raise SystemExit('Original iPhone input does not match the pinned profile')
    native, original = macho(native_data), macho(original_data)
    info, = [s for s in original['segments'] if s['name'] == '__PRELINK_INFO']
    at = backed_offset(original['segments'], info['va'], info['filesize'], len(original_data))
    metadata = unserialize_xml(original_data[at:at + info['filesize']])
    entries = {e['CFBundleIdentifier']: e for e in metadata['_PrelinkInfoDictionary']}
    if len(entries) != len(metadata['_PrelinkInfoDictionary']):
        raise SystemExit('Duplicate component identities')
    selected, pending = set(), list(profile['kernel']['prelink']['roots'])
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        if name not in entries:
            raise SystemExit('Missing declared dependency: ' + name)
        selected.add(name)
        pending.extend(entries[name].get('OSBundleLibraries', {}))
    owned = []
    for name, entry in entries.items():
        address, size = entry.get('_PrelinkExecutableLoadAddr'), entry.get('_PrelinkExecutableSize')
        if not address or not size or entry.get('OSKernelResource'):
            continue
        module = macho(original_data, backed_offset(original['segments'], address, 32, len(original_data)))
        for segment in module['segments']:
            if segment['size']:
                owned.append((segment['va'], segment['va'] + segment['size'], name))
    owned.sort()
    if any(a[1] > b[0] for a, b in zip(owned, owned[1:])):
        raise SystemExit('Overlapping original component mappings')
    starts = [row[0] for row in owned]

    def owner(address):
        index = bisect_right(starts, address) - 1
        return owned[index] if index >= 0 and address < owned[index][1] else None

    original_names = exports(original_data, original)
    native_by_name = {}
    for address, names in exports(native_data, native).items():
        for name in names:
            native_by_name.setdefault(name, set()).add(address)
    packed = metadata['_PrelinkLinkKASLROffsets']
    count, = struct.unpack_from('<I', packed)
    if len(packed) != 4 + count * 4:
        raise SystemExit('Invalid original relocation table')
    base, = [s['va'] for s in original['segments'] if s['name'] == '__PRELINK_TEXT']
    counts, gaps = Counter(), {}
    for (offset,) in struct.iter_unpack('<I', packed[4:]):
        site = base + offset
        source = owner(site)
        if source is None or source[2] not in selected:
            continue
        if owner(site + 7) != source:
            raise SystemExit('Original pointer crosses a component extent')
        at = backed_offset(original['segments'], site, 8, len(original_data))
        target, = struct.unpack_from('<Q', original_data, at)
        destination = owner(target)
        if destination:
            if destination[2] not in selected:
                raise SystemExit('Undeclared original component dependency')
            counts['component_pointer_sites'] += 1
            continue
        names = original_names.get(target, [])
        choices = {address for name in names for address in native_by_name.get(name, ())}
        if len(choices) == 1 and any(s['va'] <= next(iter(choices)) < s['va'] + s['size'] for s in native['segments']):
            counts['unique_name_pointer_sites'] += 1
            continue
        reason = 'ambiguous-native-binding' if len(choices) > 1 else 'missing-native-symbol' if names else 'unnamed-original-target'
        counts[reason + '_sites'] += 1
        row = gaps.setdefault(target, {'original_address': hex(target), 'names': names, 'reason': reason,
                                       'native_candidates': [hex(value) for value in sorted(choices)],
                                       'pointer_sites': 0, 'consumers': {}})
        row['pointer_sites'] += 1
        row['consumers'][source[2]] = row['consumers'].get(source[2], 0) + 1
    report = {'result': 'GAPS' if gaps else 'NAME_MAPPING_ONLY', 'original_sha256': original_hash,
              'native_sha256': hashlib.sha256(native_data).hexdigest(), 'selected_dependency_count': len(selected),
              'pointer_counts': dict(counts), 'unresolved_target_count': len(gaps),
              'unresolved_targets': [gaps[key] for key in sorted(gaps)],
              'binary_abi_qualified': False, 'early_security_initializer_qualified': False,
              'hardware_tested': False,
              'scope': 'Complete selected pointer-table name survey only; names do not prove layouts/calling conventions, instruction relocation or initialization.'}
    if args.try_prelink:
        candidate = WORK / 'kernel/kernel.macho'
        before = hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate.exists() else None
        log = ROOT / 'analysis/ios16-prelink.log'
        with log.open('w') as stream:
            process = subprocess.run([str(ROOT / 'unixnu'), 'prelink', '--kernelcache', str(original_path)],
                                     stdout=stream, stderr=subprocess.STDOUT)
        after = hashlib.sha256(candidate.read_bytes()).hexdigest() if candidate.exists() else None
        if process.returncode and before != after:
            raise SystemExit('Failed strict prelink changed the previous candidate')
        diagnostic = log.read_text(errors='replace')
        report['strict_prelink'] = {'exit_code': process.returncode, 'log': str(log.relative_to(ROOT)),
                                   'candidate_preserved_on_failure': before == after if process.returncode else None,
                                   'diagnostic_tail': diagnostic.splitlines()[-2:],
                                   'allow_missing': False, 'substitute_addresses': False}
        failure = re.search(r'External PC-relative encoding at (0x[0-9a-f]+);', diagnostic)
        if failure:
            from emit_prelink import pc_relative_target
            address = int(failure[1], 16)
            extent = owner(address)
            at = backed_offset(original['segments'], address, 4, len(original_data))
            word, = struct.unpack_from('<I', original_data, at)
            blocker = {'address': hex(address), 'module': extent[2] if extent else None,
                       'word': hex(word), 'word_as_float32': struct.unpack_from('<f', original_data, at)[0],
                       'nearby_literal_data_reads': [], 'emission_qualified': False}
            if extent:
                start = backed_offset(original['segments'], extent[0], extent[1] - extent[0], len(original_data))
                for delta in range(0, extent[1] - extent[0] - 3, 4):
                    instruction, = struct.unpack_from('<I', original_data, start + delta)
                    if instruction & 0x3b000000 == 0x18000000 and instruction & (1 << 26):
                        decoded = pc_relative_target(instruction, extent[0] + delta)
                        if decoded and address - 64 <= decoded[0] < address + 64:
                            blocker['nearby_literal_data_reads'].append({'site': hex(extent[0] + delta),
                                'target': hex(decoded[0]), 'word': hex(instruction), 'form': 'SIMD/FP literal-load encoding'})
            blocker['next_action'] = 'Classify and prove the complete literal-data extent against this iPhone input before extending the strict instruction inventory; retain failure until then.'
            report['strict_prelink']['first_blocker'] = blocker
    (ROOT / 'reports/ios16-bindings.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'{report["result"]}: {len(gaps)} unresolved targets; counts {dict(counts)}')
    if args.try_prelink:
        print('Strict prelink exit:', report['strict_prelink']['exit_code'])


if __name__ == '__main__':
    main()
