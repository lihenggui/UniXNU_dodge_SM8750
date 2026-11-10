#!/usr/bin/env python3
"""Inspect unchanged pinned iPhone kernelcache components; no ABI approval implied."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import backed_offset, macho, unserialize_xml


def main():
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    source = ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed'
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != profile['kernel']['prelink']['kernelcache_sha256']:
        raise SystemExit('Original iPhone kernelcache SHA256 mismatch')
    parent = macho(data)
    if parent['kind'] != 2:
        raise SystemExit('Expected ordinary ARM64 MH_EXECUTE')

    def read(address, size):
        offset = backed_offset(parent['segments'], address, size, len(data))
        return data[offset:offset + size]

    info, = [s for s in parent['segments'] if s['name'] == '__PRELINK_INFO']
    metadata = unserialize_xml(read(info['va'], info['filesize']))
    entries = {}
    for entry in metadata['_PrelinkInfoDictionary']:
        identifier = entry['CFBundleIdentifier']
        if identifier in entries:
            raise SystemExit('Duplicate original component: ' + identifier)
        entries[identifier] = entry
    roots = profile['kernel']['prelink']['roots']
    selected, pending = set(), list(roots)
    while pending:
        identifier = pending.pop()
        if identifier in selected:
            continue
        if identifier not in entries:
            raise SystemExit('Missing original dependency: ' + identifier)
        selected.add(identifier)
        pending.extend(entries[identifier].get('OSBundleLibraries', {}))
    inventory = []
    for identifier, entry in entries.items():
        row = {k: entry[k] for k in ('CFBundleIdentifier', 'CFBundleVersion', 'OSBundleLibraries',
                                    'OSKernelResource', 'MinimumOSVersion', 'DTSDKName') if k in entry}
        address = entry.get('_PrelinkExecutableLoadAddr')
        if address and entry.get('_PrelinkExecutableSize') and not entry.get('OSKernelResource'):
            module = macho(data, backed_offset(parent['segments'], address, 32, len(data)))
            if module['kind'] != 11:
                raise SystemExit('Unexpected executable type: ' + identifier)
            row['segments'] = [{'name': s['name'], 'va': hex(s['va']), 'bytes': s['filesize'],
                                'sha256': hashlib.sha256(read(s['va'], s['filesize'])).hexdigest()}
                               for s in module['segments'] if s['filesize']]
            code = [s for s in module['segments'] if s['initprot'] == 5]
            kmod = entry.get('_PrelinkKmodInfo')
            if kmod:
                start, stop = struct.unpack_from('<QQ', read(kmod + 180, 16))
                if not any(s['va'] <= start < s['va'] + s['filesize'] for s in code):
                    raise SystemExit('Kmod start is not executable: ' + identifier)
                row.update(kmod_start=hex(start), kmod_stop=hex(stop))
            row['module_initializers'] = [hex(pointer) for s in module['segments'] for section in s['sections']
                if section['name'] == '__mod_init_func'
                for (pointer,) in struct.iter_unpack('<Q', read(section['va'], section['size']))]
        inventory.append(row)
    output = ROOT / 'analysis/ios16-kext-inventory.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2) + '\n')
    report = {'result': 'PASS', 'product': profile['ipsw']['product'], 'build': profile['ipsw']['build'],
              'original_sha256': digest, 'architecture': 'arm64', 'format': 'MH_EXECUTE',
              'original_component_count': len(entries), 'roots': roots,
              'declared_dependency_closure': sorted(selected),
              'selected_executables': [r for r in inventory if r['CFBundleIdentifier'] in selected and 'segments' in r],
              'original_inputs_modified': False, 'native_binding_qualified': False,
              'early_security_initializer_qualified': False, 'hardware_tested': False}
    (ROOT / 'reports/ios16-original-components.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(entries)} original components, {len(selected)} declared dependencies; binary ABI remains unqualified')


if __name__ == '__main__':
    main()
