#!/usr/bin/env python3
"""Read back strict prelink output without claiming original-component runtime ABI."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge'
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import backed_offset, macho, unserialize_xml


def main():
    path = WORK / 'kernel/kernel.macho'
    data = path.read_bytes()
    record = json.loads(path.with_suffix('.json').read_text())
    if record.get('prelink_skipped'):
        raise SystemExit('Run strict original-component prelink before this check')
    if hashlib.sha256(data).hexdigest() != record['candidate_sha256'] or len(data) != record['candidate_bytes']:
        raise SystemExit('Prelink candidate changed after emission')
    original = json.loads((ROOT / 'reports/ios16-original-components.json').read_text())
    native = json.loads((ROOT / 'reports/native-kernel.json').read_text())
    if (record['original_sha256'], record['native_sha256']) != (original['original_sha256'], native['sha256']):
        raise SystemExit('Prelink inputs differ from their audited native/original reports')
    image = macho(data)
    for binding in record['bindings']:
        at = backed_offset(image['segments'], binding['new_site'], 8, len(data))
        if struct.unpack_from('<Q', data, at)[0] != binding['new_target']:
            raise SystemExit('Incorrect emitted pointer at ' + hex(binding['new_site']))
    executable_segments = 0
    for module in original['selected_executables']:
        for segment in module['segments']:
            if segment['name'] != '__TEXT_EXEC':
                continue
            at = backed_offset(image['segments'], int(segment['va'], 16) + record['slide'], segment['bytes'], len(data))
            if hashlib.sha256(data[at:at + segment['bytes']]).hexdigest() != segment['sha256']:
                raise SystemExit('Original executable bytes changed: ' + module['CFBundleIdentifier'])
            executable_segments += 1
    security_path = ROOT / 'profiles/os/ios-16.7.16-20H392/security-init.json'
    fixture_bytes = security_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    if record.get('early_security_fixture_sha256') != hashlib.sha256(fixture_bytes).hexdigest():
        raise SystemExit('Prelink lacks the current reviewed security fixture')
    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    at = backed_offset(image['segments'], info['va'], info['filesize'], len(data))
    entries = unserialize_xml(data[at:at + info['filesize']])['_PrelinkInfoDictionary']
    actual = {e['CFBundleIdentifier']: e['_NativePrelinkEarlySecurityInit'] for e in entries
              if '_NativePrelinkEarlySecurityInit' in e}
    expected = {name: int(entry['address'], 0) + record['slide'] for name, entry in fixture['initializers'].items()}
    if actual != expected or actual != record['early_security_initializers']:
        raise SystemExit('Emitted early security metadata differs from the reviewed entry set')
    for entry in fixture['initializers'].values():
        for block in entry['code']:
            at = backed_offset(image['segments'], int(block['va'], 0) + record['slide'], block['size'], len(data))
            if hashlib.sha256(data[at:at + block['size']]).hexdigest() != block['sha256']:
                raise SystemExit('Emitted security initializer code differs from reviewed bytes')
    host_env = dict(os.environ, PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    subprocess.run([sys.executable, str(ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'), str(path)],
                   env=host_env, check=True)
    report = {'result': 'STATIC_CHECKS_PASS', 'candidate': str(path.relative_to(ROOT)),
              'candidate_sha256': record['candidate_sha256'], 'candidate_bytes': len(data),
              'native_sha256': record['native_sha256'], 'original_sha256': record['original_sha256'],
              'components': record['components'], 'kernel_interface_count': len(record['kernel_interfaces']),
              'pointer_counts': record['pointer_counts'], 'pointer_sites_read_back': len(record['bindings']),
              'original_executable_segments_unchanged': executable_segments,
              'pc_relative_encodings_preserved': record['pc_relative_encodings_preserved'],
              'darwinboot_production_parser': 'PASS', 'strict_emission': True,
              'allow_missing': False, 'substitute_addresses': False,
              'instruction_relocation_complete': record['instruction_relocation_complete'],
              'register_dataflow_qualified': record['register_dataflow_qualified'],
              'abi_qualified': record['abi_qualified'], 'loadable': record['loadable'],
              'early_security_initializers': record['early_security_initializers'],
              'early_security_fixture_sha256': record['early_security_fixture_sha256'],
              'early_security_metadata_and_code_readback': 'PASS',
              'runtime_qualified': False, 'hardware_tested': False,
              'scope': 'Strict static emission and binary readback only; the emitter still marks ABI/runtime/loadability unqualified. Do not treat this as a bootable iPhone OS.'}
    (ROOT / 'reports/ios16-prelink.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(record["bindings"]):,} pointers, original code, {len(actual)} security entries and actual loader parsing; ABI/runtime unqualified')


if __name__ == '__main__':
    main()
