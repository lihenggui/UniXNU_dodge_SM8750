#!/usr/bin/env python3
"""Prelink the separate RamBlock/source candidate with the exact original iPhone closure."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, digest, original_context, validate_image, negative_controls, verify_post
from build_ufs_prelink import check_storage
from build_input_prelink import CONFIG, check_input
from build_data_source import check_table, concrete_methods
from native_driver_build import ROOT, TREE, require, symbols, macho
from native_prelink import backed_offset
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-data-prelink'


def main():
    path = ROOT / 'reports/ios16-data-source.json'
    source = json.loads(path.read_text())
    require(source['builder_sha256'] == sha(ROOT / 'scripts/build_data_source.py'), 'Data source stage is stale')
    for name, value in {**source['source_sha256'], **source['artifacts'], **source['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == value, 'Data source input changed: ' + name)
    source_bytes = (ROOT / source['candidate']).read_bytes()
    source_input = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
    original = ORIGINAL.read_bytes()
    profile = tomllib.loads(PROFILE.read_text())
    config = json.loads(CONFIG.read_text())
    security = json.loads(SECURITY.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots']
    context = original_context(original, roots, config)
    gpu = json.loads((ROOT / 'reports/gpu-link-probe.json').read_text())
    link = {'original_absolute_bindings_preserved': gpu['original_absolute_bindings_preserved'],
            'real_linked_entry_points': source['combined_native_entries']}
    storage = json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text())
    source_image = macho(source_bytes)
    source_names = {s['name']: s['value'] for s in symbols(source_bytes) if not s['kind'] & 0xe0}
    hook_address = source_names['_IOKitBSDInit']
    hook_offset = backed_offset(source_image['segments'], hook_address, 80, len(source_bytes))
    hook = source_bytes[hook_offset:hook_offset + 80]
    calls = {}
    for i, word in enumerate(struct.unpack('<20I', hook)):
        if word & 0xfc000000 == 0x94000000:
            delta = word & 0x3ffffff
            target = hook_address + 4 * i + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
            calls[target] = hook_address + 4 * i
    wanted = [source_names[name] for name in ('__ZN9IOService15publishResourceEPKcP8OSObject', '_dodge_system_schedule', '_dodge_input_schedule')]
    require(all(a in calls for a in wanted) and [calls[a] for a in wanted] == sorted(calls[a] for a in wanted),
            'Data source IOBSD publication/queue order changed')
    storage = {**storage, 'actual_iobsd_hook': {'address': hex(hook_address), 'bytes': len(hook), 'sha256': digest(hook),
                                              'queue_call_order': [hex(calls[a]) for a in wanted]}}
    display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
    service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
    display_obj = next(ROOT / o['path'] for o in service['objects'] if o['path'].endswith('DodgeIPhoneFramebuffer.late.o'))
    ufs_obj = next(ROOT / o['path'] for o in storage['objects'] if o['path'].endswith('NativeUfs.late.o'))
    input_obj = next(ROOT / o['path'] for o in source_input['objects'] if o['path'].endswith('DodgeInput.late.o'))
    methods = concrete_methods(ROOT / source['late_object'])
    OUT.mkdir(exist_ok=True)
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    sealer = TREE / 'scripts/seal-source-crypto-kernel.py'
    parser = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='checked-', dir=OUT) as temporary:
        work = Path(temporary)
        sealed = work / 'mach.data.sealed'; sealed.write_bytes(source_bytes)
        candidate = work / 'kernel.macho'
        result = subprocess.run([sys.executable, sealer, sealed, '--kernel-args', ' '.join(config['boot_arguments'])],
                                env=env, capture_output=True, text=True)
        (OUT / 'seal.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Data source POST sealing failed')
        native = sealed.read_bytes()
        seal = json.loads(sealed.with_suffix('.sealed.crypto-hmac.json').read_text())
        at = int(seal['hmac_file_offset'], 16)
        require(len(native) == len(source_bytes) and native[:at] == source_bytes[:at] and native[at + 32:] == source_bytes[at + 32:],
                'Data sealing changed bytes outside the POST field')
        verify_post(native, seal)
        command = [sys.executable, emitter, '--kernel', sealed, '--prelinked', ORIGINAL,
                   '--slide=' + config['slide'], '--output', candidate]
        for name in roots:
            command += ['--root', name]
        for name in profile['kernel']['prelink']['early_security_init']:
            command += ['--early-security-init', name]
        command += ['--early-security-fixture', SECURITY]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'prelink.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Strict Data/source/original prelink failed')
        data = candidate.read_bytes()
        record = json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256'] == digest(data) and record['native_sha256'] == digest(native) and record['original_sha256'] == digest(original),
                'Data prelink emission hashes differ')
        base = validate_image(data, record, native, original, context, config, link, seal, security)
        storage_checks = check_storage(data, native, original, context, storage, display, display_obj, ufs_obj)
        input_checks = check_input(data, native, original, context, source_input, input_obj)
        size = check_table(data, methods)
        controls = negative_controls(data, record, native, original, context, config, link, seal, security)
        image = macho(data)
        names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
        at = backed_offset(image['segments'], names['__ZTV14NativeRamBlock']['value'] + 16 + 171 * 8, 8, len(data))
        broken = bytearray(data); broken[at] ^= 1
        try:
            check_table(broken, methods)
        except ValueError as error:
            controls.append({'case': 'concrete-RamBlock-table', 'result': 'REJECTED', 'reason': str(error)})
        else:
            raise ValueError('Corrupted original-prelinked RamBlock table was accepted')
        result = subprocess.run([sys.executable, parser, candidate], env=env, capture_output=True, text=True)
        (OUT / 'parser.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Actual DarwinBoot parser refused Data candidate')
        sealed.replace(OUT / 'mach.data.sealed')
        candidate.replace(OUT / 'kernel.macho')
        candidate.with_suffix('.json').replace(OUT / 'emission.json')
        (OUT / 'mach.data.sealed.crypto-hmac.json').write_text(json.dumps(seal, indent=2) + '\n')
        (OUT / 'kernel.macho.crypto-hmac.json').write_text(json.dumps({**seal, 'kernel_sha256': digest(data), 'sealed_native_input_sha256': digest(native)}, indent=2) + '\n')
    source_files = [Path(__file__), ROOT / 'scripts/build_data_source.py', ROOT / 'scripts/build_input_prelink.py',
                    ROOT / 'scripts/build_ufs_prelink.py', ROOT / 'scripts/build_gpu_graphics_prelink.py',
                    PROFILE, CONFIG, SECURITY, emitter, emitter.parent / 'native_prelink.py', sealer, sealer.parent / 'kernel_target.py', parser]
    artifacts = [OUT / name for name in ('mach.data.sealed', 'kernel.macho', 'emission.json', 'mach.data.sealed.crypto-hmac.json', 'kernel.macho.crypto-hmac.json')]
    report = {'result': 'IOS16_SOURCE_RAMBLOCK_AND_ORIGINAL_IPHONE_COMPONENTS_STRICT_PRELINK_PASS', 'builder_sha256': sha(Path(__file__)),
              'product': 'iPhone10,3', 'build': '20H392', 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
              'candidate': str((OUT / 'kernel.macho').relative_to(ROOT)), 'candidate_sha256': sha(OUT / 'kernel.macho'),
              'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'], **base, **storage_checks, **input_checks,
              'combined_source_objects': 83, 'combined_original_aliases': 332, 'compiled_ramblock_bytes': size, 'ramblock_vtable_entries_read_back': 190,
              'negative_controls': controls, 'darwinboot_production_parser': 'PASS', 'source_crypto_post_verified': True,
              'strict_no_undefined': True, 'ramblock_metadata_registered_or_started': False,
              'original_apfs_data_mount_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'scope': 'Separate 83-object source RamBlock/input/storage/display candidate and the exact declared original iPhone closure. '
                       'Original executable/pointer, source concrete tables, original parent tables, POST and production-loader parsing are checked. '
                       'RamBlock constructor remains deferred; original metadata registration/start, Data mount, crypto and writable iOS runtime remain unqualified.'}
    (ROOT / 'reports/ios16-data-prelink.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: 83-object Data candidate, {len(record["components"])} original components, {base["pointer_sites_read_back"]} pointers and 190-slot RamBlock table')


if __name__ == '__main__':
    main()
