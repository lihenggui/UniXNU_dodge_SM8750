#!/usr/bin/env python3
"""Strict original-component prelink for the separate queued Data startup candidate."""
import hashlib
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
from build_data_startup import hook_readback
from native_driver_build import ROOT, TREE, require, symbols, macho
from native_prelink import backed_offset
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-data-startup-prelink'


def main():
    path = ROOT / 'reports/ios16-data-startup.json'
    source = json.loads(path.read_text())
    require(source['builder_sha256'] == sha(ROOT / 'scripts/build_data_startup.py') and source['combined_source_objects'] == 84,
            'Data startup source stage is stale')
    for name, value in {**source['source_sha256'], **source['artifacts'], **source['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == value, 'Data startup prelink input changed: ' + name)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    require(sha(CONFIG) == lock['iphone_input_prelink']['sha256'], 'Original iPhone closure pin changed')
    native_source = (ROOT / source['candidate']).read_bytes()
    data_source = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
    input_source = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
    original = ORIGINAL.read_bytes()
    profile, config, security = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text()), json.loads(SECURITY.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots']
    context = original_context(original, roots, config)
    gpu = json.loads((ROOT / 'reports/gpu-link-probe.json').read_text())
    link = {'original_absolute_bindings_preserved': gpu['original_absolute_bindings_preserved'], 'real_linked_entry_points': source['combined_native_entries']}
    storage = {**json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text()), 'actual_iobsd_hook': source['actual_iobsd_hook']}
    display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
    service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
    display_obj = next(ROOT / row['path'] for row in service['objects'] if row['path'].endswith('DodgeIPhoneFramebuffer.late.o'))
    ufs_obj = next(ROOT / row['path'] for row in storage['objects'] if row['path'].endswith('NativeUfs.late.o'))
    input_obj = next(ROOT / row['path'] for row in input_source['objects'] if row['path'].endswith('DodgeInput.late.o'))
    methods = concrete_methods(ROOT / data_source['late_object'])
    OUT.mkdir(exist_ok=True)
    emitter, sealer = TREE / 'kits/XnuPrelink/emit_prelink.py', TREE / 'scripts/seal-source-crypto-kernel.py'
    parser = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='checked-', dir=OUT) as temporary:
        work = Path(temporary)
        sealed = work / 'mach.data-startup.sealed'; sealed.write_bytes(native_source)
        candidate = work / 'kernel.macho'
        result = subprocess.run([sys.executable, sealer, sealed, '--kernel-args', ' '.join(config['boot_arguments'])], env=env, capture_output=True, text=True)
        (OUT / 'seal.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Data startup POST sealing failed')
        native = sealed.read_bytes()
        seal = json.loads(sealed.with_suffix(sealed.suffix + '.crypto-hmac.json').read_text())
        at = int(seal['hmac_file_offset'], 16)
        require(len(native) == len(native_source) and native[:at] == native_source[:at] and native[at + 32:] == native_source[at + 32:],
                'Data startup sealing changed bytes outside POST')
        verify_post(native, seal)
        command = [sys.executable, emitter, '--kernel', sealed, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', candidate]
        for name in roots: command += ['--root', name]
        for name in profile['kernel']['prelink']['early_security_init']: command += ['--early-security-init', name]
        command += ['--early-security-fixture', SECURITY]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'prelink.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Data startup strict prelink failed')
        data = candidate.read_bytes(); record = json.loads(candidate.with_suffix('.json').read_text())
        require((record['candidate_sha256'], record['native_sha256'], record['original_sha256']) == (digest(data), digest(native), digest(original)),
                'Data startup emission hashes differ')
        base_checks = validate_image(data, record, native, original, context, config, link, seal, security)
        storage_checks = check_storage(data, native, original, context, storage, display, display_obj, ufs_obj)
        input_checks = check_input(data, native, original, context, input_source, input_obj)
        require(check_table(data, methods) == 352 and hook_readback(data) == source['actual_iobsd_hook'], 'Data startup class or queue hook changed')
        controls = negative_controls(data, record, native, original, context, config, link, seal, security)
        image = macho(data); names = {s['name']: s['value'] for s in symbols(data) if not s['kind'] & 0xe0}
        changes = [('RamBlock-table', backed_offset(image['segments'], names['__ZTV14NativeRamBlock'] + 16 + 171 * 8, 8, len(data)), 'table'),
                   ('BSD-Data-call', backed_offset(image['segments'], int(source['actual_iobsd_hook']['queue_call_order'][2], 16), 4, len(data)), 'hook')]
        for name, offset, kind in changes:
            bad = bytearray(data)
            if kind == 'hook': struct.pack_into('<I', bad, offset, 0xd503201f)
            else: bad[offset] ^= 1
            try:
                if kind == 'hook': hook_readback(bad)
                else: check_table(bad, methods)
            except ValueError as error: controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
            else: raise ValueError('Damaged Data startup prelink was accepted: ' + name)
        result = subprocess.run([sys.executable, parser, candidate], env=env, capture_output=True, text=True)
        (OUT / 'parser.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Actual DarwinBoot parser refused Data startup candidate')
        sealed.replace(OUT / 'mach.data-startup.sealed'); candidate.replace(OUT / 'kernel.macho')
        candidate.with_suffix('.json').replace(OUT / 'emission.json')
        (OUT / 'mach.data-startup.sealed.crypto-hmac.json').write_text(json.dumps(seal, indent=2) + '\n')
        (OUT / 'kernel.macho.crypto-hmac.json').write_text(json.dumps({**seal, 'kernel_sha256': digest(data), 'sealed_native_input_sha256': digest(native)}, indent=2) + '\n')
    source_files = [Path(__file__), ROOT / 'scripts/build_data_startup.py', ROOT / 'scripts/build_data_source.py', ROOT / 'scripts/build_input_prelink.py',
                    ROOT / 'scripts/build_ufs_prelink.py', ROOT / 'scripts/build_gpu_graphics_prelink.py', PROFILE, CONFIG, SECURITY, emitter,
                    emitter.parent / 'native_prelink.py', sealer, sealer.parent / 'kernel_target.py', parser]
    artifacts = [OUT / name for name in ('mach.data-startup.sealed', 'kernel.macho', 'emission.json', 'mach.data-startup.sealed.crypto-hmac.json', 'kernel.macho.crypto-hmac.json')]
    report = {'result': 'IOS16_DATA_STARTUP_AND_ORIGINAL_IPHONE_STRICT_PRELINK_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files}, 'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str((OUT / 'kernel.macho').relative_to(ROOT)),
              'candidate_sha256': sha(OUT / 'kernel.macho'), 'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'],
              **base_checks, **storage_checks, **input_checks, 'combined_source_objects': 84, 'combined_original_aliases': 332,
              'ramblock_instance_bytes': 352, 'ramblock_vtable_entries_read_back': 190, 'actual_iobsd_hook': source['actual_iobsd_hook'],
              'negative_controls': controls, 'darwinboot_production_parser': 'PASS', 'source_crypto_post_verified': True, 'strict_no_undefined': True,
              'source_data_default_enabled': False, 'ramblock_metadata_registered_or_started': False, 'original_apfs_data_mount_qualified': False,
              'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'scope': 'Separate 84-object source/original candidate with actual queue-only system/Data/input IOBSD ordering, exact original component/pointer/code and concrete/parent-table readback. '
                       'POST and production-loader parser pass. No original Data mount, hardware start or writable iOS runtime qualification.'}
    (ROOT / 'reports/ios16-data-startup-prelink.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 84-object Data startup prelink,', len(record['components']), 'original components,', base_checks['pointer_sites_read_back'], 'pointers and queue hook read back')


if __name__ == '__main__':
    main()
