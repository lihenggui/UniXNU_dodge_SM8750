#!/usr/bin/env python3
"""Strictly prelink original iPhone components with the single-original-crypto source candidate."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from native_driver_build import ROOT, TREE, require, symbols, macho
from native_prelink import backed_offset, exports, unserialize_xml
from prepare_initial_data import sha
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context, native_entry_bytes
from build_input_prelink import CONFIG, check_input
from build_ufs_prelink import check_storage
from build_data_source import check_table, concrete_methods
from build_crypto_source import hook_readbacks, check_report as check_source
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback

OUT = ROOT / 'build/cph2653-crypto-prelink'


def validate(data, record, native, original, context, config, source, security):
    image, native_image = macho(data), macho(native)
    slide = int(config['slide'], 0)
    def read(raw, parsed, address, count):
        offset = backed_offset(parsed['segments'], address, count, len(raw)); return raw[offset:offset + count]
    native_names = {s['name']: s for s in symbols(native) if not s['kind'] & 0xe0}
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    require(image['kind'] == 2 and record['slide'] == slide and not any(s['kind'] == 1 for s in names.values()), 'Crypto prelink type/slide/imports differ')
    require(not any('corecrypto_kext_start' in name or 'fipspost_precalc_hmac' in name for name in native_names),
            'Independent source crypto provider or its unused POST field remained in the original-only candidate')
    require(record['components'] == config['expected_executables'] and record['kernel_interfaces'] == config['expected_kernel_interfaces'] and
            not record['codeless_components'], 'Original crypto dependency closure differs')
    # This source candidate has no independently started source provider. Its
    # former POST field is absent; original component instructions are checked
    # below. No fabricated source POST field or runtime POST result is supplied.
    for segment in native_image['segments']:
        if segment['filesize'] and segment['initprot'] & 4:
            require(read(data, image, segment['va'], segment['filesize']) ==
                    read(native, native_image, segment['va'], segment['filesize']), 'Crypto native executable bytes changed')
    bindings = record['bindings']
    require(len(bindings) == len(context['sites']) == 63889 and len({row['site'] for row in bindings}) == len(bindings) and
            sum(record['pointer_counts'].values()) == len(bindings), 'Crypto original pointer inventory differs')
    public = {}
    for address, group in exports(native, native_image).items():
        for name in group: public.setdefault(name, set()).add(address)
    for row in bindings:
        require(context['sites'].get(row['site']) == row['module'] and row['new_site'] == row['site'] + slide and
                struct.unpack('<Q', read(original, context['image'], row['site'], 8))[0] == row['target'], 'Crypto original pointer provenance differs')
        if row['kind'] == 'component':
            require(context['owner'](row['target']) is not None and row['new_target'] == row['target'] + slide, 'Crypto component pointer differs')
        else:
            choices = {address for name in context['exports'].get(row['target'], []) for address in public.get(name, ())}
            require(row['kind'] == 'kernel' and context['owner'](row['target']) is None and choices == {row['new_target']} and
                    any(s['va'] <= row['new_target'] < s['va'] + s['size'] for s in native_image['segments']), 'Crypto native pointer binding is ambiguous/unmapped')
        require(struct.unpack('<Q', read(data, image, row['new_site'], 8))[0] == row['new_target'], 'Crypto pointer readback differs')
    executable = []
    for name, module in context['modules'].items():
        for segment in module['segments']:
            if segment['name'] != '__TEXT_EXEC' or not segment['filesize']: continue
            expected = hashlib.sha256(read(original, context['image'], segment['va'], segment['filesize'])).hexdigest()
            require(hashlib.sha256(read(data, image, segment['va'] + slide, segment['filesize'])).hexdigest() ==
                    record['original_executable_sha256'][name] == expected, 'Original crypto/component executable changed: ' + name)
            executable.append({'module': name, 'sha256': expected, 'bytes': segment['filesize']})
    for name, value in source['combined_original_bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Crypto original absolute alias differs: ' + name)
    for name, value in source['combined_native_entries'].items():
        address = int(value, 16)
        require(names[name]['value'] == address and names[name]['kind'] & 0xe == 14 and
                native_entry_bytes(data, image, address, 8) == native_entry_bytes(native, native_image, address, 8), 'Crypto native source entry changed: ' + name)
    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    metadata = unserialize_xml(read(data, image, info['va'], info['filesize']))
    entries = {e['CFBundleIdentifier']: e for e in metadata['_PrelinkInfoDictionary']}
    require(len(entries) == len(metadata['_PrelinkInfoDictionary']) and set(entries) ==
            set(config['expected_executables'] + config['expected_kernel_interfaces']), 'Crypto prelink metadata closure differs')
    initializers = {name: int(entry['address'], 0) + slide for name, entry in security['initializers'].items()}
    require(record['early_security_initializers'] == initializers ==
            {name: e['_NativePrelinkEarlySecurityInit'] for name, e in entries.items() if '_NativePrelinkEarlySecurityInit' in e}, 'Crypto early security metadata differs')
    for entry in security['initializers'].values():
        for block in entry['code']:
            require(hashlib.sha256(read(data, image, int(block['va'], 0) + slide, block['size'])).hexdigest() == block['sha256'], 'Original policy entry changed')
    for name, entry in record['module_entrypoints'].items():
        old = context['entries'][name]['_PrelinkKmodInfo']
        pair = struct.unpack('<QQ', read(original, context['image'], old + 180, 16))
        expected = tuple(value + slide if value else 0 for value in pair)
        require(entry['kmod_info_va'] == old + slide and (entry['start_va'], entry['stop_va']) == expected and
                struct.unpack('<QQ', read(data, image, old + slide + 180, 16)) == expected, 'Original crypto module entrypoint changed')
    require(not any(record[key] for key in ('abi_qualified', 'loadable', 'runtime_qualified', 'instruction_relocation_complete', 'register_dataflow_qualified')),
            'Crypto static prelink overstates runtime qualification')
    require(hook_readbacks(data) == source['actual_crypto_hooks'] and hook_readback(data) == source['actual_iobsd_hook'] and
            init_hook_readback(data) == source['actual_init_hook'], 'Crypto or preserved IOBSD/init hooks differ')
    alias = source['combined_original_bindings']
    record_address = int(alias['_dodge_original_crypto_kmod'], 16)
    require(struct.unpack('<Q', read(data, image, record_address + 156, 8))[0] == int(alias['_dodge_original_crypto_header'], 16) and
            struct.unpack('<Q', read(data, image, record_address + 180, 8))[0] == int(alias['_dodge_original_crypto_entry'], 16) and
            struct.unpack('<Q', read(data, image, int(alias['_dodge_original_crypto_entry_slot'], 16), 8))[0] == int(alias['_dodge_original_crypto_real_entry'], 16),
            'Original crypto pinned wrapper/real entry/header identity differs')
    return {'pointer_sites_read_back': len(bindings), 'original_executable_segments': executable, 'native_source_entries_preserved': 97,
            'original_aliases_preserved': 339, 'original_crypto_entry_identity_preserved': True,
            'independent_source_provider_and_its_post_field_absent': True, 'original_crypto_post_executed': False}


def main():
    source_path = ROOT / 'reports/ios16-crypto-source.json'; source = json.loads(source_path.read_text()); check_source(source)
    native = (ROOT / source['candidate']).read_bytes(); original = ORIGINAL.read_bytes()
    profile, config, security = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text()), json.loads(SECURITY.read_text())
    context = original_context(original, profile['kernel']['prelink']['roots'] + config['additional_roots'], config)
    OUT.mkdir(exist_ok=True)
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    parser = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='checked-', dir=OUT) as temporary:
        work = Path(temporary); candidate = work / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', ROOT / source['candidate'], '--prelinked', ORIGINAL,
                   '--slide=' + config['slide'], '--output', candidate]
        for name in profile['kernel']['prelink']['roots'] + config['additional_roots']: command += ['--root', name]
        for name in profile['kernel']['prelink']['early_security_init']: command += ['--early-security-init', name]
        command += ['--early-security-fixture', SECURITY]
        process = subprocess.run(command, env=env, capture_output=True, text=True); (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Original crypto strict prelink failed; inspect emission.log')
        data = candidate.read_bytes(); record = json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256'] == hashlib.sha256(data).hexdigest() and record['native_sha256'] == sha(ROOT / source['candidate']) and
                record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Crypto emission identities differ')
        checked = validate(data, record, native, original, context, config, source, security)
        storage = {**json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text()), 'actual_iobsd_hook': source['actual_iobsd_hook']}
        display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
        service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
        inputs = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
        object_from = lambda report, suffix: next(ROOT / row['path'] for row in report['objects'] if row['path'].endswith(suffix))
        storage_checks = check_storage(data, native, original, context, storage, display,
                    object_from(service, 'DodgeIPhoneFramebuffer.late.o'), object_from(storage, 'NativeUfs.late.o'))
        input_checks = check_input(data, native, original, context, inputs, object_from(inputs, 'DodgeInput.late.o'))
        ram = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
        require(check_table(data, concrete_methods(ROOT / ram['late_object'])) == 352, 'Crypto prelink changed RamBlock ABI')
        image = macho(data); controls = []
        modifications = [('original-pointer', record['bindings'][0]['new_site'], 8),
                         ('original-crypto-entry', int(source['combined_original_bindings']['_dodge_original_crypto_entry'], 16), 4),
                         ('packed-crypto-start', int(source['combined_original_bindings']['_dodge_original_crypto_kmod'], 16) + 180, 8),
                         ('OSKext-owner-call', int(source['actual_crypto_hooks']['actual_oskext_owner_reuse'], 16), 4),
                         ('early-owner-call', int(source['actual_crypto_hooks']['early_owner_call'], 16), 4)]
        for name, address, count in modifications:
            offset = backed_offset(image['segments'], address, count, len(data)); bad = bytearray(data); bad[offset] ^= 1
            try: validate(bad, record, native, original, context, config, source, security)
            except ValueError as error: controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
            else: raise ValueError('Corrupted original crypto prelink was accepted: ' + name)
        process = subprocess.run([sys.executable, parser, candidate], env=env, capture_output=True, text=True)
        (OUT / 'loader-parser.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Actual DarwinBoot parser refused crypto candidate')
        candidate.replace(OUT / 'kernel.macho'); candidate.with_suffix('.json').replace(OUT / 'emission.json')
    files = [Path(__file__), ROOT / 'scripts/build_crypto_source.py', ROOT / 'scripts/build_gpu_graphics_prelink.py',
             ROOT / 'scripts/build_input_prelink.py', ROOT / 'scripts/build_ufs_prelink.py', PROFILE, CONFIG, SECURITY,
             emitter, emitter.parent / 'native_prelink.py', parser]
    report = {'result': 'IOS16_SINGLE_ORIGINAL_CRYPTO_OWNER_STRICT_PRELINK_PASS', 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(source_path.relative_to(ROOT)): sha(source_path)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (OUT / 'kernel.macho', OUT / 'emission.json')},
        'candidate': str((OUT / 'kernel.macho').relative_to(ROOT)), 'candidate_sha256': sha(OUT / 'kernel.macho'),
        'combined_source_objects': 89, 'combined_original_aliases': 339, 'native_source_entries_preserved': 97,
        'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'], **checked,
        'storage_checks': storage_checks, 'input_checks': input_checks, 'negative_controls': controls,
        'actual_crypto_hooks': source['actual_crypto_hooks'], 'actual_iobsd_hook': source['actual_iobsd_hook'],
        'actual_init_hook': source['actual_init_hook'], 'darwinboot_production_parser': 'PASS',
        'source_provider_post_field_required': False, 'original_crypto_runtime_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Strict original iPhone prelink for the 89-object/97-entry single-original-crypto source candidate. '
                 'All 63889 original pointers, original executable segments, 339 aliases, native executable bytes and existing class/hooks '
                 'are read back. The independent source-provider entry and POST field were removed by linking; no dummy field is sealed. '
                 'Original crypto start/POST instructions remain unchanged. Five corruption controls and the production DarwinBoot parser pass. '
                 'Original provider initialization/POST, full crypto ABI, policy registration and hardware remain unqualified.'}
    (ROOT / 'reports/ios16-crypto-prelink.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 89-object/97-entry original-crypto prelink, 339 aliases, 28 components, 63889 pointers and five rejection controls')


if __name__ == '__main__': main()
