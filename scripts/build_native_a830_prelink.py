#!/usr/bin/env python3
"""Prelink the native A830 candidate with the pinned iPhone component closure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from build_native_a830_kernel import REPORT as SOURCE_REPORT, check_report as check_source, check_firmware
from build_crypto_prelink import validate
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG, check_input
from build_ufs_prelink import check_storage
from build_data_source import check_table, concrete_methods
from native_driver_build import ROOT, TREE, require, sha, macho, symbols
from native_prelink import backed_offset
from prepare_surface_backing import checked as backing_checked, apply_hooks, restore_hooks, hook_readbacks
from prepare_surface_sync import checked as sync_checked
from surface_sync_execution import run_cases
from image4_boot_policy import CONTRACT as IMAGE4_CONTRACT, security_plan, check_security_starts

OUT = ROOT / 'build/cph2653-native-a830-prelink'
REPORT = ROOT / 'reports/native-a830-prelink.json'


def check_report(report):
    require(report['result'] == 'NATIVE_A830_IPHONE_STRICT_PRELINK_PASS' and report['pointer_sites_read_back'] == 63889 and
            len(report['original_sync_cpu_cases']) == 17 and not report['hardware_tested'], 'Incomplete native A830 prelink report')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native A830 prelink input changed: ' + name)
    data = (ROOT / report['candidate']).read_bytes();contract, _ = backing_checked()
    require(hook_readbacks(data, contract) == report['original_lifecycle_hooks'] and
            restore_hooks(data, contract) == (ROOT / report['unhooked_candidate']).read_bytes(), 'Native surface hooks changed')
    require(check_firmware(data, report['firmware_pins']) == report['firmware_readback'], 'Prelinked firmware changed')
    record = json.loads((ROOT / report['emission_record']).read_text())
    require(check_security_starts(data, record, report['normal_security_starts']) == report['security_start_readback'],
            'Original security start coverage changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native A830 strict iPhone prelink');return
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    native = (ROOT / source['candidate']).read_bytes();original = ORIGINAL.read_bytes()
    profile, config, security = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text()), json.loads(SECURITY.read_text())
    security, early_requests, normal_starts = security_plan(profile, security)
    context = original_context(original, profile['kernel']['prelink']['roots'] + config['additional_roots'], config)
    OUT.mkdir(parents=True, exist_ok=True);emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    security_fixture = OUT / 'security-init.json'
    security_fixture.write_text(json.dumps(security, indent=2) + '\n')
    parser_path = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0',
               PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    unhooked = OUT / 'kernel.unhooked.macho'
    command = [sys.executable, emitter, '--kernel', ROOT / source['candidate'], '--prelinked', ORIGINAL,
               '--slide=' + config['slide'], '--output', unhooked]
    for name in profile['kernel']['prelink']['roots'] + config['additional_roots']:command += ['--root', name]
    for name in early_requests:command += ['--early-security-init', name]
    command += ['--early-security-fixture', security_fixture]
    print('PRELINK: complete native A830 candidate and original iPhone components', flush=True)
    # The emitter refuses an existing destination. Emit into a fresh directory
    # so a rebuild can preserve the previous candidate until validation passes.
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / unhooked.name
        command[command.index('--output') + 1] = pending
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Native A830 strict prelink failed; inspect emission.log')
        data = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(data).hexdigest() and
            record['native_sha256'] == sha(ROOT / source['candidate']) and record['original_sha256'] == sha(ORIGINAL),
            'Native A830 prelink provenance differs')
    checked = validate(data, record, native, original, context, config, source, security)
    security_readback = check_security_starts(data, record, normal_starts)
    checked['original_aliases_preserved'] = len(source['combined_original_bindings'])
    checked['native_source_entries_preserved'] = len(source['combined_native_entries'])
    storage = {**json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text()), 'actual_iobsd_hook': source['actual_iobsd_hook']}
    service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
    inputs = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
    display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
    object_from = lambda report, suffix: next(ROOT / row['path'] for row in report['objects'] if row['path'].endswith(suffix))
    storage_checks = check_storage(data, native, original, context, storage, display,
        object_from(service, 'DodgeIPhoneFramebuffer.late.o'), object_from(storage, 'NativeUfs.late.o'))
    input_checks = check_input(data, native, original, context, inputs, object_from(inputs, 'DodgeInput.late.o'))
    ram = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
    require(check_table(data, concrete_methods(ROOT / ram['late_object'])) == 352, 'Native RamBlock table differs')
    # Prove rejection by the same validator used on the actual image.
    controls = [];image = macho(data)
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    for name, address in (('original-pointer', record['bindings'][0]['new_site']),
                          ('native-surface-prepare', names['_dodge_native_surface_prepare']['value'])):
        bad = bytearray(data);at = backed_offset(image['segments'], address, 8, len(data));bad[at] ^= 1
        try:validate(bad, record, native, original, context, config, source, security)
        except ValueError as error:controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else:raise ValueError('Changed native A830 prelink was accepted: ' + name)
    contract, _ = backing_checked();patched = apply_hooks(data, contract)
    require(restore_hooks(patched, contract) == data, 'Surface hook normalization changed unrelated bytes')
    candidate = OUT / 'kernel.macho'
    with tempfile.TemporaryDirectory(prefix='parser-', dir=OUT) as temporary:
        pending = Path(temporary) / candidate.name;pending.write_bytes(patched)
        result = subprocess.run([sys.executable, parser_path, pending], env=env, capture_output=True, text=True)
        (OUT / 'loader-parser.log').write_text(result.stdout + result.stderr)
        require(not result.returncode, 'Production DarwinBoot parser refused native A830 candidate')
    sync, _ = sync_checked();probe = ROOT / 'build/ios16-surface-producer-execution/SurfaceSyncProbe.o'
    cpu = run_cases(patched, sync, probe)
    unhooked.write_bytes(data)
    unhooked.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    candidate.write_bytes(patched)
    files = [Path(__file__), ROOT / 'scripts/build_native_a830_kernel.py', ROOT / 'scripts/build_crypto_prelink.py',
             ROOT / 'scripts/build_gpu_graphics_prelink.py', ROOT / 'scripts/build_ufs_prelink.py', ROOT / 'scripts/build_input_prelink.py',
             ROOT / 'scripts/prepare_surface_backing.py', ROOT / 'scripts/surface_sync_execution.py',
             ROOT / 'scripts/image4_boot_policy.py', IMAGE4_CONTRACT,
             PROFILE, CONFIG, SECURITY, emitter, emitter.parent / 'native_prelink.py', parser_path]
    artifacts = [candidate, unhooked, unhooked.with_suffix('.json'), security_fixture, probe]
    report = {'result': 'NATIVE_A830_IPHONE_STRICT_PRELINK_PASS',
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
        'unhooked_candidate': str(unhooked.relative_to(ROOT)),
        'emission_record': str(unhooked.with_suffix('.json').relative_to(ROOT)),
        'normal_security_starts': normal_starts, 'security_start_readback': security_readback,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(SOURCE_REPORT.relative_to(ROOT)): sha(SOURCE_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'combined_source_objects': source['combined_source_objects'], 'components': record['components'],
        'kernel_interfaces': record['kernel_interfaces'], **checked,
        'storage_checks': storage_checks, 'input_checks': input_checks, 'negative_controls': controls,
        'original_lifecycle_hooks': hook_readbacks(patched, contract), 'original_sync_cpu_cases': cpu,
        'firmware_pins': source['firmware_pins'], 'firmware_readback': check_firmware(patched, source['firmware_pins']),
        'original_surface_producer_connected': True, 'surface_ID_import_connected': True,
        'production_darwinboot_parser': 'PASS', 'original_crypto_post_executed': False,
        'default_kernel_selected': False, 'runtime_qualified': False, 'hardware_tested': False,
        'scope': 'Exact iPhone component closure, all original pointer bindings, aliases, native instructions, class tables, '
                 'firmware and storage/crypto hooks read back. Four IOSurface entry hooks are installed. '
                 'The original sync queue executes 17 ARM64 model cases from this image. Full kernel and hardware execution remain untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {source["combined_source_objects"]} objects; 28 components, 63889 pointers, four surface hooks and 17 original sync cases')


if __name__ == '__main__':main()
