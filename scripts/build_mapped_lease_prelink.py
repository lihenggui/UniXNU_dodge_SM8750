#!/usr/bin/env python3
"""Strictly prelink the isolated mapped-resource candidate with original iPhone components."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from build_mapped_lease_source import REPORT as SOURCE_REPORT, check_report as check_source
from build_crypto_prelink import validate
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG, check_input
from build_ufs_prelink import check_storage
from build_data_source import check_table, concrete_methods
from native_driver_build import ROOT, TREE, require
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-mapped-lease-wait-prelink'
REPORT = ROOT / 'reports/ios16-mapped-lease-prelink.json'
RESULT = 'IOS16_MAPPED_RESOURCE_LEASE_STRICT_PRELINK_PASS'


def check_report(report):
    require(report['result'] == RESULT and report['original_aliases_preserved'] == 341 and
            report['native_source_entries_preserved'] == 97 and report['pointer_sites_read_back'] == 63889,
            'Incomplete mapped-resource strict prelink report')
    for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Mapping lease prelink evidence changed: ' + filename)
    require(report['hardware_tested'] is False and report['runtime_qualified'] is False and
            report['all_ios_port_code_complete'] is False, 'Mapping lease prelink exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: existing mapped-resource strict prelink and 63889 pointer readbacks'); return
    source = json.loads(SOURCE_REPORT.read_text()); check_source(source)
    native = (ROOT / source['candidate']).read_bytes(); original = ORIGINAL.read_bytes()
    profile, config, security = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text()), json.loads(SECURITY.read_text())
    context = original_context(original, profile['kernel']['prelink']['roots'] + config['additional_roots'], config)
    OUT.mkdir(exist_ok=True); emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    parser_path = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0',
               PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='checked-', dir=OUT) as temporary:
        candidate = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', ROOT / source['candidate'], '--prelinked', ORIGINAL,
                   '--slide=' + config['slide'], '--output', candidate]
        for name in profile['kernel']['prelink']['roots'] + config['additional_roots']: command += ['--root', name]
        for name in profile['kernel']['prelink']['early_security_init']: command += ['--early-security-init', name]
        command += ['--early-security-fixture', SECURITY]
        print('PRELINK: mapped-resource source / unchanged original iPhone components / strict imports', flush=True)
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(process.returncode == 0, 'Mapping lease strict prelink failed; inspect emission.log')
        data = candidate.read_bytes(); record = json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256'] == hashlib.sha256(data).hexdigest() and
                record['native_sha256'] == sha(ROOT / source['candidate']) and
                record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Mapping lease prelink identities differ')
        checked = validate(data, record, native, original, context, config, source, security)
        require(checked.pop('original_aliases_preserved') == 339, 'Base original alias inventory changed')
        checked['base_original_aliases_preserved'] = 339; checked['original_aliases_preserved'] = len(source['combined_original_bindings'])
        storage = {**json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text()), 'actual_iobsd_hook': source['actual_iobsd_hook']}
        display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
        service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
        inputs = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
        object_from = lambda report, suffix: next(ROOT / row['path'] for row in report['objects'] if row['path'].endswith(suffix))
        storage_checks = check_storage(data, native, original, context, storage, display,
            object_from(service, 'DodgeIPhoneFramebuffer.late.o'), object_from(storage, 'NativeUfs.late.o'))
        input_checks = check_input(data, native, original, context, inputs, object_from(inputs, 'DodgeInput.late.o'))
        ram = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
        require(check_table(data, concrete_methods(ROOT / ram['late_object'])) == 352, 'Mapping lease prelink changed the RamBlock ABI')
        process = subprocess.run([sys.executable, parser_path, candidate], env=env, capture_output=True, text=True)
        (OUT / 'loader-parser.log').write_text(process.stdout + process.stderr)
        require(process.returncode == 0, 'Production DarwinBoot parser refused the mapped-resource candidate')
        candidate.replace(OUT / 'kernel.macho'); candidate.with_suffix('.json').replace(OUT / 'emission.json')
    files = [Path(__file__), ROOT / 'scripts/build_mapped_lease_source.py', ROOT / 'scripts/build_crypto_prelink.py',
             ROOT / 'scripts/build_gpu_graphics_prelink.py', ROOT / 'scripts/build_ufs_prelink.py', ROOT / 'scripts/build_input_prelink.py',
             ROOT / 'scripts/build_data_source.py', PROFILE, CONFIG, SECURITY, emitter, emitter.parent / 'native_prelink.py', parser_path]
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(SOURCE_REPORT.relative_to(ROOT)): sha(SOURCE_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (OUT / 'kernel.macho', OUT / 'emission.json')},
        'candidate': str((OUT / 'kernel.macho').relative_to(ROOT)), 'candidate_sha256': sha(OUT / 'kernel.macho'),
        'combined_source_objects': 90, 'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'],
        **checked, 'storage_checks': storage_checks, 'input_checks': input_checks,
        'actual_crypto_hooks': source['actual_crypto_hooks'], 'actual_iobsd_hook': source['actual_iobsd_hook'],
        'actual_init_hook': source['actual_init_hook'], 'production_darwinboot_parser': 'PASS',
        'runtime_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The isolated mapped-resource backend, preserved fresh-health frontend and original IOSurface aliases are prelinked with the '
                 'same 28 original iPhone executable components and seven interfaces. All 63889 original pointers, original '
                 'executable segments, 97 source entries, 341 aliases, source executable bytes, existing class tables and '
                 'crypto/IOBSD/init hooks are read back. The production DarwinBoot parser accepts the actual candidate. '
                 'Static prelink does not qualify original module initialization, GPU/cache/quiescence, real hardware or iOS boot.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 90-object mapped-resource strict prelink / 341 aliases / 97 entries / 63889 pointers')


if __name__ == '__main__': main()
