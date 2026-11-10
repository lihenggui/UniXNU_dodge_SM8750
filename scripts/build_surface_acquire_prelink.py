#!/usr/bin/env python3
"""Strictly prelink the isolated surface backing acquisition candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from build_surface_acquire import REPORT as SOURCE_REPORT, check_report as check_source
from build_crypto_prelink import validate
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG, check_input
from build_ufs_prelink import check_storage
from build_data_source import check_table, concrete_methods
from native_driver_build import ROOT, TREE, require
from prepare_initial_data import sha
from prepare_surface_backing import checked as backing_checked, apply_hooks, restore_hooks, hook_readbacks

OUT = ROOT / 'build/cph2653-surface-acquire-prelink'
REPORT = ROOT / 'reports/ios16-surface-acquire-prelink.json'
RESULT = 'IOS16_SURFACE_BACKING_ACQUISITION_STRICT_PRELINK_PASS'


def check_report(report):
    require(report['result'] == RESULT and report['original_aliases_preserved'] == 347 and
            report['native_source_entries_preserved'] == 112 and report['pointer_sites_read_back'] == 63889,
            'Incomplete surface backing acquisition strict prelink report')
    for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Surface identity prelink evidence changed: ' + filename)
    contract,_=backing_checked();data=(ROOT/report['candidate']).read_bytes()
    require(hook_readbacks(data,contract)==report['original_lifecycle_hooks'] and
        restore_hooks(data,contract)==(ROOT/report['unhooked_candidate']).read_bytes(),
        'Four surface lifecycle hook words/trampolines or normalized image changed')
    require(report['hardware_tested'] is False and report['runtime_qualified'] is False and
            report['all_ios_port_code_complete'] is False, 'Surface identity prelink exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: existing surface backing acquisition strict prelink and 63889 pointer readbacks'); return
    source = json.loads(SOURCE_REPORT.read_text()); check_source(source); contract, _ = backing_checked()
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
        print('PRELINK: surface backing acquisition source / unchanged original iPhone components / strict imports', flush=True)
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(process.returncode == 0, 'Surface identity strict prelink failed; inspect emission.log')
        data = candidate.read_bytes(); record = json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256'] == hashlib.sha256(data).hexdigest() and
                record['native_sha256'] == sha(ROOT / source['candidate']) and
                record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Surface identity prelink identities differ')
        checked = validate(data, record, native, original, context, config, source, security)
        require(checked.pop('original_aliases_preserved') == 339, 'Base original alias inventory changed')
        checked['base_original_aliases_preserved'] = 339; checked['original_aliases_preserved'] = len(source['combined_original_bindings'])
        require(checked.pop('native_source_entries_preserved') == 97, 'Base entry inventory changed')
        checked['base_native_source_entries_preserved'] = 97
        checked['native_source_entries_preserved'] = len(source['combined_native_entries'])
        storage = {**json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text()), 'actual_iobsd_hook': source['actual_iobsd_hook']}
        display = json.loads((ROOT / 'reports/ios16-display-kernel.json').read_text())
        service = json.loads((ROOT / 'reports/ios16-display-service.json').read_text())
        inputs = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
        object_from = lambda report, suffix: next(ROOT / row['path'] for row in report['objects'] if row['path'].endswith(suffix))
        storage_checks = check_storage(data, native, original, context, storage, display,
            object_from(service, 'DodgeIPhoneFramebuffer.late.o'), object_from(storage, 'NativeUfs.late.o'))
        input_checks = check_input(data, native, original, context, inputs, object_from(inputs, 'DodgeInput.late.o'))
        ram = json.loads((ROOT / 'reports/ios16-data-source.json').read_text())
        require(check_table(data, concrete_methods(ROOT / ram['late_object'])) == 352, 'Surface identity prelink changed the RamBlock ABI')
        process = subprocess.run([sys.executable, parser_path, candidate], env=env, capture_output=True, text=True)
        (OUT / 'loader-parser.log').write_text(process.stdout + process.stderr)
        require(process.returncode == 0, 'Production DarwinBoot parser refused the surface backing acquisition candidate')
        # The emitter's strict report describes this preserved unhooked image.
        # Exactly four reviewed entry words are changed in the separate output.
        candidate.replace(OUT / 'kernel.unhooked.macho')
        candidate.with_suffix('.json').replace(OUT / 'emission.json')
        patched = apply_hooks(data,contract)
        require(restore_hooks(patched,contract)==data,'Surface hook normalization changed unrelated bytes')
        candidate.write_bytes(patched)
        process = subprocess.run([sys.executable,parser_path,candidate],env=env,capture_output=True,text=True)
        (OUT/'hooked-loader-parser.log').write_text(process.stdout+process.stderr)
        require(process.returncode==0,'Production DarwinBoot parser refused the four-hook candidate')
        candidate.replace(OUT/'kernel.macho')
    files = [Path(__file__), ROOT / 'scripts/build_surface_acquire.py', ROOT / 'scripts/build_crypto_prelink.py',
             ROOT / 'scripts/build_gpu_graphics_prelink.py', ROOT / 'scripts/build_ufs_prelink.py', ROOT / 'scripts/build_input_prelink.py',
             ROOT / 'scripts/build_data_source.py', PROFILE, CONFIG, SECURITY, emitter, emitter.parent / 'native_prelink.py', parser_path, ROOT/'scripts/prepare_surface_backing.py']
    report = {'result': RESULT, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(SOURCE_REPORT.relative_to(ROOT)): sha(SOURCE_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (OUT / 'kernel.macho', OUT / 'kernel.unhooked.macho', OUT / 'emission.json')},
        'candidate': str((OUT / 'kernel.macho').relative_to(ROOT)), 'candidate_sha256': sha(OUT / 'kernel.macho'),
        'combined_source_objects': 97, 'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'],
        **checked, 'storage_checks': storage_checks, 'input_checks': input_checks,
        'actual_crypto_hooks': source['actual_crypto_hooks'], 'actual_iobsd_hook': source['actual_iobsd_hook'],
        'actual_init_hook': source['actual_init_hook'], 'production_darwinboot_parser': 'PASS',
        'original_lifecycle_hooks': hook_readbacks(patched,contract), 'unhooked_candidate': str((OUT/'kernel.unhooked.macho').relative_to(ROOT)),
        'unhooked_candidate_sha256': sha(OUT/'kernel.unhooked.macho'), 'original_executable_checks_exclude_exactly_four_hook_words': True,
        'all_four_original_lifecycle_observers_installed': True, 'normalization_recovers_exact_strict_emitter_image': True,
        'iosurface_producer_connected': False, 'GPU_import_backing_associated': False,
        'runtime_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The unchanged strict emitter output is preserved separately and validated against all 63889 pointers, original executable segments, 347 aliases, 112 source entries, class tables and prior hooks. The final candidate differs at exactly four IOSurface entry words: init, replacement, clear and final free branch to the native observer wrappers. Each trampoline replays the original non-PC-relative stack instruction and resumes at original +4. Restoring exactly those words reproduces the strict emitter image byte for byte; remaining original bodies and native instructions are unchanged. The actual hooked candidate passes the production DarwinBoot parser. No original allocator/init lifecycle, producer grant, backing immutability, hardware/cache/reset or iOS runtime qualification is claimed.'}

    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 97-object surface backing acquisition strict prelink / 347 aliases / 112 entries / 63889 pointers')


if __name__ == '__main__': main()
