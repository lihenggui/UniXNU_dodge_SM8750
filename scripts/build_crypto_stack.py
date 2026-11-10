#!/usr/bin/env python3
"""Build/check the five isolated original-crypto ownership preparation stages."""
import argparse
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, require
from prepare_initial_data import sha

STAGES = (('ios16-crypto-contract', 'prepare_ios16_crypto.py', 'uefi'),
          ('ios16-crypto-source', 'build_crypto_source.py', 'uefi'),
          ('ios16-crypto-prelink', 'build_crypto_prelink.py', 'uefi'),
          ('ios16-crypto-kernel', 'check_crypto_kernel.py', 'gpu'),
          ('ios16-crypto-payload', 'build_crypto_payload.py', 'uefi'))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    for script in ('check_ramblock_start_kernel.py', 'check_ios16_pmgr_kernel.py'):
        subprocess.run([ROOT / '.venv-gpu/bin/python', ROOT / 'scripts' / script, '--check-only'], check=True)
    if not args.check_only:
        for _, script, environment in STAGES:
            subprocess.run([ROOT / ('.venv-' + environment + '/bin/python'), ROOT / 'scripts' / script], check=True)
    cache, reports, artifacts = {}, {}, {}
    def digest(path):
        if path not in cache: cache[path] = sha(path)
        return cache[path]
    for name, script, _ in STAGES:
        path = ROOT / 'reports' / (name + '.json'); report = json.loads(path.read_text())
        require('PASS' in report['result'] and report['builder_sha256'] == digest(ROOT / 'scripts' / script), 'Crypto stage is stale: ' + name)
        for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
            require(digest(ROOT / filename) == value, 'Crypto stage source/dependency/artifact changed: ' + filename)
        require(not any(report.get(key) for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                    'original_crypto_post_executed', 'original_crypto_runtime_qualified', 'full_oskext_start_executed')),
                'Crypto stage overstates initialization/POST/runtime: ' + name)
        for filename, value in report['artifacts'].items():
            require(filename not in artifacts or artifacts[filename] == value, 'Conflicting crypto artifact')
            artifacts[filename] = value
        artifacts[str(path.relative_to(ROOT))] = digest(path); reports[name] = report
    contract, source, prelink, cpu, payload = [reports[name] for name, _, _ in STAGES]
    require(contract['contract_facts']['compiler_layout']['kmod_bytes'] == 196 and
            contract['contract_facts']['original_cpp_initializer_count'] == 0 and
            len(contract['contract_facts']['linked_bindings']) == 7, 'Crypto owner/module contract differs')
    require(source['combined_source_objects'] == prelink['combined_source_objects'] == payload['linked_source_objects'] == 89 and
            source['combined_original_aliases'] == prelink['combined_original_aliases'] == 339 and
            len(source['combined_native_entries']) == prelink['native_source_entries_preserved'] == payload['native_source_entries'] == 97,
            'Crypto native/source/prelink/container geometry differs')
    require(source['single_original_crypto_owner_wired'] and payload['single_original_crypto_owner_wired'] and
            not source['source_provider_fallback_after_original_attempt'] and source['actual_crypto_hooks'] == prelink['actual_crypto_hooks'] and
            source['actual_crypto_hooks']['startup_subsystem'] == 15 and
            source['actual_iobsd_hook'] == prelink['actual_iobsd_hook'] and source['actual_init_hook'] == prelink['actual_init_hook'],
            'Actual crypto/bootstrap/OSKext or existing IOBSD/init wiring differs')
    require(source['host_tests']['case_count'] == 18 and all(row['result'] == 'PASS' for row in source['host_tests']['cases']) and
            cpu['case_count'] == 33 and all(row['result'] == 'PASS' for row in cpu['cases']), 'Crypto sanitizer/CPU paths are incomplete')
    require(prelink['candidate_sha256'] == cpu['candidate_sha256'] == payload['candidate_sha256'] and
            len(prelink['components']) == 28 and len(prelink['kernel_interfaces']) == 7 and prelink['pointer_sites_read_back'] == 63889 and
            prelink['darwinboot_production_parser'] == 'PASS' and prelink['independent_source_provider_and_its_post_field_absent'] and
            not prelink['source_provider_post_field_required'], 'Original crypto strict prelink/provider selection differs')
    require(payload['actual_loader_adt_and_packed_parsers_passed'] and payload['loader_keeps_packed_input'] and
            not payload['loader_dense_2GiB_allocation_required'] and payload['packed_seed_bytes'] == 721024 and
            payload['logical_data_bytes'] == 1 << 31 and payload['boot_image_bytes'] == 170557440 and payload['boot_header_version'] == 4 and
            payload['all_original_adt_values_preserved'] and not payload['source_data_default_enabled'] and
            not payload['source_data_mount_default_enabled'] and not payload['original_userspace_included'] and not payload['original_root_windows_included'],
            'Crypto development container/handoff limits differ')
    controls = [row for report in reports.values() for row in report.get('negative_controls', [])]
    require(len(controls) == 25 and all(row['result'] == 'REJECTED' for row in controls), 'Crypto rejection controls differ')
    from build_crypto_source import check_report as check_source
    from check_crypto_kernel import check_report as check_cpu
    check_source(source); check_cpu(cpu)
    report = {'result': 'CPH2653_IPHONE_IOS16_SINGLE_ORIGINAL_CRYPTO_PREPARATION_STACK_PASS', 'builder_sha256': digest(Path(__file__)),
        'source_sha256': {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
        'base_ramblock_report': 'reports/ios16-ramblock-start-kernel.json',
        'base_ramblock_report_sha256': digest(ROOT / 'reports/ios16-ramblock-start-kernel.json'),
        'base_pmgr_report': 'reports/ios16-pmgr-kernel.json', 'base_pmgr_report_sha256': digest(ROOT / 'reports/ios16-pmgr-kernel.json'),
        'stages': {name: {'report': 'reports/' + name + '.json', 'sha256': digest(ROOT / 'reports' / (name + '.json')),
                          'result': reports[name]['result']} for name, _, _ in STAGES},
        'artifacts': [{'path': filename, 'sha256': value, 'role': 'Isolated original-crypto ownership source/build/CPU/container preparation; explicit runtime limits'}
                      for filename, value in sorted(artifacts.items())],
        'combined_source_objects': 89, 'native_entries': 97, 'original_absolute_aliases': 339,
        'original_components': 28, 'original_kernel_interfaces': 7, 'original_pointer_sites_read_back': 63889,
        'source_sanitizer_cases': 18, 'source_and_startup_cpu_cases': 33, 'negative_controls': 25,
        'single_original_crypto_owner_wired': True, 'actual_sysctl_and_oskext_owner_calls_wired': True,
        'boot_image': payload['boot_image'], 'boot_image_sha256': payload['boot_image_sha256'], 'boot_image_bytes': payload['boot_image_bytes'],
        'original_crypto_post_executed': False, 'original_crypto_runtime_qualified': False, 'full_oskext_start_executed': False,
        'original_apfs_data_mount_qualified': False, 'original_root_authentication_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Five isolated stages derive the exact original iPhone crypto owner and wire a single original initialization into '
                 'actual early SYSCTL and later OSKext loading. Eighteen sanitized owner-state paths and 33 compiled ARM64 paths '
                 'use explicit original-initializer/POST/private-PRNG peers. Original start wrappers and native table registration execute. '
                 'The independent source-provider entry/POST field is absent; original crypto code remains unchanged. Strict prelink '
                 'and production loader/container readback pass with 25 rejection controls. Original POST/provider ABI/runtime, full '
                 'OSKext and policy initialization, root/Data authentication and hardware are unqualified. No phone operations.'}
    (ROOT / 'reports/crypto-stack.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: five crypto owner stages / 89 objects / 18 sanitizer cases / 33 ARM64 paths / 25 rejection controls / container readback')


if __name__ == '__main__': main()
