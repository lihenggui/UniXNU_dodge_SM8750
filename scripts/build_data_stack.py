#!/usr/bin/env python3
"""Build/check the local APFS seeds, source lifecycle, strict link and CPU evidence."""
import argparse
import json
from pathlib import Path
import subprocess

from native_driver_build import ROOT, pinned_sources, require
from prepare_initial_data import sha

STAGES = (
    ('ios16-data-image', 'prepare_data_image.py', ()),
    ('ios16-data-volatile-image', 'prepare_data_image.py', ('--volatile',)),
    ('ios16-data-seed-host', 'check_data_seed.py', ()),
    ('ios16-data-source', 'build_data_source.py', ()),
    ('ios16-data-prelink', 'build_data_prelink.py', ()),
    ('ios16-data-kernel', 'check_data_kernel.py', ()),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if not args.check_only:
        for name, script, options in STAGES:
            interpreter = '.venv-gpu/bin/python' if name == 'ios16-data-kernel' else '.venv-uefi/bin/python'
            subprocess.run([ROOT / interpreter, ROOT / 'scripts' / script, *options], check=True)
    pinned_sources(('ramblock_reference', 'apfs_writer_reference', 'apfs_checker_reference', 'apfs_readonly_reference', 'fajita_data_reference'))
    reports, artifacts, digests = {}, {}, {}
    def digest(path):
        if path not in digests:
            digests[path] = sha(path)
        return digests[path]
    for name, script, _ in STAGES:
        path = ROOT / 'reports' / (name + '.json')
        report = json.loads(path.read_text())
        require('PASS' in report['result'] and report['builder_sha256'] == digest(ROOT / 'scripts' / script), 'Data stage is stale: ' + name)
        for file, value in {**report['source_sha256'], **report.get('tool_dependencies_sha256', {}),
                            **report.get('dependency_report_sha256', {}), **report['artifacts']}.items():
            require(digest(ROOT / file) == value, 'Data stage source/dependency/artifact changed: ' + file)
        for file, value in report['artifacts'].items():
            require(file not in artifacts or artifacts[file] == value, 'Conflicting Data stage artifact: ' + file)
            artifacts[file] = value
        require(not any(report.get(key, False) for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                    'writable_data_runtime_qualified', 'writable_apfs_runtime_qualified', 'filesystem_mounted', 'block_devices_opened')),
                'Data stage overstates its scope: ' + name)
        reports[name] = report
    image, volatile, seed, source, prelink, cpu = [reports[name] for name, _, _ in STAGES]
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    for report, pin in ((image, 'iphone_data_image'), (volatile, 'iphone_volatile_data_image')):
        require(report['profile'] == lock[pin]['path'] and digest(ROOT / report['profile']) == lock[pin]['sha256'] and
                report['source_references'] == {name: lock[name] for name in report['source_references']} and
                report['strict_checker_overlay'] == lock['apfs_checker_apple_signature_overlay'], 'Data image source/installation pins changed')
    require(source['source_reference'] == seed['source_reference'] == lock['ramblock_reference'], 'RamBlock source revision changed')
    require(image['image_bytes'] == 3 << 30 and volatile['image_bytes'] == 2 << 30 and
            image['persistent_store_required_for_ramblock_writes'] and not volatile['persistent_store_required_for_ramblock_writes'] and
            volatile['volatile_sparse_ramblock_compatible_capacity'] and image['volume']['volume_uuid_hex'] != volatile['volume']['volume_uuid_hex'],
            'Data capacities or separate installation identities differ')
    for report in (image, volatile):
        require(report['counts']['entries'] == 198 and report['counts']['files'] == 36 and report['compressed_files_preserved'] == 17 and
                report['resource_forks_preserved'] == 5 and report['all_contents_and_metadata_read_back'] and
                report['strict_apfsck_unknown_feature_qualification'] and not report['strict_unmodified_apfsck_unknown_feature_qualification'] and
                report['reproducible_image_verified'] and report['packed_entire_logical_image_read_back'] and
                len(report['negative_controls']) == 17 and all(c['result'] == 'REJECTED' for c in report['negative_controls']), 'Incomplete APFS seed evidence')
    require(seed['case_count'] == 47 and all(t['result'] == 'PASS' for t in seed['tests'].values()) and
            seed['entire_2GiB_image_read_through_actual_ramSparseIO_and_hashed'], 'Incomplete actual seed source checks')
    host = source['lifecycle_host_tests']
    require(source['combined_source_objects'] == prelink['combined_source_objects'] == 83 and
            source['compiled_instance_bytes'] == cpu['instance_layout']['instance_bytes'] == prelink['compiled_ramblock_bytes'] == 352 and
            source['concrete_vtable_entries'] == prelink['ramblock_vtable_entries_read_back'] == 190 and
            source['combined_original_aliases'] == prelink['combined_original_aliases'] == 332 and host['case_count'] == len(host['cases']) == 30 and
            all(c['result'] == 'PASS' for c in host['cases']) and source['initializer_removed_from_early_registration'] and
            source['source_instance_and_provider_pinned_before_original_init'] and source['source_init_attach_start_failure_latched_without_release'] and
            not source['default_data_boot_argument_enabled'], 'Incomplete Data source/lifecycle evidence')
    require(cpu['candidate_sha256'] == prelink['candidate_sha256'] and cpu['case_count'] == len(cpu['cases']) == 30 and
            all(c['result'] == 'PASS' for c in cpu['cases']) and cpu['annotation_text_identical_to_production'] and
            cpu['actual_original_storage_protected_constructor_and_destructor_executed'] and
            prelink['darwinboot_production_parser'] == 'PASS' and prelink['source_crypto_post_verified'] and
            len(prelink['components']) == 28 and len(prelink['kernel_interfaces']) == 7, 'Incomplete original-prelinked Data CPU evidence')
    controls = [c for report in reports.values() for c in report.get('negative_controls', [])]
    require(len(controls) == 43 and all(c['result'] == 'REJECTED' for c in controls), 'Data corruption controls differ')
    for name, _, _ in STAGES:
        path = ROOT / 'reports' / (name + '.json')
        artifacts[str(path.relative_to(ROOT))] = digest(path)
    result = {'result': 'CPH2653_IPHONE_IOS16_LOCAL_DATA_PREPARATION_STACK_PASS', 'builder_sha256': digest(Path(__file__)),
              'source_sha256': {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
              'product': 'iPhone10,3', 'build': '20H392',
              'stages': {name: {'report': 'reports/' + name + '.json', 'sha256': digest(ROOT / 'reports' / (name + '.json')), 'result': reports[name]['result']}
                         for name, _, _ in STAGES},
              'artifacts': [{'path': path, 'sha256': value, 'role': 'Separate local Data preparation artifact; scope follows its stage report'} for path, value in sorted(artifacts.items())],
              'formatted_images': [image['image'], volatile['image']], 'preferred_bringup_seed': volatile['packed_image'],
              'initial_data_entries_per_image': 198, 'compressed_files_per_image': 17, 'resource_forks_per_image': 5,
              'host_cases': seed['case_count'] + host['case_count'], 'prelinked_source_cpu_cases': cpu['case_count'], 'negative_controls': len(controls),
              'combined_source_objects': 83, 'native_entries': len(source['combined_native_entries']), 'combined_original_aliases': 332,
              'original_components': len(prelink['components']), 'kernel_interfaces': len(prelink['kernel_interfaces']),
              'original_pointer_sites_read_back': prelink['pointer_sites_read_back'],
              'exact_original_initial_data_preserved': True, 'linux_apfs_formatting_and_independent_readback_prepared': True,
              'data_registration_and_once_start_source_implemented': True, 'data_source_metadata_registered_or_started': False,
              'data_source_default_enabled': False, 'original_apfs_data_mount_qualified': False, 'writable_data_runtime_qualified': False,
              'phone_operations': 'none', 'filesystem_mounted': False, 'block_devices_opened': False, 'hardware_tested': False,
              'default_kernel_selected': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'remaining': ['Wire the source Data starter and seed into a separately gated startup/payload route.',
                            'Prepare and qualify the exact iPhone original APFS Data mount, parent init/start and media matching lifecycle.',
                            'Finish private graphics, crypto/power and other platform driver work; host/CPU checks are not a working iOS result.'],
              'scope': 'Six local construction/source/link/CPU stages. Two reproducible APFS seeds retain the exact original initial Data with distinct fixed installation identities. '
                       'The 2 GiB variant uses the existing volatile sparse capacity; the 3 GiB variant requires a persistent store for runtime writes. '
                       '77 sanitizer cases, 30 ARM64 cases, 43 corruption controls and a separate 83-object/28-component prelink pass. '
                       'New source registration/once-start is implemented and default-off; it has not registered/mounted original Data or booted iOS.'}
    (ROOT / 'reports/data-stack.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: six Data stages / 77 sanitizer cases / 30 ARM64 paths / 43 rejection controls / 83 source objects; original Data runtime remains unqualified')


if __name__ == '__main__':
    main()
