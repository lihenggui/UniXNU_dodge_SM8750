#!/usr/bin/env python3
"""Check local original-root and initial-Data inputs against the built UFS route."""
import argparse
import json
from pathlib import Path
import stat
import subprocess

from native_driver_build import ROOT, require
from prepare_root_image import make_manifest, sha
from prepare_initial_data import verify_archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', action='store_true', help='Prepare root/Data inputs and the full local Data source/check chain')
    args = parser.parse_args()
    if args.build:
        for script in ('prepare_root_image.py', 'prepare_initial_data.py'):
            subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts' / script], check=True)
        subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_data_stack.py'], check=True)
    subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_storage_stack.py', '--check-only'], check=True)
    paths = {name: ROOT / 'reports' / (name + '.json') for name in ('ios16-root-image', 'ios16-initial-data', 'storage-stack')}
    reports = {n: json.loads(p.read_text()) for n, p in paths.items()}
    root, data, storage = (reports[n] for n in paths)
    volumes = ROOT / 'reports/ios16-volumes.json'
    artifacts = {}
    for name, script in (('ios16-root-image', 'prepare_root_image.py'), ('ios16-initial-data', 'prepare_initial_data.py')):
        report = reports[name]
        require('PASS' in report['result'] and report['builder_sha256'] == sha(ROOT / 'scripts' / script), 'Input stage is stale: ' + name)
        require((report['product'], report['build']) == ('iPhone10,3', '20H392') and report['volume_report_sha256'] == sha(volumes),
                'Input volume identity/report is stale')
        for path, digest in report['source_sha256'].items():
            require(sha(ROOT / path) == digest, 'Input source changed: ' + path)
        require(report['phone_operations'] == 'none' and not report['hardware_tested'] and not report['ready_for_ios_boot'] and
                not report['block_devices_opened'] and not report['filesystem_mounted'], 'Offline input scope differs')
    require((root['selected_partition_name'], root['format'], root['format_version']) == ('unixnu', 'SHNGROOT', 1) and
            root['physical_lba_bytes'] == 4096 and root['logical_block_bytes'] == 512 and
            not root['image_contains_gpt'] and not root['writable_data_included'] and not root['root_authentication_qualified'] and
            root['consumer_production_sources_unmodified'] and root['all_window_bytes_read_back'] and
            root['host_case_count'] == len(root['host_cases']) == 32 and all(c['result'] == 'PASS' for c in root['host_cases']),
            'Original read-only root evidence incomplete')
    image = ROOT / root['image']
    require(stat.S_ISREG(image.lstat().st_mode) and image.stat().st_size == root['image_bytes'] and sha(image) == root['image_sha256'], 'Original root image changed')
    artifacts[root['image']] = root['image_sha256']
    with image.open('rb') as stream:
        require(stream.read(4096) == make_manifest(root['windows'], root['image_bytes']), 'Root-image manifest changed')
    for path_field in ('host_consumer', 'cpu_cases'):
        path, digest = root[path_field], root[path_field + '_sha256']
        require(sha(ROOT / path) == digest, 'Root consumer evidence changed: ' + path)
        artifacts[path] = digest
    require(data['source_image_sha256'] == root['windows'][0]['sha256'] and root['windows'][0]['name'] == 'OS' and
            root['windows'][1]['name'] == 'SystemOS' and data['source_path'] == '/private/var' and
            data['excluded_paths'] == ['staged_system_apps'] and data['all_archive_files_and_metadata_read_back'] and
            data['source_uid_gid_mode_times_xattrs_and_hardlinks_preserved_as_metadata'] and
            not data['source_symlinks_followed'] and not data['host_ownership_or_xattrs_changed'] and
            not data['apfs_data_image_formatted'] and not data['settings_or_activation_state_changed'] and
            len(data['negative_controls']) == 8 and all(c['result'] == 'REJECTED' for c in data['negative_controls']),
            'Initial Data content/metadata evidence incomplete')
    for path, digest in {**data['artifacts'], **data['tool_dependencies_sha256']}.items():
        require(sha(ROOT / path) == digest, 'Initial Data artifact changed: ' + path)
        if path in data['artifacts']:
            artifacts[path] = digest
    metadata = (ROOT / data['metadata']).read_bytes()
    contents = json.loads(metadata)
    require(contents['source_image_sha256'] == data['source_image_sha256'] and len(contents['entries']) == data['counts']['entries'], 'Initial Data inventory changed')
    with (ROOT / data['archive']).open('rb') as stream:
        verify_archive(stream, contents['entries'], metadata)
    subprocess.run([ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/build_data_stack.py', '--check-only'], check=True)
    paths['data-stack'] = ROOT / 'reports/data-stack.json'
    prepared_data = json.loads(paths['data-stack'].read_text())
    require(prepared_data['initial_data_entries_per_image'] == len(contents['entries']) and prepared_data['host_cases'] == 77 and
            prepared_data['prelinked_source_cpu_cases'] == 30 and prepared_data['combined_source_objects'] == 83 and
            not prepared_data['writable_data_runtime_qualified'], 'Formatted Data/source evidence differs')
    artifacts.update({item['path']: item['sha256'] for item in prepared_data['artifacts']})
    root_source = json.loads((ROOT / 'reports/ios16-ufs-root.json').read_text())
    commands = json.loads((ROOT / root_source['compile_manifest']).read_text())
    command, = [c['arguments'] for c in commands if c['source'].endswith('/NativeUfs.cpp')]
    require('-DUFS_ROOT_PARTITION="unixnu"' in command and '-DNATIVE_UFS_READ_ONLY=1' in command and
            '-DNATIVE_UFS_PROBE_ONLY=0' in command and storage['combined_source_objects'] == 68,
            'Root image does not match the actual compiled UFS selection')
    files = [Path(__file__), ROOT / 'scripts/prepare_root_image.py', ROOT / 'scripts/prepare_initial_data.py', ROOT / 'scripts/build_data_stack.py']
    result = {'result': 'IOS16_ROOT_AND_INITIAL_DATA_LOCAL_INPUTS_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in paths.values()},
              'artifacts': artifacts, 'root_image': root['image'], 'root_image_bytes': root['image_bytes'],
              'root_image_host_cases': 32, 'initial_data_archive': data['archive'], 'initial_data_counts': data['counts'],
              'initial_data_negative_controls': 8, 'root_partition_name_matches_actual_driver_compile': True,
              'original_system_windows_prepared': True, 'initial_data_content_and_metadata_prepared': True,
              'apfs_data_container_formatted': True, 'data_preparation_report': 'reports/data-stack.json',
              'data_formatted_images': prepared_data['formatted_images'], 'preferred_bringup_data_seed': prepared_data['preferred_bringup_seed'],
              'data_source_host_cases': 77, 'data_source_cpu_cases': 30, 'data_source_objects': 83,
              'data_registration_and_once_start_source_implemented': True, 'data_source_metadata_registered_or_started': False,
              'writable_data_runtime_qualified': False, 'authenticated_root_qualified': False, 'physical_partition_created_or_modified': False,
              'phone_operations': 'none', 'default_boot_image_replaced': False, 'hardware_tested': False,
              'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'remaining': ['Wire the default-off source Data registration/starter and preferred 2 GiB seed into a separately gated startup/payload route.',
                            'Qualify original APFS/authenticated-root, storage completion/matching, crypto and power lifecycle in the selected iPhone kernel.',
                            'Complete target touch/HID, remaining private graphics ABI, networking/audio/charging/thermal services.'],
              'scope': 'Local regular-file inputs for the separate complete read-only UFS/display code candidate. '
                       'Original OS/SystemOS windows and exact initial Data contents/metadata are assembled and read back; '
                       'Two separately identified APFS Data containers and packed seeds are formatted and independently read back. '
                       'An 83-object source Data candidate implements deferred registration and one-shot start; 77 sanitizer and 30 ARM64 cases pass with explicit peers. '
                       'No physical GPT, Data registration/start/mount result, root trust, kernel runtime or iOS boot result.'}
    (ROOT / 'reports/ios16-system-inputs.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: original root windows, exact Data archive, two APFS seeds and 83-object Data source/prelink evidence; original mount and authenticated root remain unqualified')


if __name__ == '__main__':
    main()
