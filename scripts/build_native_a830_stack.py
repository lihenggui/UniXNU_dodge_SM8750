#!/usr/bin/env python3
"""Build or verify the native A830 iPhone development payload."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess

from check_gpu_userspace import verify
from native_driver_build import ROOT, require, sha

REPORT = ROOT / 'reports/native-a830-stack.json'
STAGES = (
    ('backend_host', 'check_native_a830_host', (), 'native-a830-host'),
    ('board_host', 'check_native_a830_board', ('--firmware-dir', 'build/cph2653-gpu-firmware'), 'native-a830-board-host'),
    ('runtime_host', 'check_native_a830_host', ('--runtime',), 'native-a830-runtime-host'),
    ('archive', 'build_native_a830', ('--board', '--runtime'), 'native-a830-runtime'),
    ('kernel', 'build_native_a830_kernel', (), 'native-a830-kernel'),
    ('prelink', 'build_native_a830_prelink', (), 'native-a830-prelink'),
    ('turnip', 'build_turnip_ios16', ('--native-a830',), 'native-a830-turnip'),
    ('recovery_host', 'check_native_a830_recovery', (), 'native-a830-recovery-host'),
    ('bridge', 'build_metal_bridge', ('--native-a830',), 'native-a830-metal-bridge'),
    ('plugin', 'build_metal_plugin', ('--native-a830',), 'native-a830-metal-plugin'),
    ('userspace', 'check_gpu_userspace', ('--native-a830',), 'native-a830-userspace'),
    ('firmware', 'build_native_a830_firmware', (), 'native-a830-firmware'),
    ('addon', 'build_native_a830_addon', (), 'native-a830-addon'),
    ('payload', 'build_native_a830_payload', (), 'native-a830-payload'),
    ('entry', 'check_native_a830_entry', (), 'native-a830-entry'),
)


def collect():
    reports, stages = {}, {}
    for name, module, arguments, filename in STAGES:
        path = ROOT / 'reports' / (filename + '.json')
        row = json.loads(path.read_text())
        require('PASS' in row['result'] and row['hardware_tested'] is False, 'Incomplete native stage: ' + name)
        checker = getattr(importlib.import_module(module), 'check_report', None)
        if checker:
            checker(row)
        for field in ('source_sha256', 'dependency_report_sha256', 'artifacts'):
            for source, digest in row.get(field, {}).items():
                require(sha(ROOT / source) == digest, 'Native stage input changed: ' + source)
        for field in ('archive', 'library', 'candidate'):
            if field in row:
                require(sha(ROOT / row[field]) == row[field + '_sha256'], 'Native stage artifact changed: ' + name)
        script = ROOT / 'scripts' / (module + '.py')
        if 'builder_sha256' in row:
            require(sha(script) == row['builder_sha256'], 'Native stage builder changed: ' + module)
        reports[name] = row
        stages[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
                        'builder': str(script.relative_to(ROOT)), 'builder_sha256': sha(script), 'arguments': list(arguments)}

    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    runtime, host = reports['archive'], reports['runtime_host']
    require(runtime['runtime_overlay'] == host['runtime_overlay'] and runtime['object_count'] == 57,
            'Native archive and host tests use different runtime adapters')
    require(reports['backend_host']['suite_count'] == 15 and host['suite_count'] == 3 and
            reports['board_host']['stock_firmware_tested'], 'Native host coverage is incomplete')
    require(reports['kernel']['combined_source_objects'] == reports['prelink']['combined_source_objects'] == 111,
            'Native full-kernel object inventory differs')
    bridge, turnip, plugin = (reports[key] for key in ('bridge', 'turnip', 'plugin'))
    for row, field, key in ((bridge, 'native_surface_overlay', 'native_a830_metal_surface_overlay'),
                            (plugin, 'native_surface_overlay', 'native_a830_metal_surface_overlay'),
                            (turnip, 'native_surface_overlay', 'native_a830_mesa_surface_overlay'),
                            (turnip, 'native_recovery_overlay', 'native_a830_mesa_recovery_overlay'),
                            (bridge, 'native_compile_overlay', 'native_a830_compile_overlay')):
        require(row[field] == lock[key] and sha(ROOT / lock[key]['path']) == lock[key]['sha256'],
                'Native userspace adapter differs: ' + key)
    require(bridge['runtime_patches'] == lock['metal_runtime_patches'] and
            bridge['cargo_lock_sha256'] == lock['metal_bridge_dependencies']['sha256'] ==
            sha(ROOT / lock['metal_bridge_dependencies']['path']), 'Native Rust dependency inputs differ')
    require(plugin['linked'] and plugin['rust_bridge_sha256'] == bridge['archive_sha256'] and
            plugin['turnip_sha256'] == turnip['library_sha256'], 'Native plugin uses another bridge or Turnip')
    require(reports['kernel']['display_recovery_overlay'] == lock['native_a830_display_recovery_overlay'],
            'Native display uses another recovery adapter')
    for binary in reports['userspace']['binaries']:
        data = (ROOT / binary['path']).read_bytes()
        actual = verify(data, binary['filetype'])
        require(sha(ROOT / binary['path']) == binary['sha256'] and
                all(binary[key] == value for key, value in actual.items()), 'Native userspace binary changed')
    payload, prelink, firmware = (reports[key] for key in ('payload', 'prelink', 'firmware'))
    require(payload['fat_files']['EFI/UniXNU/Payloads/kernel.macho'] == prelink['candidate_sha256'] and
            payload['firmware_sha256'] == firmware['firmware_sha256'] and
            payload['original_POST_tests_in_model'] == 18, 'Native payload mixes kernel or firmware stages')
    require(reports['entry']['candidate_sha256'] == prelink['candidate_sha256'],
            'QEMU entry tested a different iPhone kernel')
    sources = [Path(__file__), ROOT / 'scripts/native_a830_userspace.py', ROOT / 'scripts/native_a830_runtime.py']
    sources += [ROOT / value['builder'] for value in stages.values()]
    return {'result': 'CPH2653_NATIVE_A830_IPHONE_DEVELOPMENT_STACK_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in sources}, 'stages': stages,
        'native_backend_revision': lock['native_a830_reference']['revision'],
        'native_SMMU_revision': lock['native_a830_smmu_reference']['revision'],
        'combined_source_objects': 111, 'native_GPU_objects': 57, 'backend_host_suites': 15,
        'runtime_host_suites': 3, 'original_components': len(prelink['components']),
        'original_pointer_readbacks': prelink['pointer_sites_read_back'],
        'candidate': prelink['candidate'], 'candidate_sha256': prelink['candidate_sha256'],
        'boot_image': payload['boot_image'], 'boot_image_sha256': payload['boot_image_sha256'],
        'surface_ID_import_and_original_producers_connected': True,
        'recovered_Vulkan_device_and_per_surface_visibility': True,
        'firmware_fresh_entropy_and_DXE_log_export': True,
        'QEMU_entry_checkpoints': [row['symbol'] for row in reports['entry']['checkpoints']],
        'QEMU_next_dependency': reports['entry']['next_stop'],
        'original_userspace_included': False, 'default_kernel_selected': False, 'hardware_tested': False,
        'phone_operations': 'none',
        'scope': 'Native A830 source/runtime, original iPhone prelink, Turnip/Metal, addon/trust inputs and '
                 'entropy/logger firmware form one locally verified development payload. Actual QEMU execution reaches '
                 'InitIOKit, then original Image4 refuses missing startup policy. GPU power, DMA/cache visibility, '
                 'rendering and system boot remain untested.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true')
    mode.add_argument('--record-existing', action='store_true', help='Validate and record completed stages')
    args = parser.parse_args()
    if not args.check_only and not args.record_existing:
        for name, module, arguments, _ in STAGES:
            print('BUILD:', name, flush=True)
            subprocess.run([ROOT / '.venv-gpu/bin/python', ROOT / 'scripts' / (module + '.py'), *arguments], cwd=ROOT, check=True)
    report = collect()
    if args.check_only:
        require(json.loads(REPORT.read_text()) == report, 'Native A830 aggregate is stale')
    else:
        REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native A830, 111-object iPhone prelink, Metal addon and actual EFI development handoff')


if __name__ == '__main__':
    main()
