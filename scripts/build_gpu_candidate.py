#!/usr/bin/env python3
"""Combine real GPU kernel-side objects and audit their remaining integration imports."""
import json
import subprocess

from native_driver_build import ROOT, NATIVE, archive_imports, inspect_object, require, sha


def main():
    backend = json.loads((ROOT / 'reports/a830-backend.json').read_text())
    require(backend['native_kernel_sha256'] == sha(NATIVE), 'GPU backend report uses an older native kernel')
    objects = []
    directory = ROOT / 'build/cph2653-a830-backend'
    for name, digest in backend['object_sha256'].items():
        matches = [path for path in directory.rglob(name) if sha(path) == digest]
        require(len(matches) == 1, 'Backend object identity is ambiguous: ' + name)
        objects += matches
    objects += [ROOT / 'build/cph2653-gpu-firmware/firmware.o', ROOT / 'build/cph2653-gpu-policy/PaganiGpuVotes.o',
                ROOT / 'build/cph2653-gpu-board/PaganiGpu.o', ROOT / 'build/cph2653-gpu-board/NativeGOPPresenter.o']
    console = json.loads((ROOT / 'reports/ios16-diagnostic-console.json').read_text())
    require(console['result'] == 'DARWIN22_POST_VM_DIAGNOSTIC_CONSOLE_BUILD_PASS' and
            console['host_renderer_tests'], 'Need the actual compiled and tested diagnostic console')
    for item in console['objects']:
        path = ROOT / item['path']
        require(sha(path) == item['sha256'], 'Diagnostic console object changed after validation')
        objects.append(path)
    swap_bridge = json.loads((ROOT / 'reports/ios16-gpu-swap-bridge.json').read_text())
    require(swap_bridge['result'] == 'DARWIN22_GPU_SWAP_BRIDGE_SOURCE_CANDIDATE_PASS' and
            swap_bridge['native_kernel_sha256'] == sha(NATIVE) and swap_bridge['host_case_count'],
            'Need the compiled and tested actual GPU completion bridge')
    for item in swap_bridge['objects']:
        path = ROOT / item['path']
        require(sha(path) == item['sha256'], 'GPU swap bridge object changed after validation')
        objects.append(path)
    refresh = json.loads((ROOT / 'reports/ios16-software-refresh.json').read_text())
    require(refresh['result'] == 'DARWIN22_SOFTWARE_REFRESH_SOURCE_CANDIDATE_PASS' and
            refresh['native_kernel_sha256'] == sha(NATIVE) and refresh['host_case_count'],
            'Need the compiled and tested real software refresh/diagnostic provider')
    for item in refresh['objects']:
        path = ROOT / item['path']
        require(sha(path) == item['sha256'], 'Software refresh object changed after validation')
        objects.append(path)
    backing = json.loads((ROOT / 'reports/ios16-surface-backing.json').read_text())
    require(backing['result'] == 'IOS16_SURFACE_BACKING_SOURCE_CANDIDATE_PASS' and backing['native_kernel_sha256'] == sha(NATIVE),
            'Need the compiled/tested real IOSurface backing provider')
    objects += [ROOT / 'build/ios16-surface-backing/DodgeSurfaceBacking.o',
                ROOT / 'build/ios16-surface-interface/original-surface-bindings.o']
    frontend = json.loads((ROOT / 'reports/ios16-display-frontend.json').read_text())
    require(frontend['result'] == 'DARWIN22_BOUNDED_IPHONE_DISPLAY_FRONTEND_CANDIDATE_PASS' and
            frontend['native_kernel_sha256'] == sha(NATIVE) and frontend['host_case_count'] and frontend['native_guard_tests']['cases'],
            'Need the native/tested bounded iPhone display frontend')
    for item in frontend['objects']:
        path = ROOT / item['path']
        require(sha(path) == item['sha256'], 'Display frontend object changed after checks')
        objects.append(path)
    for name, members in (('gpu-firmware', objects[40:41]), ('gpu-policy', objects[41:42]),
                          ('gpu-board-candidate', objects[42:44]), ('ios16-diagnostic-console', objects[44:46]),
                          ('ios16-gpu-swap-bridge', objects[46:48]), ('ios16-software-refresh', objects[48:50]),
                          ('ios16-surface-backing', objects[50:52]), ('ios16-display-frontend', objects[52:54])):
        evidence = json.loads((ROOT / 'reports' / (name + '.json')).read_text())
        archive = ROOT / evidence['archive']
        require(sha(archive) == evidence['archive_sha256'], 'Input archive changed after validation: ' + name)
        for obj in members:
            member = subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, obj.name])
            require(member == obj.read_bytes(), 'GPU object differs from its validated input archive: ' + obj.name)
    require(len(objects) == 54 and len({obj.name for obj in objects}) == 54, 'Unexpected candidate object set')
    for obj in objects:
        inspect_object(obj.read_bytes())
    imports = archive_imports(objects)
    require({'_dodge_gpu_start', '_native_gop_handoff_call', '_native_gop_handoff_memory',
             '_sm8750_gpu_gmu', '_PaganiGpuBuildStartup', '_native_legacy_overlay_rows',
             '_native_legacy_overlay_preserve', '_dodge_diagnostic_console_attach'} <= set(imports['defined']),
            'Candidate does not contain the actual board/presenter/firmware/vote entry points')
    require({'_native_legacy_gpu_complete', '_native_iphone_complete_current', '_native_gop_vsync',
             '_native_iphone_refresh_notify', '_dodge_software_refresh_create'} <= set(imports['defined']) and
            not imports['required_board_or_original_imports'],
            'Display imports must resolve to actual console, completion and software timer sources')
    frontend_entries = {name for name in frontend['imports']['defined'] if 'dodge_display_frontend_' in name}
    require(len(frontend_entries) == 7 and frontend_entries <= set(imports['defined']) and
            {'_native_iphone_surface_id', '_native_iphone_submit_default_packet'} <= set(imports['defined']),
            'Bounded frontend or exact original packet/ID bindings are absent')
    out = ROOT / 'build/cph2653-gpu-candidate'
    out.mkdir(parents=True, exist_ok=True)
    archive = out / 'libDodgeA830Candidate.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, *objects], check=True)
    report = {'result': 'CPH2653_A830_COMBINED_SOURCE_CANDIDATE_PASS', 'target': 'arm64-apple-ios16.0',
              'native_kernel_sha256': sha(NATIVE), 'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive),
              'object_count': len(objects), 'object_sha256': {obj.name: sha(obj) for obj in objects},
              'imports': imports, 'early_original_parent_initializer_removed': True,
              'diagnostic_console_report_sha256': sha(ROOT / 'reports/ios16-diagnostic-console.json'),
              'diagnostic_console_attach_invoked': False,
              'gpu_swap_bridge_report_sha256': sha(ROOT / 'reports/ios16-gpu-swap-bridge.json'),
              'gpu_swap_bridge_frontend_invoked': False,
              'software_refresh_report_sha256': sha(ROOT / 'reports/ios16-software-refresh.json'),
              'software_refresh_frontend_invoked': False,
              'software_refresh_bounded_frontend_connected': True,
              'display_frontend_report_sha256': sha(ROOT / 'reports/ios16-display-frontend.json'),
              'surface_backing_report_sha256': sha(ROOT / 'reports/ios16-surface-backing.json'),
              'bounded_display_frontend_compiled': True,
              'concrete_legacy_subclass_installed': False,
              'selected_in_default_kernel': False, 'linked_into_kernel': False,
              'original_graphics_in_default_prelink': False, 'original_graphics_full_abi_qualified': False,
              'hardware_tested': False, 'scope': 'Real backend, firmware, target vote policy, board startup, presenter, post-VM console, completion bridge, software timer, backing and bounded packet/queue frontend combined. '
                       'Exact iPhone original entries are absolute bindings; original code and a concrete Legacy subclass are not installed by this archive. '
                       'Source provider imports resolve; native static-link-only dependencies and runtime/lifecycle qualification remain explicit.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/gpu-kernel-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(objects)} real iOS 16 GPU objects; source display imports resolved; frontend remains unselected')


if __name__ == '__main__':
    main()
