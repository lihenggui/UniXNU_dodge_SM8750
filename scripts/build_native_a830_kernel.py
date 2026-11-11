#!/usr/bin/env python3
"""Link the native A830 with the complete iPhone storage, input and display candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct

from build_surface_acquire import REPORT as BASE_REPORT, check_report as check_base
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from check_gpu_link import ABSENT, assemble, run
from native_driver_build import ROOT, OBJDIR, NATIVE, archive_imports, build_objects, macho, require, sha, symbols
from native_prelink import backed_offset

OUT = ROOT / 'build/cph2653-native-a830-kernel'
REPORT = ROOT / 'reports/native-a830-kernel.json'


def check_firmware(data, pins):
    image = macho(data);names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    result = []
    for suffix, name in (('gmu', 'gen80000_gmu.bin'), ('sqe', 'gen80000_sqe.fw'),
                         ('aqe', 'gen80000_aqe.fw'), ('zap', 'gen80000_zap.mbn')):
        pin = pins[name];address = names['_sm8750_gpu_' + suffix]['value']
        at = backed_offset(image['segments'], address, pin['bytes'], len(data))
        size_at = backed_offset(image['segments'], names['_sm8750_gpu_' + suffix + '_size']['value'], 8, len(data))
        require(address % 4096 == 0 and hashlib.sha256(data[at:at + pin['bytes']]).hexdigest() == pin['sha256'] and
                struct.unpack_from('<Q', data, size_at)[0] == pin['bytes'], 'Linked native firmware differs: ' + name)
        result.append({'name': name, 'address': hex(address), **pin})
    return result


def members(archive, directory):
    directory.mkdir(parents=True, exist_ok=True)
    names = subprocess.check_output(['/usr/bin/llvm-ar-14', 't', archive], text=True).splitlines()
    require(len(names) == len(set(names)) and all(Path(n).name == n for n in names), 'Unsafe archive inventory')
    result = []
    for name in names:
        path = directory / name
        path.write_bytes(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, name]))
        result.append(path)
    return result


def check_report(report):
    require(report['result'] == 'NATIVE_A830_COMPLETE_IPHONE_SOURCE_KERNEL_PASS' and
            not report['hardware_tested'] and not report['default_kernel_selected'], 'Invalid native A830 kernel report')
    for name, digest in {**report['source_sha256'], **report['artifacts'], **report['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == digest, 'Native A830 kernel input changed: ' + name)
    data = (ROOT / report['candidate']).read_bytes()
    table = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    require(macho(data)['kind'] == 2 and not any(s['kind'] == 1 for s in table.values()), 'Native A830 kernel has unresolved symbols')
    for name, address in report['combined_original_bindings'].items():
        require(table[name]['kind'] == 3 and table[name]['value'] == int(address, 16), 'Original alias changed: ' + name)
    for name, address in report['combined_native_entries'].items():
        require(table[name]['kind'] & 14 == 14 and table[name]['value'] == int(address, 16), 'Native entry changed: ' + name)
    require(hook_readbacks(data) == report['actual_crypto_hooks'] and hook_readback(data) == report['actual_iobsd_hook'] and
            init_hook_readback(data) == report['actual_init_hook'], 'Native A830 crypto/storage hooks changed')
    require(check_firmware(data, report['firmware_pins']) == report['firmware_readback'], 'Native firmware readback changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: complete native A830 kernel and original aliases');return
    base = json.loads(BASE_REPORT.read_text());check_base(base)
    gpu_report = ROOT / 'reports/native-a830-runtime.json'
    gpu = json.loads(gpu_report.read_text())
    host_report = ROOT / 'reports/native-a830-runtime-host.json'
    host = json.loads(host_report.read_text())
    require(gpu['runtime_overlay'] == host['runtime_overlay'] and gpu['native_kernel_sha256'] == sha(NATIVE),
            'Build and host-test the same native A830 runtime first')
    for name, digest in {**gpu['source_sha256'], **host['source_sha256']}.items():
        require(sha(ROOT / name) == digest, 'Native A830 dependency changed: ' + name)
    native_archive = ROOT / gpu['archive']
    require(sha(native_archive) == gpu['archive_sha256'], 'Native A830 archive changed')
    OUT.mkdir(parents=True, exist_ok=True)
    command = json.loads((ROOT / base['link_command']).read_text())
    old_gpu = ROOT / 'build/cph2653-mapped-lease-wait/source-build/libDodgeA830MappedLease.a'
    old_members = members(old_gpu, OUT / 'old-gpu-members')
    support = [p for p in old_members if p.name in {
        'NativeGOPPresenter.o', 'BootProgress.o', 'DodgeDiagnosticConsole.o',
        'DodgeGpuSwapBridge.o', 'original-completion-binding.o', 'DodgeSoftwareRefresh.o',
        'original-refresh-binding.o', 'DodgeSurfaceBacking.o', 'original-surface-bindings.o',
        'DodgeDisplayFrontend.o', 'original-frontend-bindings.o'}]
    require(len(support) == 11, 'Display support inventory changed')
    support_archive = OUT / 'libDodgeDisplaySupport.a'
    support_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', support_archive, *support], check=True)
    old_flag = '-Wl,-force_load,' + str(old_gpu)
    require(command.count(old_flag) == 1, 'Expected the complete old GPU archive once')
    command[command.index(old_flag):command.index(old_flag)+1] = [
        '-Wl,-force_load,' + str(native_archive), '-Wl,-force_load,' + str(support_archive)]
    # NativeAdrenoMemory changed layout. Recompile the page adapter against the
    # new header; its original bindings and all other surface owners stay fixed.
    old_pages = ROOT / 'build/cph2653-surface-pages/libDodgeSurfacePages.a'
    page_source = ROOT / 'drivers/DodgeGpu/DodgeSurfacePages.cpp'
    page_objects = build_objects([page_source], OUT / 'pages', [ROOT / 'build/cph2653-native-a830-runtime/source',
        ROOT / 'drivers/DodgeGpu', ROOT / 'profiles/os/ios-16.7.16-20H392/graphics'])
    old_page_members = members(old_pages, OUT / 'old-page-members')
    page_objects += [p for p in old_page_members if p.name != 'DodgeSurfacePages.o']
    require(len(page_objects) == len(old_page_members), 'Page-adapter archive shape changed')
    pages_archive = OUT / 'libDodgeNativeSurfacePages.a';pages_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', pages_archive, *page_objects], check=True)
    command[command.index('-Wl,-force_load,' + str(old_pages))] = '-Wl,-force_load,' + str(pages_archive)
    from build_native_a830 import apply_overlay
    backing_pin = json.loads((ROOT / 'upstream.lock.json').read_text())['native_a830_backing_overlay']
    backing_stage = OUT / 'backing-source'
    staged_backing = backing_stage / backing_pin['target']
    staged_backing.parent.mkdir(parents=True, exist_ok=True)
    staged_backing.write_bytes((ROOT / backing_pin['target']).read_bytes())
    backing_patch = apply_overlay(backing_stage, backing_pin)
    backing_objects = build_objects([staged_backing], OUT / 'backing', [ROOT / 'drivers/DodgeGpu',
        ROOT / 'profiles/os/ios-16.7.16-20H392/graphics', ROOT / 'build/cph2653-native-a830-runtime/source'])
    old_backing = ROOT / 'build/cph2653-surface-acquire/libDodgeSurfaceBacking.a'
    backing_objects += [p for p in members(old_backing, OUT / 'old-backing-members') if p.name != 'DodgeSurfaceBacking.o']
    backing_archive = OUT / 'libDodgeNativeSurfaceBacking.a';backing_archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', backing_archive, *backing_objects], check=True)
    command[command.index('-Wl,-force_load,' + str(old_backing))] = '-Wl,-force_load,' + str(backing_archive)
    # Keep absent diagnostic weak imports at zero, but do not override native
    # A830's real weak fallback definitions (notably boot_log_export_put).
    gpu_objects = members(native_archive, OUT / 'native-gpu-members')
    imports = archive_imports([*gpu_objects, *support])
    absent = set(imports['optional_weak_imports'])
    definitions = set()
    for index, flag in enumerate(a for a in command if a.startswith('-Wl,-force_load,')):
        archive = Path(flag.split(',', 2)[2])
        for obj in members(archive, OUT / 'all-members' / str(index)):
            definitions.update(s['name'] for s in symbols(obj.read_bytes()) if not s['kind'] & 0xe0 and s['kind'] & 14)
    absent -= definitions
    require(absent <= ABSENT.keys(), 'Unreviewed optional native A830 import: ' + repr(absent - ABSENT.keys()))
    weak = assemble(OUT, 'absent-observers', ''.join('.globl ' + n + '\n.set ' + n + ',0\n' for n in sorted(absent)))
    command[command.index(str(ROOT / 'build/cph2653-ufs-root/absent-ufs-observers.o'))] = str(weak)
    candidate = OUT / 'mach.native-a830-iphone';command[-1] = str(candidate)
    print('LINK: native A830, iPhone graphics, UFS, input, APFS and original crypto owner', flush=True)
    run(command, OUT / 'link.log', OBJDIR)
    data = candidate.read_bytes();table = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    entry_names = [*base['combined_native_entries'], '_dodge_native_a830_start', '_adreno830_start',
        '_dodge_adreno_wait_map', '_native_adreno_retire_completed', '_native_adreno_recovery_begin', '_native_adreno_recovery_end',
        '_dodge_native_surface_prepare', '_dodge_native_surface_published', '_dodge_native_surface_completed',
        '_dodge_native_surface_changed', '_dodge_native_surface_drain', '_dodge_native_surface_healthy']
    entries = {n: hex(table[n]['value']) for n in entry_names}
    link = OUT / 'link-command.json';link.write_text(json.dumps(command, indent=2) + '\n')
    artifacts = [candidate, link, weak, support_archive, pages_archive, *page_objects, *backing_objects, staged_backing]
    artifacts += [ROOT / a.split(',',2)[2] for a in command if a.startswith('-Wl,-force_load,')]
    report = {'result': 'NATIVE_A830_COMPLETE_IPHONE_SOURCE_KERNEL_PASS',
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'link_command': str(link.relative_to(ROOT)),
        'combined_source_objects': base['combined_source_objects'] - len(old_members) + len(gpu_objects) + len(support),
        'combined_original_bindings': base['combined_original_bindings'], 'combined_native_entries': entries,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (Path(__file__), page_source,
            ROOT / 'scripts/native_driver_build.py', ROOT / 'drivers/DodgeGpu/DodgeSurfacePages.h', backing_patch,
            ROOT / backing_pin['target'], ROOT / 'scripts/build_native_a830.py')},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (BASE_REPORT, gpu_report, host_report)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data), 'actual_init_hook': init_hook_readback(data),
        'native_gpu_objects': len(gpu_objects), 'preserved_display_objects': len(support),
        'firmware_pins': gpu['target_firmware']['files'],
        'firmware_readback': check_firmware(data, gpu['target_firmware']['files']),
        'page_adapter_recompiled_for_native_memory': True, 'native_board_entry_connected': True,
        'surface_ID_import_connected': True, 'original_surface_producer_connected': True,
        'backing_mutations_notify_native_GPU': True, 'backing_overlay': backing_pin,
        'original_components_embedded': False, 'default_kernel_selected': False, 'hardware_tested': False,
        'scope': 'Complete isolated source kernel with the native A830 runtime and all prior display/storage/input/startup components. '
                 'The graphics coordinator calls the native board entry after original-family preparation. '
                 'Surface-ID import, retained page association, original producer grants and deferred fence/reset completion are wired. '
                 'Original backing hooks invalidate active batches before mutation. Hardware execution remains untested.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {report["combined_source_objects"]} source/binding objects; strict link and original aliases')


if __name__ == '__main__':main()
