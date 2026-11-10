#!/usr/bin/env python3
"""Build lifecycle-observed backing acquisition and an isolated full source kernel."""
import argparse
import json
from pathlib import Path
import subprocess

from build_surface_pages import REPORT as BASE_REPORT, check_report as check_base
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from check_gpu_link import run
from check_surface_acquire_host import run as host_tests
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, require, symbols, macho
from prepare_initial_data import sha
from prepare_surface_backing import checked, HEADER, FIXTURE

OUT = ROOT / 'build/cph2653-surface-acquire'
REPORT = ROOT / 'reports/ios16-surface-acquire-source.json'
RESULT = 'IOS16_SURFACE_OBSERVED_BACKING_ACQUISITION_SOURCE_KERNEL_PASS'


def check_report(report):
    contract, pin = checked()
    require(report['result'] == RESULT and report['contract'] == contract and report['backing_pin'] == pin and
            report['combined_source_objects'] == 97 and len(report['combined_original_bindings']) == 347 and
            len(report['combined_native_entries']) == 112 and report['host_cases'] == 25 and
            len(report['source_controls']) == 6, 'Incomplete observed surface backing source evidence')
    for name, digest in {**report['source_sha256'], **report['artifacts'], **report['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == digest, 'Backing acquisition source evidence changed: ' + name)
    require(not any(report[k] for k in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                'iosurface_producer_connected', 'GPU_import_backing_associated', 'default_kernel_selected')),
            'Backing acquisition source report exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only or REPORT.exists():
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved backing acquisition source / 97 objects / 347 aliases'); return
    base = json.loads(BASE_REPORT.read_text()); check_base(base); contract, pin = checked()
    OUT.mkdir(parents=True, exist_ok=True); host = host_tests(OUT / 'host')
    source = ROOT / 'drivers/DodgeGpu/DodgeSurfaceBacking.cpp'
    obj, = build_objects([source], OUT / 'native', [HEADER.parent, source.parent, ROOT / 'build/cph2653-mapped-lease-wait/source']); inspect_object(obj.read_bytes())
    bindings = {hook['resume_alias']: int(hook['entry'],16)-0x1000000+4 for hook in contract['hooks'].values()}
    assembly = OUT / 'surface-backing-bindings.S'
    assembly.write_text(''.join('.globl '+n+'\n.set '+n+', '+hex(v)+'\n' for n,v in sorted(bindings.items())))
    binding = OUT / 'surface-backing-bindings.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0', '-c', assembly, '-o', binding], check=True)
    require({s['name']: s['value'] for s in symbols(binding.read_bytes()) if s['kind'] == 3} == bindings,
            'Compiled original lifecycle resume binding differs')
    trampoline_asm=OUT/'surface-backing-trampolines.S';trampolines=OUT/'surface-backing-trampolines.o'
    trampoline_asm.write_text(''.join('.p2align 2\n.globl '+h['trampoline']+'\n'+h['trampoline']+':\n.word '+h['displaced_word']+'\nb '+h['resume_alias']+'\n' for h in contract['hooks'].values()))
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',trampoline_asm,'-o',trampolines],check=True)
    archive = OUT / 'libDodgeSurfaceBacking.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, obj, binding,trampolines], check=True)
    for member in (obj, binding,trampolines):
        require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, member.name]) == member.read_bytes(), 'Backing acquisition archive readback differs')
    command = json.loads((ROOT / base['link_command']).read_text()); require(command[-2] == '-o', 'Frozen link command shape changed')
    command[-2:-2] = ['-Wl,-force_load,' + str(archive)]
    candidate = OUT / 'mach.surface-acquire'; command[-1] = str(candidate)
    print('LINK: original 94 source/binding objects plus backing observer implementation and trampoline/binding / Darwin 22', flush=True)
    run(command, OUT / 'link.log', OBJDIR)
    raw = candidate.read_bytes(); table = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in table.values()), 'Backing acquisition kernel contains unresolved imports')
    aliases = {**base['combined_original_bindings'], **{n: hex(a) for n, a in bindings.items()}}
    for name, value in aliases.items():
        require(table[name]['kind'] == 3 and table[name]['value'] == int(value, 16), 'Backing acquisition kernel alias differs: ' + name)
    entries = {}
    for name in (*base['combined_native_entries'], '_dodge_copy_surface_backing', '_dodge_surface_pages_acquire', *(h['wrapper'] for h in contract['hooks'].values()), *(h['trampoline'] for h in contract['hooks'].values())):
        require(table[name]['kind'] & 14 == 14, 'Backing acquisition source entry absent: ' + name); entries[name] = hex(table[name]['value'])
    link = OUT / 'link-command.json'; link.write_text(json.dumps(command, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/check_surface_acquire_host.py', ROOT / 'scripts/prepare_surface_backing.py',
             ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/check_gpu_link.py', source,
             source.with_suffix('.h'), source.parent / 'DodgeSurfaceIdentity.h',source.parent / 'DodgeSurfacePages.h',
             ROOT / 'build/cph2653-mapped-lease-wait/source/NativeAdrenoMemory.h',
             HEADER.parent / 'OriginalIOSurfaceABI.h', HEADER, FIXTURE, ROOT / 'tests/DodgeSurfaceAcquireTest.cpp']
    files += [p for p in (ROOT / 'tests/surface_acquire_include').rglob('*') if p.is_file()]
    artifacts = [obj,binding,trampolines,assembly,trampoline_asm,archive, OUT / 'native/compile-commands.json', candidate, link, *host['artifacts']]
    report = {'result': RESULT, 'contract': contract, 'backing_pin': pin,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'dependency_report_sha256': {str(BASE_REPORT.relative_to(ROOT)): sha(BASE_REPORT)},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'link_command': str(link.relative_to(ROOT)),
        'combined_source_objects': 97, 'combined_original_bindings': aliases, 'combined_native_entries': entries,
        'actual_crypto_hooks': hook_readbacks(raw), 'actual_iobsd_hook': hook_readback(raw), 'actual_init_hook': init_hook_readback(raw),
        'host_cases': host['cases'], 'source_controls': host['source_controls'], 'sanitizers': host['sanitizers'],
        'previous_source_and_GPU_archive_objects_preserved': True, 'callable_kernel_page_association_linked': True,
        'identity_release_uses_original_custom_counter': True,
        'kernel_import_page_association_implemented': True, 'observer_reference_acquisition_implemented': True, 'all_four_original_hooks_installed_in_source_image': False,
        'GPU_import_backing_associated': False, 'GPU_user_client_association_connected': False, 'iosurface_producer_connected': False,
        'default_kernel_selected': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The kernel-only adapter resolves the current task and obtains an owned descriptor from a bounded lifecycle observer, then invokes the retained exact-page association. Original init before publication, caller-owned replacement inputs, clear and final free are observed through four entry wrappers and displaced-instruction trampolines. No borrowed getter value is retained by acquisition. OOM, exhaustion and stale/missing observations refuse acquisition. Host cases execute actual observer/page-adapter source with explicit original lifecycle, IOKit, task and reference peers. This source image contains the wrappers but does not install the original entry hooks until the separate strict prelink stage. No user ABI, producer grant, backing immutability, cache/reset or iOS runtime qualification is supplied.'}


    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: observed backing source / 25 sanitizer cases / six source controls / complete 97-object kernel')


if __name__ == '__main__': main()
