#!/usr/bin/env python3
"""Build the isolated current-task IOSurface identity bridge and full source kernel."""
import argparse
import json
from pathlib import Path
import subprocess

from build_mapped_lease_source import REPORT as BASE_REPORT, check_report as check_base
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from check_gpu_link import run
from check_surface_identity_host import run as host_tests
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, require, symbols, macho
from prepare_initial_data import sha
from prepare_surface_identity import checked, HEADER, FIXTURE

OUT = ROOT / 'build/cph2653-surface-identity'
REPORT = ROOT / 'reports/ios16-surface-identity-source.json'
RESULT = 'IOS16_TASK_AWARE_SURFACE_IDENTITY_SOURCE_KERNEL_PASS'


def check_report(report):
    contract, pin = checked()
    require(report['result'] == RESULT and report['contract'] == contract and report['identity_pin'] == pin and
            report['combined_source_objects'] == 92 and len(report['combined_original_bindings']) == 342 and
            len(report['combined_native_entries']) == 99 and report['host_cases'] == 13 and
            len(report['source_controls']) == 3, 'Incomplete task-aware surface identity source evidence')
    for name, digest in {**report['source_sha256'], **report['artifacts'], **report['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == digest, 'Identity source evidence changed: ' + name)
    require(not any(report[k] for k in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                'iosurface_producer_connected', 'GPU_import_backing_associated', 'default_kernel_selected')),
            'Identity source report exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only or REPORT.exists():
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved task-aware identity source / 92 objects / 342 aliases'); return
    base = json.loads(BASE_REPORT.read_text()); check_base(base); contract, pin = checked()
    OUT.mkdir(parents=True, exist_ok=True); host = host_tests(OUT / 'host')
    source = ROOT / 'drivers/DodgeGpu/DodgeSurfaceIdentity.cpp'
    obj, = build_objects([source], OUT / 'native', [HEADER.parent]); inspect_object(obj.read_bytes())
    bindings = {name: int(value, 16) - 0x1000000 for name, value in contract['bindings'].items()}
    assembly = OUT / 'surface-identity-bindings.S'
    assembly.write_text(''.join('.globl ' + n + '\n.set ' + n + ', ' + hex(a) + '\n' for n, a in sorted(bindings.items())))
    binding = OUT / 'surface-identity-bindings.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0', '-c', assembly, '-o', binding], check=True)
    require({s['name']: s['value'] for s in symbols(binding.read_bytes()) if s['kind'] == 3} == bindings,
            'Compiled original identity binding differs')
    archive = OUT / 'libDodgeSurfaceIdentity.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, obj, binding], check=True)
    for member in (obj, binding):
        require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, member.name]) == member.read_bytes(), 'Identity archive readback differs')
    command = json.loads((ROOT / base['link_command']).read_text()); require(command[-2] == '-o', 'Frozen link command shape changed')
    command[-2:-2] = ['-Wl,-force_load,' + str(archive)]
    candidate = OUT / 'mach.surface-identity'; command[-1] = str(candidate)
    print('LINK: original 90 source/binding objects plus identity implementation and binding / Darwin 22', flush=True)
    run(command, OUT / 'link.log', OBJDIR)
    raw = candidate.read_bytes(); table = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in table.values()), 'Identity kernel contains unresolved imports')
    aliases = {**base['combined_original_bindings'], **{n: hex(a) for n, a in bindings.items()}}
    for name, value in aliases.items():
        require(table[name]['kind'] == 3 and table[name]['value'] == int(value, 16), 'Identity kernel alias differs: ' + name)
    entries = {}
    for name in (*base['combined_native_entries'], '_dodge_copy_current_surface', '_dodge_release_surface_identity'):
        require(table[name]['kind'] & 14 == 14, 'Identity source entry absent: ' + name); entries[name] = hex(table[name]['value'])
    link = OUT / 'link-command.json'; link.write_text(json.dumps(command, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/check_surface_identity_host.py', ROOT / 'scripts/prepare_surface_identity.py',
             ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/check_gpu_link.py', source,
             source.with_suffix('.h'), HEADER, FIXTURE, ROOT / 'tests/DodgeSurfaceIdentityTest.cpp']
    files += [p for p in (ROOT / 'tests/surface_identity_include').rglob('*') if p.is_file()]
    artifacts = [obj, binding, archive, OUT / 'native/compile-commands.json', candidate, link, *host['artifacts']]
    report = {'result': RESULT, 'contract': contract, 'identity_pin': pin,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'dependency_report_sha256': {str(BASE_REPORT.relative_to(ROOT)): sha(BASE_REPORT)},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'link_command': str(link.relative_to(ROOT)),
        'combined_source_objects': 92, 'combined_original_bindings': aliases, 'combined_native_entries': entries,
        'actual_crypto_hooks': hook_readbacks(raw), 'actual_iobsd_hook': hook_readback(raw), 'actual_init_hook': init_hook_readback(raw),
        'host_cases': host['cases'], 'source_controls': host['source_controls'], 'sanitizers': host['sanitizers'],
        'previous_source_and_GPU_archive_objects_preserved': True, 'callable_current_task_resolver_linked': True,
        'lookup_retains_surface_through_original_custom_counter': True,
        'GPU_import_backing_associated': False, 'iosurface_producer_connected': False,
        'default_kernel_selected': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The real source helper resolves IOCoreSurfaceRoot without waiting and passes current_task plus a uint32 surface ID '
            'to the pinned original task-aware lookup. Kernel workers are refused. The original implementation authorizes access '
            'and try-retains the result under its locks. Every source refusal discharges owned references via virtual release. '
            'The original 90 objects and complete mapped-resource/fresh-health backend archive remain inputs to a separate 92-object '
            'kernel with 342 aliases and 99 designated entries. Host IOKit/matching/task primitives are peers. This kernel-callable '
            'helper is not yet wired to GPU import/submit, does not freeze or associate backing pages and registers no producer.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: identity source / 13 sanitizer cases / three source controls / complete 92-object kernel')


if __name__ == '__main__': main()
