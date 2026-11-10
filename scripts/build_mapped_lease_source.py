#!/usr/bin/env python3
"""Build the complete iPhone kernel with mapped-resource submission leases."""
import argparse
import json
from pathlib import Path
import subprocess

from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_fresh_gpu_source import REPORT as BASE_REPORT, check_report as check_base
from check_gpu_link import run
from check_mapped_lease_host import REPORT as HOST_REPORT, check_report as check_host
from mapped_lease_overlay import IMPL, PATCH, WAIT, checked, stage
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, macho, require, symbols
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-mapped-lease-wait/source-build'
REPORT = ROOT / 'reports/ios16-mapped-lease-source.json'
RESULT = 'IOS16_MAPPED_RESOURCE_LEASE_SOURCE_LINK_PASS'


def check_report(report):
    require(report['result'] == RESULT and report['combined_source_objects'] == 90 and
            len(report['combined_native_entries']) == 97 and len(report['combined_original_bindings']) == 341 and
            len(report['recompiled_backend_objects']) == 19 and report['preserved_gpu_members'] == 35,
            'Incomplete mapped-resource native source candidate')
    require(checked()[2] == report['overlay_pin'], 'Mapping lease source pin changed')
    for name, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == value, 'Mapping lease source evidence changed: ' + name)
    require(not any(report[key] for key in ('hardware_tested', 'gpu_failure_quiescence_qualified',
        'iosurface_producer_connected', 'default_kernel_selected', 'ready_for_ios_boot', 'all_ios_port_code_complete')),
        'Mapping lease source report exceeds its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: mapped-resource source/link evidence'); return
    base = json.loads(BASE_REPORT.read_text()); check_base(base)
    host = json.loads(HOST_REPORT.read_text()); check_host(host)
    OUT.mkdir(parents=True, exist_ok=True); source, pin = stage(OUT.parent / 'source')
    names = ('A830HwInit', 'CpInit', 'Cpu', 'GmuContext', 'GmuMemory', 'GpuContext', 'Irq', 'Memory',
             'Publish', 'Pwrup', 'Preempt', 'Ring', 'Sha256', 'SmmuContext', 'SmmuMemory', 'Submit', 'Timer', 'UserClient', 'Vm')
    files = [source / ('NativeAdreno' + name + '.cpp') for name in names]
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    includes = [source, ROOT / lock['a830_firmware_reference']['path'], ROOT / lock['sm8750']['path'] / 'kits/Sm8750Platform',
                ROOT / 'sources/UniXNU/kits/ArmSmmu4K', ROOT / 'sources/UniXNU/kits/AdrenoPM4']
    print('COMPILE: 19 production A830 backend translation units / Darwin 22 / four jobs', flush=True)
    native = OUT / 'native'; objects = build_objects(files, native, includes)
    for obj in objects: inspect_object(obj.read_bytes())
    archives = [ROOT / name for name in base['artifacts'] if name.endswith('.a')]
    require(len(archives) == 1, 'Expected the one combined fresh-health GPU archive')
    old_archive, = archives
    members = subprocess.check_output(['/usr/bin/llvm-ar-14', 't', old_archive], text=True).splitlines()
    require(len(set(members)) == len(members) == 54, 'Frozen combined GPU archive inventory changed')
    replacements = {obj.name: obj for obj in objects}; require(set(replacements) <= set(members), 'Missing backend archive members')
    directory = OUT / 'members'; directory.mkdir(exist_ok=True); inputs = []
    for name in members:
        if name in replacements: inputs.append(replacements[name]); continue
        path = directory / name; path.write_bytes(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', old_archive, name])); inputs.append(path)
    archive = OUT / 'libDodgeA830MappedLease.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, *inputs], check=True)
    for path in inputs:
        require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, path.name]) == path.read_bytes(), 'Mapping lease archive readback differs')
    command = json.loads((ROOT / base['link_command']).read_text())
    old_flag = '-Wl,-force_load,' + str(old_archive)
    require(command.count(old_flag) == 1 and command[-2] == '-o', 'Frozen fresh-health link command shape changed')
    command[command.index(old_flag)] = '-Wl,-force_load,' + str(archive)
    candidate = OUT / 'mach.mapped-lease'; command[-1] = str(candidate)
    print('LINK: complete 90-object source candidate / same original iPhone aliases and fresh-health frontend', flush=True)
    run(command, OUT / 'link.log', OBJDIR)
    raw = candidate.read_bytes(); names = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Mapping lease source has undefined imports')
    for name, value in base['combined_original_bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Mapping lease original alias changed: ' + name)
    entries = {}
    for name in base['combined_native_entries']:
        require(names[name]['kind'] & 14 == 14, 'Mapping lease source entry missing: ' + name)
        entries[name] = hex(names[name]['value'])
    for part in ('holdMapped', 'retireMapped'):
        require(sum(part in name and symbol['kind'] & 14 == 14 for name, symbol in names.items()) >= 1,
                'New mapped-resource function absent: ' + part)
    link = OUT / 'link-command.json'; link.write_text(json.dumps(command, indent=2) + '\n')
    sources = [Path(__file__), ROOT / 'scripts/mapped_lease_overlay.py', IMPL, WAIT, PATCH, *files]
    sources += [p for p in source.glob('*.h')] + [ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/check_gpu_link.py']
    artifacts = [*objects, native / 'compile-commands.json', archive, candidate, link]
    report = {'result': RESULT, 'overlay_pin': pin, 'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (BASE_REPORT, HOST_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'link_command': str(link.relative_to(ROOT)),
        'combined_source_objects': 90, 'combined_original_bindings': base['combined_original_bindings'], 'combined_native_entries': entries,
        'actual_crypto_hooks': hook_readbacks(raw), 'actual_iobsd_hook': hook_readback(raw), 'actual_init_hook': init_hook_readback(raw),
        'recompiled_backend_objects': {obj.name: sha(obj) for obj in objects}, 'preserved_gpu_members': 35,
        'regression_cases': host['regression_cases'], 'existing_host_suites': host['existing_suites'],
        'bounded_map_wait_cases': 12, 'publisher_retries_pending_map_outside_lock': True,
        'all_current_vm_mappings_held_per_job': True, 'new_mapping_waits_for_all_vm_jobs': True,
        'cache_acquisition_precedes_all_lease_releases': True, 'uncertain_zero_fence_not_recovered_as_completed': True,
        'IB_resource_disjointness_inference_disabled': True, 'fresh_gpu_frontend_preserved': True,
        'iosurface_producer_connected': False, 'producer_cache_visibility_qualified': False, 'gpu_failure_quiescence_qualified': False,
        'default_kernel_selected': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Nineteen production backend objects are recompiled consistently against the isolated mapping-lease overlay; '
            'the other 35 combined GPU members are preserved byte-for-byte, including the fresh-health display frontend. '
            'The complete 90-object source kernel keeps 341 original aliases, 97 entry names and crypto/IOBSD/init hooks. '
            'Every current VM mapping is held per submit because IBs provide no resource-use list. Completion acquires the '
            'captured writable set before releasing any lease, and uncertain publication/cache/reset failures keep resources. '
            'IOSurface identity authorization/producer registration, physical cache exclusion/reset and iOS boot remain incomplete.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: complete mapped-resource source kernel / 90 objects / 341 aliases / 97 entries')


if __name__ == '__main__': main()
