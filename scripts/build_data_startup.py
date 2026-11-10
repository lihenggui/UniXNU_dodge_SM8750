#!/usr/bin/env python3
"""Link a separate queue-only Data startup route without changing the 83-object candidate."""
import difflib
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from check_gpu_link import run
from check_data_late_host import check as check_host
from build_data_source import check_table, concrete_methods
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, require, symbols, macho
from native_prelink import backed_offset
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-data-startup'
PATCH = ROOT / 'patches/oneplus13/0009-ios16-queue-data.patch'


def hook_readback(data):
    image = macho(data)
    names = {s['name']: s['value'] for s in symbols(data) if not s['kind'] & 0xe0}
    address = names['_IOKitBSDInit']
    offset = backed_offset(image['segments'], address, 80, len(data))
    code = data[offset:offset + 80]
    calls = {}
    for i, word in enumerate(struct.unpack('<20I', code)):
        if word & 0xfc000000 == 0x94000000:
            immediate = word & 0x3ffffff
            target = address + i * 4 + 4 * (immediate - (1 << 26) if immediate & (1 << 25) else immediate)
            calls[target] = address + i * 4
    wanted = [names[name] for name in ('__ZN9IOService15publishResourceEPKcP8OSObject', '_dodge_system_schedule', '_dodge_data_schedule', '_dodge_input_schedule')]
    require(all(target in calls for target in wanted) and [calls[target] for target in wanted] == sorted(calls[target] for target in wanted),
            'Data startup publication/system/Data/input queue order changed')
    return {'address': hex(address), 'bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(),
            'queue_call_order': [hex(calls[target]) for target in wanted],
            'call_targets': ['IOBSD publication', 'system scheduler', 'Data scheduler', 'input scheduler']}


def main():
    source_path = ROOT / 'reports/ios16-data-source.json'
    base = json.loads(source_path.read_text())
    require(base['builder_sha256'] == sha(ROOT / 'scripts/build_data_source.py') and base['combined_source_objects'] == 83, 'Data source stage is stale')
    for name, value in {**base['source_sha256'], **base['artifacts'], **base['dependency_report_sha256']}.items():
        require(sha(ROOT / name) == value, 'Data startup base input changed: ' + name)
    source_input = json.loads((ROOT / 'reports/ios16-input-native.json').read_text())
    old_source = ROOT / source_input['native_object_overlay']['source']
    before = old_source.read_text()
    after = before.replace('extern "C" IOReturn dodge_input_schedule(void);',
                           'extern "C" IOReturn dodge_input_schedule(void);\nextern "C" IOReturn dodge_data_schedule(void);')
    after = after.replace('\t(void)dodge_system_schedule();', '\t(void)dodge_system_schedule();\n\t(void)dodge_data_schedule();')
    require(after != before and after.count('(void)dodge_data_schedule();') == 1, 'Data startup source hook anchor changed')
    expected = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='a/IOKitBSDInit.cpp', tofile='b/IOKitBSDInit.cpp'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    overlay = lock['dodge_data_startup_hook_overlay']
    require(PATCH.read_text() == expected and sha(PATCH) == overlay['sha256'] and sha(old_source) == overlay['base_source_sha256'],
            'Reviewed Data startup source overlay changed')
    OUT.mkdir(exist_ok=True)
    host = check_host(OUT)
    obj, = build_objects([ROOT / 'drivers/DodgeStorage/DodgeDataLate.cpp'], OUT,
                        [ROOT / 'drivers/DodgeStorage', ROOT / 'drivers/DodgeDisplay'])
    require(not any(s['size'] for seg in inspect_object(obj.read_bytes())['segments'] for s in seg['sections'] if s['name'] == '__mod_init_func'),
            'Data scheduler has an early constructor')
    archive = OUT / 'libDodgeDataLate.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, obj], check=True)
    bsd = OUT / 'IOKitBSDInit.cpp'; bsd.write_text(after)
    require(sha(bsd) == overlay['output_source_sha256'], 'Data BSD overlay output differs')
    recipe = json.loads((OBJDIR / 'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json').read_text().strip().rstrip(','))
    args, i = [], 0
    while i < len(recipe['arguments']):
        value = recipe['arguments'][i]
        if value == recipe['file']: args.append(str(bsd))
        elif value in ('-o', '-MF', '-MJ'): i += 1
        elif value not in ('-MD', '-MP'): args.append(value)
        i += 1
    bsd_object = OUT / 'IOKitBSDInit.data.cpo'
    args += ['-o', str(bsd_object)]
    run(args, OUT / 'bsd-compile.log', recipe['directory'])
    base_link_command, = [name for name in base['artifacts'] if Path(name).name == 'link-command.json']
    command = json.loads((ROOT / base_link_command).read_text())[:-2]
    filelist_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    old_filelist = Path(filelist_arg.removeprefix('-Wl,-filelist,'))
    rows = old_filelist.read_text().splitlines()
    old_bsd_object = str(ROOT / source_input['native_object_overlay']['object'])
    require(rows.count(old_bsd_object) == 1, 'Data startup base BSD object is ambiguous')
    filelist = OUT / 'combined-native.filelist'
    filelist.write_text(''.join((str(bsd_object) if row == old_bsd_object else row) + '\n' for row in rows))
    command[command.index(filelist_arg)] = '-Wl,-filelist,' + str(filelist)
    candidate = OUT / 'mach.data-startup'
    command += ['-Wl,-force_load,' + str(archive), '-o', str(candidate)]
    run(command, OUT / 'link.log', OBJDIR)
    data = candidate.read_bytes()
    names = {s['name']: s for s in symbols(data) if not s['kind'] & 0xe0}
    require(macho(data)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Data startup candidate has undefined symbols')
    for name, value in base['combined_original_bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Data startup original binding changed: ' + name)
    methods = concrete_methods(ROOT / base['late_object'])
    require(check_table(data, methods) == 352, 'Data startup source instance changed')
    hook = hook_readback(data)
    image = macho(data)
    offset = backed_offset(image['segments'], int(hook['queue_call_order'][2], 16), 4, len(data))
    broken = bytearray(data); struct.pack_into('<I', broken, offset, 0xd503201f)
    try:
        hook_readback(broken)
    except ValueError as error:
        control = {'case': 'BSD-Data-schedule-call-NOP', 'result': 'REJECTED', 'reason': str(error)}
    else:
        raise ValueError('Removing the Data queue call was accepted')
    link_command = OUT / 'link-command.json'; link_command.write_text(json.dumps(command, indent=2) + '\n')
    source_files = [Path(__file__), ROOT / 'scripts/check_data_late_host.py', ROOT / 'scripts/build_data_source.py',
                    ROOT / 'drivers/DodgeStorage/DodgeDataLate.cpp', ROOT / 'drivers/DodgeStorage/DodgeDataLate.h',
                    ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.h', ROOT / 'drivers/DodgeStorage/DodgeSystemLate.h',
                    ROOT / 'drivers/DodgeDisplay/DodgeGraphicsLate.h', ROOT / 'tests/DodgeDataLateTest.cpp', old_source, PATCH,
                    *[p for folder in ('ufs_lifecycle_include', 'graphics_late_include') for p in (ROOT / 'tests' / folder).rglob('*.h')]]
    artifacts = [obj, archive, bsd, bsd_object, filelist, candidate, OUT / 'compile-commands.json', link_command, ROOT / host['binary']]
    report = {'result': 'IOS16_SEPARATE_DATA_STARTUP_SOURCE_AND_STRICT_LINK_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in source_files},
              'dependency_report_sha256': {str(source_path.relative_to(ROOT)): sha(source_path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
              'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
              'link_command': str(link_command.relative_to(ROOT)), 'host_tests': host, 'overlay': overlay,
              'actual_iobsd_hook': hook, 'combined_source_objects': 84, 'combined_original_aliases': 332,
              'combined_original_bindings': base['combined_original_bindings'],
              'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'], '_dodge_data_schedule', '_dodge_data_late_status']},
              'negative_controls': [control], 'strict_no_undefined': True, 'queue_only_data_startup_wired': True,
              'source_data_default_enabled': False, 'ramblock_metadata_registered_or_started': False,
              'original_apfs_data_mount_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'scope': 'Separate 84-object candidate keeps the prior 83-object Data candidate unchanged. '
                       'Actual IOBSD publishes its resource then queues system, Data and input work; Data metadata/start occur only in a bounded separate thread after selected storage/graphics work. '
                       'Thirty scheduler sanitizer cases use explicit IOKit/thread/starter peers; Data is default-off and original APFS mount/runtime remain unqualified.'}
    (ROOT / 'reports/ios16-data-startup.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 84-object Data startup candidate / 30 scheduler sanitizer cases / actual IOBSD queue order and removed-call control')


if __name__ == '__main__':
    main()
