#!/usr/bin/env python3
"""Compile the bounded original-iPhone request helper and compare exact original-program captures."""
import json
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, build_objects, inspect_object, require, symbols
from prepare_initial_data import sha
from check_apfs_mount_host import check as check_host, sanitizer_environment

OUT = ROOT / 'build/ios16-apfs-mount-source'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'drivers/DodgeStorage/DodgeApfsMountArgs.cpp'
    header = ROOT / 'drivers/DodgeStorage/DodgeApfsMountArgs.h'
    abi = ROOT / 'profiles/os/ios-16.7.16-20H392/storage/OriginalApfsMountABI.h'
    test = ROOT / 'tests/DodgeApfsMountArgsTest.cpp'
    include = [source.parent, abi.parent]
    host = check_host(OUT)
    binary = ROOT / host['binary']
    environment = sanitizer_environment()
    require(host['result'] == 'PASS' and host['case_count'] == 16, 'Request sanitizer cases differ')
    program_path = ROOT / 'reports/ios16-apfs-mount-program.json'
    program = json.loads(program_path.read_text())
    require(program['builder_sha256'] == sha(ROOT / 'scripts/check_apfs_mount_program.py'), 'Original-program CPU evidence is stale')
    fixture_path, = [ROOT / name for name in program['artifacts'] if Path(name).name == 'captures.json']
    require(sha(fixture_path) == program['artifacts'][str(fixture_path.relative_to(ROOT))], 'Original-program capture changed')
    captures = json.loads(fixture_path.read_text())
    comparisons = []
    for row in captures:
        if row['outcome'] != 'mount-boundary' or not row['user_device_pointer'] or row['flags'] & ~0x200001:
            continue
        result = subprocess.run([binary, '--capture', str(row['user_device_pointer']), str(row['flags']), str(row['uid']), str(row['gid'])],
                                capture_output=True, text=True, check=True, env=environment)
        require(not result.stderr and result.stdout.strip() == row['payload_hex'], 'Source request differs from exact original: ' + row['case'])
        comparisons.append({'case': row['case'], 'result': 'PASS', 'all_336_bytes_match_original': True})
    require(len(comparisons) == 12, 'Original ordinary-request comparison count differs')
    probe = OUT / 'ApfsMountLayout.cpp'
    labels = [('user_bytes', 'sizeof(DodgeOriginalApfsMountArgs)'), ('fspec', 'offsetof(DodgeOriginalApfsMountArgs,fspec)'),
              ('flags', 'offsetof(DodgeOriginalApfsMountArgs,flags)'), ('mode', 'offsetof(DodgeOriginalApfsMountArgs,mode)'),
              ('uid', 'offsetof(DodgeOriginalApfsMountArgs,ownerUID)'), ('gid', 'offsetof(DodgeOriginalApfsMountArgs,ownerGID)'),
              ('tail', 'offsetof(DodgeOriginalApfsMountArgs,tailPadding)'), ('readonly', 'MNT_RDONLY'),
              ('unknown_owners', 'MNT_UNKNOWNPERMISSIONS'), ('update', 'MNT_UPDATE'), ('vfs_entry_name', 'offsetof(vfs_fsentry,vfe_fsname)'),
              ('vfs_mount_slot', 'offsetof(vfsops,vfs_mount)')]
    probe.write_text('#include <sys/mount.h>\n#include "OriginalApfsMountABI.h"\nextern "C" const unsigned dodge_apfs_mount_layout[]={' +
                     ','.join('unsigned(' + value + ')' for _, value in labels) + '};\n')
    obj, layout_obj = build_objects([source, probe], OUT, include)
    data = layout_obj.read_bytes(); image = inspect_object(data)
    symbol, = [s for s in symbols(data) if not s['kind'] & 0xe0 and s['name'] == '_dodge_apfs_mount_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(labels)) + 'I', data, section['fileoff'] + symbol['value'] - section['va'])
    layout = dict(zip((name for name, _ in labels), values))
    require(list(values) == [336, 0, 8, 16, 324, 328, 332, 1, 0x200000, 0x10000, 28, 0], 'Actual iPhone source compiler ABI/constants differ')
    archive = OUT / 'libDodgeApfsMountArgs.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, obj], check=True)
    evidence = OUT / 'host-cases.json'
    evidence.write_text(json.dumps({'host': host, 'original_comparisons': comparisons}, indent=2) + '\n')
    sources = [Path(__file__), ROOT / 'scripts/check_apfs_mount_host.py', source, header, abi, test]
    report = {'result': 'IOS16_ORIGINAL_APFS_ORDINARY_REQUEST_SOURCE_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'dependency_report_sha256': {str(program_path.relative_to(ROOT)): sha(program_path)},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, layout_obj, archive, binary, evidence, OUT / 'compile-commands.json')},
              'native_object': str(obj.relative_to(ROOT)), 'native_archive': str(archive.relative_to(ROOT)), 'compiler_layout': layout,
              'sanitizer_case_count': 16, 'original_request_comparison_count': 12, 'original_comparisons': comparisons,
              'rejects_preserve_output_and_valid_output_redzones': True, 'mount_called': False,
              'full_apfs_mount_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False, 'negative_controls': [],
              'scope': 'The actual request helper passes ASan/UBSan, matches all 336 bytes in twelve independently captured original-program requests '
                       'and compiles with actual iPhone kernel layouts/constants. Unsupported/remount flags and unresolved owners are rejected without writes. '
                       'It serializes a caller-validated user pointer; no user VM, mount, device registry or APFS runtime is provided by this helper.'}
    (ROOT / 'reports/ios16-apfs-mount-source.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 16 request sanitizer cases / 12 exact original-request comparisons / native iPhone ABI compilation')


if __name__ == '__main__':
    main()
