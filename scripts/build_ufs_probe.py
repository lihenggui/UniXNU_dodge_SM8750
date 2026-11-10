#!/usr/bin/env python3
"""Build an independent Darwin 22 UFS probe and exercise read-only host transports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree'
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import backed_offset, exports, macho


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--partition', required=True,
                        help='Explicit diagnostic lookup name; no physical partition or GPT is created')
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,35}', args.partition), 'Invalid diagnostic partition selector')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    for name in ('pagani_reference', 'sm8750'):
        spec = lock[name]
        source = ROOT / spec['path']
        actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        require(actual == spec['revision'], 'Unexpected UFS reference revision')
        require(not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True),
                'UFS references must be unmodified')
    source = ROOT / lock['pagani_reference']['path'] / 'drivers/NativeUfs'
    shared = ROOT / lock['sm8750']['path'] / 'kits'
    out = ROOT / 'build/cph2653-ufs-probe'
    out.mkdir(parents=True, exist_ok=True)
    recipe = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.loads(recipe.read_text().strip().rstrip(','))
    command, index, arguments = [], 0, record['arguments']
    while index < len(arguments):
        value = arguments[index]
        if value == record['file']:
            command.append(str(source / 'NativeUfs.cpp'))
        elif value in ('-o', '-MF', '-MJ'):
            index += 1
        elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
            index += 1
        elif value not in ('-MD', '-MP') and not value.startswith('-W'):
            command.append(value)
        index += 1
    command += ['-o', str(out / 'NativeUfs.o'), '-I', str(shared),
                '-DNATIVE_UFS_PROBE_ONLY=1', '-DNATIVE_UFS_SM8750=1', '-DNATIVE_UFS_READ_ONLY=1',
                f'-DUFS_ROOT_PARTITION="{args.partition}"', '-mgeneral-regs-only',
                '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                '-Wno-unnecessary-virtual-specifier', '-Wno-missing-designated-field-initializers',
                '-Wno-c99-designator', '-Wno-reorder-init-list',
                # Probe mode intentionally omits root publication and its callers.
                '-Wno-unused-function', '-Wno-unneeded-internal-declaration']
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (out / 'compile.log').open('w') as stream:
        process = subprocess.run(command, cwd=record['directory'], stdout=stream, stderr=subprocess.STDOUT)
    require(process.returncode == 0, 'UFS probe compile failed; see build/cph2653-ufs-probe/compile.log')
    data = (out / 'NativeUfs.o').read_bytes()
    image = macho(data)
    require(image['kind'] == 1, 'Expected an ARM64 relocatable source probe')
    version, = [at for command, at, _ in image['commands'] if command == 0x32]
    require(struct.unpack_from('<II', data, version + 8) == (2, 0x100000), 'Probe is not targeted at iOS 16.0')
    symcmd, = [at for command, at, _ in image['commands'] if command == 2]
    symoff, count, stroff, strsize = struct.unpack_from('<4I', data, symcmd + 8)
    require(symoff + count * 16 <= len(data) and stroff + strsize <= len(data), 'Invalid probe symbol table')
    undefined, names = [], []
    for index in range(count):
        strx, kind, _, _, _ = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        require(strx < strsize, 'Invalid probe string index')
        end = data.index(b'\0', stroff + strx, stroff + strsize)
        name = data[stroff + strx:end].decode()
        names.append(name)
        if kind & 1 and not kind & 0xee:
            undefined.append(name)
    native_path = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped'
    native = native_path.read_bytes()
    native_image = macho(native)
    provided = {name for names in exports(native, native_image).values() for name in names}
    internal = set(undefined) - provided
    # This is a source archive for the native link. XNU keeps its UBSAN helper
    # local in the final symbol table, so it is not a public kext import. Check
    # the real source-runtime function rather than exporting or replacing it.
    require(internal <= {'___ubsan_handle_add_overflow_minimal'},
            'Probe has unresolved native imports: ' + repr(sorted(internal)))
    runtime = []
    if internal:
        symcmd, = [at for command, at, _ in native_image['commands'] if command == 2]
        symoff, count, stroff, strsize = struct.unpack_from('<4I', native, symcmd + 8)
        for index in range(count):
            strx, kind, _, _, address = struct.unpack_from('<IBBHQ', native, symoff + index * 16)
            if kind & 0xe0 or kind & 0x0e != 0x0e:
                continue
            end = native.index(b'\0', stroff + strx, stroff + strsize)
            name = native[stroff + strx:end].decode()
            if name not in internal:
                continue
            require(any(s['initprot'] == 5 and s['va'] <= address < s['va'] + s['filesize']
                        for s in native_image['segments']), 'UBSAN runtime target is not executable')
            at = backed_offset(native_image['segments'], address, 8, len(native))
            trap, ret = struct.unpack_from('<II', native, at)
            require(trap & 0xffe0001f == 0xd4200000 and (trap >> 5) & 0xffff == 0x1206
                    and ret == 0xd65f03c0, 'Native signed-overflow runtime handler changed')
            runtime.append({'name': name, 'va': hex(address), 'trap': '0x1206',
                            'body_sha256': hashlib.sha256(native[at:at + 8]).hexdigest()})
        require(len(runtime) == len(internal), 'Missing or ambiguous native UBSAN runtime definition')
    require(any(name.startswith('__ZN9NativeUfs') for name in names), 'NativeUfs class was not compiled')
    require(not any('NativeUfsBlock' in name or 'IOBlockStorageDevice' in name for name in names),
            'Probe unexpectedly contains original-family root publication code')
    require(b'this image only probes storage; root publication is not built' in data,
            'Probe no longer refuses root mode')
    archive = out / 'libNativeUfsProbe.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', str(archive), str(out / 'NativeUfs.o')], check=True)
    tests = ('Sm8750', 'LunDiscovery', 'RootCommands', 'RootDiagnostics', 'RootLayout',
             'SmmuTakeover', 'RootWindowRead', 'TransferPoll')
    log = out / 'host-tests.log'
    with tempfile.TemporaryDirectory(prefix='ufs-host-', dir=ROOT / 'build') as directory, log.open('w') as stream:
        for name in tests:
            binary = Path(directory) / name
            command = ['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                       '-g', '-I' + str(shared), '-DNATIVE_UFS_SM8750=1',
                       f'-DUFS_ROOT_PARTITION="{args.partition}"', '-DNATIVE_UFS_READ_ONLY=1',
                       str(source / 'tests' / (name + '.cpp')), '-o', str(binary)]
            if name == 'RootLayout':
                command += ['-lcrypto']
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=60)
            subprocess.run([str(binary)], stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=30,
                           env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
            stream.write('PASS: ' + name + '\n')
            stream.flush()
    report = {'result': 'SOURCE_PROBE_AND_HOST_TESTS_PASS', 'target': 'arm64-apple-ios16.0',
              'source_revision': lock['pagani_reference']['revision'], 'soc_revision': lock['sm8750']['revision'],
              'source_sha256': hashlib.sha256((source / 'NativeUfs.cpp').read_bytes()).hexdigest(),
              'native_sha256': hashlib.sha256(native).hexdigest(),
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
              'object_sha256': hashlib.sha256(data).hexdigest(), 'probe_only': True, 'read_only': True,
              'diagnostic_partition_selector': args.partition, 'partition_created': False,
              'public_native_imports_matched_by_name': len(set(undefined) - internal),
              'link_time_source_runtime_dependencies': runtime, 'requires_native_static_link': True,
              'original_storage_family_imports': 0, 'root_publication_built': False,
              'host_suites_passed': list(tests), 'sanitizers': ['address', 'undefined'],
              'host_log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
              'selected_in_default_kernel': False, 'mmio_executed': False,
              'storage_family_abi_qualified': False, 'hardware_tested': False,
              'scope': 'Independent native-source probe archive and production read-only controller/queue/DMA/root-parser host tests. No hardware access, kernel activation, physical partition or iPhone root publication.'}
    (ROOT / 'reports/ufs-source-probe.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: iOS 16 ARM64 UFS probe, {len(undefined)} native imports and 8 read-only transport suites; no root publication or hardware IO')


if __name__ == '__main__':
    main()
