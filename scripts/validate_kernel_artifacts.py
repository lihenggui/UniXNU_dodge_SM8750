#!/usr/bin/env python3
"""Read back the source-only iPhone kernel, compile targets and loader contract."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge'
TREE = WORK / 'tree'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def definitions(record):
    args = record['arguments']
    return {args[i + 1] for i, value in enumerate(args[:-1]) if value == '-D'} | {
        value[2:] for value in args if value.startswith('-D') and len(value) > 2}


def main():
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    native = TREE / profile['kernel']['prelink']['kernel']
    candidate = WORK / 'kernel/kernel.macho'
    data = native.read_bytes()
    sys.path.insert(0, str(TREE / 'kits/XnuPrelink'))
    from native_prelink import backed_offset, exports, macho
    image = macho(data)
    if image['kind'] != 2:
        raise SystemExit('Expected a plain ARM64 MH_EXECUTE native kernel')
    symbols = {name: address for address, names in exports(data, image).items() for name in names}
    required = ['__start', '_source_corecrypto14_status', '_source_pthread_status',
                '_armcpu_registered', '_armdt_platform_configured',
                '_kalloc_sparse_prelink_index_version', '_native_prelink_security_init_version']
    if set(required) - symbols.keys():
        raise SystemExit('Missing actual linked entry points: ' + str(sorted(set(required) - symbols.keys())))
    for name in ('_kalloc_sparse_prelink_index_version', '_native_prelink_security_init_version'):
        at = backed_offset(image['segments'], symbols[name], 4, len(data))
        if struct.unpack_from('<I', data, at)[0] != 1:
            raise SystemExit('Unsupported native prelink ABI: ' + name)
    for segment in image['segments']:
        if segment['fileoff'] + segment['filesize'] > len(data):
            raise SystemExit('Native segment exceeds the file: ' + segment['name'])
        if segment['va'] % 4096:
            raise SystemExit('Native segment has no 4 KiB alignment: ' + segment['name'])
    threads = [(at, length) for command, at, length in image['commands'] if command == 5]
    if len(threads) != 1 or threads[0][1] != 288:
        raise SystemExit('Missing ARM64 Unix thread entry required by DarwinBoot')
    entry = struct.unpack_from('<Q', data, threads[0][0] + 272)[0]
    if entry != symbols['__start']:
        raise SystemExit('DarwinBoot entry differs from the actual linked __start symbol')
    seal = json.loads(native.with_suffix(native.suffix + '.crypto-hmac.json').read_text())
    if seal['kernel_sha256'] != hashlib.sha256(data).hexdigest():
        raise SystemExit('POST report belongs to another kernel')
    start, size = int(seal['code_file_offset'], 16), seal['code_bytes']
    at = int(seal['hmac_file_offset'], 16)
    calculated = hmac.digest(b'\0', data[start:start + size], 'sha256')
    if calculated.hex() != seal['hmac_sha256'] or data[at:at + 32] != calculated:
        raise SystemExit('Source crypto POST integrity field does not match the actual instructions')
    os.environ.update(UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION=profile['os']['ios_version'])
    sys.path.insert(0, str(TREE / 'scripts'))
    from kernel_target import check_object
    obj = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    cases = {
        'osfmk/DEVELOPMENT/prng_random.o': {'XNU_SOURCE_CORECRYPTO14=1', 'XNU_NATIVE_PAN=1'},
        'osfmk/DEVELOPMENT/start.o': {'XNU_NATIVE_ARCH_TIMER=1', 'XNU_NATIVE_PAN=1'},
        'iokit/DEVELOPMENT/IOPlatformExpert.cpo': {'XNU_NATIVE_PAN=1'},
        'bsd/DEVELOPMENT/vfs_conf.o': {'XNU_NATIVE_PAN=1'},
    }
    records = []
    for name, flags in cases.items():
        path = obj / name
        check_object(path.read_bytes(), name)
        record = path.with_suffix(path.suffix + '.json')
        if flags - definitions(json.loads(record.read_text().strip().rstrip(','))):
            raise SystemExit('Missing real native compile flags: ' + name)
        records.append({'object': name, 'required_definitions': sorted(flags), 'record_sha256': digest(record)})
    staged = json.loads(candidate.with_suffix('.json').read_text())
    native_candidate = staged.get('prelink_skipped', False)
    if native_candidate and candidate.read_bytes() != data:
        raise SystemExit('Native-only staging changed the source kernel bytes')
    parser = ROOT / 'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    host_env = dict(os.environ, PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    subprocess.run([sys.executable, str(parser), str(native), *([str(candidate)] if native_candidate else [])], env=host_env, check=True)
    archives = []
    for name in ('corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a',
                 'armcpu/libArmCpu.a', 'armdt-platform/libArmDTPlatform.a',
                 'mockfs-fixture/libmockfs_fixture.a', 'libpthread-kernel/libpthread_kernel.a'):
        path = TREE / 'build' / name
        archives.append({'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': digest(path)})
    report = {
        'result': 'PASS', 'architecture': 'arm64', 'deployment': 'iOS ' + profile['os']['ios_version'],
        'native': str(native.relative_to(ROOT)),
        'native_staging': 'byte-identical' if native_candidate else 'separate prelink candidate is outside this native-only check',
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'entry': hex(entry),
        'source_revision': profile['os']['xnu_revision'], 'compiled_records': records,
        'linked_entry_points': {name: hex(symbols[name]) for name in required},
        'archives': archives, 'darwinboot_production_parser': 'PASS',
        'source_crypto_post_field': 'HMAC matches final linked instructions; runtime POST not executed',
        'native_only': True, 'original_kexts_added': False, 'hardware_tested': False,
        'scope': 'Host compiler/linker, Mach-O, actual loader parser and source integrity field only; no iOS boot or original-kext ABI qualification.'}
    (ROOT / 'reports/native-kernel.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: native ARM64/iOS 16 kernel, actual feature flags, POST field and DarwinBoot parser')


if __name__ == '__main__':
    main()
