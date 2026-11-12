#!/usr/bin/env python3
"""Prepare local owner-signed immutable root inputs for the iPhone QEMU build."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True

from native_driver_build import ROOT, build_objects, macho, pinned_sources, require, sha, symbols
from native_prelink import backed_offset
from prepare_ios16_pmgr import original

OUT = ROOT / 'build/qemu-owner-root-policy'
REPORT = ROOT / 'reports/ios16-qemu-root-policy.json'


def file_sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream, 'sha256').hexdigest()


def rsa_contract(out):
    source = out / 'RsaLayout.c'
    source.write_text('#include <libkern/crypto/register_crypto.h>\n#include <libkern/crypto/rsa.h>\n'
        'const unsigned root_policy_layout[]={sizeof(rsa_pub_ctx),_Alignof(rsa_pub_ctx),'
        '__builtin_offsetof(struct crypto_functions,ccrsa_make_pub_fn),'
        '__builtin_offsetof(struct crypto_functions,ccrsa_verify_pkcs1v15_fn)};\n')
    obj, = build_objects([source], out)
    data = obj.read_bytes();image = macho(data)
    address, = [row['value'] for row in symbols(data) if row['name'] == '_root_policy_layout']
    at = backed_offset(image['segments'], address, 16, len(data))
    facts = dict(zip(('rsa_bytes', 'rsa_alignment', 'make_offset', 'verify_offset'), struct.unpack_from('<4I', data, at)))
    require(tuple(facts.values()) == (1584, 8, 304, 312), 'Darwin 22 RSA layout changed')
    raw, _, read, _, _ = original()
    contract = json.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/crypto-contract.json').read_text())
    require(hashlib.sha256(raw).hexdigest() == contract['original_kernelcache_sha256'], 'Wrong original RSA input')
    base = 0xfffffff0056d67e0
    words = struct.unpack('<5I', read(base, 20))
    values = []
    for index, register in ((0, 8), (2, 9)):
        a, b = words[index:index + 2]
        require(a & 0x9f00001f == 0x90000000 | register and
                b & 0xffc003ff == 0x91000000 | register << 5 | register, 'Original RSA registration changed')
        delta = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
        if delta & (1 << 20):delta -= 1 << 21
        values.append(((base + index * 4) & -4096) + (delta << 12) + ((b >> 10) & 4095))
    require(words[4] == 0xa9132668 and values == [0xfffffff0056b2668, 0xfffffff0056cf8c0],
            'Original RSA callbacks no longer occupy the native 304/312-byte slots')
    facts.update(original_registration={'address': hex(base), 'bytes': 20, 'sha256': hashlib.sha256(read(base, 20)).hexdigest()},
        original_make_public=hex(values[0]), original_verify=hex(values[1]),
        original_callback_prefix_sha256=[hashlib.sha256(read(address, 96)).hexdigest() for address in values])
    return facts, [source, obj, out / 'compile-commands.json']


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_OWNER_ROOT_POLICY_INPUTS_PASS' and not report['hardware_tested'] and
            len(report['images']) == 2 and report['scope'] == 'owner-development', 'Invalid owner root inputs')
    require(report['reference'] == json.loads((ROOT / 'upstream.lock.json').read_text())['verified_root_reference'],
            'VerifiedRoot source pin changed')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Owner root input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--host-only', action='store_true', help='Run C/signature tests without original iPhone inputs')
    args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: recorded owner-signed root inputs');return
    reference = pinned_sources(('verified_root_reference',))['verified_root_reference']
    OUT.mkdir(parents=True, exist_ok=True)
    # Keep the independent upstream C/RSA tests, adapting only its host build
    # commands. The actual iPhone cross-compile belongs to the kernel builder.
    tests = reference / 'tests/check.py';staged = OUT / 'host-tests.py'
    text = tests.read_text().replace("ROOT = Path(__file__).resolve().parents[1]", 'ROOT = Path(' + repr(str(reference)) + ')')
    before = text.index("sdk = subprocess.check_output(")
    after = text.index('\n\nclass View', before)
    text = text[:before] + text[after:]
    text = text.replace("['xcrun', 'clang'", "['cc'").replace("'-dynamiclib'", "'-shared', '-fPIC'")
    text = text.replace('verified-root.dylib', 'verified-root.so').replace('native_arm64_ios17_cross_compile=True', 'native_arm64_ios17_cross_compile=False')
    staged.write_text(text)
    host = OUT / 'host'
    process = subprocess.run([sys.executable, staged, '--output', host, '--openssl-prefix', '/usr'], capture_output=True, text=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    (OUT / 'host-tests.log').write_text(process.stdout + process.stderr)
    require(not process.returncode, 'VerifiedRoot host tests failed; inspect host-tests.log')
    print(process.stdout.strip(), flush=True)
    if args.host_only:return
    facts, artifacts = rsa_contract(OUT)
    private_dir = ROOT / '.cache/qemu-root-owner';private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    private, public = private_dir / 'owner.pem', private_dir / 'owner-public.pem'
    if not private.exists():
        fd = os.open(private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600);os.close(fd)
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', private],
                       check=True, capture_output=True)
    os.chmod(private, 0o600)
    subprocess.run(['openssl', 'pkey', '-in', private, '-pubout', '-out', public], check=True, capture_output=True)
    module = importlib.util.spec_from_file_location('root_manifest', reference / 'tools/manifest.py')
    manifest = importlib.util.module_from_spec(module);module.loader.exec_module(manifest)
    volumes_path = ROOT / 'reports/ios16-volumes.json';volumes = json.loads(volumes_path.read_text())
    require((volumes['product'], volumes['build']) == ('iPhone10,3', '20H392') and
            [row['name'] for row in volumes['images']] == ['OS', 'SystemOS'], 'Wrong root policy target')
    images = []
    for image in volumes['images']:
        path = ROOT / image['path'];out = OUT / image['name']
        require(stat.S_ISREG(path.lstat().st_mode) and file_sha(path) == image['raw_sha256'], 'Original root image changed')
        uuid = image['apfs']['observed_volumes'][0]['uuid']
        with path.open('rb') as stream:record = manifest.make(stream, image['raw_bytes'], private, public, uuid, 1, out)
        require(record['image_sha256'] == image['raw_sha256'], 'Signed image differs from the pinned volume')
        process = subprocess.run([sys.executable, reference / 'tools/verify_image.py', '--library', host / 'verified-root.so',
            '--manifest', out / 'manifest.bin', '--trusted-key', out / 'trusted-key.bin', '--image', path,
            '--volume-uuid', uuid, '--minimum-generation', '1', '--output', out / 'verification.json'], capture_output=True, text=True)
        (out / 'verification.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Original root block verification failed: ' + image['name'])
        print(image['name'] + ': ' + process.stdout.strip(), flush=True)
        images.append({**record, 'name': image['name'], 'image': image['path'],
            'manifest': str((out / 'manifest.bin').relative_to(ROOT)),
            'anchor': str((out / 'trusted-key.bin').relative_to(ROOT))})
        artifacts += [path, out / 'manifest.bin', out / 'manifest.json', out / 'verification.json', out / 'trusted-key.bin']
    artifacts += [staged, host / 'checks.json', host / 'verified-root.so', OUT / 'host-tests.log']
    sources = [Path(__file__), tests, reference / 'tools/manifest.py', reference / 'tools/verify_image.py',
        reference / 'src/verified_root.c', reference / 'tests/openssl_provider.c', reference / 'include/verified_root.h',
        ROOT / 'profiles/os/ios-16.7.16-20H392/crypto-contract.json',
        ROOT / 'sources/xnu-ios16/libkern/crypto/corecrypto_rsa.c', ROOT / 'sources/xnu-ios16/libkern/libkern/crypto/rsa.h',
        ROOT / 'sources/xnu-ios16/libkern/libkern/crypto/register_crypto.h',
        ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_ios16_pmgr.py']
    report = {'result': 'IOS16_QEMU_OWNER_ROOT_POLICY_INPUTS_PASS', 'scope': 'owner-development',
        'reference': json.loads((ROOT / 'upstream.lock.json').read_text())['verified_root_reference'],
        'source_sha256': {str(path.relative_to(ROOT)): file_sha(path) for path in sources},
        'dependency_report_sha256': {str(volumes_path.relative_to(ROOT)): file_sha(volumes_path)},
        'artifacts': {str(path.relative_to(ROOT)): file_sha(path) for path in artifacts},
        'images': images, 'Darwin22_RSA_contract': facts, 'original_images_modified': False,
        'host_test_groups': len(json.loads((host / 'checks.json').read_text())['checks']),
        'kernel_RSA_executed': False, 'Apple_root_authentication': False, 'hardware_tested': False,
        'generation_policy': 'Minimum generation 1 for this development image; persistent anti-rollback state is separate.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: owner signatures and every original OS/SystemOS block verified by the C implementation')


if __name__ == '__main__':main()
