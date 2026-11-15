#!/usr/bin/env python3
"""Derive native Qualcomm TRNG inputs and the exact original iPhone seedctl interface."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import urllib.request

from compare_oneplus13t import read_fdt, registers
from check_gpu_link import run
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols, macho
from native_prelink import backed_offset
from prepare_qemu_root_policy import file_sha

OUT = ROOT / 'build/cph2653-native-entropy'
REPORT = ROOT / 'reports/ios16-native-entropy.json'
CONTRACT = ROOT / 'hardware/dodge-entropy.json'
CAPTURE_SHA = 'f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11'
REFERENCES = ((ROOT / '.cache/input-reference/qcom-rng-v6.12.c', 'https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/crypto/qcom-rng.c'),
    (ROOT / '.cache/input-reference/qcom-prng-v6.12.yaml', 'https://raw.githubusercontent.com/torvalds/linux/v6.12/Documentation/devicetree/bindings/crypto/qcom,prng.yaml'))


def consumer():
    volumes_path = ROOT / 'reports/ios16-volumes.json';volumes = json.loads(volumes_path.read_text())
    os_image, = [row for row in volumes['images'] if row['name'] == 'OS']
    require((volumes['product'], volumes['build']) == ('iPhone10,3', '20H392') and file_sha(ROOT / os_image['path']) == os_image['raw_sha256'], 'Wrong original iPhone OS')
    recorded = json.loads((ROOT / 'reports/ios16-display-cache.json').read_text());extractor = ROOT / recorded['extractor']
    require(sha(extractor) == recorded['extractor_sha256'] and sha(ROOT / 'tools/ApfsExtract.cpp') == recorded['extractor_source_sha256'], 'APFS extractor changed')
    path = OUT / 'prng_seedctl.original'
    if not path.exists():subprocess.run([extractor, ROOT / os_image['path'], '0', '/usr/libexec/prng_seedctl', path], check=True)
    raw = path.read_bytes();image = macho(raw)
    require(struct.unpack_from('<3I', raw) == (0xfeedfacf, 0x100000c, 0), 'Expected original ordinary ARM64 seedctl')
    def read(address, count):
        at = backed_offset(image['segments'], address, count, len(raw));return raw[at:at + count]
    def cstring(address):
        at = backed_offset(image['segments'], address, 1, len(raw));return raw[at:raw.index(b'\0', at)].decode()
    def code(address, count):return {'address': hex(address), 'bytes': count, 'sha256': hashlib.sha256(read(address, count)).hexdigest()}
    uuid_at, = [at for command, at, _ in image['commands'] if command == 0x1b]
    # Actual seedctl const pointers use DYLD_CHAINED_PTR_64_OFFSET (format 6).
    fixup_at, = [at for command, at, _ in image['commands'] if command == 0x80000034]
    fixups, = struct.unpack_from('<I', raw, fixup_at + 8)
    starts = fixups + struct.unpack_from('<I', raw, fixups + 4)[0]
    count, = struct.unpack_from('<I', raw, starts)
    formats = [struct.unpack_from('<H', raw, starts + offset + 6)[0]
        for offset in struct.unpack_from('<' + str(count) + 'I', raw, starts + 4) if offset]
    require(formats == [6], 'Original seedctl pointer format changed')
    base = 0x100000000
    names = [cstring(base + (value & ((1 << 36) - 1))) for value in struct.unpack('<4Q', read(0x1000040c8, 32))]
    require(names[0] == 'kern.prng.user_reseed_count' and
        struct.unpack('<2I', read(0x1000036b0, 8)) == (0x52800108, 0xa9027fe8) and
        struct.unpack('<7I', read(0x100003900, 28)) == (0xb94023e0, 0x9100c3e4, 0x9100a3e5, 0x52800001,
            0xd2800002, 0xd2800003, 0x940000f0), 'Original seedctl request width/selector changed')
    require(cstring(0x100003eea) == 'AppleVirtIOEntropy' and cstring(0x100003f30) == '/dev/random', 'Original seedctl identities changed')
    facts = {'OS_sha256': os_image['raw_sha256'], 'path': '/usr/libexec/prng_seedctl', 'sha256': sha(path),
        'uuid': raw[uuid_at + 8:uuid_at + 24].hex(), 'sysctl_names': names, 'sysctl_output_bytes': 8,
        'service_class': 'AppleVirtIOEntropy', 'open_type': 0, 'selector': 0, 'structure_input_bytes': 0,
        'structure_output_bytes': 32, 'seed_path': '/var/db/prng.seed', 'seed_bytes': 32,
        'blocks': {'sysctl_query': code(0x1000036b0, 64), 'entropy_query': code(0x1000038f0, 48),
            'load_saved_seed': code(0x100003ba4, 304), 'save_new_seed': code(0x100003a74, 300)}}
    return facts, path, [volumes_path, ROOT / 'reports/ios16-display-cache.json'], [extractor]


def derive():
    capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
    dtb = Path(capture['source_directory']) / 'device-tree.dtb';require(sha(dtb) == CAPTURE_SHA, 'Captured CPH2653 DTB changed')
    tree = read_fdt(dtb.read_bytes());node, = [entry for entry in tree.walk() if 'qcom,trng' in entry.strings('compatible')]
    regions = registers(node)
    require(regions == [(0x10c3000, 0x1000)] and 'clocks' not in node.properties and
        ('status' not in node.properties or node.strings('status') == ['okay']), 'Captured TRNG resource/clock contract differs')
    for path, url in REFERENCES:
        if not path.exists():
            with urllib.request.urlopen(url, timeout=30) as stream:path.write_bytes(stream.read())
    reference = REFERENCES[0][0].read_text()
    require('#define PRNG_STATUS\t\t0x0004' in reference and '#define PRNG_DATA_OUT\t\t0x0000' in reference and
        '.skip_init = true,\n\t.hwrng_support = true,' in reference, 'Reviewed Qualcomm TRNG protocol changed')
    original, executable, dependencies, tools = consumer()
    facts = {'schema_version': 1, 'device': 'OnePlus 13 CPH2653 / SM8750', 'captured_dtb_sha256': CAPTURE_SHA,
        'compatible': 'qcom,trng', 'physical': hex(regions[0][0]), 'bytes': regions[0][1], 'clock_required': False,
        'initialize_configuration': False, 'status_offset': 4, 'data_offset': 0, 'data_available_mask': 1,
        'source_references': [{'path': str(path.relative_to(ROOT)), 'url': url, 'sha256': sha(path),
            'license': 'GPL-2.0, register-protocol reference only; no Linux implementation linked'} for path, url in REFERENCES],
        'iPhone_consumer': original, 'hardware_tested': False, 'entropy_rate_qualified': False}
    return facts, dtb, executable, dependencies, tools


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_TRNG_SOURCE_AND_SEEDCTL_ABI_PASS' and report['host_cases'] >= 350 and
        report['original_consumer']['structure_output_bytes'] == 32 and not report['hardware_tested'] and
        not report['entropy_rate_qualified'] and not report['PRNG_used_as_entropy_source'], 'Incomplete native TRNG source')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(file_sha(ROOT / name) == digest, 'Native TRNG input changed: ' + name)
    raw = (ROOT / report['object']).read_bytes();image = inspect_object(raw)
    require(all(not section['size'] for segment in image['segments'] for section in segment['sections']
        if section['name'] == '__mod_init_func'), 'TRNG class initializer is still early')


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--write-contract', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native TRNG source, bounded transactions and original seedctl interface');return
    OUT.mkdir(parents=True, exist_ok=True)
    facts, dtb, executable, dependencies, tools = derive()
    if args.write_contract:
        require(not CONTRACT.exists(), 'Refuse to overwrite a reviewed TRNG contract')
        CONTRACT.write_text(json.dumps(facts, indent=2) + '\n')
    require(json.loads(CONTRACT.read_text()) == facts, 'Native TRNG/original seedctl contract changed')
    header = OUT / 'DodgeTrngHardware.h'
    header.write_text('#pragma once\n#include <stdint.h>\nstatic const uint64_t dodgeTrngPhysical = UINT64_C(' +
        facts['physical'] + ');\nstatic const uint64_t dodgeTrngBytes = UINT64_C(' + str(facts['bytes']) + ');\n')
    directory = ROOT / 'drivers/DodgeSecurity';source = directory / 'DodgeNativeEntropy.cpp'
    obj, = build_objects([source], OUT, [OUT, directory])
    late = OUT / 'DodgeNativeEntropy.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=__GLOBAL__sub_I_DodgeNativeEntropy.cpp', obj, late], check=True)
    archive = OUT / 'libDodgeNativeEntropy.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, late], check=True)
    binary = OUT / 'trng-host';test = ROOT / 'tests/DodgeTrngTest.cpp'
    run(['/usr/bin/clang++-14', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', directory, test, '-o', binary], OUT / 'host-compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'TRNG refusal tests failed; inspect host.log')
    files = [Path(__file__), CONTRACT, source, directory / 'DodgeTrngRead.h', directory / 'DodgeOwnerSystem.h', test,
        *[path for path, _ in REFERENCES], dtb]
    # The captured input path stays local; public report export sanitizes it.
    sources = {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path): sha(path) for path in files}
    artifacts = [header, obj, late, archive, binary, log, executable, OUT / 'compile-commands.json', *tools]
    report = {'result': 'IOS16_NATIVE_TRNG_SOURCE_AND_SEEDCTL_ABI_PASS', 'source_sha256': sources,
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in dependencies},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'object': str(late.relative_to(ROOT)), 'archive': str(archive.relative_to(ROOT)),
        'host_cases': int(result.stdout.split()[1]), 'original_consumer': facts['iPhone_consumer'],
        'hardware_tested': False, 'entropy_rate_qualified': False, 'PRNG_used_as_entropy_source': False,
        'phone_operations': 'none', 'scope': 'Independent native read-only Qualcomm TRNG register consumer, original iPhone '
        'AppleVirtIOEntropy class search and selector-0/32-byte user-client interface, root-only opens, bounded polling, '
        'all-or-nothing output and latched stuck-output rejection. Exact source compilation and sanitizer/model inputs pass. '
        'Firmware-initialized TRNG hardware, statistical entropy quality and real service dispatch remain unqualified.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', report['host_cases'], 'TRNG cases; captured native resource and exact original iPhone seedctl interface')


if __name__ == '__main__':main()
