#!/usr/bin/env python3
"""Derive the iPhone corecrypto owner, packed module record and used KPI boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, build_objects, inspect_object, require, symbols
from native_prelink import backed_offset, macho
from prepare_initial_data import sha
from prepare_ios16_pmgr import original

OUT = ROOT / 'build/ios16-crypto-abi'
FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/crypto-contract.json'
HEADER = FIXTURE.parent / 'security/OriginalCryptoABI.h'


def layout():
    OUT.mkdir(exist_ok=True)
    fields = [('kmod_bytes', 'sizeof(kmod_info_t)'), *[('kmod_' + name, '__builtin_offsetof(kmod_info_t,' + name + ')') for name in
              ('info_version', 'name', 'version', 'address', 'size', 'start', 'stop')],
              ('crypto_bytes', 'sizeof(struct crypto_functions)'),
              *[('crypto_' + name, '__builtin_offsetof(struct crypto_functions,' + name + ')') for name in
                ('ccdigest_init_fn', 'ccmd5_di', 'ccsha256_di', 'ccrng_fn', 'random_generate_fn', 'random_kmem_init_fn', 'digest_ctx_size_fn')],
              ('prng_bytes', 'sizeof(struct cckprng_funcs)'),
              *[('prng_' + name, '__builtin_offsetof(struct cckprng_funcs,' + name + ')') for name in
                ('init', 'initgen', 'reseed', 'refresh', 'generate', 'init_with_getentropy')],
              ('sysctl_stage', 'STARTUP_SUB_SYSCTL'), ('early_boot_stage', 'STARTUP_SUB_EARLY_BOOT')]
    source = OUT / 'CryptoLayout.c'
    source.write_text('#include <mach/kmod.h>\n#include <libkern/crypto/register_crypto.h>\n#include <corecrypto/cckprng.h>\n'
                      '#include <kern/startup.h>\nconst unsigned dodge_crypto_layout[]={' +
                      ','.join('(unsigned)(' + value + ')' for _, value in fields) + '};\n')
    obj, = build_objects([source], OUT)
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_crypto_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(fields)) + 'I', raw, section['fileoff'] + symbol['value'] - section['va'])
    facts = dict(zip((name for name, _ in fields), values))
    require(facts['kmod_bytes'] == 196 and facts['kmod_address'] == 156 and facts['kmod_start'] == 180 and
            facts['crypto_bytes'] == 448 and facts['crypto_digest_ctx_size_fn'] == 352 and facts['prng_bytes'] == 48 and
            facts['prng_init_with_getentropy'] == 40 and facts['sysctl_stage'] < facts['early_boot_stage'], 'Crypto compiler boundaries changed')
    return facts, obj


def derive(facts):
    raw, image, read, entries, names = original()
    entry = entries['com.apple.kec.corecrypto']; record = entry['_PrelinkKmodInfo']
    data = read(record, facts['kmod_bytes'])
    def field(name, width=8): return int.from_bytes(data[facts['kmod_' + name]:facts['kmod_' + name] + width], 'little')
    def text(name): return data[facts['kmod_' + name]:facts['kmod_' + name] + 64].split(b'\0', 1)[0].decode()
    require(field('info_version', 4) == 1 and text('name') == entry['CFBundleIdentifier'] and
            text('version') == '1.0.0d1' and entry['CFBundleVersion'] == '12.0' and field('address') == entry['_PrelinkExecutableLoadAddr'],
            'Original crypto packed record does not match its prelink metadata')
    child = macho(raw, backed_offset(image['segments'], field('address'), 32, len(raw)))
    require(not any(s['size'] for seg in child['segments'] for s in seg['sections']
                    if s['name'] in ('__mod_init_func', '__mod_term_func')), 'Original crypto unexpectedly requires C++ initialization')
    executable, = [s for s in child['segments'] if s['name'] == '__TEXT_EXEC']
    def inside(address): return executable['va'] <= address < executable['va'] + executable['filesize']
    def words(address, count): return struct.unpack('<' + str(count) + 'I', read(address, 4 * count))
    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Crypto ADRP changed')
        delta = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & -4096) + ((delta - (1 << 21) if delta & (1 << 20) else delta) << 12)
    def materialize(pc, register):
        a, b = words(pc, 2)
        require(a & 31 == register and b & 0xffc003ff == 0x91000000 | (register << 5) | register, 'Crypto address materialization changed')
        return adrp(pc, a) + ((b >> 10) & 4095)
    def imported_call(pc):
        word, = words(pc, 1); require(word & 0xfc000000 == 0x94000000, 'Crypto BL changed')
        delta = word & 0x3ffffff; stub = pc + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
        a, b, c = words(stub, 3)
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200, 'Crypto import changed')
        target, = struct.unpack('<Q', read(adrp(stub, a) + ((b >> 10) & 4095) * 8, 8))
        return stub, target
    wrapper = field('start'); require(inside(wrapper) and inside(field('stop')), 'Crypto wrapper left its executable')
    w = words(wrapper, 7); slot = materialize(wrapper, 8)
    require(w[2:] == (0xf9400102, 0xb4000042, 0xd61f0040, 0x52800000, 0xd65f03c0), 'Crypto module start wrapper changed')
    real_entry, = struct.unpack('<Q', read(slot, 8)); require(inside(real_entry), 'Crypto real entry left its executable')
    require(real_entry == 0xfffffff0056d5f3c, 'Crypto real entry identity changed')
    prng_functions = materialize(0xfffffff0056d6664, 8); prng_context = materialize(0xfffffff0056d667c, 0)
    crypto_functions = materialize(0xfffffff0056d6694, 19)
    require(words(0xfffffff0056d666c, 4) == (0xad400500, 0xad0107e0, 0x3dc00900, 0x3d8013e0) and
            words(0xfffffff0056d6684, 1) == (0x910083e1,), 'Original six-function PRNG registration argument changed')
    prng_stub, prng_target = imported_call(0xfffffff0056d6688)
    crypto_stub, crypto_target = imported_call(0xfffffff0056d69d0)
    require(prng_target == names['_register_and_init_prng'] and crypto_target == names['_register_crypto_functions'] and
            words(0xfffffff0056d69cc, 1) == (0xaa1303e0,), 'Original crypto/PRNG registration imports changed')
    prng_pointers = struct.unpack('<6Q', read(prng_functions, 48))
    require(all(inside(value) for value in prng_pointers), 'Original PRNG callback left the crypto module')
    slide = -0x1000000
    bindings = {'_dodge_original_crypto_kmod': record, '_dodge_original_crypto_header': field('address'),
                '_dodge_original_crypto_entry': wrapper, '_dodge_original_crypto_real_entry': real_entry,
                '_dodge_original_crypto_entry_slot': slot, '_dodge_original_crypto_functions': crypto_functions,
                '_dodge_original_crypto_prng_context': prng_context}
    candidate = ROOT / 'build/ios16-apfs-mount-prelink/kernel.macho'
    current = candidate.read_bytes(); target = macho(current)
    at = backed_offset(target['segments'], record + slide, facts['kmod_bytes'], len(current)); rebased = current[at:at + facts['kmod_bytes']]
    for name in ('address', 'start', 'stop'):
        require(int.from_bytes(rebased[facts['kmod_' + name]:facts['kmod_' + name] + 8], 'little') == field(name) + slide,
                'Existing candidate rebased crypto record differs')
    blocks = [('packed_kmod', record, facts['kmod_bytes']), ('start_wrapper', wrapper, 28), ('real_entry', real_entry, 3212),
              ('prng_registration', 0xfffffff0056d6664, 40), ('crypto_registration', 0xfffffff0056d6694, 832)]
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392', 'module': entry['CFBundleIdentifier'],
        'module_version': entry['CFBundleVersion'], 'module_record_version': text('version'),
        'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(),
        'module_bytes': field('size'), 'compiler_layout': facts, 'slide': hex(slide),
        'original_bindings': {name: hex(value) for name, value in bindings.items()},
        'linked_bindings': {name: hex(value + slide) for name, value in bindings.items()},
        'prng_functions': {'address': hex(prng_functions), 'bytes': 48, 'sha256': hashlib.sha256(read(prng_functions, 48)).hexdigest(),
                           'pointers': [hex(value) for value in prng_pointers]},
        'registration': {'prng_call': '0xfffffff0056d6688', 'prng_stub': hex(prng_stub),
                         'crypto_call': '0xfffffff0056d69d0', 'crypto_stub': hex(crypto_stub), 'prng_precedes_crypto_table': True},
        'blocks': {name: {'address': hex(address), 'bytes': size, 'sha256': hashlib.sha256(read(address, size)).hexdigest()}
                   for name, address, size in blocks},
        'existing_candidate': str(candidate.relative_to(ROOT)), 'existing_candidate_sha256': sha(candidate),
        'existing_candidate_record_rebasing_verified': True, 'original_crypto_post_executed': False,
        'original_cpp_initializer_count': 0,
        'complete_crypto_table_abi_qualified': False, 'appended_digest_hmac_kpis_qualified': False, 'hardware_tested': False}


def header(facts):
    return ('// SPDX-License-Identifier: BSD-2-Clause-Patent\n// Measured iPhone10,3 / 20H392 corecrypto owner; ordinary arm64 only.\n'
        '#pragma once\n#include <mach/kmod.h>\n#ifdef __cplusplus\nextern "C" {\n#endif\n'
        'extern kmod_info_t dodge_original_crypto_kmod;\n'
        'extern const unsigned char dodge_original_crypto_header[], dodge_original_crypto_functions[], dodge_original_crypto_prng_context[];\n'
        'extern kmod_start_func_t dodge_original_crypto_entry, dodge_original_crypto_real_entry;\n'
        'extern kmod_start_func_t *const dodge_original_crypto_entry_slot;\n'
        '#ifdef __cplusplus\n}\n#endif\n'
        'static const char DodgeOriginalCryptoName[]="com.apple.kec.corecrypto";\n'
        'static const char DodgeOriginalCryptoRecordVersion[]="' + facts['module_record_version'] + '";\n'
        'static const char DodgeOriginalCryptoBundleVersion[]="' + facts['module_version'] + '";\n'
        'static const vm_size_t DodgeOriginalCryptoModuleBytes=' + str(facts['module_bytes']) + ';\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    compiler, obj = layout(); actual = derive(compiler)
    if args.write:
        require(not FIXTURE.exists() and not HEADER.exists(), 'Refuse to replace reviewed crypto inputs')
        FIXTURE.write_text(json.dumps(actual, indent=2) + '\n'); HEADER.write_text(header(actual))
    require(json.loads(FIXTURE.read_text()) == actual and HEADER.read_text() == header(actual), 'Original crypto contract/header changed')
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_crypto_contract']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and pin['sha256'] == sha(FIXTURE) and
            pin['header'] == str(HEADER.relative_to(ROOT)) and pin['header_sha256'] == sha(HEADER), 'Reviewed original crypto contract pin changed')
    sources = [Path(__file__), FIXTURE, HEADER, ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_ios16_pmgr.py']
    report = {'result': 'IOS16_ORIGINAL_CRYPTO_OWNER_AND_USED_KPI_BOUNDARIES_STATIC_PASS', 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources}, 'dependency_report_sha256': {},
        'artifacts': {str(obj.relative_to(ROOT)): sha(obj)}, 'contract': str(FIXTURE.relative_to(ROOT)), 'contract_facts': actual,
        'source_pin': pin,
        'original_crypto_post_executed': False, 'original_crypto_runtime_qualified': False, 'all_ios_port_code_complete': False,
        'hardware_tested': False, 'ready_for_ios_boot': False,
        'scope': 'Actual Darwin 22 compiler layouts and exact original iPhone packed kmod, wrapper, registration calls and PRNG callbacks. '
                 'Seven absolute inputs are measured and rebasing of the old candidate record is read back. '
                 'No initializer/POST is executed and appended digest/HMAC APIs or the complete crypto table are not qualified.'}
    (ROOT / 'reports/ios16-crypto-contract.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: packed 196-byte original crypto module, exact start/PRNG/table inputs and existing candidate rebasing')


if __name__ == '__main__': main()
