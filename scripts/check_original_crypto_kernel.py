#!/usr/bin/env python3
"""Run the original iPhone crypto initializer/POST and native consumers with bounded platform peers."""
import argparse
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, TREE, build_objects, inspect_object, require, symbols
from original_crypto_execution import run_case
from prepare_crypto_execution import FIXTURE, derive
from prepare_initial_data import sha
from prepare_ios16_crypto import FIXTURE as OWNER

OUT = ROOT / 'build/cph2653-original-crypto-kernel'
REPORT = ROOT / 'reports/ios16-original-crypto-kernel.json'
RESULT = 'IOS16_REAL_ORIGINAL_CRYPTO_POST_NATIVE_PRNG_AND_CONSUMERS_ARM64_PASS'
CONTROLS = ('bad-stop-code', 'bad-hmac-answer', 'post-RET', 'ready-store-NOP')
DEPENDENCIES = ('crypto-stack', 'ios16-crypto-contract', 'ios16-crypto-source', 'ios16-crypto-prelink',
                'ios16-crypto-kernel', 'ios16-crypto-payload')


def layout():
    directory = OUT / 'abi'; directory.mkdir(parents=True, exist_ok=True)
    fields = ('sha256_context', 'sha384_context', 'sha512_context', 'sha256_digest', 'sha384_digest', 'sha512_digest')
    source = directory / 'OriginalCryptoContexts.c'
    source.write_text('#include <libkern/crypto/sha2.h>\n#include <libkern/crypto/rand.h>\n#include <kern/zalloc.h>\n'
                      'const unsigned long long dodge_original_random_layout[]={CRYPTO_RANDOM_MAX_CTX_SIZE,ZPCPU_MANGLE_MASK,ZALIGN_PTR};\n'
                      'const unsigned dodge_original_crypto_contexts[]={\n'
                      'sizeof(SHA256_CTX),sizeof(SHA384_CTX),sizeof(SHA512_CTX),\n'
                      'SHA256_DIGEST_LENGTH,SHA384_DIGEST_LENGTH,SHA512_DIGEST_LENGTH};\n')
    obj, = build_objects([source], directory)
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_original_crypto_contexts']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<6I', raw, section['fileoff'] + symbol['value'] - section['va'])
    require(values == (112, 208, 208, 32, 48, 64), 'Actual native SHA context/digest ABI changed')
    random_symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_original_random_layout']
    random_section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= random_symbol['value'] < s['va'] + s['size']]
    random_values = struct.unpack_from('<3Q', raw, random_section['fileoff'] + random_symbol['value'] - random_section['va'])
    require(random_values == (256, 0xc0c0000000000000, 7), 'Native random/per-CPU context contract changed')
    return dict(zip(fields, values)), dict(zip(('maximum_context_bytes', 'percpu_mangle_mask', 'percpu_alignment_mask'), random_values)), [source, obj, directory / 'compile-commands.json']


def reviewed():
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_crypto_execution']
    require(pin['path'] == str(FIXTURE.relative_to(ROOT)) and pin['sha256'] == sha(FIXTURE) and
            (pin['product'], pin['build']) == ('iPhone10,3', '20H392'), 'Reviewed original POST execution pin changed')
    contract = json.loads(FIXTURE.read_text())
    require(derive() == contract, 'Original default POST/known-answer boundaries changed')
    return contract, pin


def dependencies():
    rows, hashes, cache = {}, {}, {}
    def digest(path):
        if path not in cache: cache[path] = sha(path)
        return cache[path]
    for name in DEPENDENCIES:
        path = ROOT / 'reports' / (name + '.json'); row = json.loads(path.read_text())
        require('PASS' in row['result'], 'Original crypto dependency failed: ' + name)
        for filename, value in {**row.get('source_sha256', {}), **row.get('dependency_report_sha256', {})}.items():
            require(digest(ROOT / filename) == value, 'Original crypto dependency input changed: ' + filename)
        artifacts = row['artifacts']
        if isinstance(artifacts, list): artifacts = {item['path']: item['sha256'] for item in artifacts}
        for filename, value in artifacts.items():
            require(digest(ROOT / filename) == value, 'Original crypto dependency artifact changed: ' + filename)
        rows[name] = row; hashes[str(path.relative_to(ROOT))] = digest(path)
    stack, prelink = rows['crypto-stack'], rows['ios16-crypto-prelink']
    for item in stack['stages'].values():
        require(digest(ROOT / item['report']) == item['sha256'], 'Frozen crypto stage identity changed')
    require(prelink['candidate_sha256'] == digest(ROOT / prelink['candidate']) and prelink['pointer_sites_read_back'] == 63889,
            'Need the exact strict original-crypto prelinked candidate')
    return ROOT / prelink['candidate'], hashes


def check_report(report):
    contract, pin = reviewed(); candidate, dependency_hashes = dependencies()
    require(report['result'] == RESULT and report['builder_sha256'] == sha(Path(__file__)) and
            report['execution_pin'] == pin and report['contract_facts'] == contract and
            report['dependency_report_sha256'] == dependency_hashes and report['candidate'] == str(candidate.relative_to(ROOT)) and
            report['candidate_sha256'] == sha(candidate), 'Original crypto execution report is stale')
    for filename, value in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Original crypto execution input/artifact changed: ' + filename)
    normal, controls = report['positive_execution'], report['negative_controls']
    require(normal['case'] == 'normal' and normal['result'] == 'PASS' and normal['actual_post_return'] == [0] and
            normal['actual_passed_post_tests'] == contract['required_passed_tests'] and len(normal['native_sha_vectors']) == 18 and
            all(row['result'] == 'PASS' for row in normal['native_sha_vectors']) and
            [row['bytes'] for row in normal['native_prng_transfers']] == [1, 32, 4096, 65536] and
            all(row['result'] == 'PASS' and row['all_output_bytes_written'] and sum(row['generator_chunks']) == row['bytes']
                for row in normal['native_prng_transfers']) and normal['actual_cached_loader_span']['result'] == 'PASS' and
            normal['actual_native_prng_ready'] and normal['actual_native_prng_context_matches_original'] and
            normal['actual_registered_table_matches_original'] and normal['seed_fixture_cleared'], 'Real crypto positive evidence is incomplete')
    memory = normal['native_memory_random_consumers']; startup = memory['actual_early_boot_kmem']
    require(memory['result'] == 'PASS' and memory['direct_case_count'] == len(memory['direct_cases']) == 16 and
            all(row['result'] == 'PASS' and row['all_output_bytes_written'] for row in memory['direct_cases']) and
            startup['result'] == 'PASS' and startup['native_size_classes_initialized'] == 14 and startup['percpu_fixture_count'] == 1 and
            startup['all_published_pointers_read_back'], 'Native random consumers/EARLY_BOOT kmem evidence is incomplete')
    require([row['case'] for row in controls] == list(CONTROLS) and all(row['result'] == 'REJECTED' for row in controls),
            'Real crypto rejection controls are incomplete')
    require(all(report[key] for key in ('original_initializer_executed_in_arm64_model', 'original_default_post_executed_in_arm64_model',
            'native_prng_and_registration_executed_in_arm64_model', 'native_sha_consumers_executed_in_arm64_model')) and
            not any(report[key] for key in ('crypto_algorithm_or_result_peers_installed', 'full_oskext_start_executed',
            'target_entropy_quality_qualified', 'original_crypto_runtime_qualified', 'original_apfs_data_mount_qualified',
            'hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Real crypto evidence overstates its scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text())); print('PASS: preserved actual original crypto/POST/native PRNG/consumer CPU evidence'); return
    contract, pin = reviewed(); candidate, hashes = dependencies(); facts, random_geometry, artifacts = layout()
    owner = json.loads(OWNER.read_text()); context_sizes = tuple(facts.values())
    normal = run_case(candidate, contract, owner, context_sizes, 'normal', random_geometry)
    print('PASS: real original initialization, all 18 default POST tests, native PRNG/table registration and consumers', flush=True)
    controls = []
    for scenario in CONTROLS:
        controls.append(run_case(candidate, contract, owner, context_sizes, scenario))
        print('REJECTED:', scenario, flush=True)
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({'compiler_layout': facts, 'positive_execution': normal,
                'negative_controls': controls}, indent=2) + '\n'); artifacts.append(evidence)
    files = [Path(__file__), ROOT / 'scripts/original_crypto_execution.py', ROOT / 'scripts/prepare_crypto_execution.py',
             ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/native_driver_build.py', ROOT / 'scripts/prepare_initial_data.py',
             ROOT / 'scripts/prepare_ios16_pmgr.py', ROOT / 'scripts/prepare_ios16_crypto.py', FIXTURE, OWNER,
             *[TREE / '.cache/xnu-work' / filename for filename in ('libkern/libkern/crypto/sha2.h', 'libkern/libkern/crypto/rand.h',
                'osfmk/kern/zalloc.h', 'osfmk/vm/vm_kern.c', 'libkern/crypto/corecrypto_rand.c')]]
    report = {'result': RESULT, 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files}, 'dependency_report_sha256': hashes,
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(candidate.relative_to(ROOT)),
        'candidate_sha256': sha(candidate), 'execution_pin': pin, 'contract_facts': contract, 'compiler_layout': facts,
        'compiler_random_layout': random_geometry,
        'positive_execution': normal, 'negative_controls': controls, 'original_default_post_tests': 18, 'native_sha_vectors': 18,
        'native_prng_transfers': 4, 'actual_cached_loader_subpaths': 1, 'native_memory_random_direct_cases': 16,
        'actual_early_boot_kmem_size_classes': 14,
        'original_initializer_executed_in_arm64_model': True, 'original_default_post_executed_in_arm64_model': True,
        'native_prng_and_registration_executed_in_arm64_model': True, 'native_sha_consumers_executed_in_arm64_model': True,
        'crypto_algorithm_or_result_peers_installed': False, 'full_oskext_start_executed': False,
        'target_entropy_quality_qualified': False, 'original_crypto_runtime_qualified': False, 'original_apfs_data_mount_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'The exact original iPhone initializer and full default-mode POST run in an ARM64 instruction model. '
                 'All 18 real subtests return success before the actual native PRNG and crypto-table registration. '
                 'The six original PRNG callbacks and native readiness/context accessors execute without peers. '
                 'Eighteen native SHA-256/384/512 vectors match hashlib; four native read_random transfers call the original generator '
                 'and write every output byte. One actual post-C++ OSKext fragment reuses the same owner after the loader version stamp. '
                 'Sixteen additional native kmem generate/uniform and ccrng/random_buf cases run; the weak kmem generator acquires no mutex '
                 'after initialization. The actual EARLY_BOOT kmem callback allocates, initializes and publishes all 14 size-class random contexts, '
                 'with native per-CPU count/demangling and explicit CPU0/per-CPU allocation fixtures. '
                 'Four in-memory controls cover damaged original code, a damaged HMAC expected answer, a skipped POST and missing native PRNG readiness. '
                 'Platform allocation/libc/locks/CPU0/time/sysctl/entropy collection are explicit peers. A private host boot seed is supplied, '
                 'with zero additional interrupt samples and no positive entropy estimate. No boot-seed quality, MMIO, full OSKext/C++ loading, '
                 'complete crypto table ABI, target runtime, root/Data authentication, phone boot or complete port is qualified. '
                 'Original on-disk code, production crypto results and frozen earlier reports/artifacts are unchanged.'}
    check_report(report); REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: actual original POST 18 / native SHA 18 / native PRNG transfers 4 / cached loader 1 / native random consumers 16 / kmem classes 14 / rejection controls 4')


if __name__ == '__main__': main()
