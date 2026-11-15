#!/usr/bin/env python3
"""Expose actual completed user entropy reseeds without replacing the original PRNG."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from check_gpu_link import assemble, run
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols
from prepare_ios16_prng import CONTRACT as PRNG_CONTRACT, reviewed as prng_reviewed

OUT = ROOT / 'build/cph2653-user-entropy'
REPORT = ROOT / 'reports/ios16-user-entropy.json'
BASE_REPORT = ROOT / 'reports/ios16-crypto-source.json'
CONTRACT = ROOT / 'hardware/dodge-entropy.json'


def instructions(path):
    raw = path.read_bytes();image = inspect_object(raw)
    section, = [s for segment in image['segments'] for s in segment['sections'] if s['name'] == '__text']
    return raw[section['fileoff']:section['fileoff'] + section['size']]


def check_report(report):
    tree = prng_reviewed()
    require(report['result'] == 'IOS16_USER_ENTROPY_RESEED_ACCOUNTING_PASS' and report['original_PRNG_instructions_preserved'] and
        report['host_concurrent_reseeds'] == 4000 and report['original_bindings'] == tree['linked_binding'] and
        report['original_sysctl_tree_shared'] and report['original_observation_count'] == 99 and
        not report['new_entropy_source'] and not report['hardware_tested'], 'Incomplete user entropy source')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'User entropy input changed: ' + name)
    require(hashlib.sha256(instructions(ROOT / report['original_object'])).hexdigest() == report['PRNG_text_sha256'], 'PRNG instructions changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual user reseed accounting and unchanged original PRNG implementation');return
    base = json.loads(BASE_REPORT.read_text())
    tree = prng_reviewed()
    consumer = json.loads(CONTRACT.read_text())['iPhone_consumer']
    require(consumer['sysctl_output_bytes'] == 8 and consumer['sysctl_names'][0] == 'kern.prng.user_reseed_count',
        'Original iPhone user entropy counter width/name differs')
    recipe_path = ROOT / 'build/cph2653-crypto-source/overlay-compile-commands.json'
    recipe, = [row for row in json.loads(recipe_path.read_text()) if row['source'].endswith('/prng_random.crypto.c')]
    source = Path(recipe['source']);original_object = source.with_suffix('.o')
    for path in (source, original_object, recipe_path):
        require(base['artifacts'][str(path.relative_to(ROOT))] == sha(path), 'Recorded PRNG source/recipe/object changed')
    OUT.mkdir(parents=True, exist_ok=True)
    obj = OUT / 'prng_random.original.o';command = list(recipe['arguments'])
    command[command.index('-o') + 1] = str(obj)
    command += ['-Dwrite_random=dodge_write_random_original']
    run(command, OUT / 'prng-compile.log', recipe['directory'])
    require(instructions(obj) == instructions(original_object), 'User reseed accounting changed the original PRNG instructions')
    wrapper = ROOT / 'drivers/DodgeSecurity/DodgeUserEntropy.c'
    pool_source = wrapper.with_name('DodgePrngPools.c')
    accounting, pools = build_objects([wrapper, pool_source], OUT)
    names = {row['name'] for row in symbols(accounting.read_bytes()) if row['kind'] & 14 == 14}
    require({'_write_random', '_sysctl__kern_prng_user_reseed_count',
        '_dodge_user_entropy_reseeds', '_dodge_user_entropy_bytes'} <= names, 'Native sysctl/reseed implementation missing')
    require('_sysctl__kern_prng' not in names and any(row['name'] == '_sysctl__kern_prng_children' and row['kind'] == 1
        for row in symbols(accounting.read_bytes())), 'User counter must use the original PRNG tree')
    bindings = tree['linked_binding']
    alias = assemble(OUT, 'original-prng-tree', ''.join('.globl ' + name + '\n.set ' + name + ',' + value + '\n'
        for name, value in bindings.items()))
    archive = OUT / 'libDodgeUserEntropy.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, accounting, pools, alias], check=True)
    binary = OUT / 'user-entropy-host';test = ROOT / 'tests/DodgeUserEntropyTest.cpp'
    run(['/usr/bin/clang++-14', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
        '-I', ROOT / 'tests/entropy_include', test, '-o', binary], OUT / 'host-compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'User entropy host checks failed; inspect host.log')
    command_path = OUT / 'compile-prng.json';command_path.write_text(json.dumps(command, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/prepare_ios16_prng.py', PRNG_CONTRACT, CONTRACT, wrapper, pool_source, test, source, recipe_path,
        *sorted((ROOT / 'tests/entropy_include').rglob('*.h'))]
    artifacts = [obj, accounting, pools, alias, archive, binary, log, command_path, OUT / 'compile-commands.json']
    report = {'result': 'IOS16_USER_ENTROPY_RESEED_ACCOUNTING_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(BASE_REPORT.relative_to(ROOT)): sha(BASE_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'original_object': str(obj.relative_to(ROOT)), 'archive': str(archive.relative_to(ROOT)),
        'PRNG_text_sha256': hashlib.sha256(instructions(obj)).hexdigest(), 'original_PRNG_instructions_preserved': True,
        'host_concurrent_reseeds': 4000, 'sysctl': 'kern.prng.user_reseed_count', 'sysctl_bytes': 8, 'read_only': True,
        'original_bindings': bindings, 'original_sysctl_tree_shared': True, 'original_observation_count': 99,
        'original_iPhone_consumer_sha256': consumer['sha256'], 'original_iPhone_consumer_width_derived': True,
        'new_entropy_source': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Actual read-only user reseed counter increments only after nonempty input reaches the existing Darwin 22 '
        'hash/reseed/clear implementation. Its instructions, crypto owner hooks and registered iPhone PRNG remain unchanged. '
        'Concurrent requests, zero reads, empty/null input, backend errors and sysctl output errors are checked under ASan/UBSan. '
        'The counter shares the measured original PRNG child list; no second kern.prng root is defined. '
        'The unchanged iPhone owner supplies its own scheduled reseed and 32-pool observations. '
        'This provides accounting, not a virtual RNG or new hardware entropy source.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: real user reseed accounting, 4000 concurrent calls and unchanged PRNG instructions')


if __name__ == '__main__':main()
