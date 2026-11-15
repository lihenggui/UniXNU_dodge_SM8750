#!/usr/bin/env python3
"""Execute original PRNG registration, native sysctl lookup and real observation updates."""
import argparse
import json
from pathlib import Path
import struct

from build_native_system import REPORT as KERNEL_REPORT, check_report as check_kernel
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols
from original_crypto_execution import Execution
from prepare_ios16_prng import CONTRACT, reviewed

OUT = ROOT / 'build/cph2653-native-prng-check'
REPORT = ROOT / 'reports/ios16-native-prng-check.json'


def layout():
    source = OUT / 'PrngSysctlLayout.c'
    fields = [('oid_bytes', 'sizeof(struct sysctl_oid)'), ('req_bytes', 'sizeof(struct sysctl_req)'),
        *[('req_' + name, '__builtin_offsetof(struct sysctl_req,' + name + ')') for name in
        ('oldlen', 'oldfunc', 'newptr', 'newlen')]]
    source.write_text('#include <sys/sysctl.h>\nconst unsigned dodge_prng_sysctl_layout[]={' +
        ','.join(value for _, value in fields) + '};\n')
    obj, = build_objects([source], OUT)
    raw = obj.read_bytes();image = inspect_object(raw)
    symbol, = [row for row in symbols(raw) if row['name'] == '_dodge_prng_sysctl_layout']
    section, = [s for segment in image['segments'] for s in segment['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<6I', raw, section['fileoff'] + symbol['value'] - section['va'])
    require(values == (80, 80, 24, 40, 48, 56), 'Native sysctl ABI changed')
    return dict(zip((name for name, _ in fields), values)), [source, obj, OUT / 'compile-commands.json']


def execution(candidate, facts, abi):
    owner_path = ROOT / 'profiles/os/ios-16.7.16-20H392/crypto-contract.json'
    post_path = owner_path.with_name('crypto-execution.json')
    owner = json.loads(owner_path.read_text());post = json.loads(post_path.read_text())
    run = Execution(candidate, post, owner, 'normal');m = run.model;n = m.names
    require(n['_sysctl__kern_prng_children'] == int(facts['linked_children'], 16) and '_sysctl__kern_prng' not in n,
        'User accounting defines a duplicate PRNG root or uses the wrong child list')
    user = n['_sysctl__kern_prng_user_reseed_count']
    require(int.from_bytes(m.read(user, 8), 'little') == n['_sysctl__kern_prng_children'], 'User accounting is attached to another tree')
    # Execute actual native registration, including mutable-list insertion and
    # OID allocation. Only its primitive geometry lock is a platform peer.
    del m.peers[n['_sysctl_register_oid']]
    held = [False]
    def lock(args):
        require(not held[0] and args[0] == n['_sysctl_geometry_lock'], 'Unexpected sysctl geometry lock')
        held[0] = True;m.returned()
    def unlock(args):
        require(held[0] and args[0] == n['_sysctl_geometry_lock'], 'Unbalanced sysctl geometry lock')
        held[0] = False;m.returned()
    m.bind('_lck_rw_lock_exclusive', lock);m.bind('_lck_rw_unlock_exclusive', unlock)
    m.bind('_strlen', lambda args: m.returned(len(m.string(args[0]))))
    registered = []
    run.observe(n['_sysctl_register_oid'], lambda cpu, pc, size, ignored: registered.append(m.register(0)))
    m.call('_sysctl_register_oid_early', [n['_sysctl__kern']])
    m.call('_sysctl_register_oid_early', [user])
    for pool in range(32):m.call('_sysctl_register_oid_early', [n['_sysctl__kern_prng_pool' + str(pool)]])
    require(not run.panics, 'Native early sysctl registration failed')
    run.bootstrap()
    passed = [message.rsplit(' - ', 1)[-1].strip() for message in run.logs if 'PASSED:' in message]
    require(run.post_returns == [0] and not run.panics and not held[0] and
        passed == post['required_passed_tests'] and m.read(n['_bootseed'], 32) == bytes(32) and
        all(run.counts[key] == 1 for key in ('original_entry', 'original_wrapper', 'post_entry', 'native_prng', 'native_table', 'entropy_init')) and
        len(registered) == len(set(registered)) and registered[:facts['node_count']] ==
        [int(row['address'], 16) + run.slide for row in facts['nodes']], 'Original PRNG registration/POST failed or repeated')
    # Resolve every diagnostic path using the unchanged native name2oid body.
    def lookup(name):
        text, output, count = m.heap + 0x1000, m.heap + 0x2000, m.heap + 0x3000
        m.put(text, name.encode() + b'\0');m.put(output, bytes(48));m.put(count, bytes(8))
        result = m.call('_name2oid', [text, output, count])
        size, = struct.unpack('<Q', m.read(count, 8))
        require(result == 0 and size in (3, 4), 'Native name lookup failed: ' + name)
        return list(struct.unpack('<' + str(size) + 'I', m.read(output, size * 4)))
    paths = {};counters = []
    for index, row in enumerate(facts['nodes']):
        address = int(row['address'], 16) + run.slide
        if not index:continue
        prefix = 'kern.prng.' if index < 4 or (index - 4) % 4 == 0 else 'kern.prng.pool_' + str((index - 4) // 4) + '.'
        path = prefix + row['name'];paths[path] = lookup(path)
        if row['handler'] != '0x0':counters.append((path, address, int(row['arg1'], 16) + run.slide))
    paths['kern.prng.user_reseed_count'] = lookup('kern.prng.user_reseed_count')
    for pool in range(32):
        for part in ('sample_count', 'drain_count', 'max_sample_count'):
            path = 'kern.prng.pool' + str(pool) + '.' + part;paths[path] = lookup(path)
            require(paths[path][:2] == paths['kern.prng.pool_' + str(pool) + '.' + part][:2] and
                paths[path][-1] == paths['kern.prng.pool_' + str(pool) + '.' + part][-1], 'Pool alias changed the original counter identity')
        alias = n['_sysctl__kern_prng_pool' + str(pool)]
        require(int.from_bytes(m.read(alias + 24, 8), 'little') == int(facts['linked_children'], 16) + 8 * (pool + 1),
            'Pool alias does not retain the original pool list')
    require(len(paths) == 228 and len({tuple(value) for value in paths.values()}) == len(paths) and len(counters) == 99,
        'PRNG paths are hidden or alias one another')
    # Invoke the real handlers through their installed pointers. The output
    # copy is an explicit peer; statistics and PRNG algorithm calls are not.
    request = m.heap + 0x4000;output_call = m.scratch + 0xf000;captured = [];error = [0]
    def output(args):
        require(args[0] == request and args[2] == 8, 'PRNG sysctl output ABI changed')
        captured.append(m.read(args[1], 8));m.returned(error[0])
    m.peers[output_call] = ('sysctl-output', output)
    def read_counter(address):
        captured.clear();m.put(request, bytes(abi['req_bytes']))
        m.put(request + abi['req_oldfunc'], struct.pack('<Q', output_call))
        m.put(request + abi['req_oldlen'], struct.pack('<Q', 8))
        arg1, = struct.unpack('<Q', m.read(address + 24, 8));handler, = struct.unpack('<Q', m.read(address + 48, 8))
        m.names['_measured_counter_handler'] = handler
        result = m.call('_measured_counter_handler', [address, arg1, 0, request])
        require(result == error[0] and len(captured) == 1, 'PRNG observation handler failed')
        return int.from_bytes(captured[0], 'little')
    before = {path: read_counter(address) for path, address, _ in counters}
    require(not any(before.values()), 'Original boot fixture started with accumulated entropy samples')
    # Synthetic entropy is confined to this instruction model. This checks
    # actual original accounting transitions, not board entropy quality.
    samples = [0]
    def entropy(args):
        capacity, = struct.unpack('<Q', m.read(args[0], 8));require(capacity >= 32, 'PRNG entropy buffer is too small')
        samples[0] += 1;m.put(args[1], bytes(range(32)));m.put(args[0], struct.pack('<Q', 32));m.returned(1024)
    m.bind('_entropy_provide', entropy)
    for _ in range(40):m.call('_read_random', [m.heap + 0x6000, 32], limit=3000000)
    after = {path: read_counter(address) for path, address, _ in counters}
    require(samples[0] == 40 and after['kern.prng.scheduled_reseed_count'] > 0 and
        after['kern.prng.scheduled_reseed_max_sample_count'] >= 1024 and
        after['kern.prng.entropy_max_sample_count'] >= 1024 and any(after[path] for path in after if '.pool_' in path),
        'Original PRNG did not update its real scheduled/pool observations')
    for path, address, value in counters:
        require(read_counter(address) == int.from_bytes(m.read(value, 8), 'little'), 'Counter read does not match its original owner: ' + path)
    require(read_counter(user) == 0, 'Diagnostic reads or scheduled entropy invented a user reseed')
    seed = m.heap + 0x7000;m.put(seed, bytes(range(32)));m.call('_write_random', [seed, 32], limit=3000000)
    require(read_counter(user) == 1, 'Actual original user reseed was not accounted')
    error[0] = 14;read_counter(user);read_counter(counters[0][1]);error[0] = 0
    require(not run.panics and n['_sysctl_register_oid'] not in m.peers and
        n['_sysctl_handle_quad'] not in m.peers and n['_name2oid'] not in m.peers, 'PRNG registration/lookup/handler used a peer')
    return {'result': 'PASS', 'original_nodes_registered': facts['node_count'], 'unique_paths_resolved': len(paths),
        'real_counters_read': len(counters), 'entropy_model_requests': samples[0],
        'scheduled_reseeds_in_model': after['kern.prng.scheduled_reseed_count'], 'user_reseeds_in_model': read_counter(user),
        'original_POST_tests': len(passed), 'actual_passed_POST_tests': passed, 'output_error_controls': 2,
        'paths': paths, 'observation_values_in_model': after, 'shared_original_child_list': True}


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_ORIGINAL_PRNG_TREE_CPU_PASS' and report['execution']['result'] == 'PASS' and
        report['execution']['real_counters_read'] == 99 and report['execution']['unique_paths_resolved'] == 228 and
        report['execution']['original_POST_tests'] == len(report['execution']['actual_passed_POST_tests']) == 18 and
        report['execution']['shared_original_child_list'] and not report['hardware_tested'], 'Incomplete native PRNG evidence')
    reviewed()
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native PRNG input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original PRNG tree, real sysctl registration/lookup/reads and counter updates');return
    kernel = json.loads(KERNEL_REPORT.read_text());check_kernel(kernel);facts = reviewed();OUT.mkdir(parents=True, exist_ok=True)
    abi, artifacts = layout();candidate = ROOT / kernel['candidate'];result = execution(candidate, facts, abi)
    files = [Path(__file__), ROOT / 'scripts/original_crypto_execution.py', ROOT / 'scripts/prepare_ios16_prng.py', CONTRACT]
    report = {'result': 'IOS16_NATIVE_ORIGINAL_PRNG_TREE_CPU_PASS', 'compiler_layout': abi, 'execution': result,
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(KERNEL_REPORT.relative_to(ROOT)): sha(KERNEL_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in [*artifacts, candidate]},
        'hardware_tested': False, 'phone_operations': 'none', 'scope': 'Actual native registration, list insertion, OID allocation, '
        'name resolution and installed handlers expose the unchanged original iPhone scheduled/pool statistics beside the source '
        'user counter. Original initializer and all default POST tests execute. Forty synthetic entropy requests exercise real '
        'original PRNG accounting and one actual user reseed increments only its counter. Platform memory/locks/copy and entropy '
        'collection are explicit instruction-model peers; no target entropy quality or native hardware function is qualified.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: one original PRNG tree, 228 unique paths, 99 actual observations, original accounting and user reseed')


if __name__ == '__main__':main()
