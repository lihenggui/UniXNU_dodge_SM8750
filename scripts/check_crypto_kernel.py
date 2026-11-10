#!/usr/bin/env python3
"""Execute compiled original-crypto ownership and actual startup/OSKext subpaths with an explicit initializer peer."""
import argparse
import json
from pathlib import Path
import struct

from check_data_mount_kernel import Model
from native_driver_build import ROOT, build_objects, inspect_object, require, symbols
from prepare_initial_data import sha

OUT = ROOT / 'build/cph2653-crypto-kernel'
CASES = ('bootstrap-success', 'direct-success', 'loader-stamped-version', 'explicit-fips-zero', 'fips-one', 'fips-two', 'fips-high',
         'null-module', 'wrong-module', 'wrong-info-version', 'wrong-name', 'wrong-version', 'wrong-header', 'wrong-size',
         'wrong-start', 'wrong-real-entry', 'existing-crypto', 'existing-prng', 'entry-failure', 'entry-partial-failure',
         'missing-crypto', 'missing-prng', 'wrong-prng-context', 'wrong-crypto-table', 'owner-lost-after-success',
         'actual-early-success', 'actual-early-failure', 'actual-early-existing', 'actual-early-fips',
         'actual-oskext-cold', 'actual-oskext-cached', 'actual-oskext-other', 'actual-oskext-cpp-failure')


def layout():
    directory = OUT / 'abi'; directory.mkdir(parents=True, exist_ok=True)
    fields = [('status_bytes', 'sizeof(struct DodgeCryptoStatus)'), *[(name, '__builtin_offsetof(struct DodgeCryptoStatus,' + name + ')')
              for name in ('phase', 'attempts', 'last', 'providerOwned')],
              ('cold', 'DodgeCryptoCold'), ('starting', 'DodgeCryptoStarting'), ('ready', 'DodgeCryptoReady'), ('failed', 'DodgeCryptoFailed'),
              ('success', 'KERN_SUCCESS'), ('failure', 'KERN_FAILURE'), ('invalid', 'KERN_INVALID_ARGUMENT')]
    source = directory / 'CryptoStatusLayout.c'
    source.write_text('#include "DodgeCryptoBootstrap.h"\n#include "DodgeCryptoOnce.h"\nconst unsigned dodge_crypto_status_layout[]={' +
                      ','.join('(unsigned)(' + value + ')' for _, value in fields) + '};\n')
    obj, = build_objects([source], directory, [ROOT / 'drivers/DodgeSecurity'])
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_crypto_status_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(fields)) + 'I', raw, section['fileoff'] + symbol['value'] - section['va'])
    return dict(zip((name for name, _ in fields), values)), obj


def emulate(path, case, facts, mutation=False):
    model = Model(path.read_bytes()); names = model.names
    module = names['_dodge_original_crypto_kmod']; functions = names['_dodge_original_crypto_functions']
    prng_context = names['_dodge_original_crypto_prng_context']
    other, status, kext = model.heap + 0x1000, model.heap + 0x2000, model.heap + 0x3000
    userdata = model.heap + 0x4000
    fixture = {'prng': case in ('existing-prng', 'actual-early-existing'), 'owner': True}
    calls, wrappers, registered, panics, boundaries, others = [], [], [], [], [], []
    malformed = {'wrong-info-version': (8, struct.pack('<I', 2)), 'wrong-name': (16, b'x'),
                 'wrong-version': (80, b'x'), 'wrong-header': (156, struct.pack('<Q', names['_dodge_original_crypto_header'] + 4)),
                 'wrong-size': (164, bytes(8)), 'wrong-start': (180, struct.pack('<Q', names['_dodge_original_crypto_entry'] + 4))}
    if case in malformed:
        offset, data = malformed[case]; model.put(module + offset, data)
    if case == 'loader-stamped-version': model.put(module + 80, b'12.0\0')
    if case == 'wrong-real-entry': model.put(names['_dodge_original_crypto_entry_slot'], bytes(8))
    if case == 'existing-crypto': model.put(names['_g_crypto_funcs'], struct.pack('<Q', functions))
    def parse(args):
        require(model.string(args[0]) == 'fips_mode' and args[2] == 4, 'Crypto bootstrap parsed another option')
        selected = case in ('explicit-fips-zero', 'fips-one', 'fips-two', 'fips-high', 'actual-early-fips')
        if selected:
            value = 0 if case == 'explicit-fips-zero' else 2 if case == 'fips-two' else 0xffffffff if case == 'fips-high' else 1
            model.put(args[1], struct.pack('<I', value))
        model.returned(selected)
    model.bind('_PE_parse_boot_argn', parse)
    model.bind('_dodge_crypto_prng_ready', lambda args: model.returned(fixture['prng']))
    def matches(args):
        require(args[0] == prng_context, 'Crypto owner queried a different original PRNG context')
        model.returned(fixture['prng'] and fixture['owner'])
    model.bind('_dodge_crypto_prng_matches', matches)
    def compare(args):
        require(args[2] <= 64, 'Crypto module comparison exceeded its bounded name/version')
        a, b = model.read(args[0], args[2]), model.read(args[1], args[2]); model.returned((a > b) - (a < b))
    model.bind('_memcmp', compare)
    def observed_wrapper(cpu, pc, size, ignored): wrappers.append(pc)
    model.cpu.hook_add(model.u.UC_HOOK_CODE, observed_wrapper, begin=names['_dodge_original_crypto_entry'], end=names['_dodge_original_crypto_entry'])
    register_address = names['_register_crypto_functions']
    def observed_register(cpu, pc, size, ignored): registered.append(model.register(0))
    model.cpu.hook_add(model.u.UC_HOOK_CODE, observed_register, begin=register_address, end=register_address)
    trampoline = model.stop + 0x1000; model.map(trampoline, 4096)
    def original_entry(args):
        require(args[0] == module and args[1] == (userdata if case == 'direct-success' else 0), 'Original crypto peer received different module/data')
        require(not calls, 'Original crypto initializer ran more than once')
        calls.append([args[0], args[1]])
        fixture['prng'] = case not in ('entry-failure', 'missing-prng')
        fixture['owner'] = case != 'wrong-prng-context'
        result = 77 if case in ('entry-failure', 'entry-partial-failure', 'actual-early-failure') else 0
        if case in ('entry-failure', 'missing-crypto'):
            model.returned(result); return
        pointer = functions + 8 if case == 'wrong-crypto-table' or mutation == 'poison-provider' else functions
        # The explicit original-initializer peer then calls the actual native
        # registration body. Its result/table store is not a registration peer.
        words = (0xa9bf7bfd, 0x910003fd, 0x580000c0, 0x580000f0, 0xd63f0200,
                 0x52800000 | (result << 5), 0xa8c17bfd, 0xd65f03c0)
        model.put(trampoline, struct.pack('<8I2Q', *words, pointer, register_address))
        model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, trampoline)
    model.bind('_dodge_original_crypto_real_entry', original_entry)
    def panic(args):
        require('original corecrypto initialization failed: %d' in model.string(args[0]),
                'Early crypto hit another panic: ' + model.string(args[0]))
        sp = model.cpu.reg_read(model.arm.UC_ARM64_REG_SP)
        panics.append(struct.unpack('<I', model.read(sp, 4))[0]); model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
    model.bind('_panic', panic)
    model.bind('___stack_chk_fail', lambda args: (_ for _ in ()).throw(ValueError('Crypto guard escaped its stack')))
    source = json.loads((ROOT / 'reports/ios16-crypto-source.json').read_text())
    hooks = source['actual_crypto_hooks']
    if mutation == 'api-RET': model.put(names['_dodge_crypto_start_once'], struct.pack('<I', 0xd65f03c0))
    if mutation in ('early-call-NOP', 'OSKext-call-NOP'):
        address = int(hooks['early_owner_call' if mutation == 'early-call-NOP' else 'actual_oskext_owner_reuse'], 16)
        model.put(address, struct.pack('<I', 0xd503201f))
    result = None
    if case.startswith('actual-oskext-'):
        if case == 'actual-oskext-cached': require(model.call('_dodge_crypto_bootstrap') == 0, 'Crypto bootstrap before OSKext failed')
        # Actual OSKext::load stamps CFBundleVersion over the original record
        # before start(), including when the early provider already ran.
        if case in ('actual-oskext-cold', 'actual-oskext-cached'): model.put(module + 80, b'12.0\0')
        begin = int(hooks['original_cpp_call'], 16) + 4
        word, load = struct.unpack('<2I', model.read(begin, 8))
        require(word & 0xff00001f == 0x35000000 and load & 0xffc003ff == 0xf9400260, 'Compiled post-C++ OSKext span changed')
        delta = (word >> 5) & 0x7ffff; boundary = begin + 4 * (delta - (1 << 19) if delta & (1 << 18) else delta)
        field = ((load >> 10) & 4095) * 8
        model.put(kext + field, struct.pack('<Q', other if case == 'actual-oskext-other' else module))
        model.cpu.reg_write(model.arm.UC_ARM64_REG_X19, kext)
        peer = model.stop + 0x500
        pc = int(hooks['actual_oskext_owner_reuse'], 16) - 4
        branch, = struct.unpack('<I', model.read(pc, 4))
        require(branch & 0xff00001f == 0x34000008, 'Compiled OSKext non-crypto branch changed')
        delta = (branch >> 5) & 0x7ffff
        fallback = pc + 4 * (delta - (1 << 19) if delta & (1 << 18) else delta)
        indirect, = struct.unpack('<I', model.read(fallback, 4))
        require(indirect & 0xfffffc1f == 0xd63f0000, 'OSKext non-crypto start no longer calls its original function pointer')
        model.cpu.reg_write(getattr(model.arm, 'UC_ARM64_REG_X' + str((indirect >> 5) & 31)), peer)
        model.names['_other_module_start_peer'] = peer
        def other_start(args):
            require(args[0] == other and args[1] == 0, 'Non-crypto OSKext fallback changed its module/data')
            others.append(args[0]); model.returned(42)
        model.bind('_other_module_start_peer', other_start)
        model.names['_actual_oskext_span'] = begin; model.names['_after_oskext_owner'] = boundary
        def after(args): boundaries.append(model.register(0) & 0xffffffff); model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
        model.bind('_after_oskext_owner', after)
        model.call('_actual_oskext_span', [77 if case == 'actual-oskext-cpp-failure' else 0])
        result = boundaries[0] if boundaries else None
        want = 42 if case == 'actual-oskext-other' else 77 if case == 'actual-oskext-cpp-failure' else 0
        require(boundaries == [want] and len(others) == int(case == 'actual-oskext-other'), 'Actual OSKext ownership span or fallback differs')
    elif case.startswith('actual-early-'):
        model.call('_source_corecrypto14_bootstrap')
        want = [] if case == 'actual-early-success' else [77] if case == 'actual-early-failure' else [4] if case == 'actual-early-fips' else [5]
        require(panics == want, 'Actual early crypto bootstrap did not stop on its failure')
        result = panics[0] if panics else 0
    elif case.startswith(('wrong-', 'null-')) or case == 'direct-success':
        value = 0 if case == 'null-module' else other if case == 'wrong-module' else module
        result = model.call('_dodge_crypto_start_once', [value, userdata if case == 'direct-success' else 0])
    else:
        result = model.call('_dodge_crypto_bootstrap')
    malformed_case = case in malformed or case in ('null-module', 'wrong-module', 'wrong-real-entry')
    fips_bad = case in ('fips-one', 'fips-two', 'fips-high', 'actual-early-fips')
    no_init = malformed_case or fips_bad or case in ('existing-crypto', 'existing-prng', 'actual-early-existing',
                                                   'actual-oskext-other', 'actual-oskext-cpp-failure')
    failed_entry = case in ('entry-failure', 'entry-partial-failure', 'missing-crypto', 'missing-prng', 'wrong-prng-context',
                           'wrong-crypto-table', 'actual-early-failure')
    failed_before = case in ('existing-crypto', 'existing-prng', 'actual-early-existing')
    phase = facts['cold'] if no_init and not failed_before else facts['failed'] if failed_entry or failed_before else facts['ready']
    wanted_result = facts['invalid'] if malformed_case or fips_bad else 77 if case in ('entry-failure', 'entry-partial-failure', 'actual-early-failure',
                    'actual-oskext-cpp-failure') else 42 if case == 'actual-oskext-other' else facts['failure'] if failed_entry or failed_before else facts['success']
    require(result == wanted_result and len(calls) == int(not no_init) and len(wrappers) == len(calls), 'Native crypto return/start count differs: ' + case)
    if not no_init:
        repeat = model.call('_dodge_crypto_start_once', [module, userdata if case == 'direct-success' else 0])
        require(repeat == wanted_result and len(calls) == 1, 'OSKext-style repeat started original crypto again or changed its result')
    if case == 'owner-lost-after-success':
        fixture['owner'] = False
        require(model.call('_dodge_crypto_start_once', [module, 0]) == facts['failure'] and len(calls) == 1, 'Lost original ownership was accepted')
    model.put(status - 32, bytes([0xa5]) * (facts['status_bytes'] + 64))
    model.call('_dodge_crypto_status', [status]); model.call('_dodge_crypto_status', [0])
    def status_field(name): return struct.unpack('<I', model.read(status + facts[name], 4))[0]
    require(status_field('phase') == phase and status_field('attempts') == len(calls) and
            model.read(status - 32, 32) == model.read(status + facts['status_bytes'], 32) == bytes([0xa5]) * 32,
            'Native crypto status phase/attempts or bounds differ')
    provider_pointer, = struct.unpack('<Q', model.read(names['_g_crypto_funcs'], 8))
    require(status_field('providerOwned') == int(provider_pointer == functions and fixture['prng'] and fixture['owner']),
            'Native crypto status accepted a different table/PRNG owner')
    require(model.call('_dodge_crypto_is_original', [module]) == 1 and model.call('_dodge_crypto_is_original', [other]) == 0,
            'Native crypto identity predicate changed')
    expected_registration = int(not no_init and case not in ('entry-failure', 'missing-crypto'))
    require(len(registered) == expected_registration, 'Native crypto table registration body was skipped/repeated')
    return {'case': case, 'result': 'PASS', 'api_or_boundary_return': result, 'phase': phase, 'original_initializer_calls': len(calls),
            'actual_original_start_wrapper_calls': len(wrappers), 'actual_native_table_registration_calls': len(registered),
            'actual_early_panic_codes': panics, 'actual_oskext_span_results': boundaries, 'other_module_start_calls': len(others),
            'original_initializer_post_and_private_prng_state_are_explicit_peers': True,
            'original_crypto_post_executed': False, 'full_oskext_start_executed': False, 'hardware_tested': False}


def check_report(report):
    require(report['result'] == 'IOS16_COMPILED_CRYPTO_OWNER_AND_STARTUP_SUBPATH_ARM64_PASS' and report['builder_sha256'] == sha(Path(__file__)),
            'Crypto CPU report is stale')
    for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Crypto CPU input/artifact changed: ' + filename)
    require(report['case_count'] == len(CASES) == len(report['cases']) and all(row['result'] == 'PASS' for row in report['cases']) and
            len(report['negative_controls']) == 4 and all(row['result'] == 'REJECTED' for row in report['negative_controls']), 'Crypto CPU path evidence differs')
    require(not any(report[key] for key in ('original_crypto_post_executed', 'full_oskext_start_executed', 'original_crypto_runtime_qualified',
            'hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'Crypto CPU scope overstates execution')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    path = ROOT / 'reports/ios16-crypto-kernel.json'
    if args.check_only:
        check_report(json.loads(path.read_text())); print('PASS: preserved actual crypto ownership/startup CPU evidence'); return
    dependency = ROOT / 'reports/ios16-crypto-prelink.json'; source = json.loads(dependency.read_text())
    require(source['builder_sha256'] == sha(ROOT / 'scripts/build_crypto_prelink.py') and source['pointer_sites_read_back'] == 63889,
            'Need the current original crypto strict prelink')
    for filename, value in {**source['source_sha256'], **source['dependency_report_sha256'], **source['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Crypto prelink CPU input changed: ' + filename)
    facts, obj = layout(); candidate = ROOT / source['candidate']
    rows = []
    for case in CASES:
        rows.append(emulate(candidate, case, facts)); print('PASS: compiled crypto owner:', case, flush=True)
    controls = []
    for case, mutation in (('direct-success', 'api-RET'), ('actual-early-success', 'early-call-NOP'),
                           ('actual-oskext-cold', 'OSKext-call-NOP'), ('bootstrap-success', 'poison-provider')):
        try: emulate(candidate, case, facts, mutation)
        except ValueError as error: controls.append({'case': mutation, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Corrupt crypto ownership/startup code or peer was accepted: ' + mutation)
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({'layout': facts, 'cases': rows, 'negative_controls': controls}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'drivers/DodgeSecurity/DodgeCryptoBootstrap.h',
             ROOT / 'drivers/DodgeSecurity/DodgeCryptoOnce.h']
    report = {'result': 'IOS16_COMPILED_CRYPTO_OWNER_AND_STARTUP_SUBPATH_ARM64_PASS', 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files}, 'dependency_report_sha256': {str(dependency.relative_to(ROOT)): sha(dependency)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, evidence)}, 'candidate': str(candidate.relative_to(ROOT)),
        'candidate_sha256': sha(candidate), 'compiler_layout': facts, 'case_count': len(rows), 'cases': rows, 'negative_controls': controls,
        'original_crypto_post_executed': False, 'full_oskext_start_executed': False, 'original_crypto_runtime_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Thirty-three ARM64 paths execute actual compiled owner validation, the unchanged original start wrapper, native table registration '
                 'and bounded actual early-bootstrap or post-C++ OSKext ownership subpaths. Original initializer/POST and private PRNG readiness '
                 'are explicit peers; crypto success is not a runtime qualification. A trampoline makes the initializer peer call actual native '
                 'register_crypto_functions. Cold/cached original OSKext starts call the peer only once; other modules keep their original fallback. '
                 'Four altered-code/provider controls are rejected. Full original initialization/POST, full OSKext/C++ loading and hardware remain unqualified.'}
    path.write_text(json.dumps(report, indent=2) + '\n'); check_report(report)
    print('PASS:', len(rows), 'actual crypto owner/startup ARM64 paths and four rejection controls; original initializer/POST/PRNG peers explicit')


if __name__ == '__main__': main()
