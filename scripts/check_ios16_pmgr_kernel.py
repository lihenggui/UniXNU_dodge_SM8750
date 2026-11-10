#!/usr/bin/env python3
"""Execute the original iPhone PMGR gate and T8015 register path on synthetic resources."""
import argparse
import json
from pathlib import Path
import struct

from check_data_mount_kernel import Model
from native_driver_build import ROOT, require
from prepare_initial_data import sha
from prepare_ios16_pmgr import FIXTURE, KERNEL, OUT, original, reviewed

CASES = ('zero-register', 'mask-already-set', 'all-ones', 'high-bits', 'lowest-bit', 'null-provider', 'base-provider',
         'missing-service', 'wrong-class', 'matching-allocation-failed', 'empty-bank', 'short-region')


def emulate(case, mutation=False):
    contract = json.loads(FIXTURE.read_text()); raw, _, _, _, native = original(); model = Model(raw)
    nub, dictionary, dictionary_table, provider = [model.heap + offset for offset in (0x1000, 0x2000, 0x3000, 0x10000)]
    classes, register = contract['classes'], contract['target_register']
    nub_size, provider_size = classes['ApplePMGRNub']['instance_bytes'], classes['AppleT8015PMGR']['instance_bytes']
    provider_vptr = int(classes['ApplePMGR' if case == 'base-provider' else 'AppleT8015PMGR']['vptr'], 16)
    for address, count in ((nub, nub_size), (provider, provider_size)):
        model.put(address - 64, bytes([0xa5]) * (count + 128)); model.put(address, bytes(count))
    model.put(nub, struct.pack('<Q', int(classes['ApplePMGRNub']['vptr'], 16)))
    model.put(nub + contract['dispatch']['provider_field_offset'], struct.pack('<Q', 0 if case == 'null-provider' else provider))
    model.put(provider, struct.pack('<Q', provider_vptr))
    model.put(provider + register['bank_count_field'], struct.pack('<I', 0 if case == 'empty-bank' else 1))
    resource = provider + register['resource_table_field'] + register['region'] * register['region_stride']
    mmio = 0x900000000
    mmio_address = mmio + register['byte_offset']
    model.map(mmio_address & -4096, 4096)
    model.put(resource + register['resource_pointer_field'], struct.pack('<Q', mmio))
    model.put(resource + register['resource_length_field'], struct.pack('<I', register['byte_offset'] if case == 'short-region' else 1 << 20))
    initial = {'mask-already-set': 4, 'all-ones': 0xffffffff, 'high-bits': 0x87654321, 'lowest-bit': 1}.get(case, 0)
    model.put(mmio_address - 32, bytes([0xa5]) * 68); model.put(mmio_address, struct.pack('<I', initial))
    releases, events, messages, accesses = [], [], [], []
    owned = {}
    release_address, = struct.unpack('<Q', model.read(int(classes['ApplePMGRNub']['vptr'], 16) + 5 * 8, 8))
    model.put(dictionary_table, bytes(512)); model.put(dictionary_table + 5 * 8, struct.pack('<Q', release_address))
    model.put(dictionary, struct.pack('<Q', dictionary_table))
    model.names['_pmgr_release_peer'] = release_address
    def release(args):
        require(args[0] in owned and owned[args[0]] == 1, 'Original gate released an unowned object')
        owned[args[0]] = 0; releases.append(args[0]); model.returned()
    model.bind('_pmgr_release_peer', release)
    for name in ('__ZN9IOService15serviceMatchingEPKcP12OSDictionary', '__ZN9IOService22waitForMatchingServiceEP12OSDictionaryy',
                 '__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass', '_IOLog', '_panic'):
        model.names[name] = native[name]
    def matching(args):
        require(model.string(args[0]) == contract['amfi']['service_class'] and not args[1], 'AMFI matched another power service')
        if case == 'matching-allocation-failed': model.returned(); return
        owned[dictionary] = 1; model.returned(dictionary)
    model.bind('__ZN9IOService15serviceMatchingEPKcP12OSDictionary', matching)
    def waiting(args):
        require(args[0] == (0 if case == 'matching-allocation-failed' else dictionary) and args[1] == contract['amfi']['matching_timeout_ns'],
                'Original PMGR service wait arguments changed')
        if case in ('missing-service', 'matching-allocation-failed'): model.returned(); return
        owned[nub] = 1; model.returned(nub)
    model.bind('__ZN9IOService22waitForMatchingServiceEP12OSDictionaryy', waiting)
    def cast(args):
        require(args[1] == int(classes['ApplePMGRNub']['metaclass'], 16) and args[0] in (nub, 0), 'AMFI typed another PMGR class')
        model.returned(0 if case == 'wrong-class' else args[0])
    model.bind('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass', cast)
    def log(args):
        require(model.string(args[0]) == 'AMFI: PMGRAON latched to: %x\n', 'Original gate logged another message')
        sp = model.cpu.reg_read(model.arm.UC_ARM64_REG_SP)
        messages.append(struct.unpack('<I', model.read(sp, 4))[0]); model.returned()
    model.bind('_IOLog', log)
    def stop(label):
        def reached(args): events.append(label); model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
        return reached
    model.bind('_panic', stop('original-panic-boundary'))
    model.names['_pmgr_success_boundary'] = int(contract['amfi']['success_boundary'], 16)
    model.names['_pmgr_missing_boundary'] = int(contract['amfi']['missing_nub_boundary'], 16)
    model.bind('_pmgr_success_boundary', stop('after-original-pmgr-gate'))
    model.bind('_pmgr_missing_boundary', stop('original-missing-nub-boundary'))
    def mmio_access(cpu, kind, address, size, value, ignored):
        require(address == mmio_address and size == 4, 'Original T8015 path escaped its 32-bit synthetic register')
        accesses.append({'operation': 'write' if kind == model.u.UC_MEM_WRITE else 'read',
                         'bytes': size, 'value': value & 0xffffffff if kind == model.u.UC_MEM_WRITE else None})
    model.cpu.hook_add(model.u.UC_HOOK_MEM_READ | model.u.UC_HOOK_MEM_WRITE, mmio_access,
                       begin=mmio_address & -4096, end=(mmio_address & -4096) + 4095)
    visits = set()
    tracked = {int(contract['dispatch'][key], 16): key for key in ('read_entry', 'write_entry')}
    tracked.update({int(block['address'], 16): name for name, block in contract['blocks'].items()
                    if name not in ('amfi_matching_gate', 'nub_read', 'nub_write')})
    for address, name in tracked.items():
        def observed(cpu, pc, size, ignored, label=name): visits.add(label)
        model.cpu.hook_add(model.u.UC_HOOK_CODE, observed, begin=address, end=address)
    if mutation == 'nub-read-RET': model.put(int(contract['dispatch']['read_entry'], 16), struct.pack('<I', 0xd65f03c0))
    if mutation == 'nub-write-RET': model.put(int(contract['dispatch']['write_entry'], 16), struct.pack('<I', 0xd65f03c0))
    if mutation == 'ipad-read-slot':
        address = int(contract['dispatch']['read_entry'], 16) + 12
        value, = struct.unpack('<I', model.read(address, 4)); model.put(address, struct.pack('<I', value ^ ((312 ^ 320) << 10)))
    if mutation == 'wrong-update-mask': model.put(0xfffffff0056fe794, struct.pack('<I', 0x321d0015))
    model.names['_original_pmgr_gate'] = int(contract['amfi']['entry'], 16)
    model.call('_original_pmgr_gate', limit=100000)
    missing = case in ('missing-service', 'wrong-class', 'matching-allocation-failed')
    panic = case in ('empty-bank', 'short-region')
    fallback = case in ('null-provider', 'base-provider')
    expected_event = 'original-missing-nub-boundary' if missing else 'original-panic-boundary' if panic else 'after-original-pmgr-gate'
    require(events == [expected_event], 'Original PMGR gate reached a wrong boundary: ' + case)
    if missing or panic:
        require(not messages and not accesses, 'Original PMGR failure reached the register or success log')
    else:
        expected = 0xffffffff if fallback else initial | contract['amfi']['value_update_mask']
        require(messages == [expected] and releases == [nub, dictionary] and not any(owned.values()),
                'Original PMGR gate lost its value or owned service/matching references')
        require(model.read(mmio_address, 4) == struct.pack('<I', initial if fallback else expected),
                'Original T8015 gate stored a different value')
        require(accesses == ([] if fallback else [{'operation': 'read', 'bytes': 4, 'value': None},
                                                  {'operation': 'write', 'bytes': 4, 'value': expected}]),
                'Original T8015 gate did not execute the exact read/write register operations')
        if not fallback:
            require({'read_entry', 'write_entry', 'target_read', 'target_write', 'read_wrapper', 'write_wrapper',
                     'resource_lookup', 'region_size', 'generic_read', 'generic_write', 'target_write_override'} <= visits,
                    'Original T8015 path skipped a required dispatch or bank operation')
    for address, count in ((nub, nub_size), (provider, provider_size)):
        require(model.read(address - 64, 64) == model.read(address + count, 64) == bytes([0xa5]) * 64, 'PMGR path escaped synthetic object bounds')
    require(model.read(mmio_address - 32, 32) == model.read(mmio_address + 4, 32) == bytes([0xa5]) * 32,
            'PMGR path escaped the synthetic register')
    return {'case': case, 'result': 'PASS', 'boundary': events[0], 'register_accesses': accesses,
            'initial_register_value': hex(initial), 'logged_value': hex(messages[0]) if messages else None,
            'executed_original_functions': sorted(visits), 'owned_references_remaining_at_terminal_boundary': sum(owned.values()),
            'fault_boundary_may_retain_objects_until_original_panic': missing or panic,
            'base_or_null_fallback_is_not_a_qualifying_provider': fallback,
            'original_register_path_executed': not (missing or panic or fallback),
            'service_allocation_matching_class_membership_logging_are_explicit_peers': True,
            'objects_and_register_resources_are_synthetic': True, 'phone_or_actual_mmio_execution': False}


def check_report(report):
    reviewed()
    require(report['builder_sha256'] == sha(Path(__file__)) and report['case_count'] == 12 and
            report['result'] == 'IOS16_ORIGINAL_PMGR_GATE_AND_T8015_SYNTHETIC_REGISTER_CPU_PASS', 'PMGR CPU report is stale')
    for filename, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == digest, 'PMGR CPU input/artifact changed: ' + filename)
    require(len(report['cases']) == 12 and all(row['result'] == 'PASS' for row in report['cases']) and
            len(report['negative_controls']) == 4 and all(row['result'] == 'REJECTED' for row in report['negative_controls']), 'PMGR CPU cases differ')
    require(json.loads((OUT / 'cpu-cases.json').read_text()) == {'cases': report['cases'], 'negative_controls': report['negative_controls']},
            'PMGR report and CPU evidence differ')
    require(not any(report[key] for key in ('hardware_tested', 'sm8750_security_latch_mapping_derived', 'power_provider_implemented',
            'original_policy_registration_qualified', 'ready_for_ios_boot', 'all_ios_port_code_complete')), 'PMGR CPU scope overstates integration')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    path = ROOT / 'reports/ios16-pmgr-kernel.json'
    if args.check_only:
        check_report(json.loads(path.read_text())); print('PASS: preserved original iPhone PMGR CPU evidence'); return
    dependency = ROOT / 'reports/ios16-pmgr-contract.json'
    abi = json.loads(dependency.read_text())
    require(abi['builder_sha256'] == sha(ROOT / 'scripts/prepare_ios16_pmgr.py'), 'Prepare the current iPhone PMGR contract first')
    for filename, digest in abi['source_sha256'].items(): require(sha(ROOT / filename) == digest, 'PMGR contract input changed: ' + filename)
    rows = [emulate(case) for case in CASES]
    controls = []
    for mutation in ('nub-read-RET', 'nub-write-RET', 'ipad-read-slot', 'wrong-update-mask'):
        try: emulate('zero-register', mutation)
        except ValueError as error: controls.append({'case': mutation, 'result': 'REJECTED', 'reason': str(error)})
        else: raise ValueError('Altered original PMGR path was accepted: ' + mutation)
    evidence = OUT / 'cpu-cases.json'; evidence.write_text(json.dumps({'cases': rows, 'negative_controls': controls}, indent=2) + '\n')
    sources = [Path(__file__), ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'scripts/prepare_ios16_pmgr.py', FIXTURE]
    report = {'result': 'IOS16_ORIGINAL_PMGR_GATE_AND_T8015_SYNTHETIC_REGISTER_CPU_PASS', 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources}, 'dependency_report_sha256': {str(dependency.relative_to(ROOT)): sha(dependency)},
        'artifacts': {str(evidence.relative_to(ROOT)): sha(evidence)}, 'case_count': len(rows), 'cases': rows, 'negative_controls': controls,
        'original_kernelcache_sha256': sha(KERNEL), 'original_t8015_register_load_store_executed': True,
        'sm8750_security_latch_mapping_derived': False, 'power_provider_implemented': False,
        'original_policy_registration_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Twelve paths execute the original AMFI PMGR subpath through original nub/target/bank dispatch and actual ARM64 loads/stores '
                 'to a synthetic register, or original missing/error/fallback boundaries. Objects and resource descriptors are explicit fixtures; '
                 'allocation/matching/class membership/logging are peers. No MMIO method or latch result is supplied by a success peer. '
                 'Five target cases preserve every bit except the original OR 0x4 update. Null/base fallbacks are not qualifying replacements. '
                 'Full AMFI policy initialization, original service start, Qualcomm security semantics and physical hardware remain unqualified.'}
    path.write_text(json.dumps(report, indent=2) + '\n'); check_report(report)
    print('PASS: 12 original iPhone PMGR paths, actual synthetic-register load/store and four altered-code controls')


if __name__ == '__main__': main()
