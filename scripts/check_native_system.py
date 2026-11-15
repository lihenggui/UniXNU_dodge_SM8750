#!/usr/bin/env python3
"""Execute native owner startup gates and original iPhone entropy request instructions locally."""
import argparse
import json
from pathlib import Path
import struct

from build_native_system import REPORT as SOURCE_REPORT, check_report as check_source
from build_native_entropy import REPORT as TRNG_REPORT, check_report as check_trng
from check_data_mount_kernel import Model
from native_driver_build import ROOT, require, sha

OUT = ROOT / 'build/cph2653-native-system-check'
REPORT = ROOT / 'reports/ios16-native-system-check.json'


def prepare_cases(raw):
    model = Model(raw);selection = {'allowed': True, 'security': 0};events = []
    def allowed(args):events.append('identity');model.returned(int(selection['allowed']))
    def security(args):events.append('security');model.returned(selection['security'])
    model.bind('_dodge_owner_system_allowed', allowed);model.bind('_dodge_native_security_start', security)
    rows = []
    for name, permitted, error, phase in (('foreign-identity', False, 0, 0), ('security-failed', True, 0xe00002cd, 3),
        ('prepared', True, 0, 2)):
        events.clear();selection.update(allowed=permitted, security=error)
        model.put(model.names['_dodge_native_system_phase'], bytes(4))
        model.put(model.names['_dodge_native_system_result'], struct.pack('<I', 0xdeadbeef))
        result = model.call('_dodge_native_system_prepare')
        actual_phase, = struct.unpack('<I', model.read(model.names['_dodge_native_system_phase'], 4))
        actual_result, = struct.unpack('<I', model.read(model.names['_dodge_native_system_result'], 4))
        require(actual_phase == phase and events == (['identity', 'security'] if permitted else ['identity']) and
            (result == error and actual_result == error if permitted else result != 0 and actual_result == 0xdeadbeef),
            'Native system preparation crossed a failed identity/security gate')
        rows.append({'case': name, 'result': 'PASS', 'phase': actual_phase, 'calls': list(events)})
        if permitted:
            events.clear();repeated = model.call('_dodge_native_system_prepare')
            require(repeated != 0 and events == ['identity'] and
                int.from_bytes(model.read(model.names['_dodge_native_system_phase'], 4), 'little') == phase,
                'Native system preparation repeated a latched security operation')
            rows.append({'case': name + '-repeat', 'result': 'REFUSED', 'phase': phase})
    return rows


def iobsd_cases(raw):
    model = Model(raw);events = [];selection = {'result': 0}
    labels = {'_dodge_native_system_prepare': 'owner-security', '_dodge_system_schedule': 'storage',
        '_dodge_data_schedule': 'Data', '_dodge_input_schedule': 'input'}
    def publish(args):
        require(model.string(args[0]) == 'IOBSD' and not args[1], 'Wrong native IOBSD resource')
        events.append('IOBSD');model.returned()
    model.bind('__ZN9IOService15publishResourceEPKcP8OSObject', publish)
    for name, label in labels.items():
        def call(args, label=label):
            events.append(label);model.returned(selection['result'] if label == 'owner-security' else 0)
        model.bind(name, call)
    if '_thread_call_allocate_with_options' in model.names:
        model.bind('_thread_call_allocate_with_options', lambda args: model.returned(model.heap))
    expected = ['IOBSD', 'owner-security', 'storage', 'Data', 'input'];rows = []
    for name, error in (('permitted', 0), ('identity-or-security-refused', 0xe00002cd)):
        events.clear();selection['result'] = error;result = model.call('_IOKitBSDInit')
        require(events == (expected if not error else expected[:2]) and result == (0 if not error else 5),
            'IOBSD scheduled native hardware after a rejected owner/security preparation')
        rows.append({'case': name, 'result': 'PASS', 'calls': list(events), 'IOBSD_return': result})
    # Turn the actual conditional gate into an unconditional success branch in
    # model memory. The refusal assertion must detect the resulting schedules.
    start = model.names['_IOKitBSDInit'];target = model.names['_dodge_native_system_prepare']
    found = []
    for offset, word in enumerate(struct.unpack('<25I', model.read(start, 100))):
        if word & 0xfc000000 != 0x94000000:continue
        delta = word & 0x3ffffff
        if start + offset * 4 + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta) == target:found.append(start + offset * 4 + 4)
    require(len(found) == 1, 'Ambiguous IOBSD security call')
    gate = found[0];word, = struct.unpack('<I', model.read(gate, 4))
    require(word & 0x7e00001f == 0x34000000, 'IOBSD security result is no longer a CBZ/CBNZ on register 0')
    delta = (word >> 5) & 0x7ffff
    if delta & (1 << 18):delta -= 1 << 19
    replacement = 0xd503201f if word & 0x1000000 else 0x14000000 | (delta & 0x3ffffff)
    model.put(gate, struct.pack('<I', replacement));model.cpu.ctl_remove_cache(gate, gate + 4)
    events.clear();selection['result'] = 0xe00002cd
    model.call('_IOKitBSDInit')
    require(events == expected, 'Mutated control did not bypass the gate: ' + repr(events))
    rows.append({'case': 'unconditional-security-success-control', 'result': 'REJECTED',
        'unsafe_calls_observed_only_in_model_control': list(events)})
    return rows


def seedctl_cases(path):
    raw = path.read_bytes();model = Model(raw);rows = []
    # Complete the four verified format-6 constant rebases in model memory.
    values = struct.unpack('<4Q', model.read(0x1000040c8, 32))
    model.put(0x1000040c8, struct.pack('<4Q', *[0x100000000 + (value & ((1 << 36) - 1)) for value in values]))
    model.names['_seedctl_sysctl_query'] = 0x1000036b0
    def query(args):
        size, = struct.unpack('<Q', model.read(args[2], 8))
        require(model.string(args[0]) == 'kern.prng.user_reseed_count' and size == 8 and not args[3] and not args[4],
            'Original seedctl did not query a read-only 64-bit reseed counter')
        rows.append({'case': 'original-sysctlbyname-instructions', 'result': 'PASS', 'output_bytes': size})
        model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
    model.peers[0x100003dbc] = ('sysctlbyname', query)
    model.call('_seedctl_sysctl_query')
    model.names['_seedctl_entropy_query'] = 0x1000038f0
    model.put(model.stack + 0xff000 + 32, struct.pack('<I', 0x1234))
    def request(args):
        size, = struct.unpack('<Q', model.read(args[5], 8))
        require(args[:4] == [0x1234, 0, 0, 0] and size == 32 and model.read(args[4], size) == bytes(32),
            'Original seedctl entropy selector/input/output shape changed')
        rows.append({'case': 'original-IOConnectCallStructMethod-instructions', 'result': 'PASS', 'selector': 0, 'output_bytes': size})
        model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
    model.peers[0x100003cd8] = ('IOConnectCallStructMethod', request)
    model.call('_seedctl_entropy_query')
    require(len(rows) == 2, 'Original entropy client calls were not observed')
    return rows


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_SYSTEM_STARTUP_AND_SEEDCTL_CPU_PASS' and
        len(report['preparation']) == 5 and len(report['IOBSD']) == 3 and len(report['original_seedctl']) == 2 and
        report['root_write_protection'] == {'result': 'PASS', 'write_protected': True} and
        not report['hardware_tested'], 'Incomplete native system CPU checks')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Native system CPU input changed: ' + name)


def main():
    global OUT, REPORT, SOURCE_REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--persistent-data', action='store_true');args = parser.parse_args()
    if args.persistent_data:
        OUT = OUT.with_name(OUT.name + '-persistent');REPORT = REPORT.with_name(REPORT.stem + '-persistent.json')
        SOURCE_REPORT = SOURCE_REPORT.with_name(SOURCE_REPORT.stem + '-persistent.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: native owner/security gate, scheduler refusal and original entropy client CPU paths');return
    source = json.loads(SOURCE_REPORT.read_text());check_source(source)
    require(source['persistent_store_capable'] == args.persistent_data, 'Wrong native store-capability kernel')
    trng = json.loads(TRNG_REPORT.read_text());check_trng(trng)
    candidate = ROOT / source['candidate'];executable = ROOT / 'build/cph2653-native-entropy/prng_seedctl.original'
    require(sha(executable) == trng['original_consumer']['sha256'], 'Original iPhone entropy client changed')
    OUT.mkdir(parents=True, exist_ok=True);raw = candidate.read_bytes()
    root_model = Model(raw);output = root_model.heap + 64
    root_model.put(output, bytes([0xa5]) * 8)
    require(root_model.call('__ZN14NativeUfsBlock21reportWriteProtectionEPb', [0, output]) == 0 and
        root_model.read(output, 8) == b'\x01' + bytes([0xa5]) * 7, 'Native UFS root is not write protected')
    report = {'result': 'IOS16_NATIVE_SYSTEM_STARTUP_AND_SEEDCTL_CPU_PASS', 'preparation': prepare_cases(raw),
        'IOBSD': iobsd_cases(raw), 'original_seedctl': seedctl_cases(executable),
        'root_write_protection': {'result': 'PASS', 'write_protected': True}, 'persistent_store_capable': args.persistent_data,
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (Path(__file__), ROOT / 'scripts/check_data_mount_kernel.py')},
        'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (SOURCE_REPORT, TRNG_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in (candidate, executable)},
        'hardware_tested': False, 'phone_operations': 'none', 'scope': 'Actual native kernel preparation/IOBSD instructions '
        'refuse foreign identities, preserve single-attempt failure latches and never schedule storage/Data/input after failed security. '
        'An unconditional-success model control is detected. Actual original iPhone seedctl instructions request the derived 8-byte '
        'counter and selector-0/32-byte entropy output. Registry/security/scheduler/system-call boundaries are explicit peers; '
        'no physical driver, entropy estimate or full system functionality is qualified.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: ten native startup/refusal and original iPhone seedctl CPU paths')


if __name__ == '__main__':main()
