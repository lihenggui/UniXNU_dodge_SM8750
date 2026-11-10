#!/usr/bin/env python3
"""Execute unchanged original HID callers with explicit descriptor/gate peers."""
import json
from pathlib import Path
import struct

from check_ios16_swap import original_input
from native_driver_build import ROOT, require, sha
from native_prelink import backed_offset, macho, unserialize_xml


def emulate(case, control=None):
    import unicorn
    import unicorn.arm64_const as reg
    require(unicorn.__version__ == '2.1.4', 'Use the pinned Unicorn 2.1.4')
    _, raw, image, read = original_input()
    info = next(s for s in image['segments'] if s['name'] == '__PRELINK_INFO')
    entry = next(e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']
                 if e['CFBundleIdentifier'] == 'com.apple.iokit.IOHIDFamily')
    module = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    pages = set()

    def put(a, data=b'', size=0):
        p, last = a & ~4095, (a + max(len(data), size) + 4095) & ~4095
        while p < last:
            if p in pages:
                p += 4096
                continue
            end = p + 4096
            while end < last and end not in pages:
                end += 4096
            uc.mem_map(p, end - p)
            pages.update(range(p, end, 4096))
            p = end
        if data:
            uc.mem_write(a, data)

    for seg in module['segments']:
        if seg['size'] and seg['initprot']:
            data = read(seg['va'], seg['filesize']) if seg['filesize'] else b''
            put(seg['va'], data, seg['size'])
    storage, obj, table, descriptor, expansion, gate, string, stack, halt = (
        0x200000, 0x200040, 0x210000, 0x220000, 0x230000, 0x240000, 0x250000, 0x300000, 0x400000)
    for a, n in ((storage, 4096), (table, 4096), (descriptor, 4096), (expansion, 4096),
                 (gate, 4096), (string, 4096), (stack, 65536), (halt, 4096)):
        put(a, size=n)
    put(storage, b'\xa5' * (208 + 128))
    state = bytearray(208)
    struct.pack_into('<Q', state, 0, table)
    state[176] = int(case != 'report-not-ready')
    struct.pack_into('<Q', state, 200, expansion)
    put(obj, bytes(state))
    put(expansion + 72, struct.pack('<Q', gate))
    pointers = list(struct.unpack('<207Q', read(0xfffffff006cbe2d0, 207 * 8)))
    callback, handle_start, new_descriptor, property_value = halt + 0x100, halt + 0x200, halt + 0x300, halt + 0x400
    pointers[197] = callback if control != 'wrong-dispatch' else pointers[196]
    pointers[168], pointers[180] = handle_start, new_descriptor
    if case.startswith('transport-'):
        pointers[171] = property_value
    if case.startswith('product-'):
        pointers[173] = property_value
    put(table, struct.pack('<207Q', *pointers))
    events = []
    timestamp = 0xfedcba9876543210 if case == 'report-timestamp-high' else 0x12345678
    report_type = {'report-output': 1, 'report-feature': 2}.get(case, 0)
    options = 0x80000001 if case == 'report-high-options' else 0
    wanted_report = 0 if case == 'report-null-forwarding' else descriptor
    result_code = 0xe00002bc if case == 'report-submission-error' else 0
    sp = stack + 65024
    peers = {}

    def args(n=8):
        return [uc.reg_read(getattr(reg, 'UC_ARM64_REG_X' + str(i))) for i in range(n)]

    def returned(value=0):
        uc.reg_write(reg.UC_ARM64_REG_X0, value)
        uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(reg.UC_ARM64_REG_LR))

    def uptime(a):
        put(a[0], struct.pack('<Q', timestamp))
        events.append('uptime-peer')
        returned()

    def enter(a):
        require(a[0] == gate, 'Original HID gate pointer changed')
        events.append('gate-enter-peer')
        returned()

    def leave(a):
        require(a[0] == gate, 'Original HID gate release pointer changed')
        events.append('gate-leave-peer')
        returned()

    def report(a):
        require(a[:5] == [obj, timestamp, wanted_report, report_type, options], 'Original HID report argument dataflow changed')
        events.append('slot-197-report-peer')
        returned(result_code)

    def start(a):
        require(a[:2] == [obj, gate], 'Original handleStart self/provider changed')
        events.append('handle-start-peer')
        returned(int(case != 'descriptor-handle-start-false'))

    def describe(a):
        require(a[:2] == [obj, sp + 24], 'Original descriptor self/output argument changed')
        events.append('new-descriptor-peer')
        target = obj + 32 if control == 'output-alias' else a[1]
        put(target, struct.pack('<Q', 0 if case == 'descriptor-null-output' else descriptor))
        returned(0xe00002bc if case == 'descriptor-error' else 0)

    def property_callback(a):
        require(a[0] == obj, 'Original property getter self changed')
        events.append('property-getter-peer')
        returned(0 if case.endswith('-null') else string)

    peers.update({0xfffffff00575c73c: uptime, 0xfffffff005751e00: enter, 0xfffffff005751e04: leave,
                  callback: report, handle_start: start, new_descriptor: describe, property_value: property_callback})
    if case.startswith('report-'):
        begin, end = 0xfffffff00572a730, halt
        allowed = [(begin, 156)]
        for i, value in enumerate((obj, wanted_report, report_type, options)):
            uc.reg_write(getattr(reg, 'UC_ARM64_REG_X' + str(i)), value)
    elif case.startswith('descriptor-'):
        begin = 0xfffffff005727190
        end = (0xfffffff005727954 if case == 'descriptor-handle-start-false' else
               0xfffffff005727770 if case in ('descriptor-error', 'descriptor-null-output') or control == 'output-alias' else 0xfffffff0057271c8)
        allowed = [(begin, 56)]
        uc.reg_write(reg.UC_ARM64_REG_X19, obj)
        uc.reg_write(reg.UC_ARM64_REG_X20, gate)
    else:
        begin = 0xfffffff005728ea4 if case.startswith('transport-') else 0xfffffff00572903c
        end = (0xfffffff005728ee8 if case.startswith('transport-') else 0xfffffff005729080) if case.endswith('-null') else begin + 24
        allowed = [(begin, 24)]
        uc.reg_write(reg.UC_ARM64_REG_X20, obj)

    def hook(engine, a, n, user):
        if a in peers:
            peers[a](args())
            return
        require(any(start <= a < start + length for start, length in allowed), 'Unqualified HID implementation reached')

    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    uc.reg_write(reg.UC_ARM64_REG_SP, sp)
    uc.reg_write(reg.UC_ARM64_REG_LR, halt)
    uc.emu_start(begin, end, timeout=1000000, count=1000)
    require(uc.reg_read(reg.UC_ARM64_REG_PC) == end, 'Original bounded HID caller did not reach its expected exit')
    require(bytes(uc.mem_read(obj, 208)) == bytes(state), 'Original HID caller changed object storage')
    require(bytes(uc.mem_read(storage, 64)) == b'\xa5' * 64 and bytes(uc.mem_read(obj + 208, 64)) == b'\xa5' * 64, 'HID allocation canary changed')
    if case == 'report-not-ready':
        require(events == ['uptime-peer'] and uc.reg_read(reg.UC_ARM64_REG_X0) == 0xe00002d7, 'Original HID not-ready guard changed')
    elif case.startswith('report-'):
        require(events == ['uptime-peer', 'gate-enter-peer', 'slot-197-report-peer', 'gate-leave-peer'] and
                uc.reg_read(reg.UC_ARM64_REG_X0) == result_code, 'Original report gate/result contract changed')
    elif case.startswith('descriptor-'):
        require(events == ['handle-start-peer'] + ([] if case == 'descriptor-handle-start-false' else ['new-descriptor-peer']), 'Descriptor refusal order changed')
        if case == 'descriptor-success':
            require(uc.reg_read(reg.UC_ARM64_REG_X0) == descriptor, 'Original descriptor caller lost its returned descriptor')
    else:
        require(events == ['property-getter-peer'], 'Original property getter changed')
        if not case.endswith('-null'):
            require(uc.reg_read(reg.UC_ARM64_REG_X24) == string, 'Original getter pointer return changed')
    return {'case': case, 'result': 'PASS', 'events': events, 'complete_original_report_wrapper': case.startswith('report-'),
            'bounded_original_start_or_property_block': not case.startswith('report-'), 'original_iokit_and_gate_implementation_executed': False}


def main():
    source = ROOT / 'reports/ios16-hid-source-interface.json'
    interface = json.loads(source.read_text())
    require('PASS' in interface['result'], 'Prepare bounded HID source interface first')
    for name, digest in interface['source_sha256'].items():
        require(sha(ROOT / name) == digest, 'HID source interface changed: ' + name)
    names = ['report-not-ready', 'report-input', 'report-output', 'report-feature', 'report-high-options', 'report-submission-error',
             'report-timestamp-high', 'report-null-forwarding', 'descriptor-handle-start-false', 'descriptor-error', 'descriptor-null-output',
             'descriptor-success', 'transport-null', 'transport-string', 'product-null', 'product-string']
    cases = [emulate(name) for name in names]
    controls = []
    for case, name, expected in (('report-input', 'wrong-dispatch', 'Unqualified HID implementation reached'),
                                 ('descriptor-success', 'output-alias', 'Original HID caller changed object storage')):
        try:
            emulate(case, name)
        except ValueError as error:
            require(str(error) == expected, 'HID corruption refused for unrelated reason: ' + str(error))
            controls.append({'case': name, 'result': 'REJECTED', 'check': str(error)})
        else:
            raise ValueError('Corrupt HID ABI passed: ' + name)
    out = ROOT / 'build/ios16-hid-source-interface/cpu-cases.json'
    out.write_text(json.dumps({'result': 'PASS', 'cases': cases, 'negative_controls': controls}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/prepare_hid_source_interface.py', ROOT / 'scripts/check_ios16_swap.py']
    report = {'result': 'IOS16_ORIGINAL_HID_REPORT_AND_SOURCE_OVERRIDE_CALLERS_CPU_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files}, 'interface_report_sha256': sha(source),
              'case_count': len(cases), 'cases': cases, 'negative_controls': controls, 'cpu_cases': str(out.relative_to(ROOT)), 'cpu_cases_sha256': sha(out),
              'original_report_wrapper_body_executed': True, 'original_start_and_property_bounded_blocks_executed': True,
              'clock_command_gate_descriptor_and_final_report_are_peers': True, 'complete_original_start_or_hid_parser_executed': False,
              'actual_hid_service_or_ui_execution': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'scope': 'Eight full unchanged original handleReport wrapper paths and eight bounded original descriptor/property caller blocks. '
                       'Checks self/output pointers, timestamp/report/type/options, original ready guard, gate order and return status. '
                       'Clock, gate operations, source callbacks and slot-197 implementation are explicit peers; no original full start, parser or HID service executes.'}
    (ROOT / 'reports/ios16-hid-source-calls.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 16 unchanged original HID report/descriptor/property caller cases and two rejected controls; runtime APIs remain peers')


if __name__ == '__main__':
    main()
