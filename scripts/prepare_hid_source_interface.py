#!/usr/bin/env python3
"""Prepare only the HID operations used by the source driver; forbid opaque calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from check_ios16_swap import original_input
from native_driver_build import ROOT, NATIVE, build_objects, inspect_object, require, sha, symbols

OUT = ROOT / 'build/ios16-hid-source-interface'
BASE = ROOT / 'profiles/os/ios-16.7.16-20H392/hid-device-abi.json'
HEADER = BASE.parent / 'input/OriginalHidDeviceABI.h'
CONTRACT = BASE.parent / 'hid-source-interface.json'


def header():
    # IOService's virtual signatures are independently fixed by the consuming
    # native kernel. Only four additional HID slots are callable from source.
    text = '''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact iPhone10,3/20H392 table shape. Opaque declarations describe slot
// positions only: their original prototypes are NOT asserted and source
// calls are a compile error. Every inherited pointer is checked at link time.
#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/hid/IOHIDDeviceTypes.h>
#include <libkern/c++/OSString.h>
class IOHIDDevice : public IOService {
    OSDeclareAbstractStructors(IOHIDDevice)
    unsigned char originalPrivate[208-sizeof(IOService)];
public:
    using IOService::setProperty;
    IOReturn Dispatch(IORPC) override;
    void free() override;
    bool init(OSDictionary *properties=nullptr) override;
    bool setProperty(const OSSymbol *,OSObject *) override;
    bool willTerminate(IOService *,IOOptionBits) override;
    IOReturn configureReport(IOReportChannelList *,IOReportConfigureAction,void *,void *) override;
    IOReturn updateReport(IOReportChannelList *,IOReportUpdateAction,void *,void *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    bool handleOpen(IOService *,IOOptionBits,void *) override;
    void handleClose(IOService *,IOOptionBits) override;
    bool handleIsOpen(const IOService *) const override;
    bool matchPropertyTable(OSDictionary *,SInt32 *) override;
    IOReturn message(UInt32,IOService *,void *) override;
    IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) override;
'''
    declarations = {
        171: 'virtual OSString *newTransportString() const;',
        173: 'virtual OSString *newProductString() const;',
        180: 'virtual IOReturn newReportDescriptor(IOMemoryDescriptor **) const=0;',
        181: 'virtual IOReturn handleReport(IOMemoryDescriptor *,IOHIDReportType,IOOptionBits);',
    }
    for slot in range(168, 207):
        text += '    ' + declarations.get(slot, 'virtual void dodgeOpaque' + str(slot) +
                 '() __attribute__((unavailable("Opaque original slot: source calls are forbidden")));') + '\n'
    text += '};\nstatic_assert(sizeof(IOHIDDevice)==208,"Exact original iPhone HID storage");\n'
    return text


def concrete_methods(obj, name):
    raw = obj.read_bytes()
    image, table = inspect_object(raw), symbols(raw)
    symbol, = [s for s in table if s['name'] == '__ZTV' + str(len(name)) + name]
    section = next(s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size'])
    offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56)
    slots = {}
    for i in range(count):
        at, bits = struct.unpack_from('<2I', raw, offset + 8 * i)
        address = section['va'] + at
        if symbol['value'] + 16 <= address < symbol['value'] + 16 + 207 * 8:
            require(bits >> 24 == 14 and (address - symbol['value'] - 16) % 8 == 0, 'Unexpected concrete HID table relocation')
            slot = (address - symbol['value'] - 16) // 8
            require(slot not in slots, 'Duplicate concrete HID table relocation')
            slots[slot] = table[bits & 0xffffff]['name']
    require(set(slots) == set(range(207)), 'Concrete HID table must cover all 207 slots')
    return [slots[i] for i in range(207)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    report = json.loads((ROOT / 'reports/ios16-hid-abi.json').read_text())
    require('PASS' in report['result'] and report['contract_sha256'] == sha(BASE) == lock['iphone_hid_abi']['sha256'], 'Original HID facts are stale')
    for path, digest in report['source_sha256'].items():
        require(sha(ROOT / path) == digest, 'Original HID facts source changed: ' + path)
    if args.write:
        require(not HEADER.exists() and not CONTRACT.exists(), 'Refuse to replace a reviewed HID source interface')
        HEADER.write_text(header())
    require(HEADER.read_text() == header(), 'Bounded HID declarations changed')
    base = json.loads(BASE.read_text())
    _, original, image, read = original_input()
    require(base['original_kernelcache_sha256'] == report['original_kernelcache_sha256'], 'Original HID identity differs')
    # Complete original report wrapper: x1 descriptor, w2 type and w3 options
    # are preserved; getUptime supplies a timestamp; slot 197 receives all five
    # arguments under the original command gate when ready is set.
    blocks = {
        'report_wrapper': (0xfffffff00572a730, 156),
        'handle_start_and_descriptor_callers': (0xfffffff005727190, 56),
        'transport_property_caller': (0xfffffff005728ea4, 48),
        'product_property_caller': (0xfffffff00572903c, 48),
    }
    require(struct.unpack('<4I', read(0xfffffff005727190, 16)) == (0xf9400268, 0xf942a108, 0xaa1303e0, 0xaa1403e1), 'Original handleStart call shape changed')
    require(struct.unpack('<5I', read(0xfffffff0057271a8, 20)) == (0xf9400268, 0xf942d108, 0x910063e1, 0xaa1303e0, 0xd63f0100),
            'Original descriptor caller self/output ABI changed')
    require(struct.unpack('<7I', read(0xfffffff00572a77c, 28)) == (0xf9400268, 0xf9431508, 0xaa1303e0, 0xaa1603e2, 0xaa1503e3, 0xaa1403e4, 0xd63f0100),
            'Original report wrapper dispatch/dataflow changed')
    contract = {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392', 'original_class_contract_sha256': sha(BASE),
                'instance_bytes': 208, 'vtable_entries': 207, 'typed_additional_slots': [171, 173, 180, 181],
                'source_parent_calls_allowed_slots': [14, 86, 87, 181],
                'opaque_additional_slots': [i for i in range(168, 207) if i not in (171, 173, 180, 181)],
                'full_private_prototypes_qualified': False, 'opaque_source_calls_allowed': False,
                'source_does_not_write_original_private_fields': True,
                'blocks': {n: {'address': hex(a), 'bytes': length, 'sha256': hashlib.sha256(read(a, length)).hexdigest()} for n, (a, length) in blocks.items()}}
    if args.write:
        CONTRACT.write_text(json.dumps(contract, indent=2) + '\n')
    require(json.loads(CONTRACT.read_text()) == contract, 'Bounded original HID dataflow contract changed')
    if not args.write:
        pin = lock['iphone_hid_source_interface']
        require(sha(HEADER) == pin['header_sha256'] and sha(CONTRACT) == pin['sha256'], 'Bounded HID interface pin changed')
    OUT.mkdir(parents=True, exist_ok=True)
    probe = OUT / 'DodgeHidInterfaceProbe.cpp'
    probe.write_text('#include "OriginalHidDeviceABI.h"\n'
                     'class DodgeHidInterfaceProbe : public IOHIDDevice {\nOSDeclareDefaultStructors(DodgeHidInterfaceProbe)\npublic:\n'
                     'OSString *newTransportString() const override {return nullptr;}\n'
                     'OSString *newProductString() const override {return nullptr;}\n'
                     'IOReturn newReportDescriptor(IOMemoryDescriptor **out) const override {if(out)*out=nullptr;return kIOReturnUnsupported;}\n};\n'
                     'OSDefineMetaClassAndStructors(DodgeHidInterfaceProbe,IOHIDDevice)\n'
                     'static_assert(sizeof(DodgeHidInterfaceProbe)==208,"Exact base layout");\n')
    include = ROOT / report['generated_iig_header']
    include = include.parents[1]
    target = ROOT / 'sources/iphoneos-sdk/iPhoneOS16.5.sdk/usr/include/TargetConditionals.h'
    objects = build_objects([probe], OUT, [HEADER.parent, include], ['-include', str(target), '-Wno-macro-redefined'])
    methods = concrete_methods(objects[0], 'DodgeHidInterfaceProbe')
    owned = [i for i, name in enumerate(methods) if '22DodgeHidInterfaceProbe' in name]
    require(owned == [0, 1, 7, 171, 173, 180], 'Probe overrides an unqualified HID slot')
    require(not any(name == '___cxa_pure_virtual' for name in methods), 'Concrete HID source probe remains abstract')
    negative = OUT / 'OpaqueCall.cpp'
    negative.write_text('#include "OriginalHidDeviceABI.h"\nvoid forbidden(IOHIDDevice *p){p->dodgeOpaque205();}\n')
    from native_driver_build import compile_command
    cmd = compile_command(negative, OUT / 'invalid.o', [HEADER.parent, include], ['-include', str(target), '-Wno-macro-redefined'])
    process = subprocess.run(cmd['arguments'], cwd=cmd['directory'], capture_output=True, text=True)
    require(process.returncode and 'source calls are forbidden' in process.stderr, 'Opaque HID source call was not refused by the real compiler')
    sources = [Path(__file__), ROOT / 'scripts/native_driver_build.py', BASE, HEADER, CONTRACT, target]
    result = {'result': 'IOS16_BOUNDED_HID_SOURCE_INTERFACE_AND_CONCRETE_TABLE_PASS', 'builder_sha256': sha(Path(__file__)),
              'native_kernel_sha256': sha(NATIVE), 'original_hid_abi_report_sha256': sha(ROOT / 'reports/ios16-hid-abi.json'),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'header': str(HEADER.relative_to(ROOT)), 'header_sha256': sha(HEADER), 'contract': str(CONTRACT.relative_to(ROOT)), 'contract_sha256': sha(CONTRACT),
              'reference_object': str(objects[0].relative_to(ROOT)), 'reference_object_sha256': sha(objects[0]),
              'compile_manifest': str((OUT / 'compile-commands.json').relative_to(ROOT)), 'compile_manifest_sha256': sha(OUT / 'compile-commands.json'),
              'concrete_vtable_entries': 207, 'compiled_probe_instance_bytes': 208, 'owned_probe_slots': owned,
              'typed_additional_slots': [171, 173, 180, 181], 'opaque_additional_slots': contract['opaque_additional_slots'],
              'unknown_slot_source_call_control': 'REJECTED', 'full_private_prototypes_qualified': False,
              'original_private_fields_written': False, 'driver_installed': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'scope': 'A bounded source interface, not a claim of all private HID prototypes. Exact native IOService overrides and four additional used HID slots are declared. '
                       'Other slots are unavailable placeholders used only to preserve the vtable; source calls are a compiler error and actual pointers must be checked when linking. '
                       'The real iOS compiler emits a concrete 207-slot/208-byte probe. No parent implementation is invented, linked or run here.'}
    (ROOT / 'reports/ios16-hid-source-interface.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: bounded iPhone HID interface, actual 207-slot concrete table and rejected opaque call; private ABI remains explicitly limited')


if __name__ == '__main__':
    main()
