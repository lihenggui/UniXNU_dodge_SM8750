#!/usr/bin/env python3
"""Prepare a partial, abstract iPhone Legacy source interface from exact original code."""
import argparse
import hashlib
import json
import struct

from check_ios16_display import derive as derive_classes, validate_fixture, FIXTURE
from native_driver_build import ROOT, build_objects, macho, require, sha, symbols
from native_prelink import backed_offset, exports, unserialize_xml
from audit_ios16_backend_contracts import derive as derive_backend, FIXTURE as BACKEND_FIXTURE

CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/display-interface.json'
HEADER = ROOT / 'profiles/os/ios-16.7.16-20H392/graphics/OriginalLegacyFramebufferABI.h'


def derive():
    classes = derive_classes()
    validate_fixture(classes, json.loads(FIXTURE.read_text()))
    raw = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    image = macho(raw)

    def read(address, count):
        offset = backed_offset(image['segments'], address, count, len(raw))
        return raw[offset:offset + count]

    def branch(pc, link=True):
        word, = struct.unpack('<I', read(pc, 4))
        require(word & 0xfc000000 == (0x94000000 if link else 0x14000000), 'Expected original direct branch')
        value = word & 0x3ffffff
        return pc + 4 * (value - (1 << 26) if value & (1 << 25) else value)

    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'Expected ADRP')
        value = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & ~4095) + ((value - (1 << 21) if value & (1 << 20) else value) << 12)

    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    entry, = [e for e in unserialize_xml(read(info['va'], info['filesize']))['_PrelinkInfoDictionary']
              if e['CFBundleIdentifier'] == 'com.apple.iokit.IOMobileGraphicsFamily']
    module = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
    text, = [s for s in module['segments'] if s['name'] == '__TEXT_EXEC']
    code = read(text['va'], text['filesize'])
    legacy = classes['classes']['IOMobileFramebufferLegacy']
    vp = int(legacy['vptr'], 16)
    methods = struct.unpack('<338Q', read(vp, 338 * 8))
    names = {name: address for address, group in exports(raw, image).items() for name in group}
    native_base = struct.unpack('<168Q', read(names['__ZTV9IOService'] + 16, 168 * 8))
    changed = [i for i, pair in enumerate(zip(native_base, methods)) if pair[0] != pair[1]]
    require(changed == [0, 1, 7, 14, 21, 44, 79, 85, 86, 87, 111, 141, 155], 'Original public lifecycle slots differ')
    constructors = []
    for offset in range(12, len(code) - 64, 4):
        pc = text['va'] + offset
        a, b, c = struct.unpack_from('<3I', code, offset)
        if not (a & 0x9f00001f == 0x90000008 and b & 0xffc003ff == 0x91000108 and c == 0x91004108):
            continue
        if adrp(pc, a) + ((b >> 10) & 4095) + 16 != vp:
            continue
        start = pc - 12
        words = struct.unpack('<19I', read(start, 76))
        require(words[:3] == (0xd100c3ff, 0xa9027bfd, 0x910083fd) and
                words[6:12] == (0xf90007e8, 0xf81f83a0, 0xf9000be1, 0xf85f83a0, 0xf90003e0, 0xf9400be1) and
                words[13:] == (0xf94003e0, 0xf94007e8, 0xf9000008, 0xa9427bfd, 0x9100c3ff, 0xd65f03c0),
                'Original protected Legacy constructor this/metadata path differs')
        constructors.append(start)
    constructor, = constructors
    parent_constructor = branch(constructor + 48)
    require(parent_constructor == 0xfffffff005c0186c and branch(parent_constructor + 48) == 0xfffffff005c01674,
            'Protected Legacy -> Service -> Framebuffer constructor chain differs')
    destructor = constructor + 76
    words = struct.unpack('<11I', read(destructor, 44))
    require(words[:6] == (0xd10083ff, 0xa9017bfd, 0x910043fd, 0xf90007e0, 0xf94007e0, 0xf90003e0) and
            words[7:] == (0xf94003e0, 0xa9417bfd, 0x910083ff, 0xd65f03c0) and
            branch(destructor + 24) == 0xfffffff005c018b8, 'Original protected Legacy destructor chain differs')
    # The abstract class's vtable destructors trap. They are not substitutes
    # for its real protected D2 entry when an owned subclass is destroyed.
    require(struct.unpack('<I', read(methods[0] + 16, 4))[0] == 0xd4200020, 'Expected actual abstract D1 trap')
    getter = methods[246]
    words = struct.unpack('<28I', read(getter, 112))
    require(words[:6] == (0xd10083ff, 0xf9000fe0, 0xf9000be1, 0xf90007e2, 0xf9400fe8, 0xf90003e8) and
            words[11:15] == (0xf94003e8, 0xb9545908, 0xf9400be9, 0xb9000128) and
            words[21:25] == (0xf94003e8, 0xb9545d08, 0xf94007e9, 0xb9000128) and
            words[26:] == (0x910083ff, 0xd65f03c0),
            'Complete original two-output dimension getter differs')
    hardware_call = 0xfffffff005c0d5c0
    words = struct.unpack('<15I', read(hardware_call, 60))
    require(words[:8] == (0xf9404fe0, 0xd282a589, 0xaa0003e8, 0x8b090108, 0x3900011f,
                         0xf9400008, 0xf9444908, 0xd63f0100) and words[8] & 0xff00001f == 0x37000000,
            'Original no-argument bool start_hardware dispatch differs')
    label = b'start_hardware failed\n\0'
    require(read(0xfffffff004f65e41, len(label)) == label, 'Original hardware refusal label differs')
    require(read(methods[274], 24) == struct.pack('<6I', 0xd10043ff, 0xf90007e0, 0x52800008,
            0x12000100, 0x910043ff, 0xd65f03c0), 'Original default hardware backend no longer returns false')
    # Qualify only the frontend hooks with direct original caller/body
    # evidence. These declarations do not implement the nine backend leaves.
    packet_caller=0xfffffff005bfde54
    require(struct.unpack('<7I',read(packet_caller,28))==
        (0xf94007e2,0xf9406c40,0xf9400fe1,0xf9400008,0xf942c908,0xd63f0100,0xb81fc3a0),
        'Original packet dispatch self/packet/opaque submitter/status changed')
    validate_caller=0xfffffff005c165a8
    require(struct.unpack('<10I',read(validate_caller,40))==
        (0xf94067e0,0xf85303a1,0xf9400008,0xf9446908,0xd63f0100,0x52800028,0x0a080008,0x3811f3a8,0x3851f3a8,0x37000288),
        'Original request validation argument/low bool-bit result differs')
    kick_caller=0xfffffff005c16ff8
    require(struct.unpack('<5I',read(kick_caller,20))==(0xf94007e0,0xf9400008,0xf9445108,0xd63f0100,0xb81fc3bf),
        'Original self-only kick dispatch/result ignored shape changed')
    require(struct.unpack('<4I',read(methods[276],16))==(0xd10043ff,0xf90007e0,0x910043ff,0xd65f03c0) and
        struct.unpack('<7I',read(methods[282],28))==(0xd10043ff,0xf90007e0,0xf90003e1,0x52800008,0x12000100,0x910043ff,0xd65f03c0),
        'Original kick/no-op or validation/false default body changed')
    require(methods[178]==0xfffffff005c14930 and methods[281]==0xfffffff005c1ace4 and
        struct.unpack('<11I',read(methods[281],44))==
        (0xd10083ff,0xa9017bfd,0x910043fd,0xf90007e0,0xf94007e0,0x52800028,0x12000101,0x97ffd50b,0xa9417bfd,0x910083ff,0xd65f03c0),
        'Original completion self-only wrapper/true internal argument differs')
    def hook(slot,size,prototype,caller=None,caller_bytes=0):
        result={'slot':slot,'address':hex(methods[slot]),'bytes':size,'sha256':hashlib.sha256(read(methods[slot],size)).hexdigest(),'prototype':prototype}
        if caller is not None:result.update(caller=hex(caller),caller_bytes=caller_bytes,caller_sha256=hashlib.sha256(read(caller,caller_bytes)).hexdigest())
        return result
    # The independent original framework/kernel scalar-method chain names the
    # two words through CGSize conversion; no reference-iPad role is needed.
    role_fixture=ROOT/'profiles/os/ios-16.7.16-20H392/display-userland.json'
    role_pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_userland']
    roles=json.loads(role_fixture.read_text())
    require(sha(role_fixture)==role_pin['sha256'] and roles['original_kernelcache_sha256']==classes['original_kernelcache_sha256'] and
        roles['size_selector']==8 and roles['size_scalar_outputs']==2 and roles['size_display_word_offsets']==[5208,5212],
        'Reviewed original display-size scalar/CGSize role contract differs')
    backend=derive_backend()
    backend_pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_backend_discovery']
    require(sha(BACKEND_FIXTURE)==backend_pin['sha256'] and json.loads(BACKEND_FIXTURE.read_text())==backend and
            backend['original_kernelcache_sha256']==classes['original_kernelcache_sha256'],
            'Reviewed raw backend caller/body contract differs')
    return {'schema_version': 1, 'product': 'iPhone10,3', 'build': '20H392',
        'original_kernelcache_sha256': classes['original_kernelcache_sha256'],
        'legacy_metadata': legacy['metadata'], 'legacy_instance_bytes': 5728, 'legacy_vptr': legacy['vptr'],
        'legacy_virtual_entries': 338, 'abstract_slots': legacy['abstract_slots'], 'lifecycle_override_slots': changed,
        'protected_constructor': hex(constructor), 'protected_constructor_sha256': hashlib.sha256(read(constructor, 76)).hexdigest(),
        'protected_destructor': hex(destructor), 'protected_destructor_sha256': hashlib.sha256(read(destructor, 44)).hexdigest(),
        'abstract_complete_destructor_traps': True,
        'dimension_getter': {'slot': 246, 'address': hex(getter), 'bytes': 112,
            'sha256': hashlib.sha256(read(getter, 112)).hexdigest(), 'output_word_offsets': [5208, 5212],
            'prototype': 'void (self, uint32_t *, uint32_t *)', 'width_height_roles_inferred_from_reference': False,
            'original_size_role_contract':str(role_fixture.relative_to(ROOT)),'original_size_role_contract_sha256':sha(role_fixture)},
        'start_hardware': {'slot': 274, 'address': hex(methods[274]), 'prototype': 'bool (self)',
            'original_default_result': False, 'caller': hex(hardware_call),
            'caller_sha256': hashlib.sha256(read(hardware_call, 60)).hexdigest()},
        'swap_frontend_hooks':{
            'packet':hook(178,5628,'int32_t (self, const void *packet, void *opaque submitter)',packet_caller,28),
            'kick':hook(276,16,'void (self)',kick_caller,20),
            'complete':hook(281,44,'void (self)'),
            'validate':hook(282,28,'bool (self, IOMFBSwapIORequest *)',validate_caller,40)},
        'backend_contract':str(BACKEND_FIXTURE.relative_to(ROOT)),'backend_contract_sha256':sha(BACKEND_FIXTURE),
        'qualified_raw_backend_calls':backend['qualified_raw_call_shapes'],
        'unclassified_backend_argument_slots':backend['unclassified_argument_slots'],
        'all_private_methods_qualified': False}


def header_for(contract):
    header = '''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Partial interface for exact iPhone10,3 / 20H392. This remains abstract.
// Opaque inherited declarations are dispatch placeholders, never source calls.
#pragma once
#include <IOKit/IOService.h>
struct IOMFBSwapIORequest;
class IOMobileFramebufferLegacy : public IOService {
    OSDeclareAbstractStructors(IOMobileFramebufferLegacy)
    unsigned char originalPrivate[5728-sizeof(IOService)];
public:
    void free() override;
    bool init(OSDictionary *properties=nullptr) override;
    IOReturn setProperties(OSObject *) override;
    void systemWillShutdown(IOOptionBits) override;
    IOService *probe(IOService *,SInt32 *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    IOWorkLoop *getWorkLoop() const override;
    IOReturn newUserClient(task_t,void *,UInt32,IOUserClient **) override;
    IOReturn setPowerState(unsigned long,IOService *) override;
'''
    for slot in range(168, 338):
        if slot == 178:
            header += '    virtual IOReturn submitPacket(const void *,void *opaqueSubmitter);\n'
        elif slot == 246:
            header += '    virtual void getDimensionWords(uint32_t *,uint32_t *);\n'
        elif slot == 274:
            header += '    virtual bool startHardware();\n'
        elif slot == 276:
            header += '    virtual void kickSwapQueue();\n'
        elif slot == 281:
            header += '    virtual void completeCurrentSwap();\n'
        elif slot == 282:
            header += '    virtual bool validateSwapRequest(IOMFBSwapIORequest *);\n'
        elif str(slot) in contract['qualified_raw_backend_calls']:
            header += '    virtual '+contract['qualified_raw_backend_calls'][str(slot)]['declaration']+'=0;\n'
        elif slot in contract['abstract_slots']:
            header += f'    virtual __attribute__((deprecated("Raw ABI only; arguments unclassified, never call from source"))) void opaque{slot}()=0;\n'
        else:
            header += f'    virtual __attribute__((deprecated("Unclassified iPhone display ABI; never call from source"))) void opaque{slot}();\n'
    return header + '};\nstatic_assert(sizeof(IOService)==136 && sizeof(IOMobileFramebufferLegacy)==5728,"Exact iPhone Legacy extent");\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record-fixture', action='store_true')
    args = parser.parse_args()
    contract = derive()
    if args.record_fixture:
        require(not CONTRACT.exists() and not HEADER.exists(), 'Reviewed interface inputs already exist')
        CONTRACT.write_text(json.dumps(contract, indent=2) + '\n')
        HEADER.write_text(header_for(contract))
        print('Derived partial abstract Legacy header and exact constructor/getter contract for review')
        return
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_display_interface']
    require(sha(CONTRACT) == lock['sha256'] and sha(HEADER) == lock['header_sha256'], 'Reviewed iPhone interface changed')
    require(json.loads(CONTRACT.read_text()) == contract and HEADER.read_text() == header_for(contract), 'Derived display interface differs')
    out = ROOT / 'build/ios16-display-interface'
    out.mkdir(parents=True, exist_ok=True)
    source = out / 'dispatch.cpp'
    source.write_text('#include "OriginalLegacyFramebufferABI.h"\n'
        'extern "C" void iphone_dimensions(IOMobileFramebufferLegacy *p,uint32_t *a,uint32_t *b) {p->getDimensionWords(a,b);}\n'
        'extern "C" bool iphone_hardware(IOMobileFramebufferLegacy *p) {return p->startHardware();}\n'
        'extern "C" IOReturn iphone_packet(IOMobileFramebufferLegacy *p,const void *a,void *b) {return p->submitPacket(a,b);}\n'
        'extern "C" void iphone_kick(IOMobileFramebufferLegacy *p) {p->kickSwapQueue();}\n'
        'extern "C" void iphone_complete(IOMobileFramebufferLegacy *p) {p->completeCurrentSwap();}\n'
        'extern "C" bool iphone_validate(IOMobileFramebufferLegacy *p,IOMFBSwapIORequest *r) {return p->validateSwapRequest(r);}\n'
        'extern "C" uint32_t iphone_backend211(IOMobileFramebufferLegacy *p,uint32_t a,void *b,uint32_t c) {return p->backend211(a,b,c);}\n'
        'extern "C" uint32_t iphone_backend212(IOMobileFramebufferLegacy *p,uint32_t a,uint32_t *b,void *c) {return p->backend212(a,b,c);}\n'
        'extern "C" uint32_t iphone_backend242(IOMobileFramebufferLegacy *p,void *a,void *b) {return p->backend242(a,b);}\n'
        'extern "C" void iphone_backend292(IOMobileFramebufferLegacy *p,void *a,bool b) {p->backend292(a,b);}\n'
        'extern "C" uint32_t iphone_backend293(IOMobileFramebufferLegacy *p,void *a,void *b) {return p->backend293(a,b);}\n'
        'extern "C" uint32_t iphone_backend321(IOMobileFramebufferLegacy *p,uint32_t a,void *b,uint32_t *c,uint32_t d) {return p->backend321(a,b,c,d);}\n'
        'extern "C" void iphone_backend322(IOMobileFramebufferLegacy *p,uint32_t a) {p->backend322(a);}\n'
        'extern "C" uint32_t iphone_backend329(IOMobileFramebufferLegacy *p) {return p->backend329();}\n')
    obj, = build_objects([source], out, [HEADER.parent], ['-Wno-overloaded-virtual'])
    data = obj.read_bytes()
    image = macho(data)
    text, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
    dispatch_slots={'_iphone_dimensions':246,'_iphone_hardware':274,'_iphone_packet':178,'_iphone_kick':276,'_iphone_complete':281,'_iphone_validate':282}
    dispatch_slots.update({'_iphone_backend'+slot:int(slot) for slot in contract['qualified_raw_backend_calls']})
    functions = sorted((s['value'], s['name']) for s in symbols(data) if s['name'] in dispatch_slots and s['kind'] & 0xe)
    require(len(functions) == len(dispatch_slots), 'Expected fourteen actual native dispatch probes')
    for index, (address, name) in enumerate(functions):
        end = functions[index + 1][0] if index + 1 < len(functions) else text['va'] + text['size']
        at = text['fileoff'] + address - text['va']
        words = struct.unpack('<%dI' % ((end - address) // 4), data[at:at + end - address])
        slot = dispatch_slots[name]
        loads = [((word >> 10) & 4095) * 8 for word in words if word & 0xffc00000 == 0xf9400000]
        require(slot * 8 in loads, 'Native compiler dispatch offset differs from original: ' + name)
    report = {'result': 'IOS16_PARTIAL_DISPLAY_SOURCE_INTERFACE_PASS', 'contract': str(CONTRACT.relative_to(ROOT)),
        'builder_sha256':sha(ROOT/'scripts/prepare_ios16_display_interface.py'),
        'contract_sha256': sha(CONTRACT), 'header': str(HEADER.relative_to(ROOT)), 'header_sha256': sha(HEADER),
        'native_probe_object_sha256': sha(obj), 'native_target': 'arm64-apple-ios16.0',
        'qualified_virtual_dispatch_slots': sorted(dispatch_slots.values()), 'protected_constructor': contract['protected_constructor'],
        'backend_contract_sha256':contract['backend_contract_sha256'],
        'unclassified_backend_argument_slots':contract['unclassified_backend_argument_slots'],
        'protected_destructor': contract['protected_destructor'], 'abstract_complete_destructor_traps': True,
        'object_instantiated': False, 'display_provider_complete': False, 'hardware_tested': False,
        'scope': 'Exact original protected lifetime, six frontend/leaf calls and eight raw backend call shapes with native header/dispatch checks. '
                 'All nine backend methods remain abstract; slot 243 arguments, operation/status semantics, concrete instantiation and full lifecycle remain incomplete.'}
    (ROOT / 'reports/ios16-display-interface.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: abstract iPhone Legacy header, true protected C2/D2, and fourteen native dispatch slots; slot 243 arguments remain open')


if __name__ == '__main__':
    main()
