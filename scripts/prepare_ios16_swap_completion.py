#!/usr/bin/env python3
"""Bind exact iPhone completion and execute bounded CPU paths with lifetime peers."""
import argparse
import hashlib
import json
import struct
import subprocess
import tomllib

from check_ios16_swap import original_input
from native_driver_build import ROOT, NATIVE, build_objects, inspect_object, macho, require, sha, symbols
from native_prelink import backed_offset, exports

FIXTURE = ROOT / 'profiles/os/ios-16.7.16-20H392/display-completion.json'
HEADER = FIXTURE.parent / 'graphics/OriginalLegacySwapCompletionABI.h'


def derive():
    classes, raw, image, read = original_input()
    names = {name: address for address, group in exports(raw, image).items() for name in group}
    legacy = classes['classes']['IOMobileFramebufferLegacy']
    wrapper, = struct.unpack('<Q', read(int(legacy['vptr'], 16) + 281 * 8, 8))
    require(wrapper == 0xfffffff005c1ace4, 'Original completion slot changed')
    words = struct.unpack('<11I', read(wrapper, 44))
    require(words[:7] == (0xd10083ff, 0xa9017bfd, 0x910043fd, 0xf90007e0,
                         0xf94007e0, 0x52800028, 0x12000101) and
            words[8:] == (0xa9417bfd, 0x910083ff, 0xd65f03c0), 'Completion self/true argument path changed')
    require(words[7] & 0xfc000000 == 0x94000000, 'Completion wrapper does not call its body')
    immediate = words[7] & 0x3ffffff
    body = wrapper + 28 + 4 * (immediate - (1 << 26) if immediate & (1 << 25) else immediate)
    require(body == 0xfffffff005c1012c, 'Completion body changed')
    require(struct.unpack('<4I', read(body + 48, 16)) ==
            (0xf81d03a0, 0x52800028, 0x0a080028, 0x381cf3a8), 'Completion bool is not the w1 argument')
    # The original tail releases through request virtual 5, clears Current,
    # wakes the original command gate at &Head with oneThread=false, then clears
    # a family state word. None of those operations is reimplemented here.
    tail = 0xfffffff005c10758
    require(struct.unpack('<18I', read(tail, 72)) == (
        0xf94013e8, 0xf9498500, 0xf9400008, 0xf9401508, 0xd63f0100, 0xf94013e8,
        0xf909851f, 0xf949d900, 0xd2826209, 0x8b090101, 0xf9400008, 0xf9408508,
        0x52800009, 0x12000122, 0xd63f0100, 0xf94013e8, 0xb9148d1f, 0x14000001),
        'Original release/current-clear/gate-wakeup order changed')
    require(struct.unpack('<Q', read(names['__ZTV8OSObject'] + 16 + 5 * 8, 8))[0] ==
            names['__ZNK8OSObject7releaseEv'], 'Original public release slot changed')
    require(struct.unpack('<Q', read(names['__ZTV13IOCommandGate'] + 16 + 33 * 8, 8))[0] ==
            names['__ZN13IOCommandGate13commandWakeupEPvb'], 'Original command gate wakeup slot changed')
    # Prove the gate field is filled by the actual IOCommandGate factory.
    factory_stub = 0xfffffff005c26e90
    a, b, c = struct.unpack('<3I', read(factory_stub, 12))
    require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200,
            'Command gate factory import stub changed')
    displacement = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
    displacement -= (1 << 21) if displacement & (1 << 20) else 0
    pointer = (factory_stub & ~4095) + (displacement << 12) + ((b >> 10) & 4095) * 8
    require(struct.unpack('<Q', read(pointer, 8))[0] ==
            names['__ZN13IOCommandGate11commandGateEP8OSObjectPFiS1_PvS2_S2_S2_E'], 'Wrong original gate factory')
    require(struct.unpack('<4I', read(0xfffffff005c0c4e4, 16)) ==
            (0xd2800001, 0x94006a6a, 0xf9400be8, 0xf909d900), 'Original gate assignment changed')
    # Follow the request's own metaclass allocation into the real protected
    # constructor. Its refcount slots inherit OSObject; free remains private.
    meta_vptr, request_vptr = 0xfffffff006dee5a8, 0xfffffff006dee510
    require(struct.unpack('<Q', read(meta_vptr + 13 * 8, 8))[0] == 0xfffffff005c04a9c,
            'Request metaclass allocation dispatch changed')
    require(struct.unpack('<12I', read(0xfffffff005c04a9c, 48)) == (
        0xd10083ff, 0xa9017bfd, 0x910043fd, 0xf90007e0, 0xd2812f00, 0x94000007,
        0xf90003e0, 0x94000010, 0xf94003e0, 0xa9417bfd, 0x910083ff, 0xd65f03c0),
        'Original request allocation/constructor/size flow changed')
    constructor = 0xfffffff005c04b24
    constructor_words = struct.unpack('<23I', read(constructor, 92))
    require(constructor_words[3:10] == (0xd0008f48, 0x91140108, 0x91004108, 0xf90007e8,
                                      0xf81f83a0, 0xf85f83a0, 0xf9000be0) and
            constructor_words[13] == 0x94008967 and constructor_words[18] == 0x940089c2 and
            constructor_words[14:18] == (0xf94003e0, 0xf94007e8, 0xf9400be9, 0xf9000128),
            'Original request this/vptr installation changed')
    def stub_target(pc):
        x, y, z = struct.unpack('<3I', read(pc, 12))
        require(x & 0x9f00001f == 0x90000010 and y & 0xffc003ff == 0xf9400210 and z == 0xd61f0200,
                'Unexpected request constructor import stub')
        value = ((x >> 5) & 0x7ffff) * 4 + ((x >> 29) & 3)
        value -= (1 << 21) if value & (1 << 20) else 0
        address = (pc & ~4095) + (value << 12) + ((y >> 10) & 4095) * 8
        return struct.unpack('<Q', read(address, 8))[0]
    require(stub_target(0xfffffff005c270f4) == names['__ZN8OSObjectC2EPK11OSMetaClass'] and
            stub_target(0xfffffff005c27274) == names['__ZNK11OSMetaClass19instanceConstructedEv'],
            'Request parent construction/instance registration imports changed')
    refcounts = {2: '__ZNK8OSObject7releaseEi', 3: '__ZNK8OSObject14getRetainCountEv',
                 4: '__ZNK8OSObject6retainEv', 5: '__ZNK8OSObject7releaseEv',
                 9: '__ZNK8OSObject12taggedRetainEPKv', 10: '__ZNK8OSObject13taggedReleaseEPKv',
                 11: '__ZNK8OSObject13taggedReleaseEPKvi'}
    for slot, symbol in refcounts.items():
        require(struct.unpack('<Q', read(request_vptr + slot * 8, 8))[0] == names[symbol],
                'Request refcount method overrides original OSObject: ' + symbol)
    require(struct.unpack('<Q', read(request_vptr + 14 * 8, 8))[0] == 0xfffffff005c04cdc,
            'Private request free hook changed')
    def fingerprint(address,size):
        return {'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
    completion_helpers={name:fingerprint(address,size) for name,address,size in (
        ('request_notification',0xfffffff005c0f538,0x370),('mode_index',0xfffffff005c1a490,0xa4),
        ('mode_word',0xfffffff005c19d5c,0x6c),('statistics',0xfffffff005c1b63c,0x108),('after_completion',0xfffffff005c24c80,16))}
    for slot,name in ((327,'statistics'),(337,'after_completion')):
        require(struct.unpack('<Q',read(int(legacy['vptr'],16)+slot*8,8))[0]==int(completion_helpers[name]['address'],16),
                'Original completion virtual helper changed')
    return {'schema_version': 3, 'product': 'iPhone10,3', 'build': '20H392',
            'original_kernelcache_sha256': classes['original_kernelcache_sha256'],
            'legacy_instance_bytes': 5728, 'completion_slot': 281,
            'wrapper': {'address': hex(wrapper), 'bytes': 44, 'sha256': hashlib.sha256(read(wrapper, 44)).hexdigest(),
                        'prototype': 'void (self)', 'body_bool_register': 'w1', 'body_bool_value': True},
            'body': {'address': hex(body), 'bytes': 1792, 'sha256': hashlib.sha256(read(body, 1792)).hexdigest()},
            'retirement_tail': {'address': hex(tail), 'bytes': 72, 'sha256': hashlib.sha256(read(tail, 72)).hexdigest()},
            'current_offset': 4872, 'head_offset': 4880, 'command_gate_offset': 5040,
            'request_release_slot': 5, 'request_release_overridden': False,
            'request_reference_dispatch_qualified': True, 'request_vptr': hex(request_vptr),
            'request_refcount_slots': {str(slot): symbol for slot, symbol in refcounts.items()},
            'request_constructor': {'address': hex(constructor), 'bytes': 92,
                                    'sha256': hashlib.sha256(read(constructor, 92)).hexdigest()},
            'request_free_hook': hex(0xfffffff005c04cdc), 'request_free_execution_qualified': False,
            'command_gate_wakeup_slot': 33, 'command_gate_one_thread': False,
            'bounded_retirement_cpu':{
                'helpers':completion_helpers,
                'trace_template':fingerprint(0xfffffff004f68210,20),
                'debug_flag_import':fingerprint(0xfffffff006deb458,8),
                'debug_flag_address':hex(struct.unpack('<Q',read(0xfffffff006deb458,8))[0]),
                'stack_guard_import':fingerprint(0xfffffff006deb3b8,8),
                'stack_guard_address':hex(struct.unpack('<Q',read(0xfffffff006deb3b8,8))[0]),
                'frame_counter_offset':172,'last_id_offsets':[5220,5224],
                'background_word_offset':5228,'completion_state_word_offset':5260,
                'mode_index_offset':5448,'mode_word_offset':5452,'statistics_counts_offset':5460,
                'surface_commit_and_lifetime_are_peers':True,'notification_clients_required_empty':True},
            'original_retirement_body_execution_qualified': False,
            'full_original_graphics_lifecycle_qualified': False}


def emulate(contract, obj):
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC
    require(unicorn.__version__ == '2.1.4', 'Use the hash-pinned Unicorn 2.1.4 environment')
    _, _, _, read = original_input()
    data = obj.read_bytes(); image = macho(data); table = symbols(data)
    text, = [section for segment in image['segments'] for section in segment['sections'] if section['name'] == '__text']
    code = bytearray(data[text['fileoff']:text['fileoff'] + text['size']])
    base, wrapper, display, stack, stop = 0x100000, 0x130000, 0x200000, 0x300000, 0x400000
    body = wrapper + int(contract['body']['address'], 16) - int(contract['wrapper']['address'], 16)
    relocation, count = struct.unpack_from('<2I', data, text['command_offset'] + 56)
    require(count == 1, 'Expected one original completion call relocation')
    at, bits = struct.unpack_from('<2I', data, relocation)
    require(bits >> 24 & 1 and bits >> 25 & 3 == 2 and bits >> 27 & 1 and bits >> 28 == 2 and
            table[bits & 0xffffff]['name'] == '_native_iphone_complete_current', 'Unexpected completion relocation')
    instruction, = struct.unpack_from('<I', code, at)
    require(instruction == 0x94000000, 'Expected a plain completion call without addend')
    struct.pack_into('<I', code, at, instruction | (((wrapper - base - at) // 4) & 0x3ffffff))
    function, = [symbol for symbol in table if symbol['name'] == '_iphone_dispatch_completion' and symbol['kind'] & 0xe]
    results = []
    for name, this, expected, current in (
        ('current-A', display, 0x210000, 0x210000), ('current-B', display, 0x220000, 0x220000),
        ('null-display', 0, 0x210000, 0x210000), ('null-expected', display, 0, 0x210000),
        ('no-current', display, 0x210000, 0), ('different-current', display, 0x220000, 0x210000)):
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for address, length in ((base, 4096), (wrapper, 4096), (body & ~4095, 4096),
                                (display, 8192), (stack, 16384), (stop, 4096)):
            machine.mem_map(address, length)
        machine.mem_write(base, bytes(code))
        machine.mem_write(wrapper, read(int(contract['wrapper']['address'], 16), 44))
        content = bytearray([0xa5]) * 5728
        struct.pack_into('<Q', content, 4872, current)
        machine.mem_write(display, bytes(content))
        machine.reg_write(UC_ARM64_REG_X0, this); machine.reg_write(UC_ARM64_REG_X1, expected)
        machine.reg_write(UC_ARM64_REG_SP, stack + 0x3f00); machine.reg_write(UC_ARM64_REG_LR, stop)
        calls = []
        def hook(engine, address, size, user):
            if address == body:
                # A call-trace peer returns immediately. It executes none of
                # the original completion body, release, wakeup or fence code.
                calls.append((engine.reg_read(UC_ARM64_REG_X0), engine.reg_read(UC_ARM64_REG_X1)))
                engine.reg_write(UC_ARM64_REG_PC, engine.reg_read(UC_ARM64_REG_LR))
        def access(engine, kind, address, size, value, user):
            require(display <= address and address + size <= display + 5728 or
                    stack <= address and address + size <= stack + 16384, 'Completion ABI probe escaped fixture memory')
        machine.hook_add(UC_HOOK_CODE, hook)
        machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access)
        machine.emu_start(base + function['value'] - text['va'], stop, timeout=100000, count=256)
        success = bool(this and expected and current == expected)
        require(machine.reg_read(UC_ARM64_REG_PC) == stop and machine.reg_read(UC_ARM64_REG_X0) == success and
                calls == ([(display, 1)] if success else []) and bytes(machine.mem_read(display, 5728)) == bytes(content),
                'Completion argument/refusal/object-preservation mismatch: ' + name)
        results.append({'case': name, 'call_dispatched': success, 'result': 'PASS'})
    # The additional request references use real native C++ virtual calls.
    # These targets are register-trace peers, not OSObject implementations.
    for operation, slot in (('hold', 4), ('drop', 5)):
        function, = [symbol for symbol in table if symbol['name'] == '_iphone_request_' + operation and symbol['kind'] & 0xe]
        for null in (False, True):
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            request, vtable, peer = 0x230000, 0x240000, 0x150000
            for address, length in ((base, 4096), (request, 4096), (vtable, 4096), (peer, 4096), (stack, 16384), (stop, 4096)):
                machine.mem_map(address, length)
            machine.mem_write(base, bytes(code))
            content = bytearray([0xa5]) * 2424
            struct.pack_into('<Q', content, 0, vtable)
            machine.mem_write(request, bytes(content))
            machine.mem_write(vtable + slot * 8, struct.pack('<Q', peer))
            machine.reg_write(UC_ARM64_REG_X0, 0 if null else request)
            machine.reg_write(UC_ARM64_REG_SP, stack + 0x3f00); machine.reg_write(UC_ARM64_REG_LR, stop)
            calls = []
            def ref_hook(engine, address, size, user):
                if address == peer:
                    calls.append(engine.reg_read(UC_ARM64_REG_X0))
                    engine.reg_write(UC_ARM64_REG_PC, engine.reg_read(UC_ARM64_REG_LR))
            def ref_access(engine, kind, address, size, value, user):
                require(request <= address and address + size <= request + 2424 or
                        vtable <= address and address + size <= vtable + 16 * 8 or
                        stack <= address and address + size <= stack + 16384, 'Reference ABI probe escaped fixture memory')
            machine.hook_add(UC_HOOK_CODE, ref_hook)
            machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, ref_access)
            machine.emu_start(base + function['value'] - text['va'], stop, timeout=100000, count=128)
            require(machine.reg_read(UC_ARM64_REG_PC) == stop and calls == ([] if null else [request]) and
                    bytes(machine.mem_read(request, 2424)) == bytes(content), 'Native request refcount dispatch differs')
            results.append({'case': operation + ('-null' if null else '-request'), 'call_dispatched': not null,
                            'virtual_slot': slot, 'result': 'PASS'})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record-fixture', action='store_true')
    args = parser.parse_args(); contract = derive()
    if args.record_fixture:
        require(not FIXTURE.exists(), 'Reviewed completion fixture already exists')
        FIXTURE.write_text(json.dumps(contract, indent=2) + '\n')
        print('Derived exact original completion call and release/wakeup contract for review')
        return
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_display_completion']
    require(sha(FIXTURE) == lock['sha256'] and sha(HEADER) == lock['header_sha256'] and
            json.loads(FIXTURE.read_text()) == contract, 'Reviewed completion interface changed')
    out = ROOT / 'build/ios16-swap-completion'; out.mkdir(parents=True, exist_ok=True)
    source = out / 'completion.cpp'
    source.write_text('#include "OriginalLegacySwapCompletionABI.h"\n'
        'extern "C" bool iphone_dispatch_completion(void *p,IOMFBSwapIORequest *q) '
        '{return IPhone16Swap::dispatchCompletionIfCurrent(p,q);}\n'
        'extern "C" void iphone_request_hold(IOMFBSwapIORequest *q) {IPhone16Swap::retainExtraRequest(q);}\n'
        'extern "C" void iphone_request_drop(IOMFBSwapIORequest *q) {IPhone16Swap::releaseExtraRequest(q);}\n')
    obj, = build_objects([source], out, [HEADER.parent])
    native = NATIVE.read_bytes(); native_image = macho(native)
    native_names = {name: address for address, group in exports(native, native_image).items() for name in group}
    for slot, name in ((4, '__ZNK8OSObject6retainEv'), (5, '__ZNK8OSObject7releaseEv')):
        location = backed_offset(native_image['segments'], native_names['__ZTV8OSObject'] + 16 + slot * 8, 8, len(native))
        require(struct.unpack_from('<Q', native, location)[0] == native_names[name], 'Native OSObject refcount slot differs')
    cases = emulate(contract, obj)
    from ios16_completion_emulation import emulate_body
    body_cases=emulate_body(contract,obj)
    profile = tomllib.loads((FIXTURE.parent / 'profile.toml').read_text())
    slide = int(profile['kernel']['prelink']['slide'], 0)
    target = int(contract['wrapper']['address'], 16) + slide
    assembly = out / 'original-completion-binding.S'
    assembly.write_text(f'.globl _native_iphone_complete_current\n.set _native_iphone_complete_current, {target:#x}\n')
    binding = out / 'original-completion-binding.o'
    subprocess.run([ROOT / '.toolchains/xnu-linux/llvm/bin/clang', '-target', 'arm64-apple-ios16.0',
                    '-c', assembly, '-o', binding], check=True)
    inspect_object(binding.read_bytes())
    require({symbol['name']: symbol['value'] for symbol in symbols(binding.read_bytes()) if symbol['kind'] == 3} ==
            {'_native_iphone_complete_current': target}, 'Absolute completion binding differs from the iPhone slide')
    archive = out / 'libIPhone16SwapCompletion.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, binding], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 'p', archive, binding.name]) == binding.read_bytes(),
            'Original completion binding archive readback differs')
    report = {'result': 'IOS16_ORIGINAL_SWAP_COMPLETION_CALL_AND_BOUNDED_BODY_PASS', 'original_kernelcache_sha256': contract['original_kernelcache_sha256'],
              'native_kernel_sha256': sha(NATIVE), 'builder_sha256': sha(ROOT / 'scripts/prepare_ios16_swap_completion.py'),
              'contract': str(FIXTURE.relative_to(ROOT)), 'contract_sha256': sha(FIXTURE),
              'header': str(HEADER.relative_to(ROOT)), 'header_sha256': sha(HEADER),
              'queue_header_sha256': sha(HEADER.parent / 'OriginalLegacySwapABI.h'),
              'native_probe': str(obj.relative_to(ROOT)), 'native_probe_sha256': sha(obj),
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive), 'slide': slide,
              'binding_address': hex(target), 'arm64_call_cases': cases,
              'arm64_body_cases':body_cases,'bounded_body_case_count':len(body_cases),
              'full_body_paths_executed':sum(case['unchanged_full_body_executed'] for case in body_cases),
              'tail_paths_executed':sum(case['original_tail_executed'] for case in body_cases),
              'body_emulator_sha256':sha(ROOT/'scripts/ios16_completion_emulation.py'),
              'unicorn_version': '2.1.4', 'archive_member_readback': True,
              'native_original_request_refcount_slots_match': True, 'actual_request_refcount_operations_executed': False,
              'original_wrapper_bytes_changed': False, 'original_completion_body_executed': True,
              'original_notification_and_mode_helpers_executed':True,
              'original_request_release_and_gate_are_peers':True,'original_surface_commit_is_peer':True,
              'original_release_clear_wakeup_instructions_executed':True,
              'actual_original_retirement_lifetime_qualified':False,
              'request_released': False, 'gate_wakeup_executed': False, 'fence_signalled': False,
              'full_display_provider_complete': False, 'default_kernel_selected': False, 'hardware_tested': False,
              'scope': 'Exact original wrapper/calling convention and native guarded call/refcount probes. '
                       'Additional bounded CPU cases execute the unchanged full completion body, empty-client notification, mode/statistics helpers and release/current-clear/wakeup instruction order. '
                       'Trace, surface commit, backend report, timestamp, request release and gate wakeup use explicit peers. '
                       'No original reference decrement, destruction, surface fence, gate implementation, full lifecycle or hardware is executed or qualified.'}
    (ROOT / 'reports/ios16-swap-completion.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact iPhone completion/refcount bindings, ten call cases and '+str(len(body_cases))+' bounded body/guard CPU cases; lifetime/fence/gate implementations remain peers')


if __name__ == '__main__':
    main()
