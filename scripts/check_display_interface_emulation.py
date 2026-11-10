#!/usr/bin/env python3
"""Execute real native dispatch probes and unchanged original display methods on an ARM64 CPU model."""
import hashlib
import json
import struct

import unicorn
from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE)
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC

from native_driver_build import ROOT, macho, require, sha, symbols
from native_prelink import backed_offset
from audit_ios16_backend_contracts import BACKEND_DECLARATIONS,emulate_native_dispatch


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())['iphone_display_interface']
    contract_path = ROOT / lock['path']
    require(sha(contract_path) == lock['sha256'], 'Exact display interface contract changed')
    contract = json.loads(contract_path.read_text())
    original = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    require(hashlib.sha256(original).hexdigest() == contract['original_kernelcache_sha256'], 'Original iPhone KC changed')
    image = macho(original)

    def read(address, count):
        at = backed_offset(image['segments'], address, count, len(original))
        return original[at:at + count]

    dimension = contract['dimension_getter']
    getter = read(int(dimension['address'], 16), dimension['bytes'])
    require(hashlib.sha256(getter).hexdigest() == dimension['sha256'], 'Original getter bytes changed')
    hardware = read(int(contract['start_hardware']['address'], 16), 24)
    path = ROOT / 'build/ios16-display-interface/dispatch.o'
    report = json.loads((ROOT / 'reports/ios16-display-interface.json').read_text())
    require(sha(path) == report['native_probe_object_sha256'], 'Native dispatch probe changed')
    obj = path.read_bytes()
    probe_image = macho(obj)
    text, = [s for seg in probe_image['segments'] for s in seg['sections'] if s['name'] == '__text']
    require(struct.unpack_from('<I', obj, text['command_offset'] + 60)[0] == 0, 'Dispatch text has unresolved relocations')
    native_code = obj[text['fileoff']:text['fileoff'] + text['size']]
    functions = {s['name']: s['value'] - text['va'] for s in symbols(obj) if s['name'].startswith('_iphone_') and s['kind'] & 0xe}
    expected_functions={'_iphone_dimensions','_iphone_hardware','_iphone_packet','_iphone_kick','_iphone_complete','_iphone_validate'}
    expected_functions.update('_iphone_backend'+str(slot) for slot in BACKEND_DECLARATIONS)
    require(set(functions)==expected_functions,'Native fourteen-method dispatch probes differ')
    code_base, getter_base, hardware_base, stop = 0x100000, 0x110000, 0x120000, 0x130000
    vtable, instance, output, stack = 0x200000, 0x210000, 0x220000, 0x300000
    # These two leaf methods contain only local branches and data/stack
    # accesses. Their unchanged bytes can run at fixture addresses. The
    # fixture table/object is not an original kernel object or vtable.
    results = []

    def run(kind, null_a=False, null_b=False, wrong_slot=None):
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for address, length in ((code_base, 4096), (getter_base, 4096), (hardware_base, 4096), (stop, 4096),
                                (vtable, 4096), (instance, 8192), (output, 4096), (stack, 16384)):
            machine.mem_map(address, length, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        probe = bytearray(native_code)
        if wrong_slot is not None:
            expected = 246 if kind == 'dimensions' else 274
            positions = [at for at in range(0, len(probe), 4)
                         if struct.unpack_from('<I', probe, at)[0] & 0xffc00000 == 0xf9400000 and
                         ((struct.unpack_from('<I', probe, at)[0] >> 10) & 4095) == expected]
            require(len(positions) == 1, 'Cannot identify the own probe slot-load instruction')
            at, = positions
            word, = struct.unpack_from('<I', probe, at)
            struct.pack_into('<I', probe, at, (word & ~(4095 << 10)) | (wrong_slot << 10))
        machine.mem_write(code_base, bytes(probe))
        machine.mem_write(getter_base, getter)
        machine.mem_write(hardware_base, hardware)
        machine.mem_write(vtable + 246 * 8, struct.pack('<Q', getter_base))
        machine.mem_write(vtable + 274 * 8, struct.pack('<Q', hardware_base))
        machine.mem_write(instance, bytes([0xa5]) * 5728)
        machine.mem_write(instance, struct.pack('<Q', vtable))
        first, second = 0x13579bdf, 0x2468ace0
        machine.mem_write(instance + 5208, struct.pack('<2I', first, second))
        instance_before = bytes(machine.mem_read(instance, 5728))
        machine.mem_write(output, bytes([0xcc]) * 16)
        machine.reg_write(UC_ARM64_REG_X0, instance)
        machine.reg_write(UC_ARM64_REG_X1, 0 if null_a else output)
        machine.reg_write(UC_ARM64_REG_X2, 0 if null_b else output + 4)
        machine.reg_write(UC_ARM64_REG_SP, stack + 0x3f00)
        machine.reg_write(UC_ARM64_REG_LR, stop)
        accesses, instructions = [], []

        def memory_hook(engine, access, address, size, value, user):
            allowed = ((stack <= address and address + size <= stack + 16384) or
                       (output <= address and address + size <= output + 16) or
                       (vtable <= address and address + size <= vtable + 338 * 8) or
                       (instance <= address and address + size <= instance + 5728))
            require(allowed, 'Display method escaped fixture object/stack/output bounds')
            accesses.append((access, address, size))

        machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory_hook)
        machine.hook_add(UC_HOOK_CODE, lambda engine, address, size, user: instructions.append(address))
        entry = code_base + functions['_iphone_dimensions' if kind == 'dimensions' else '_iphone_hardware']
        error = None
        try:
            machine.emu_start(entry, stop, timeout=100000, count=256)
        except UcError as caught:
            error = str(caught)
        if wrong_slot is not None:
            require(error is not None and not any(getter_base <= pc < getter_base + len(getter) or
                    hardware_base <= pc < hardware_base + len(hardware) for pc in instructions),
                    'Wrong-OS dispatch unexpectedly reached an original qualified method')
            results.append({'case': kind + '-wrong-slot-' + str(wrong_slot), 'result': 'REJECTED', 'error': error})
            return
        require(error is None and machine.reg_read(UC_ARM64_REG_PC) == stop, 'ARM64 call did not return normally: ' + str(error))
        require(bytes(machine.mem_read(instance, 5728)) == instance_before, 'Original leaf modified its fixture object')
        if kind == 'dimensions':
            a, b, guard1, guard2 = struct.unpack('<4I', machine.mem_read(output, 16))
            require((a, b) == (0xcccccccc if null_a else first, 0xcccccccc if null_b else second) and
                    guard1 == guard2 == 0xcccccccc, 'Original dimension getter produced wrong output or overwrote a guard')
            require(getter_base in instructions, 'The native probe did not execute the actual original getter')
        else:
            require(machine.reg_read(UC_ARM64_REG_X0) == 0 and hardware_base in instructions,
                    'Original hardware refusal was lost across the native bool call')
        results.append({'case': kind + (f'-null-{int(null_a)}-{int(null_b)}' if kind == 'dimensions' else '-original-refusal'),
                        'result': 'PASS', 'instructions': len(instructions), 'memory_accesses': len(accesses)})

    for null_a in (False, True):
        for null_b in (False, True):
            run('dimensions', null_a, null_b)
    run('hardware')
    run('dimensions', wrong_slot=249)
    run('hardware', wrong_slot=288)
    def dispatch(kind,status=0,original_leaf=False,wrong=False,null_argument=False):
        hook=contract['swap_frontend_hooks'][kind];slot=hook['slot'];target=0x140000
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        windows=((vtable,338*8),(instance,5728),(stack,16384))
        for address,length in ((code_base,4096),(target,4096),(stop,4096),*((p,(n+4095)&~4095) for p,n in windows)):
            machine.mem_map(address,length)
        probe=bytearray(native_code)
        if wrong:
            positions=[at for at in range(0,len(probe),4) if
                struct.unpack_from('<I',probe,at)[0]&0xffc00000==0xf9400000 and
                (struct.unpack_from('<I',probe,at)[0]>>10&4095)==slot]
            require(len(positions)==1,'Cannot identify own frontend-hook slot load')
            at,=positions;word,=struct.unpack_from('<I',probe,at)
            struct.pack_into('<I',probe,at,(word&~(4095<<10))|((slot+1)<<10))
        machine.mem_write(code_base,bytes(probe));machine.mem_write(vtable+slot*8,struct.pack('<Q',target))
        machine.mem_write(instance,struct.pack('<Q',vtable));before=bytes(machine.mem_read(instance,5728))
        if original_leaf:
            require(kind in ('kick','validate'),'Only unchanged local no-op/false hooks may execute here')
            body=read(int(hook['address'],16),hook['bytes'])
            require(hashlib.sha256(body).hexdigest()==hook['sha256'],'Original frontend leaf body changed')
        else:body=struct.pack('<I',0xd65f03c0) # Explicit register-recording peer, never an original method body.
        machine.mem_write(target,body)
        argument=0 if null_argument else 0x123456789abcdef0
        opaque=0xfedcba9876543210;records=[];visited=[]
        machine.reg_write(UC_ARM64_REG_X0,instance);machine.reg_write(UC_ARM64_REG_X1,argument);machine.reg_write(UC_ARM64_REG_X2,opaque)
        machine.reg_write(UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(UC_ARM64_REG_LR,stop)
        def memory(engine,access,address,size,value,user):
            require(any(p<=address and address+size<=p+n for p,n in windows),'Native frontend dispatch escaped exact object/table/stack windows')
        def instruction(engine,address,size,user):
            visited.append(address)
            if address==target:
                records.append(tuple(engine.reg_read(register) for register in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)))
                if not original_leaf:engine.reg_write(UC_ARM64_REG_X0,status)
        machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory);machine.hook_add(UC_HOOK_CODE,instruction)
        error=None
        try:machine.emu_start(code_base+functions['_iphone_'+kind],stop,timeout=100000,count=256)
        except UcError as caught:error=str(caught)
        if wrong:
            require(error is not None and not records,'Wrong sparse hook slot unexpectedly reached a method')
        else:
            require(error is None and machine.reg_read(UC_ARM64_REG_PC)==stop and len(records)==1,'Native frontend hook did not dispatch/return once')
            require(records[0][0]==instance,'Native frontend hook changed self')
            if kind in ('packet','validate'):require(records[0][1]==argument,'Native hook truncated or changed its packet/request pointer')
            if kind=='packet':
                require(records[0][2]==opaque and machine.reg_read(UC_ARM64_REG_X0)&0xffffffff==status&0xffffffff,'Packet hook changed opaque submitter or status')
            if kind=='validate':require(machine.reg_read(UC_ARM64_REG_X0)==(0 if original_leaf else status&1),'Validation hook changed its bool result')
        require(bytes(machine.mem_read(instance,5728))==before,'Native frontend hook dispatch modified its object')
        results.append({'case':kind+('-sparse-wrong-slot' if wrong else '-original-leaf' if original_leaf else '-register-peer-'+hex(status))+('-null' if null_argument else ''),
            'result':'REJECTED' if wrong else 'PASS','original_hook_body_executed':original_leaf,'register_callee_peer':not original_leaf,'instructions':len(visited)})
    for status in (0,0xe00002c7):dispatch('packet',status)
    for null in (False,True):dispatch('validate',original_leaf=True,null_argument=null)
    dispatch('validate',status=1);dispatch('kick',original_leaf=True);dispatch('complete')
    for kind in ('packet','kick','complete','validate'):dispatch(kind,wrong=True)
    backend_path=ROOT/contract['backend_contract'];backend=json.loads(backend_path.read_text())
    backend_pin=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_backend_discovery']
    require(sha(backend_path)==contract['backend_contract_sha256']==backend_pin['sha256'] and
            backend['qualified_raw_call_shapes']==contract['qualified_raw_backend_calls'] and
            backend['original_kernelcache_sha256']==contract['original_kernelcache_sha256'],
            'Native backend probes do not match the exact reviewed caller/body contract')
    backend_cases=emulate_native_dispatch(backend,native_code,functions,read)
    result = {'result': 'IOS16_DISPLAY_FOURTEEN_METHOD_ARM64_EMULATION_PASS', 'emulator': 'Unicorn ' + unicorn.__version__,
        'builder_sha256':sha(ROOT/'scripts/check_display_interface_emulation.py'),
        'interface_report_sha256':sha(ROOT/'reports/ios16-display-interface.json'),
        'native_probe_sha256': sha(path), 'interface_contract_sha256': sha(contract_path),
        'backend_contract_sha256':sha(backend_path),'backend_emulator_sha256':sha(ROOT/'scripts/audit_ios16_backend_contracts.py'),
        'backend_cases':backend_cases,'qualified_virtual_dispatch_slots':report['qualified_virtual_dispatch_slots'],
        'total_case_count':len(results)+len(backend_cases),
        'original_getter_sha256': hashlib.sha256(getter).hexdigest(), 'original_hardware_body_sha256': hashlib.sha256(hardware).hexdigest(),
        'cases': results, 'original_method_bytes_changed': False, 'fixture_own_probe_changed_for_negative_controls': True,
        'negative_controls_use_sparse_fixture_table': True, 'wrong_os_original_vtables_executed': False,
        'real_iokit_instance_constructed': False, 'full_kernel_or_ios_executed': False,
        'stock_controller_is_peer':True,'stock_report_helpers_are_peers':True,
        'original_full_report_or_controller_implementation_executed':False,
        'hardware_tested': False, 'scope': 'Actual native ARM64 virtual-call code reaches unchanged original dimension, hardware-refusal, kick/no-op and validation/false leaves '
            'over a synthetic bounded object/table/stack. Packet/complete/validation-success callees are explicit register peers. '
            'Eight additional native probes execute unchanged stock controller forwarders, scalar leaves and bounded/empty report paths. '
            'Stock controller and report prelude/logging are explicit peers over a separate 7896-byte stock fixture. '
            'Slot 243 arguments and operation/status semantics remain unclassified; no original hardware, full request lifecycle or display operation is claimed.'}
    (ROOT / 'reports/ios16-display-emulation.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: fourteen real ARM64 dispatch probes, '+str(len(results)+len(backend_cases))+' original-body/explicit-peer and sparse wrong-slot CPU cases')


if __name__ == '__main__':
    main()
