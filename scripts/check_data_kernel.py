#!/usr/bin/env python3
"""Execute the compiled RamBlock I/O method with original-content seed fixtures."""
import json
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, require, symbols, inspect_object, macho
from prepare_initial_data import sha
from prepare_data_image import load_packer
from native_prelink import backed_offset

OUT = ROOT / 'build/cph2653-data-kernel'
FIELDS = ('gate', 'memory', 'capacity', 'online', 'sparse', 'big', 'isBig', 'direct', 'directFailed', 'overlay')
CASES = ('null-buffer', 'null-completion', 'null-action', 'zero-count', 'block-at-end', 'count-overflow',
         'short-buffer', 'bad-direction', 'no-gate', 'offline', 'read-seed', 'read-hole', 'read-cross-page',
         'write-existing', 'write-hole', 'write-cross-page', 'write-last-sector', 'allocate-failure',
         'allocate-partial', 'short-read', 'short-write', 'big-read', 'big-write-no-store', 'sticky-direct-failure',
         'dense-read', 'dense-write')


def layout(source):
    out = OUT / 'abi'
    out.mkdir(parents=True, exist_ok=True)
    original = ROOT / 'sources/UniXNU/drivers/RamBlock/NativeRamBlock.cpp'
    before = original.read_text()
    anchor = '  OSDeclareDefaultStructors(NativeRamBlock)\n'
    require(before.count(anchor) == 1, 'RamBlock layout anchor changed')
    (out / 'NativeRamBlock.cpp').write_text(before.replace(anchor, anchor + 'public: // access annotation only\n'))
    wrapper = ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp'
    annotated = out / wrapper.name
    labels = ['instance_bytes', *FIELDS, 'sparse_pages', 'sparse_bytes', 'sparse_resident', 'big_bytes', 'big_count',
              'big_index', 'big_page', 'completion_bytes', 'completion_target', 'completion_action', 'completion_parameter',
              'success', 'bad_argument', 'not_ready', 'io_error', 'no_memory', 'direction_in', 'direction_out', 'zero_alloc_flags',
              'overlay_readonly', 'overlay_header']
    values = ['sizeof(NativeRamBlock)', *['offsetof(NativeRamBlock,' + name + ')' for name in FIELDS],
              'offsetof(RamSparseDisk,pages)', 'offsetof(RamSparseDisk,bytes)', 'offsetof(RamSparseDisk,resident)',
              'offsetof(SeedDisk,bytes)', 'offsetof(SeedDisk,count)', 'offsetof(SeedDisk,index)', 'offsetof(SeedDisk,page)',
              'sizeof(IOStorageCompletion)', 'offsetof(IOStorageCompletion,target)', 'offsetof(IOStorageCompletion,action)',
              'offsetof(IOStorageCompletion,parameter)', 'kIOReturnSuccess', 'kIOReturnBadArgument', 'kIOReturnNotReady',
              'kIOReturnIOError', 'kIOReturnNoMemory', 'kIODirectionIn', 'kIODirectionOut', 'Z_ZERO',
              'offsetof(persist::Overlay,readOnly)', 'offsetof(persist::Overlay,header)']
    annotated.write_text(wrapper.read_text() + '\nextern "C" const unsigned dodge_data_layout[]={' + ','.join('unsigned(' + v + ')' for v in values) + '};\n')
    commands = json.loads((ROOT / 'build/cph2653-data-source/compile-commands.json').read_text())
    recipe, = [c for c in commands if c['source'] == str(wrapper)]
    args = recipe['arguments'][:]
    obj = out / 'DodgeRamBlock.o'
    args[args.index(str(wrapper))] = str(annotated)
    args[args.index('-o') + 1] = str(obj)
    args += ['-Wno-invalid-' 'offsetof', '-I', str(original.parent)]
    with (out / 'compile.log').open('w') as log:
        result = subprocess.run(args, cwd=recipe['directory'], stdout=log, stderr=subprocess.STDOUT)
    require(not result.returncode, 'RamBlock layout compilation failed: ' + str(out / 'compile.log'))
    def text(path):
        raw = path.read_bytes()
        section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(text(obj) == text(ROOT / 'build/cph2653-data-source/DodgeRamBlock.o'), 'Layout annotation changed production text')
    raw = obj.read_bytes()
    symbol, = [s for s in symbols(raw) if s['name'] == '_dodge_data_layout' and not s['kind'] & 0xe0]
    section, = [s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(labels)) + 'I', raw, section['fileoff'] + symbol['value'] - section['va'])
    return dict(zip(labels, values)), obj


def emulate(candidate, case, facts, inputs, control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__ == '2.1.4', 'Use pinned Unicorn 2.1.4')
    raw = candidate.read_bytes()
    image = macho(raw)
    names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0 and s['kind'] & 14}
    source_object = ROOT / 'build/cph2653-data-source/DodgeRamBlock.late.o'
    source_raw = source_object.read_bytes()
    source_image = inspect_object(source_raw)
    text_section, = [s for seg in source_image['segments'] for s in seg['sections'] if s['name'] == '__text']
    own_names = {s['name'] for s in symbols(source_raw) if not s['kind'] & 0xe0 and s['kind'] & 14 and
                 text_section['va'] <= s['value'] < text_section['va'] + text_section['size'] and not s['name'].startswith('ltmp')}
    text_addresses = sorted({s['value'] for s in symbols(raw) if not s['kind'] & 0xe0 and s['kind'] & 14 and
                             any(t['va'] <= s['value'] < t['va'] + t['size'] for seg in image['segments'] for t in seg['sections'] if t['name'] == '__text')})
    ranges = []
    for name in own_names:
        if name in names:
            start = names[name]
            end = next((a for a in text_addresses if a > start), start + 4)
            ranges.append((start, end))
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    mapped = set()
    def put(address, data=b'', size=0):
        page = address & ~4095
        end = (address + max(len(data), size) + 4095) & ~4095
        while page < end:
            if page in mapped:
                page += 4096; continue
            stop = page + 4096
            while stop < end and stop not in mapped:
                stop += 4096
            uc.mem_map(page, stop - page); mapped.update(range(page, stop, 4096)); page = stop
        if data:
            uc.mem_write(address, data)
    for segment in image['segments']:
        if segment['size'] and segment['initprot']:
            put(segment['va'], raw[segment['fileoff']:segment['fileoff'] + segment['filesize']], segment['size'])
    obj, descriptor, completion, gate, stack, halt, callback, page_array = 0x100040, 0x110040, 0x120040, 0x130040, 0x200000, 0x300000, 0x400000, 0x10000040
    put(obj - 64, b'\xa5' * (facts['instance_bytes'] + 128)); put(obj, bytes(facts['instance_bytes']))
    put(descriptor, struct.pack('<Q', names['__ZTV18IOMemoryDescriptor'] + 16), 256)
    put(completion, bytes(facts['completion_bytes'])); put(gate, size=256)
    put(stack, size=65536); put(halt, size=4096); put(callback, size=4096)
    variant = '' if case.startswith('big-') else '-volatile'
    data = inputs[variant]
    packer, _ = load_packer()
    logical, extents = packer.regions((ROOT / data['packed_image']).read_bytes())
    initial = {((base + at) // 4096): bytes(payload[at:at + 4096]) for base, payload in extents for at in range(0, len(payload), 4096)}
    guards = []
    allocations = []
    next_page = 0x20000040
    def page(value):
        nonlocal next_page
        address = next_page; next_page += 0x3000
        put(address - 64, b'\xa5' * (4096 + 128)); put(address, value)
        guards.append((address - 64, address + 4096)); return address
    def field(name, value, width=8):
        put(obj + facts[name], int(value).to_bytes(width, 'little'))
    field('gate', 0 if case == 'no-gate' else gate)
    field('capacity', logical // 512)
    field('online', case != 'offline', 1)
    put(obj, struct.pack('<Q', names['__ZTV14NativeRamBlock'] + 16))
    if case.startswith('big-'):
        index_array, pointer_array = 0x30000040, 0x31000040
        put(index_array, b''.join(struct.pack('<Q', i) for i in sorted(initial)))
        put(pointer_array, b''.join(struct.pack('<Q', page(initial[i])) for i in sorted(initial)))
        field('isBig', 1, 1)
        for name, value in (('big_bytes', logical), ('big_count', len(initial)), ('big_index', index_array), ('big_page', pointer_array)):
            put(obj + facts['big'] + facts[name], struct.pack('<Q', value))
    elif case.startswith('dense-'):
        field('memory', page(initial[0]))
    else:
        put(page_array - 64, b'\xa5' * 64, logical // 4096 * 8 + 128)
        put(page_array + logical // 4096 * 8, b'\xa5' * 64)
        for i, value in initial.items():
            put(page_array + i * 8, struct.pack('<Q', page(value)))
        for name, value in (('sparse_pages', page_array), ('sparse_bytes', logical), ('sparse_resident', len(initial) * 4096)):
            put(obj + facts['sparse'] + facts[name], struct.pack('<Q', value))
    if case == 'sticky-direct-failure':
        field('direct', 1, 1); field('directFailed', 1, 1)
    target, parameter = 0x12340000, 0x56780000
    for name, value in (('completion_target', target), ('completion_action', 0 if case == 'null-action' else callback), ('completion_parameter', parameter)):
        put(completion + facts[name], struct.pack('<Q', value))
    hole = next(i for i in range(logical // 4096 - 8) if all(i + j not in initial for j in range(8)))
    write = case.startswith('write-') or case in ('allocate-failure', 'allocate-partial', 'short-write', 'big-write-no-store', 'sticky-direct-failure', 'dense-write')
    block, count = 0, 1
    if case in ('read-hole', 'write-hole', 'allocate-failure', 'allocate-partial'):
        block = hole * 8
    if case == 'allocate-partial': count = 16
    if case == 'read-cross-page': block, count = 7, 3
    if case == 'write-cross-page': block, count = hole * 8 + 7, 3
    if case == 'write-last-sector': block = logical // 512 - 1
    if case == 'zero-count': count = 0
    if case == 'block-at-end': block = logical // 512
    if case == 'count-overflow': count = logical // 512 + 1
    length = min(count * 512, 16384)
    buffer = bytearray((i * 31 + 7) & 255 for i in range(length)) if write else bytearray(b'\xcd' * length)
    original_buffer = bytes(buffer)
    direction = facts['direction_out'] if write else facts['direction_in']
    if case == 'bad-direction': direction = 3
    descriptor_length = count * 512 - 1 if case == 'short-buffer' else count * 512
    peers, visits, completions = {}, [], []
    locks = [0, 0]
    def args(n=8):
        return [uc.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i))) for i in range(n)]
    def returned(value=0):
        uc.reg_write(arm.UC_ARM64_REG_X0, value & ((1 << 64) - 1)); uc.reg_write(arm.UC_ARM64_REG_PC, uc.reg_read(arm.UC_ARM64_REG_LR))
    def bind(name, fn):
        require(name in names, 'Missing RamBlock I/O peer: ' + name); peers[names[name]] = (name, fn)
    def lock(a):
        require(a[0] == gate and locks[0] == locks[1], 'Unbalanced RamBlock lock'); locks[0] += 1; returned()
    def unlock(a):
        require(a[0] == gate and locks[0] == locks[1] + 1, 'Unbalanced RamBlock unlock'); locks[1] += 1; returned()
    bind('_lck_mtx_lock', lock); bind('_lck_mtx_unlock', unlock)
    bind('__ZNK18IOMemoryDescriptor9getLengthEv', lambda a: returned(descriptor_length))
    bind('__ZNK18IOMemoryDescriptor12getDirectionEv', lambda a: returned(direction))
    def transfer(a, outgoing):
        require(a[0] == descriptor and a[1] <= len(buffer) and a[3] <= len(buffer) - a[1], 'Descriptor peer exceeded bounds')
        n = min(a[3], 29) if case in ('short-read', 'short-write') else a[3]
        if outgoing:
            put(a[2], bytes(buffer[a[1]:a[1] + n]))
        else:
            buffer[a[1]:a[1] + n] = bytes(uc.mem_read(a[2], n))
        returned(n)
    bind('__ZN18IOMemoryDescriptor9readBytesEyPvy', lambda a: transfer(a, True))
    bind('__ZN18IOMemoryDescriptor10writeBytesEyPKvy', lambda a: transfer(a, False))
    def allocate(a):
        require(a[0] == names['_KHEAP_DEFAULT'] and a[1] == 4096 and a[2] == facts['zero_alloc_flags'],
                'RamBlock allocator heap, page size or zeroing flags differ')
        budget = 0 if case == 'allocate-failure' else 1 if case == 'allocate-partial' else 16
        if len(allocations) >= budget: returned(); return
        address = page(bytes(4096)); allocations.append(address); returned(address)
    bind('_IOMalloc_internal', allocate)
    bind('_bzero', lambda a: (put(a[0], bytes(a[1])), returned()))
    bind('_memcpy', lambda a: (put(a[0], bytes(uc.mem_read(a[1], a[2]))), returned(a[0])))
    def completed(a):
        require(a[0] == target and a[1] == parameter and locks[0] == locks[1], 'Completion ran under the lock or changed context')
        completions.append((a[2] & 0xffffffff, a[3])); returned()
    peers[callback] = ('IOStorageCompletionAction', completed)
    entry = names['__ZN14NativeRamBlock16doAsyncReadWriteEP18IOMemoryDescriptoryyP19IOStorageAttributesP19IOStorageCompletion']
    if control:
        put(entry, struct.pack('<I', 0xd65f03c0))
    def hook(engine, address, size, user):
        if address in peers:
            name, fn = peers[address]; visits.append(name); fn(args()); return
        require(any(start <= address < end for start, end in ranges), 'RamBlock I/O escaped its source functions at ' + hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    for i, value in enumerate((obj, 0 if case == 'null-buffer' else descriptor, block, count, 0, 0 if case == 'null-completion' else completion)):
        uc.reg_write(getattr(arm, 'UC_ARM64_REG_X' + str(i)), value)
    uc.reg_write(arm.UC_ARM64_REG_SP, stack + 0xff00); uc.reg_write(arm.UC_ARM64_REG_LR, halt)
    uc.emu_start(entry, halt, timeout=5000000, count=1000000)
    require(uc.reg_read(arm.UC_ARM64_REG_PC) == halt and locks[0] == locks[1], 'RamBlock I/O did not return/unlock')
    result = uc.reg_read(arm.UC_ARM64_REG_X0) & 0xffffffff
    invalid = case in CASES[:8]
    if invalid:
        require(result == facts['bad_argument'] and not completions and not allocations and not locks[0], 'Bad argument was accepted')
    elif case in ('no-gate', 'offline', 'big-write-no-store'):
        require(result == facts['not_ready'] and not completions and not allocations, 'Unavailable source disk completed an I/O')
    else:
        status = facts['no_memory'] if case.startswith('allocate-') else facts['io_error'] if case in ('short-read', 'short-write', 'sticky-direct-failure') else facts['success']
        actual = 0 if case in ('allocate-failure', 'sticky-direct-failure') else 4096 if case == 'allocate-partial' else 29 if case in ('short-read', 'short-write') else count * 512
        require(result == facts['success'] and completions == [(status, actual)], 'Source completion status or byte count differs: ' + str((result, completions, status, actual)))
        if not write and case != 'short-read':
            with (ROOT / data['image']).open('rb') as stream:
                stream.seek(block * 512); expected = stream.read(count * 512)
            require(buffer == expected, 'Source I/O differs from the original-content APFS image')
        if write and status == facts['success']:
            if case.startswith('dense-'):
                pointer = int.from_bytes(bytes(uc.mem_read(obj + facts['memory'], 8)), 'little')
                observed = bytes(uc.mem_read(pointer + block * 512, len(buffer)))
            else:
                observed = bytearray()
                at = block * 512
                while len(observed) < len(buffer):
                    pointer = int.from_bytes(bytes(uc.mem_read(page_array + (at // 4096) * 8, 8)), 'little')
                    n = min(4096 - at % 4096, len(buffer) - len(observed))
                    observed += bytes(uc.mem_read(pointer + at % 4096, n)); at += n
            require(observed == original_buffer, 'Source write stored different bytes')
    require(bytes(uc.mem_read(obj - 64, 64)) == b'\xa5' * 64 and
            bytes(uc.mem_read(obj + facts['instance_bytes'], 64)) == b'\xa5' * 64, 'Source driver canary changed')
    for before, after in guards:
        require(bytes(uc.mem_read(before, 64)) == bytes(uc.mem_read(after, 64)) == b'\xa5' * 64, 'Source page canary changed')
    if not case.startswith(('big-', 'dense-')):
        require(bytes(uc.mem_read(page_array - 64, 64)) == bytes(uc.mem_read(page_array + logical // 4096 * 8, 64)) == b'\xa5' * 64,
                'Sparse pointer-array canary changed')
    return {'case': case, 'result': 'PASS', 'return': hex(result), 'completions': completions,
            'balanced_lock_pairs': locks[0], 'allocated_pages': len(allocations), 'explicit_peers': sorted(set(visits))}


def lifetime(candidate, facts, poison=False, init_case=None):
    import unicorn
    import unicorn.arm64_const as arm
    raw = candidate.read_bytes(); image = macho(raw)
    names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0 and s['kind'] & 14}
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    for segment in image['segments']:
        if segment['size'] and segment['initprot']:
            size = (segment['size'] + 4095) & ~4095
            uc.mem_map(segment['va'], size); uc.mem_write(segment['va'], raw[segment['fileoff']:segment['fileoff'] + segment['filesize']])
    obj, stack, halt = 0x100040, 0x200000, 0x300000
    uc.mem_map(obj & ~4095, 4096); uc.mem_map(stack, 65536); uc.mem_map(halt, 4096)
    uc.mem_write(obj - 64, b'\xa5' * (facts['instance_bytes'] + 128))
    uc.mem_write(obj, (b'\x5a' if poison else b'\x00') * facts['instance_bytes'])
    functions = {name: (names[symbol], length) for name, symbol, length in (
        ('IOService.C2', '__ZN9IOServiceC2EPK11OSMetaClass', 32), ('IORegistryEntry.C2', '__ZN15IORegistryEntryC2EPK11OSMetaClass', 32),
        ('OSObject.C2', '__ZN8OSObjectC2EPK11OSMetaClass', 40), ('OSMetaClassBase.C2', '__ZN15OSMetaClassBaseC2Ev', 16),
        ('IOService.D2', '__ZN9IOServiceD2Ev', 4), ('IORegistryEntry.D2', '__ZN15IORegistryEntryD2Ev', 4),
        ('OSObject.D2', '__ZN8OSObjectD2Ev', 4), ('OSMetaClassBase.D2', '__ZN15OSMetaClassBaseD2Ev', 12))}
    fixture = json.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/storage-abi.json').read_text())
    slide = int(fixture['slide'], 0)
    functions['original-storage.C2'] = (int(fixture['protected_constructor'], 16) + slide, 32)
    functions['original-storage.D2'] = (int(fixture['protected_destructor'], 16) + slide, 4)
    def branch(address, link):
        word, = struct.unpack('<I', bytes(uc.mem_read(address, 4)))
        require(word & 0xfc000000 == (0x94000000 if link else 0x14000000), 'Original parent import branch changed')
        delta = word & 0x3ffffff
        return address + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
    functions['original-storage.C2-import'] = (branch(functions['original-storage.C2'][0] + 8, True), 12)
    functions['original-storage.D2-import'] = (branch(functions['original-storage.D2'][0], False), 12)
    for name in ('__ZN14NativeRamBlockC1Ev', '__ZN14NativeRamBlockD1Ev', '__ZNK14NativeRamBlock12getMetaClassEv'):
        start = names[name]; functions[name] = (start, min(a for a in names.values() if a > start) - start)
    visits, accounting, init_events = [], [], []
    init_address = names['__ZN20IOBlockStorageDevice4initEP12OSDictionary']
    if init_case:
        functions['original-storage.init'] = (init_address, 88)
    parent_init_address, = struct.unpack('<Q', bytes(uc.mem_read(names['__ZTV9IOService'] + 16 + 21 * 8, 8)))
    dictionary = 0x12345678
    def returned(value):
        uc.reg_write(arm.UC_ARM64_REG_X0, value); uc.reg_write(arm.UC_ARM64_REG_PC, uc.reg_read(arm.UC_ARM64_REG_LR))
    def cstring(address):
        result = bytearray()
        for i in range(64):
            byte = bytes(uc.mem_read(address + i, 1))
            if byte == b'\0': return result.decode()
            result += byte
        raise ValueError('Unbounded original storage init property')
    def hook(engine, address, size, user):
        if address == names['__ZNK11OSMetaClass19instanceConstructedEv']:
            accounting.append(uc.reg_read(arm.UC_ARM64_REG_X0)); uc.reg_write(arm.UC_ARM64_REG_PC, uc.reg_read(arm.UC_ARM64_REG_LR)); return
        if init_case and address == parent_init_address:
            require(uc.reg_read(arm.UC_ARM64_REG_X0) == obj and uc.reg_read(arm.UC_ARM64_REG_X1) == dictionary, 'Original storage init changed parent self/dictionary')
            init_events.append('native-parent-init-peer'); returned(int(init_case != 'init-parent-failure')); return
        if init_case and address == names['__ZN15IORegistryEntry11setPropertyEPKcS1_']:
            require(uc.reg_read(arm.UC_ARM64_REG_X0) == obj and cstring(uc.reg_read(arm.UC_ARM64_REG_X1)) == 'device-type' and
                    cstring(uc.reg_read(arm.UC_ARM64_REG_X2)) == 'Generic', 'Original storage init property changed')
            init_events.append('registry-string-property-peer'); returned(int(init_case != 'init-property-failure')); return
        require(any(start <= address < start + length for start, length in functions.values()), 'RamBlock constructor left its bounded original/source/native code: ' + hex(address))
        visits.extend(name for name, (start, length) in functions.items() if start == address)
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(name, properties=0):
        uc.reg_write(arm.UC_ARM64_REG_X0, obj); uc.reg_write(arm.UC_ARM64_REG_SP, stack + 0xff00); uc.reg_write(arm.UC_ARM64_REG_LR, halt)
        uc.reg_write(arm.UC_ARM64_REG_X1, properties)
        uc.emu_start(names[name], halt, timeout=1000000, count=20000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC) == halt, 'RamBlock constructor/destructor did not return')
    execute('__ZN14NativeRamBlockC1Ev')
    expected = bytearray(facts['instance_bytes'])
    struct.pack_into('<Q', expected, 0, names['__ZTV14NativeRamBlock'] + 16)
    struct.pack_into('<I', expected, 8, 1)
    expected[facts['overlay'] + facts['overlay_readonly']] = 1
    struct.pack_into('<I', expected, facts['overlay'] + facts['overlay_header'], 0xffffffff)
    require(bytes(uc.mem_read(obj, len(expected))) == expected, 'RamBlock constructor did not produce canonical object bytes')
    require(accounting == [names['__ZN14NativeRamBlock10gMetaClassE']], 'RamBlock constructor accounted a different class')
    execute('__ZNK14NativeRamBlock12getMetaClassEv')
    require(uc.reg_read(arm.UC_ARM64_REG_X0) == names['__ZN14NativeRamBlock10gMetaClassE'], 'RamBlock source class identity changed')
    if init_case:
        execute('__ZN20IOBlockStorageDevice4initEP12OSDictionary', dictionary)
        require(uc.reg_read(arm.UC_ARM64_REG_X0) == int(init_case == 'init-success') and
                init_events == ['native-parent-init-peer'] + ([] if init_case == 'init-parent-failure' else ['registry-string-property-peer']),
                'Original storage init failure/result order changed')
    execute('__ZN14NativeRamBlockD1Ev')
    struct.pack_into('<Q', expected, 0, (1 << 64) - 1)
    require(bytes(uc.mem_read(obj, len(expected))) == expected, 'RamBlock destructor changed other object storage')
    require(all(visits.count(name) == 1 for name in functions), 'RamBlock source/original/native parent constructor chain differs')
    require(bytes(uc.mem_read(obj - 64, 64)) == bytes(uc.mem_read(obj + facts['instance_bytes'], 64)) == b'\xa5' * 64, 'RamBlock lifetime canary changed')
    return {'case': init_case or 'source-original-native-C1-D1', 'result': 'PASS', 'original_parent_C2_D2_executed': True,
            'original_storage_init_executed': bool(init_case), 'init_peers': init_events,
            'instance_bytes': facts['instance_bytes'], 'visited': visits, 'explicit_peer': 'OSMetaClass::instanceConstructed accounting; native parent init and registry property only for init cases'}


def main():
    OUT.mkdir(exist_ok=True)
    path = ROOT / 'reports/ios16-data-source.json'
    source = json.loads(path.read_text())
    prelink_path = ROOT / 'reports/ios16-data-prelink.json'
    prelink = json.loads(prelink_path.read_text())
    candidate = ROOT / prelink['candidate']
    require(source['builder_sha256'] == sha(ROOT / 'scripts/build_data_source.py') and
            prelink['builder_sha256'] == sha(ROOT / 'scripts/build_data_prelink.py') and
            prelink['dependency_report_sha256'][str(path.relative_to(ROOT))] == sha(path) and
            sha(candidate) == prelink['candidate_sha256'], 'Data source/prelink candidate is stale')
    for name, digest in source['source_sha256'].items():
        require(sha(ROOT / name) == digest, 'Data native source changed: ' + name)
    inputs = {variant: json.loads((ROOT / ('reports/ios16-data' + variant + '-image.json')).read_text()) for variant in ('', '-volatile')}
    for data in inputs.values():
        require(sha(ROOT / data['packed_image']) == data['artifacts'][data['packed_image']], 'Data seed changed')
    facts, obj = layout(source)
    require(facts['instance_bytes'] == source['compiled_instance_bytes'] == 352, 'Data source instance size changed')
    cases = [emulate(candidate, case, facts, inputs) for case in CASES]
    cases.append(lifetime(candidate, facts))
    cases.extend(lifetime(candidate, facts, init_case=case) for case in ('init-parent-failure', 'init-property-failure', 'init-success'))
    try:
        emulate(candidate, 'read-seed', facts, inputs, control=True)
    except ValueError as error:
        control = {'case': 'source-I/O-entry-ret', 'result': 'REJECTED', 'reason': str(error)}
    else:
        raise ValueError('Removing source I/O entry was accepted')
    try:
        lifetime(candidate, facts, poison=True)
    except ValueError as error:
        require('canonical object bytes' in str(error), 'Poisoned allocation control failed another check')
        allocation_control = {'case': 'noncanonical-poisoned-allocation', 'result': 'REJECTED', 'reason': str(error)}
    else:
        raise ValueError('Poisoned RamBlock allocation was accepted')
    cpu_cases = OUT / 'cpu-cases.json'
    cpu_cases.write_text(json.dumps(cases, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'drivers/DodgeStorage/DodgeRamBlock.cpp', ROOT / 'sources/UniXNU/drivers/RamBlock/NativeRamBlock.cpp',
             *[ROOT / 'sources/UniXNU/drivers/RamBlock' / name for name in ('SparseDisk.h', 'SeedDisk.h', 'DirectDisk.h', 'PersistOverlay.h')]]
    report = {'result': 'IOS16_ACTUAL_SOURCE_RAMBLOCK_IO_ARM64_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in [path, prelink_path, *[ROOT / ('reports/ios16-data' + variant + '-image.json') for variant in inputs]]},
              'candidate': prelink['candidate'], 'candidate_sha256': sha(candidate), 'instance_layout': facts,
              'annotation_text_identical_to_production': True, 'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, cpu_cases)},
              'case_count': len(cases), 'cases': cases, 'negative_controls': [control, allocation_control],
              'actual_original_storage_protected_constructor_and_destructor_executed': True,
              'original_storage_parent_init_executed_with_native_init_and_registry_peers': True,
              'original_storage_parent_start_or_free_executed': False, 'hardware_tested': False,
              'writable_apfs_runtime_qualified': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
              'phone_operations': 'none', 'scope': 'Actual compiled 352-byte RamBlock doAsyncReadWrite and source sparse/dense/seed paths in the 83-object original-prelinked candidate. '
                       'Fixtures use the actual APFS seeds and real compiler field/completion layouts. IOMemoryDescriptor, allocator, locks, memcpy/bzero and completion are explicit peers. '
                       'The original storage init body and protected C2/D2 execute with bounded native-init/registry/accounting peers; complete original lifecycle, disk matching, APFS mount and phone execution remain unqualified.'}
    (ROOT / 'reports/ios16-data-kernel.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(cases)} actual RamBlock ARM64 I/O paths with original-content APFS fixtures and explicit peers; negative entry control rejected')


if __name__ == '__main__':
    main()
