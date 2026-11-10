#!/usr/bin/env python3
"""Execute original IOSurface queues and the original iPhone display callbacks."""
import hashlib
import struct

from check_data_mount_kernel import Model
from native_driver_build import require, macho, symbols
from native_prelink import backed_offset


def load_probe(model, path, bindings):
    raw = path.read_bytes(); image = macho(raw); table = symbols(raw)
    text, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
    body = bytearray(raw[text['fileoff']:text['fileoff'] + text['size']])
    base = (max(s['va'] + s['size'] for s in model.image['segments']) + 8191) & -4096
    reloc, count = struct.unpack_from('<2I', raw, text['command_offset'] + 56)
    require(count == 3, 'Expected only the two typed registration calls and one signal call')
    for index in range(count):
        at, bits = struct.unpack_from('<2I', raw, reloc + index * 8)
        require(bits >> 24 & 1 and bits >> 25 & 3 == 2 and bits >> 27 & 1 and bits >> 28 == 2,
                'Unexpected surface sync probe relocation')
        name = table[bits & 0xffffff]['name']
        require(name in bindings, 'Unexpected surface sync probe import: ' + name)
        word, = struct.unpack_from('<I', body, at)
        require(word in (0x14000000, 0x94000000), 'Unexpected surface sync branch addend')
        delta = bindings[name] - base - at
        require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'Typed probe call is out of branch range')
        struct.pack_into('<I', body, at, word | ((delta // 4) & 0x3ffffff))
    model.map(base, len(body)); model.put(base, bytes(body))
    entries = {s['name']: base + s['value'] - text['va'] for s in table
               if not s['kind'] & 0xe0 and s['kind'] & 14 and s['name'].startswith('_dodge_sync_')}
    require(set(entries) == {'_dodge_sync_read', '_dodge_sync_write', '_dodge_sync_signal', '_dodge_sync_ready'},
            'Typed surface sync probe entry set differs')
    model.names.update(entries)
    return entries


class Execution:
    """Synthetic objects, real notifier algorithms; scheduler/IOKit primitives are peers."""
    def __init__(self, raw, contract, probe, slide=-0x1000000, control=None):
        self.m = m = Model(raw); self.contract = contract; self.slide = slide
        self.next = m.heap + 0x10000; self.objects = {}; self.references = {}
        self.events = []; self.blocks = {}; self.locks = {}; self.deleted = set(); self.notifiers = []
        self.peer_index = 0; self.kicks = []; self.cancelled = []; self.grants = []; self.now = 1000
        self.raw = raw; self.region = []
        for name, block in contract['blocks'].items():
            address = self.a(int(block['address'], 16)); at = backed_offset(m.image['segments'], address, block['bytes'], len(raw))
            require(hashlib.sha256(raw[at:at + block['bytes']]).hexdigest() == block['sha256'],
                    'Linked original IOSurface/display instructions changed: ' + name)
            self.blocks[address] = name; m.names['original_' + name] = address
        bindings = {name: self.a(int(value, 16)) for name, value in contract['bindings'].items()}
        self.probe_entries = load_probe(m, probe, bindings)
        self.display = self.allocate(5728, 'display'); self.request = self.allocate(2424, 'request')
        self.display_vptr = self.allocate(338 * 8, 'display-vtable')
        self.request_vptr = self.allocate(64, 'request-vtable')
        self.gate = self.allocate(64, 'command-gate'); self.gate_vptr = self.allocate(32 * 8, 'gate-vtable')
        self.root = self.allocate(512, 'root'); self.root_lock = self.allocate(64, 'root-lock')
        self.event_source = self.allocate(64, 'event-source'); self.event_vptr = self.allocate(32 * 8, 'event-vtable')
        self.p64(self.display, self.display_vptr); self.p64(self.request, self.request_vptr)
        for obj, table in ((self.display, self.display_vptr), (self.request, self.request_vptr)):
            self.references[obj] = 1
            self.p64(table + 32, self.peer('retain-' + hex(obj), lambda args: self.reference(args, 1)))
            self.p64(table + 40, self.peer('release-' + hex(obj), lambda args: self.reference(args, -1)))
        self.p64(self.display_vptr + 239 * 8, self.peer('display-time', lambda args: m.returned(self.now)))
        self.p64(self.display_vptr + 276 * 8, self.peer('display-kick', self.kick))
        self.p64(self.display_vptr + 324 * 8, self.peer('display-cancel', self.cancel))
        self.p64(self.display + 5040, self.gate); self.p64(self.gate, self.gate_vptr)
        self.p64(self.gate_vptr + 29 * 8, self.peer('command-gate-action', self.enter_gate))
        self.p64(self.root + 440, self.root_lock); self.locks[self.root_lock] = 0
        self.p64(self.root + 456, self.root + 448); self.p64(self.root + 432, self.event_source)
        self.p64(self.event_source, self.event_vptr)
        self.p64(self.event_vptr + 31 * 8, self.peer('event-source-wakeup', self.wakeup))
        self.p64(self.display + 4880, self.request); self.p64(self.display + 4888, self.request + 2408)
        self.p64(self.request + 2416, self.display + 4880); self.p32(self.request + 788, 0x11223344)
        self.p64(self.a(int(contract['notification_metadata'], 16)),
                 self.a(int(contract['notification_metadata_vptr'], 16)))
        self.stub('typed-allocation', 0xfffffff005a6736c, self.typed_new)
        self.stub('base-object-constructor', 0xfffffff005a6760c, self.base_ctor)
        self.stub('metadata-instance-constructed', 0xfffffff005a67690, lambda args: m.returned())
        base_vptr = self.u64(self.a(0xfffffff006d85310))
        self.peer('base-object-init', lambda args: m.returned(1), self.u64(base_vptr + 120))
        self.peer('base-object-free-delete-dispatch', self.base_free, self.u64(base_vptr + 128))
        self.stub('base-object-destructor', 0xfffffff005a67618, lambda args: m.returned())
        self.stub('typed-delete', 0xfffffff005a67360, self.typed_delete)
        self.stub('recursive-lock', 0xfffffff005a67300, lambda args: self.lock(args, 1))
        self.stub('recursive-unlock', 0xfffffff005a67318, lambda args: self.lock(args, -1))
        self.stub('absolute-time', 0xfffffff005a67768, self.time)
        self.stub('kernel-trace', 0xfffffff005a67738, lambda args: m.returned())
        self.stub('backtrace', 0xfffffff005a6733c, lambda args: m.returned(0))
        self.stub('hide-address', 0xfffffff005a678ac, self.hide_address)
        # These maintain registry-side accounting, not access eligibility or
        # notification queue state. The actual use count update still runs.
        self.stub('root-use-count-changed', 0xfffffff005a5b0ec, lambda args: m.returned())
        self.stub('surface-panic', 0xfffffff005a677bc, self.panic)
        self.stub('display-panic', 0xfffffff005c274f0, self.panic)
        self.producer_callback = self.peer('external-producer-ready-callback', self.producer_granted)
        self.executed = set(); self.instruction_count = 0
        self.m.cpu.hook_add(m.u.UC_HOOK_CODE, self.observe)
        self.m.cpu.hook_add(m.u.UC_HOOK_MEM_READ | m.u.UC_HOOK_MEM_WRITE, self.memory)
        if control:
            address, word = control; self.m.put(self.a(address), struct.pack('<I', word))

    def a(self, address): return address + self.slide
    def p64(self, address, value): self.m.put(address, struct.pack('<Q', value))
    def p32(self, address, value): self.m.put(address, struct.pack('<I', value & 0xffffffff))
    def u64(self, address): return struct.unpack('<Q', self.m.read(address, 8))[0]
    def u32(self, address): return struct.unpack('<I', self.m.read(address, 4))[0]

    def allocate(self, size, kind):
        address = self.next + 16; self.next += (size + 63) & -32
        require(self.next < self.m.heap + 0x100000, 'Bounded surface model arena exhausted')
        self.m.put(address - 16, b'\xa5' * (size + 32)); self.m.put(address, bytes(size))
        self.objects[address] = (size, kind); return address

    def peer(self, name, function, address=None):
        if address is None:
            address = self.m.heap + 0x1c0000 + self.peer_index * 4; self.peer_index += 1
        require(address not in self.m.peers and address not in self.blocks, 'Peer masks original algorithm: ' + name)
        self.m.names['peer_' + name] = address; self.m.bind('peer_' + name, function); return address

    def stub(self, name, address, function): return self.peer(name, function, self.a(address))
    def reference(self, args, delta):
        require(args[0] in self.references, 'Peer lifetime called with an unknown object')
        self.references[args[0]] += delta
        require(self.references[args[0]] >= 1, 'Original code consumed an externally owned object')
        self.events.append(('retain' if delta > 0 else 'release', hex(args[0]))); self.m.returned()

    def typed_new(self, args):
        require(args[:2] == [self.a(0xfffffff006d899b8), 216], 'Original notifier allocation type/size differs')
        obj = self.allocate(216, 'original-notifier'); self.notifiers.append(obj); self.m.returned(obj)

    def base_ctor(self, args):
        require(args[0] in self.notifiers and args[1] == self.a(int(self.contract['notification_metadata'], 16)),
                'Original notifier base constructor type differs')
        self.p32(args[0] + 12, 1); self.m.returned(args[0])

    def base_free(self, args):
        require(args[0] in self.notifiers and self.u32(args[0] + 12) == 0,
                'Original notifier delete dispatched with a live reference')
        # OSObject::free's primitive delete dispatch is a peer. The actual
        # deleting destructor, surface release and typed delete tail execute.
        self.m.cpu.reg_write(self.m.arm.UC_ARM64_REG_PC, self.m.names['original_notifier_delete'])

    def typed_delete(self, args):
        require(args[0] == self.a(0xfffffff006d899b8) and args[1] in self.notifiers and args[2] == 216 and
                args[1] not in self.deleted, 'Original notifier typed delete differs')
        self.deleted.add(args[1]); self.m.returned()

    def lock(self, args, delta):
        require(args[0] in self.locks, 'Unknown recursive mutex')
        self.locks[args[0]] += delta; require(self.locks[args[0]] >= 0, 'Unlock without lock')
        self.m.returned()

    def time(self, args): self.now += 10; self.m.returned(self.now)
    def hide_address(self, args): self.p64(args[1], 0); self.m.returned()
    def panic(self, args): raise ValueError('Original synchronization panic: ' + self.m.string(args[0]))
    def wakeup(self, args):
        require(args[:4] == [self.event_source, 0, 0, 0], 'Original root event-source wake arguments differ')
        require(not any(self.locks.values()), 'Original root wakeup retains a mutex')
        self.events.append(('event-wakeup',)); self.m.returned()

    def enter_gate(self, args):
        require(args[:2] == [self.gate, self.m.names['original_family_callback_action']] and
                not any(self.locks.values()), 'Original display callback did not enter its gate after unlocking')
        self.events.append(('display-gate-action',))
        self.m.cpu.reg_write(self.m.arm.UC_ARM64_REG_X0, self.display)
        for index in range(1, 5):
            self.m.cpu.reg_write(getattr(self.m.arm, 'UC_ARM64_REG_X' + str(index)), args[index + 1])
        self.m.cpu.reg_write(self.m.arm.UC_ARM64_REG_PC, args[1])

    def kick(self, args):
        require(args[0] == self.display, 'Original display kicked an unrelated object')
        self.kicks.append(self.u32(self.request + 796)); self.events.append(('display-kick', self.kicks[-1])); self.m.returned()

    def cancel(self, args):
        require(args[:4] == [self.display, self.request, 0, 7], 'Original error callback cancellation arguments differ')
        self.cancelled.append(7); self.m.put(self.request + 1354, b'\1'); self.m.returned()

    def producer_granted(self, args):
        require(not any(self.locks.values()), 'Original producer grant callback retains a mutex')
        require(args[2] in self.references and args[3] == 0, 'Unexpected original producer callback')
        self.grants.append({'target': args[0], 'context': args[1], 'surface': args[2], 'status': args[3]})
        self.m.returned()

    def observe(self, cpu, pc, size, ignored):
        self.instruction_count += 1
        if pc in self.blocks: self.executed.add(self.blocks[pc])

    def memory(self, cpu, kind, address, size, value, ignored):
        # CPU accesses may read linked text/constants/globals, exact object
        # bodies or its stack. No MMIO, physical address or unknown heap.
        stack = self.m.stack <= address and address + size <= self.m.stack + 0x100000
        obj = next((a for a, (n, _) in self.objects.items() if a <= address and address + size <= a + n), None)
        image = any(s['va'] <= address and address + size <= s['va'] + s['size'] for s in self.m.image['segments'])
        require(stack or obj is not None or image, 'Original sync access escaped bounded memory: ' + hex(address))
        if kind == self.m.u.UC_MEM_WRITE:
            require(stack or obj is not None, 'Original sync wrote linked code or an unqualified global')
            require(obj not in self.deleted, 'Original sync wrote a deleted notifier')

    def surface(self, label=42):
        surface = self.allocate(1168, 'surface'); table = self.allocate(64, 'surface-vtable')
        state = self.allocate(64, 'surface-use-state'); lock = self.allocate(64, 'surface-lock')
        history = self.allocate(968, 'notification-history')
        self.p64(surface, table); self.references[surface] = 1; self.locks[lock] = 0
        self.p64(table + 32, self.peer('surface-retain-' + str(label), lambda args: self.reference(args, 1)))
        self.p64(table + 40, self.peer('surface-release-' + str(label), lambda args: self.reference(args, -1)))
        for field, value in ((40, self.root), (128, lock), (192, state), (544, surface + 536),
                             (560, surface + 552), (992, history)): self.p64(surface + field, value)
        self.p32(surface + 12, label)
        return surface

    def call(self, name, args=()):
        result = self.m.call(name, args, limit=500000)
        require(not any(self.locks.values()), 'Original sync returned holding a mutex')
        self.canaries(); return result

    def begin(self, surface, write=True, label=77, target=0x123456789, context=0xabcdef012):
        output = self.allocate(8, 'ticket-output')
        result = self.call('_dodge_sync_write' if write else '_dodge_sync_read',
                           [surface, output, label, self.producer_callback, target, context])
        token = self.u64(output)
        require(token in self.notifiers and self.u64(token + 16) == surface and self.u32(token + 32) == label and
                self.u32(token + 36) == (2 if write else 1) and self.u64(token + 40) == self.producer_callback and
                self.u64(token + 48) == target and self.u64(token + 56) == context,
                'Typed native registration argument widths/order or ticket writeback differ')
        return result, token

    def family(self, surfaces):
        require(1 <= len(surfaces) <= 4, 'Synthetic family layer count differs')
        for index, surface in enumerate(surfaces):
            self.p64(self.request + 2184 + index * 8, surface)
            self.p64(self.request + 2216 + index * 8, surface)
        self.p32(self.request + 792, sum(1 << i for i, s in enumerate(surfaces) if s))
        self.call('original_family_registration', [self.display, self.request])
        return [self.u64(self.request + 2152 + index * 8) for index in range(len(surfaces)) if surfaces[index]]

    def signal(self, token, status=0): return self.call('_dodge_sync_signal', [token, status])
    def drain(self): self.call('original_root_worker', [self.root])
    def ready(self): return self.call('_dodge_sync_ready', [self.request])
    def use_count(self, surface): return self.u64(self.u64(surface + 192) + 24)
    def release(self, token):
        self.m.names['release_ticket'] = self.u64(self.u64(token) + 40)
        self.call('release_ticket', [token])

    def cleanup(self):
        # Complete every still-live test access, then let the real queues and
        # destructors retire it. These are explicit test-producer operations.
        for token in self.notifiers:
            if token not in self.deleted and not self.u32(token + 76): self.signal(token)
        self.drain()
        for token in self.notifiers:
            if token not in self.deleted: self.release(token)
        require(set(self.notifiers) == self.deleted and all(value == 1 for value in self.references.values()),
                'Original callback/ticket cleanup leaked or consumed an external reference')
        require(self.u64(self.root + 448) == 0 and self.u64(self.root + 456) == self.root + 448,
                'Original root queue did not return to its empty invariant')
        for surface, (_, kind) in self.objects.items():
            if kind != 'surface': continue
            require(self.use_count(surface) == 0 and self.u64(surface + 536) == self.u64(surface + 552) == 0 and
                    self.u64(surface + 544) == surface + 536 and self.u64(surface + 560) == surface + 552,
                    'Original surface use count or queue links leaked')

    def canaries(self):
        for address, (size, _) in self.objects.items():
            require(self.m.read(address - 16, 16) == self.m.read(address + size, 16) == b'\xa5' * 16,
                    'Original synchronization object guard changed')

    def result(self, name):
        return {'case': name, 'result': 'PASS', 'instructions': self.instruction_count,
                'original_entries_executed': sorted(self.executed), 'display_kicks': self.kicks,
                'producer_grant_callbacks': len(self.grants), 'notifiers': len(self.notifiers),
                'notifier_deletes': len(self.deleted), 'all_object_canaries_preserved': True}


def run_cases(raw, contract, probe, control=None):
    rows = []
    for layers in range(1, 5):
        e = Execution(raw, contract, probe, control=control)
        surfaces = [e.surface(42 + index) for index in range(layers)]
        writers = [e.begin(s)[1] for s in surfaces]; readers = e.family(surfaces)
        require(e.ready() == 0 and not e.kicks and e.references[e.request] == 1 + layers,
                'Original family accepted an unfinished writer')
        e.drain(); require(e.ready() == 0 and not e.kicks, 'A wakeup without producer completion retired a frame')
        for index, writer in enumerate(reversed(writers)):
            e.signal(writer); e.drain()
            expected = ((1 << (index + 1)) - 1) << (layers - index - 1)
            require(e.u32(e.request + 796) == expected and len(e.kicks) == index + 1 and
                    e.ready() == int(index == layers - 1),
                    'Original multi-layer callback/ready-word ordering differs')
        require(e.ready() == 1 and len(e.kicks) == layers and all(e.u32(r + 76) == 0 for r in readers),
                'Original frame readiness did not follow all writers')
        e.cleanup(); rows.append(e.result('writer-to-family-' + str(layers) + '-layers'))
    for layers in range(1, 5):
        e = Execution(raw, contract, probe, control=control)
        readers = e.family([e.surface(42 + index) for index in range(layers)])
        require(e.ready() == 1 and e.references[e.request] == 1 and not e.kicks,
                'Original immediate family grant invoked a deferred callback or leaked its request')
        e.cleanup(); rows.append(e.result('immediate-family-' + str(layers) + '-layers'))
    for same in (False, True):
        e = Execution(raw, contract, probe, control=control); surface = e.surface()
        first_ready, first = e.begin(surface, label=0x80000057)
        next_ready, second = e.begin(surface, label=0x80000057 if same else 78)
        require(first_ready == 1 and next_ready == int(same) and not e.grants and
                e.m.read(second + 83, 1) == bytes([int(same)]),
                'A pending writer was treated as active')
        readers = e.family([surface]); e.signal(first); e.drain()
        require(len(e.grants) == int(not same) and (same or e.grants[0]['target'] == 0x123456789 and
                e.grants[0]['context'] == 0xabcdef012) and e.ready() == 0 and not e.kicks,
                'Original writer-to-writer handoff or consumer exclusion differs')
        e.signal(second); e.drain(); require(e.ready() == 1 and len(e.kicks) == 1, 'Last writer did not release consumer')
        e.cleanup(); rows.append(e.result('serial-writers-' + ('same-label' if same else 'different-label')))
    e = Execution(raw, contract, probe, control=control); surface = e.surface()
    ready, read = e.begin(surface, write=False); require(ready == 1, 'Initial shared read was not active')
    readers = e.family([surface]); require(e.ready() == 1 and not e.grants and not e.kicks, 'Shared readers blocked each other')
    e.cleanup(); rows.append(e.result('shared-readers-are-immediate'))
    for status in (0xe00002bc, 0xe00002eb):
        e = Execution(raw, contract, probe, control=control); surface = e.surface(); _, writer = e.begin(surface)
        e.family([surface]); e.signal(writer, status); e.drain()
        require(e.u32(writer + 72) == status and e.ready() == 1 and e.kicks == [1] and not e.cancelled,
                'Original writer-error behavior changed; never infer GPU success from this reader grant')
        e.cleanup(); row = e.result('writer-error-does-not-propagate-' + hex(status))
        row['writer_error_propagated_to_reader'] = False; rows.append(row)
    e = Execution(raw, contract, probe, control=control); surface = e.surface(); _, writer = e.begin(surface)
    readers = e.family([surface]); e.signal(writer); e.signal(writer); e.drain(); e.drain()
    require(e.kicks == [1] and e.references[e.request] == 1, 'Duplicate signal/drain duplicated the family callback')
    e.cleanup(); rows.append(e.result('duplicate-signal-and-empty-root-worker'))
    for removed in (False, True):
        e = Execution(raw, contract, probe, control=control); surface = e.surface(); _, writer = e.begin(surface)
        e.family([surface])
        if removed:
            e.p64(e.display + 4880, 0); e.p64(e.display + 4888, e.display + 4880)
        else:
            replacement = e.allocate(2424, 'replacement-request')
            e.p64(replacement, e.request_vptr); e.p32(replacement + 788, 0x99887766)
            e.p64(replacement + 2416, e.display + 4880)
            e.p64(e.display + 4880, replacement); e.p64(e.display + 4888, replacement + 2408)
        e.signal(writer); e.drain()
        require(e.ready() == 0 and not e.kicks and e.references[e.request] == 1,
                'Stale/dequeued original callback marked a different request ready or leaked its reference')
        e.cleanup(); rows.append(e.result('callback-after-' + ('dequeue' if removed else 'queue-replacement')))
    # Original error callback path, delivered by the actual surface walker.
    # The error is on this reader, rather than on its upstream writer.
    e = Execution(raw, contract, probe, control=control); surface = e.surface(); _, writer = e.begin(surface)
    readers = e.family([surface]); reader = readers[0]
    e.p32(reader + 72, 0xe00002bc); e.signal(writer); e.drain()
    require(e.cancelled == [7] and not e.kicks and e.ready() == 0 and e.references[e.request] == 1,
            'Original reader error did not request cancellation and release its request')
    e.cleanup(); row = e.result('reader-own-error-cancels-family-request')
    row['reader_status_is_explicit_fixture'] = True; row['family_cancellation_implementation_is_peer'] = True; rows.append(row)
    return rows
