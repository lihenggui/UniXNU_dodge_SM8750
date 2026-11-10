#!/usr/bin/env python3
"""Run original task authorization and IOSurface reference algorithms on ARM64."""
import hashlib
import struct

from check_data_mount_kernel import Model
from native_driver_build import require, macho, symbols
from native_prelink import backed_offset


def load_probe(m, path, binding):
    raw = path.read_bytes(); image = macho(raw); table = symbols(raw)
    text, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
    body = bytearray(raw[text['fileoff']:text['fileoff'] + text['size']])
    base = (max(s['va'] + s['size'] for s in m.image['segments']) + 8191) & -4096
    offset, count = struct.unpack_from('<2I', raw, text['command_offset'] + 56)
    require(count == 1, 'Identity probe must have only the task-aware lookup import')
    at, bits = struct.unpack_from('<2I', raw, offset)
    require(bits >> 24 & 1 and bits >> 25 & 3 == 2 and bits >> 27 & 1 and bits >> 28 == 2 and
            table[bits & 0xffffff]['name'] == '_native_iphone_surface_copy_for_task', 'Identity probe relocation differs')
    word, = struct.unpack_from('<I', body, at); delta = binding - base - at
    require(word in (0x14000000, 0x94000000) and delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27),
            'Identity probe branch is not representable')
    struct.pack_into('<I', body, at, word | (delta // 4 & 0x3ffffff))
    m.map(base, len(body)); m.put(base, bytes(body))
    entries = {s['name']: base + s['value'] - text['va'] for s in table
               if not s['kind'] & 0xe0 and s['kind'] & 14 and s['name'].startswith('_dodge_identity_')}
    require(set(entries) == {'_dodge_identity_lookup', '_dodge_identity_retain', '_dodge_identity_release'},
            'Identity probe entry inventory differs')
    m.names.update(entries)


class Execution:
    """Exact bounded objects, original policy/cache/CAS; mutex/proc/base refs are peers."""
    def __init__(self, raw, contract, probe, control=None):
        self.m = m = Model(raw); self.contract = contract; self.next = m.heap + 0x10000
        self.objects = {}; self.blocks = {}; self.locks = {}; self.refs = {}; self.events = []
        self.executed = set(); self.instructions = 0; self.peer_index = 0; self.proc_calls = 0
        for name, block in contract['blocks'].items():
            address = self.a(int(block['address'], 16)); size = block['bytes']
            at = backed_offset(m.image['segments'], address, size, len(raw))
            require(hashlib.sha256(raw[at:at + size]).hexdigest() == block['sha256'],
                    'Original identity instructions changed: ' + name)
            self.blocks[address] = name; m.names['original_' + name] = address
        load_probe(m, probe, self.a(int(contract['bindings']['_native_iphone_surface_copy_for_task'], 16)))
        self.root = self.allocate(contract['root_bytes'], 'root')
        self.task = self.allocate(32, 'task'); self.foreign = self.allocate(32, 'foreign-task')
        self.table = self.allocate(16 * 8, 'root-surface-table'); self.p64(self.root + 192, self.table); self.p32(self.root + 200, 16)
        self.root_lock = self.new_lock('surface-lock'); self.client_lock = self.new_lock('client-list-lock')
        self.p64(self.root + 280, self.root_lock); self.p64(self.root + 984, self.client_lock)
        self.p64(self.a(int(contract['root_singleton_global'], 16)), self.root)
        self.surface = self.allocate(contract['surface_bytes'], 'surface'); self.id = 7
        self.p64(self.surface, self.a(int(contract['surface_vptr'], 16)))
        self.p32(self.surface + 12, self.id); self.p64(self.surface + 40, self.root)
        self.p64(self.surface + 112, self.task); self.p32(self.surface + 1000, 1)
        self.p64(self.table + self.id * 8, self.surface)
        self.client = self.allocate(contract['userclient_bytes'], 'root-userclient'); self.refs[self.client] = 1
        vptr = self.allocate(16 * 8, 'userclient-vtable'); self.p64(self.client, vptr)
        self.p64(vptr + 32, self.peer('base-client-retain', lambda a: self.base_ref(a, 1)))
        self.p64(vptr + 40, self.peer('base-client-release', lambda a: self.base_ref(a, -1)))
        self.user_lock = self.new_lock('userclient-lock'); self.p64(self.client + 216, self.user_lock)
        self.entries = self.allocate(16 * 8, 'client-entry-table')
        self.p64(self.client + 256, self.entries); self.p32(self.client + 264, 16); self.p64(self.client + 272, self.task)
        self.entry = self.allocate(contract['client_entry_bytes'], 'surface-client-entry')
        self.p64(self.entry + 16, self.task); self.p64(self.entry + 64, self.surface)
        self.pairs = self.allocate(3 * 16, 'dynamic-client-pairs'); self.p64(self.root + 1048, self.pairs)
        self.stub('mutex-lock', 0xfffffff005a67258, lambda a: self.lock(a, 1, False))
        self.stub('mutex-unlock', 0xfffffff005a67264, lambda a: self.lock(a, -1, False))
        self.stub('recursive-lock', 0xfffffff005a67300, lambda a: self.lock(a, 1, True))
        self.stub('recursive-unlock', 0xfffffff005a67318, lambda a: self.lock(a, -1, True))
        self.stub('task-bsd-process', 0xfffffff005a67708, self.process)
        for address in (0xfffffff005a5c9d8, 0xfffffff005a61f58, 0xfffffff005a677bc,
                        0xfffffff005a670ec, 0xfffffff005a671b8, 0xfffffff005a671e4, 0xfffffff005a6718c):
            self.stub('panic-' + hex(address), address, lambda a: self.panic())
        # No authorization, table lookup, task cache, custom reference update
        # or original helper in contract['blocks'] may be hidden by a peer.
        self.m.cpu.hook_add(m.u.UC_HOOK_CODE, self.observe)
        self.m.cpu.hook_add(m.u.UC_HOOK_MEM_READ | m.u.UC_HOOK_MEM_WRITE, self.memory)
        if control:
            address, word = control; self.m.put(self.a(address), struct.pack('<I', word))

    @staticmethod
    def a(address): return address - 0x1000000
    def p64(self, at, value): self.m.put(at, struct.pack('<Q', value))
    def p32(self, at, value): self.m.put(at, struct.pack('<I', value))
    def u64(self, at): return struct.unpack('<Q', self.m.read(at, 8))[0]
    def u32(self, at): return struct.unpack('<I', self.m.read(at, 4))[0]
    def allocate(self, size, kind):
        at = self.next + 16; self.next += (size + 63) & -32
        require(self.next < self.m.heap + 0x100000, 'Identity arena exhausted')
        self.m.put(at - 16, b'\xa5' * (size + 32)); self.m.put(at, bytes(size)); self.objects[at] = size, kind
        return at
    def new_lock(self, kind):
        lock = self.allocate(64, kind); self.locks[lock] = 0; return lock
    def peer(self, name, fn, address=None):
        if address is None:
            address = self.m.heap + 0x1c0000 + self.peer_index * 4; self.peer_index += 1
        require(address not in self.m.peers and address not in self.blocks, 'Peer masks original identity algorithm')
        self.m.names['peer_' + name] = address; self.m.bind('peer_' + name, fn); return address
    def stub(self, name, at, fn): return self.peer(name, fn, self.a(at))
    def base_ref(self, args, delta):
        require(args[0] == self.client, 'Unknown primitive client reference')
        self.refs[self.client] += delta
        require(self.refs[self.client] >= 1, 'Original lookup consumed an external client reference')
        self.events.append(('client-ref', delta)); self.m.returned()
    def lock(self, args, delta, recursive):
        at = args[0]; require(at in self.locks and recursive == (at == self.root_lock), 'Wrong lookup mutex primitive')
        if delta == 1:
            require(not self.locks[at], 'Unexpected recursive identity lookup')
            if at == self.client_lock: require(not any(self.locks.values()), 'Client-list lock inversion')
            if at == self.user_lock: require(not self.locks[self.client_lock], 'User mutex nested under client-list lock')
            if at == self.root_lock: require(not self.locks[self.client_lock], 'Surface lock nested under client-list lock')
        self.locks[at] += delta; require(self.locks[at] in (0, 1), 'Identity mutex imbalance')
        self.events.append(('lock' if delta > 0 else 'unlock', self.objects[at][1])); self.m.returned()
    def process(self, args):
        require(args[0] == self.task, 'Original policy logged the wrong task'); self.proc_calls += 1; self.m.returned(0)
    def panic(self): raise ValueError('Original identity invariant panic')
    def observe(self, cpu, pc, size, ignored):
        self.instructions += 1
        if pc in self.blocks: self.executed.add(self.blocks[pc])
    def memory(self, cpu, kind, address, size, value, ignored):
        stack = self.m.stack <= address and address + size <= self.m.stack + 0x100000
        obj = next((at for at, (n, _) in self.objects.items() if at <= address and address + size <= at + n), None)
        image = any(s['va'] <= address and address + size <= s['va'] + s['size'] for s in self.m.image['segments'])
        require(stack or obj is not None or image, 'Original identity access escaped bounded memory: ' + hex(address))
        if kind == self.m.u.UC_MEM_WRITE: require(stack or obj is not None, 'Original lookup wrote unqualified linked data')
        if self.table <= address < self.table + 16 * 8:
            require(self.locks[self.root_lock], 'Original surface table accessed without root lock')
        if self.entries <= address < self.entries + 16 * 8:
            require(self.locks[self.root_lock] and self.locks[self.user_lock], 'Original client table accessed without both locks')
    def client_mode(self, mode, member=True):
        self.p64(self.surface + 112, self.foreign)
        if member: self.p64(self.entries + self.id * 8, self.entry)
        if mode in (0, 1): self.p64(self.root + 1008 + mode * 16, self.task); self.p64(self.root + 1016 + mode * 16, self.client)
        elif mode == 'dynamic':
            self.p32(self.root + 992, 3); self.p64(self.pairs + 32, self.task); self.p64(self.pairs + 40, self.client)
        else: raise ValueError('Unknown task client fixture')
    def lookup(self, id=None):
        self.m.call('_dodge_identity_lookup', [self.root, self.id if id is None else id, self.task])
        result = self.m.register(0)
        require(not any(self.locks.values()) and self.refs[self.client] == 1, 'Lookup leaked lock/client reference')
        return result
    def release(self): self.m.call('_dodge_identity_release', [self.surface])
    def finish(self, name, expected, id=None):
        before = self.u32(self.surface + 1000); result = self.lookup(id)
        require(result == (self.surface if expected else 0) and self.u32(self.surface + 1000) == before + int(expected),
                'Wrong task authorization or original retained surface reference: ' + name)
        require(self.u32(self.surface + 12) == self.id, 'Lookup/reference update corrupted the surface ID')
        if expected: self.release(); require(self.u32(self.surface + 1000) == before, 'Original virtual release did not balance owned result')
        for at, (size, _) in self.objects.items():
            require(self.m.read(at - 16, 16) == self.m.read(at + size, 16) == b'\xa5' * 16, 'Identity object canary changed')
        return {'case': name, 'result': 'PASS', 'authorized': expected, 'instructions': self.instructions,
                'original_entries_executed': sorted(self.executed), 'process_peer_calls': self.proc_calls,
                'balanced_locks_and_client_references': True, 'surface_ID_preserved': True}


def run_cases(raw, contract, probe, control=None):
    rows = []
    def new(): return Execution(raw, contract, probe, control)
    e = new(); rows.append(e.finish('owner-task-without-client', True))
    e = new(); e.m.put(e.surface + 867, b'\1'); rows.append(e.finish('owner-can-resolve-restricted-surface', True))
    for id, name in ((0, 'zero-ID'), (16, 'past-table-ID'), (0x80000057, 'high-bit-ID')):
        e = new(); rows.append(e.finish(name, False, id))
    e = new(); e.p64(e.table + e.id * 8, 0); rows.append(e.finish('empty-surface-table-slot', False))
    e = new(); e.p32(e.surface + 1000, 0); rows.append(e.finish('dying-surface-cannot-be-resurrected', False))
    for mode in (0, 1, 'dynamic'):
        e = new(); e.client_mode(mode); e.m.put(e.surface + 867, b'\1')
        rows.append(e.finish('registered-client-' + str(mode), True))
        if mode == 'dynamic':
            require(e.u64(e.root + 1008) == e.task and e.u64(e.root + 1016) == e.client and
                    e.u32(e.root + 1000) == 1, 'Original dynamic task cache did not populate/toggle')
    e = new(); e.client_mode('dynamic', False); rows.append(e.finish('client-without-surface-membership-refused', False))
    e = new(); e.p64(e.surface + 112, e.foreign); rows.append(e.finish('foreign-task-policy-zero-refused', False))
    e = new(); e.p64(e.surface + 112, e.foreign); e.p32(e.root + 404, 1); e.m.put(e.surface + 867, b'\1')
    rows.append(e.finish('restricted-surface-denies-global-sharing-policy', False))
    for flags, marked, allowed in ((1, 0, True), (4, 1, True), (4, 0, False), (0, 1, False)):
        e = new(); e.p64(e.surface + 112, e.foreign); e.p32(e.root + 404, flags); e.m.put(e.surface + 33, bytes([marked]))
        rows.append(e.finish('original-global-sharing-policy-' + str(flags) + '-mark-' + str(marked), allowed))
    e = new(); e.client_mode('dynamic'); e.p32(e.root + 1000, 1)
    rows.append(e.finish('cache-fill-second-slot', True))
    require(e.u64(e.root + 1024) == e.task and e.u64(e.root + 1032) == e.client and e.u32(e.root + 1000) == 0,
            'Original second cache slot did not fill')
    before = e.instructions; rows.append(e.finish('subsequent-task-cache-hit', True)); rows[-1]['cache_hit_instructions'] = e.instructions - before
    e = new(); e.m.call('_dodge_identity_retain', [e.surface])
    require(e.u32(e.surface + 1000) == 2 and e.u32(e.surface + 12) == e.id, 'Original virtual retain changed wrong field')
    e.release(); rows.append(e.finish('virtual-retain-release-uses-custom-reference-counter', True))
    return rows


def instruction_controls(raw, contract, probe):
    rows = []
    for name, address, word in (
        ('lookup-without-authorization-or-retain', 0xfffffff005a59e04, 0xd65f03c0),
        ('owner-and-client-authorization-bypassed', 0xfffffff005a59bb4, 0x1400000c),
        ('try-retain-increment-skipped', 0xfffffff005a664d4, 0x11000289),
        ('surface-release-skipped', 0xfffffff005a4c2ec, 0xd65f03c0),
        ('client-membership-result-ignored', 0xfffffff005a59bd4, 0x14000004),
    ):
        try: run_cases(raw, contract, probe, (address, word))
        except ValueError as error:
            rows.append({'case': name, 'result': 'REJECTED', 'instruction_address': hex(address), 'reason': str(error)})
        else: raise ValueError('Identity checker accepted a broken original algorithm: ' + name)
    return rows


def invariant_controls(raw, contract, probe):
    rows = []
    for name in ('surface-table-ID-corrupt', 'client-entry-wrong-task', 'client-entry-wrong-root', 'reference-overflow', 'release-underflow'):
        e = Execution(raw, contract, probe)
        if name == 'surface-table-ID-corrupt': e.p32(e.surface + 12, e.id + 1)
        elif name.startswith('client-entry-'):
            e.client_mode(0)
            if name == 'client-entry-wrong-task': e.p64(e.entry + 16, e.foreign)
            else: e.p64(e.surface + 40, 0)
        elif name == 'reference-overflow': e.p32(e.surface + 1000, 0x0fffffff)
        else: e.p32(e.surface + 1000, 0)
        try:
            if name == 'release-underflow': e.release()
            else: e.lookup()
        except ValueError as error:
            require(str(error) == 'Original identity invariant panic', 'Identity invariant reached an unrelated failure')
            rows.append({'case': name, 'result': 'ORIGINAL_PANIC'})
        else: raise ValueError('Original identity invariant not enforced: ' + name)
    return rows


class SourceExecution(Execution):
    """Actual linked source resolver -> original lookup -> actual source release."""
    def __init__(self, raw, contract, probe, control=None):
        super().__init__(raw, contract, probe)
        m = self.m; self.kernel = self.allocate(32, 'kernel-task'); self.current = self.task
        self.output = self.allocate(16, 'source-identity-output'); self.matching = self.allocate(32, 'matching-dictionary')
        self.refs[self.root] = self.refs[self.matching] = 1
        self.matching_failed = self.root_missing = self.root_inactive = self.root_wrong = self.surface_wrong = self.terminate_late = False
        self.match_calls = self.inactive_calls = 0
        for obj in (self.root, self.matching):
            table = self.allocate(16 * 8, 'source-provider-vtable'); self.p64(obj, table)
            self.p64(table + 40, self.peer('provider-release-' + hex(obj), self.provider_release))
        m.put(m.names['_kernel_task'], struct.pack('<Q', self.kernel))
        for name, fn in (
            ('_current_task', lambda a: m.returned(self.current)),
            ('__ZN9IOService12nameMatchingEPKcP12OSDictionary', self.match),
            ('__ZN9IOService19copyMatchingServiceEP12OSDictionary', self.matching_service),
            ('__ZNK9IOService10isInactiveEv', self.inactive),
            ('__ZNK15OSMetaClassBase8metaCastEPKc', self.meta_cast),
        ):
            require(name in m.names, 'Missing linked native primitive: ' + name)
            self.peer('source-primitive-' + name, fn, m.names[name])
        if control:
            name, words = control; m.put(m.names[name], struct.pack('<' + str(len(words)) + 'I', *words))
    def provider_release(self, args):
        require(args[0] in (self.root, self.matching) and self.refs[args[0]] == 2, 'Source released unowned provider reference')
        self.refs[args[0]] -= 1; self.m.returned()
    def match(self, args):
        require(self.m.string(args[0]) == 'IOCoreSurfaceRoot' and args[1] == 0, 'Source root match arguments changed')
        self.match_calls += 1
        if self.matching_failed: self.m.returned(0); return
        self.refs[self.matching] += 1; self.m.returned(self.matching)
    def matching_service(self, args):
        require(args[0] == self.matching and self.refs[self.matching] == 2, 'Source matching dictionary not owned')
        if self.root_missing: self.m.returned(0); return
        self.refs[self.root] += 1; self.m.returned(self.root)
    def inactive(self, args):
        require(args[0] == self.root and self.refs[self.root] == 2, 'Source checked an unowned root')
        self.inactive_calls += 1
        self.m.returned(int(self.root_inactive or (self.terminate_late and self.inactive_calls == 2)))
    def meta_cast(self, args):
        name = self.m.string(args[1])
        require((args[0], name) in ((self.root, 'IOSurfaceRoot'), (self.surface, 'IOSurface')),
                'Source type check arguments differ')
        wrong = self.root_wrong if args[0] == self.root else self.surface_wrong
        self.m.returned(0 if wrong else args[0])


def source_cases(raw, contract, probe, control=None):
    rows = []
    common = 0xe0000000
    for name, expected in (
        ('owner', 0), ('registered-client', 0), ('foreign-task', common | 0x2e2),
        ('kernel-worker', common | 0x2e2), ('missing-task', common | 0x2e2),
        ('occupied-output', common | 0x2c2), ('zero-ID', common | 0x2c2), ('null-output', common | 0x2c2),
        ('matching-allocation-failed', common | 0x2bd), ('root-absent', common | 0x2d8),
        ('root-wrong-type', common | 0x2d8), ('root-inactive', common | 0x2d8),
        ('root-terminated-during-lookup', common | 0x2d8), ('surface-wrong-type', common | 0x2d8),
        ('dying-surface', common | 0x2e2), ('surface-absent', common | 0x2e2), ('out-of-range-ID', common | 0x2e2),
    ):
        e = SourceExecution(raw, contract, probe, control); id = e.id; output = e.output
        if name == 'registered-client': e.client_mode('dynamic'); e.m.put(e.surface + 867, b'\1')
        elif name == 'foreign-task': e.p64(e.surface + 112, e.foreign); e.m.put(e.surface + 867, b'\1')
        elif name == 'kernel-worker': e.current = e.kernel
        elif name == 'missing-task': e.current = 0
        elif name == 'occupied-output': e.p64(output, e.surface)
        elif name == 'zero-ID': id = 0
        elif name == 'null-output': output = 0
        elif name == 'matching-allocation-failed': e.matching_failed = True
        elif name == 'root-absent': e.root_missing = True
        elif name == 'root-wrong-type': e.root_wrong = True
        elif name == 'root-inactive': e.root_inactive = True
        elif name == 'root-terminated-during-lookup': e.terminate_late = True
        elif name == 'surface-wrong-type': e.surface_wrong = True
        elif name == 'dying-surface': e.p32(e.surface + 1000, 0)
        elif name == 'surface-absent': e.p64(e.table + e.id * 8, 0)
        elif name == 'out-of-range-ID': id = 0x80000057
        before = e.u32(e.surface + 1000)
        status = e.m.call('_dodge_copy_current_surface', [id, output])
        require(status == expected, 'Actual linked source identity status differs: ' + name + ' / ' + hex(status))
        require(e.refs == {e.client: 1, e.root: 1, e.matching: 1} and not any(e.locks.values()), 'Source identity provider/lock leak')
        if expected == 0:
            require(e.u64(output) == e.surface and e.u32(output + 8) == id and e.u32(e.surface + 1000) == before + 1,
                    'Actual source failed to transfer original retained result')
            e.m.call('_dodge_release_surface_identity', [output]); e.m.call('_dodge_release_surface_identity', [output])
            require(not e.u64(output) and not e.u32(output + 8), 'Actual source did not clear released identity')
        elif name not in ('occupied-output', 'null-output'):
            require(not e.u64(output) and not e.u32(output + 8), 'Source refusal populated an identity')
        require(e.u32(e.surface + 1000) == before and e.u32(e.surface + 12) == e.id, 'Source corrupted original surface lifetime/ID')
        for at, (size, _) in e.objects.items():
            require(e.m.read(at - 16, 16) == e.m.read(at + size, 16) == b'\xa5' * 16, 'Source identity canary changed')
        rows.append({'case': name, 'result': 'PASS', 'status': hex(status), 'instructions': e.instructions,
                     'original_entries_executed': sorted(e.executed), 'surface_ID_and_all_references_preserved': True})
    return rows
