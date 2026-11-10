#!/usr/bin/env python3
"""Execute the actual linked ARM64 VM lease and memory-reference algorithms."""
import concurrent.futures
import json
from pathlib import Path
import struct
import subprocess

from check_adreno_display_timeline import parse_layout
from check_data_mount_kernel import Model
from native_driver_build import ROOT, macho, require
from prepare_initial_data import sha


def layouts(out):
    out.mkdir(parents=True, exist_ok=True)
    recipe = ROOT / 'build/cph2653-mapped-lease-wait/source-build/native/compile-commands.json'
    records = [r for r in json.loads(recipe.read_text()) if Path(r['source']).stem in
               ('NativeAdrenoVm', 'NativeAdrenoMemory', 'NativeAdrenoSubmit', 'NativeAdrenoPublish')]
    require(len(records) == 4, 'Expected four production native layout recipes')
    def text(path):
        raw = path.read_bytes(); image = macho(raw)
        section, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    def compile_one(record):
        stem = Path(record['source']).stem; obj = out / (stem + '.probe.o'); log = out / (stem + '.layouts.log')
        command = record['arguments'][:]; original = Path(command[command.index('-o') + 1])
        command[command.index('-o') + 1] = str(obj); command += ['-Xclang', '-fdump-record-layouts']
        process = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
        log.write_text(process.stdout + process.stderr)
        require(process.returncode == 0 and text(original) == text(obj), 'Native layout probe changed production instructions: ' + stem)
        return log.read_text(), [obj, log]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results = list(pool.map(compile_one, records))
    logs = ''.join(log for log, _ in results); artifacts = [path for _, paths in results for path in paths]
    facts = {key: parse_layout(logs, name, fields) for key, name, fields in (
        ('vm', 'NativeAdrenoVm', ('mappings_', 'high_', 'next_handle_', 'attached_', 'poisoned_', 'fault_streams_')),
        ('mapping', 'NativeAdrenoVm::Mapping', ('memory', 'handle', 'iova', 'permissions', 'writeback', 'jobs')),
        ('memory', 'NativeAdrenoMemory', ('descriptor_', 'imported_', 'mapping_', 'spans_', 'bytes_', 'span_count_',
             'device_references_', 'prepared_', 'quarantined_', 'owner_uncached_', 'write_combined_')),
        ('submit', 'NativeAdrenoSubmit', ('jobs_', 'preempt_on_', 'ring_count_')),
        ('jobs', 'NativeAdrenoSubmit::JobList', ('items', 'count')),
        ('job', 'NativeAdrenoSubmit::Job', ('active', 'ring', 'mapped_count', 'vm_next')),
        ('published', '(anonymous namespace)::Published', ('published', 'ring', 'submit', 'lock')),
        ('ring', 'NativeAdrenoRing', ('poisoned_', 'seqno_')),
        ('map_wait', 'DodgeMapWaitOps', ('context', 'attempt', 'now', 'idle')),
    )}
    baseline = json.loads((ROOT / 'reports/adreno-display-timeline.json').read_text())['native_layouts']
    for record in ('published', 'ring', 'submit'):
        expected = baseline[record]
        require(facts[record]['bytes'] == expected['bytes'] and all(facts[record]['fields'][name] == offset
            for name, offset in expected['fields'].items()), 'Existing timeline layout changed: ' + record)
    return facts, artifacts, recipe


class Execution:
    def __init__(self, raw, facts, count=2, imported=False, readonly=False, control=None):
        self.m = m = Model(raw); self.facts = facts; self.regions = []; self.cursor = m.heap + 4096
        self.vm = self.alloc(facts['vm']['bytes']); self.maps = self.alloc(facts['mapping']['bytes'] * count)
        self.output = self.alloc(16); self.memories = []; self.cache = []; self.cache_fail = 0
        self.field('vm', self.vm, 'mappings_', self.maps); self.field('vm', self.vm, 'high_', count)
        self.field('vm', self.vm, 'next_handle_', count + 1); self.field('vm', self.vm, 'attached_', 1)
        for index in range(count):
            memory = self.alloc(facts['memory']['bytes']); self.memories.append(memory)
            span = self.alloc(24); data = self.alloc(4096, 4096)
            m.put(span, struct.pack('<3Q', 0, 0x40000000 + index * 8192, 4096))
            self.field('memory', memory, 'descriptor_', data)
            self.field('memory', memory, 'mapping_', data)
            if imported: self.field('memory', memory, 'imported_', data)
            self.field('memory', memory, 'spans_', span); self.field('memory', memory, 'bytes_', 4096)
            self.field('memory', memory, 'span_count_', 1); self.field('memory', memory, 'prepared_', 1)
            self.field('memory', memory, 'device_references_', 1)
            mapping = self.maps + index * facts['mapping']['bytes']
            self.field('mapping', mapping, 'memory', memory); self.field('mapping', mapping, 'handle', index + 1)
            self.field('mapping', mapping, 'iova', 0x800000 + index * 4096)
            self.field('mapping', mapping, 'permissions', 1 if readonly else 3)
        self.functions = {}
        for key, part in (('hold', 'NativeAdrenoVm10holdMapped'), ('retire', 'NativeAdrenoVm12retireMapped'),
            ('memory_hold', 'NativeAdrenoMemory13holdForDevice'), ('memory_retire', 'NativeAdrenoMemory21retireAfterQuiescence'),
            ('memory_acquire', 'NativeAdrenoMemory19acquireDeviceWrites'), ('map', 'NativeAdrenoVm3map'),
            ('disjoint', 'NativeAdrenoSubmit12ringDisjoint')):
            matches = [name for name in m.names if part in name]; require(len(matches) == 1, 'Missing actual lease function: ' + part)
            self.functions[key] = matches[0]
        for part, peer in (('NativeAdrenoMaintainOwnedPages', self.owned_cache),
                           ('NativeAdrenoMaintainPhysicalPages', self.physical_cache), ('NativeAdrenoNotePhase', self.phase)):
            names = [name for name in m.names if part in name]; require(len(names) == 1, 'Missing cache primitive: ' + part)
            m.bind(names[0], peer)
        self.globals = [(m.names['_native_adreno_io_coherent'], 4), (m.names['_native_adreno_coherent_skips'], 16)]
        m.put(m.names['_native_adreno_io_coherent'], bytes(4)); self.visits = set()
        self.ubsan = {v for n, v in m.names.items() if 'ubsan' in n}
        m.cpu.hook_add(m.u.UC_HOOK_CODE, self.instruction)
        m.cpu.hook_add(m.u.UC_HOOK_MEM_READ | m.u.UC_HOOK_MEM_WRITE, self.access)
        if control:
            key, words = control; m.put(m.names[self.functions[key]], struct.pack('<' + str(len(words)) + 'I', *words))

    def alloc(self, size, alignment=32):
        address = (self.cursor + 16 + alignment - 1) & -alignment
        self.cursor = (address + size + 63) & -32
        self.m.put(address - 16, b'\xa5' * (size + 32)); self.m.put(address, bytes(size)); self.regions.append((address, size))
        return address

    def field(self, record, address, name, value=None):
        size = (1 if name in ('attached_', 'poisoned_', 'fault_streams_', 'prepared_', 'quarantined_',
            'owner_uncached_', 'write_combined_', 'active', 'ring') else 4 if name in
            ('permissions', 'writeback', 'jobs', 'device_references_') else 8)
        at = address + self.facts[record]['fields'][name]
        if value is not None: self.m.put(at, value.to_bytes(size, 'little'))
        return int.from_bytes(self.m.read(at, size), 'little')

    def refs(self): return [self.field('memory', p, 'device_references_') for p in self.memories]
    def jobs(self): return [self.field('mapping', self.maps + i * self.facts['mapping']['bytes'], 'jobs') for i in range(len(self.memories))]

    def owned_cache(self, args):
        require(args[1:3] == [4096, 2], 'Owned completion must invalidate the entire mapped page')
        self.cache.append({'kind': 'owned', 'references': self.refs(), 'jobs': self.jobs()})
        self.m.returned(0xe00002bc if len(self.cache) == self.cache_fail else 0)

    def physical_cache(self, args):
        require(args[0] & 4095 == 0 and args[1:3] == [4096, 1], 'Imported completion changed its pinned maintenance contract')
        self.cache.append({'kind': 'physical', 'references': self.refs(), 'jobs': self.jobs()})
        self.m.returned(0xe00002bc if len(self.cache) == self.cache_fail else 0)

    def phase(self, args):
        require(args[1] == 4096, 'Cache phase escaped the mapped page'); self.m.returned()

    def instruction(self, cpu, address, size, ignored):
        for key, name in self.functions.items():
            if address == self.m.names[name]: self.visits.add(key)
        require(address not in self.ubsan, 'Lease reached an overflow/type failure')

    def access(self, cpu, kind, address, size, value, ignored):
        require(any(start <= address and address + size <= start + length for start, length in
            [*self.regions, *self.globals, (self.m.stack, 0x100000)]), 'Native lease escaped bounded records/cache counters/stack')

    def hold(self):
        result = self.m.call(self.functions['hold'], [self.vm, self.output, self.output + 8])
        before, count = struct.unpack('<2Q', self.m.read(self.output, 16)); self.canaries()
        return result, before, count

    def retire(self, before, count, acquire=True):
        result = self.m.call(self.functions['retire'], [self.vm, before, count, int(acquire)]); self.canaries(); return result

    def canaries(self):
        for address, size in self.regions:
            require(self.m.read(address - 16, 16) == self.m.read(address + size, 16) == b'\xa5' * 16,
                    'Native lease wrote an object/output guard')


def run_cases(raw, facts, control=None):
    rows = []
    def row(name, e):
        e.canaries(); rows.append({'case': name, 'result': 'PASS', 'references': e.refs(), 'jobs': e.jobs(),
            'cache_operations': e.cache, 'actual_native_entries': sorted(e.visits)})
    for imported in (False, True):
        e = Execution(raw, facts, imported=imported, control=control); result, before, count = e.hold()
        require(not result and (before, count) == (3, 2) and e.refs() == [2, 2] and e.jobs() == [1, 1],
                'Actual full mapped hold is missing or differs')
        require(not e.retire(before, count) and e.refs() == [1, 1] and e.jobs() == [0, 0] and len(e.cache) == 2,
                'Actual complete write acquisition/retirement is missing')
        require(all(c['references'] == [2, 2] and c['jobs'] == [1, 1] for c in e.cache),
                'A mapping was released before the whole cache acquisition finished')
        row('imported-physical-acquire' if imported else 'owned-cacheable-acquire', e)
    e = Execution(raw, facts); _, before, count = e.hold(); require(not e.retire(before, count, False), 'Unpublished cancellation failed')
    require(not e.cache and e.refs() == [1, 1], 'Unpublished cancellation acquired device writes'); row('unpublished-cancellation', e)
    e = Execution(raw, facts); _, before, count = e.hold(); e.hold()
    require(not e.retire(before, count) and e.refs() == [2, 2] and e.jobs() == [1, 1], 'First job dropped a later job hold')
    require(not e.retire(before, count) and e.refs() == [1, 1], 'Second job failed to retire'); row('overlapping-job-holds', e)
    for kind in ('quarantine', 'reference-overflow', 'job-overflow'):
        e = Execution(raw, facts)
        if kind == 'quarantine': e.field('memory', e.memories[1], 'quarantined_', 1)
        elif kind == 'reference-overflow': e.field('memory', e.memories[1], 'device_references_', 0xffffffff)
        else: e.field('mapping', e.maps + facts['mapping']['bytes'], 'jobs', 0xffffffff)
        prior_refs, prior_jobs = e.refs(), e.jobs(); result, before, count = e.hold()
        require(result and (before, count) == (0, 0) and e.refs() == prior_refs and e.jobs() == prior_jobs,
                'Failed partial hold changed original ownership')
        row('partial-hold-' + kind, e)
    for failure in (1, 2):
        e = Execution(raw, facts); _, before, count = e.hold(); e.cache_fail = failure
        require(e.retire(before, count) and e.refs() == [2, 2] and e.jobs() == [1, 1] and
                e.field('vm', e.vm, 'poisoned_') == 1 and
                all(e.field('memory', p, 'quarantined_') == 1 for p in e.memories), 'Cache failure released an incomplete lease')
        row('cache-failure-' + str(failure), e)
    for boundary, expected, name in ((0, 2, 'zero-boundary'), (4, 2, 'future-boundary'), (2, 2, 'truncated-boundary'), (3, 3, 'wrong-count')):
        e = Execution(raw, facts); e.hold()
        require(e.retire(boundary, expected) and e.refs() == [2, 2] and e.jobs() == [1, 1] and not e.cache,
                'Invalid lease identity changed ownership')
        row(name, e)
    e = Execution(raw, facts, readonly=True); _, before, count = e.hold()
    require(not e.retire(before, count) and not e.cache and e.refs() == [1, 1], 'Read-only mapping acquired GPU writes')
    row('read-only-resource-holds', e)
    e = Execution(raw, facts); e.hold(); memory = e.memories[0]
    old = e.m.read(e.maps, facts['mapping']['bytes'] * 2)
    result = e.m.call(e.functions['map'], [e.vm, memory, 0, 0x900000, 3, 0, 2, e.output])
    require(result and e.m.read(e.output, 8) == bytes(8) and e.m.read(e.maps, facts['mapping']['bytes'] * 2) == old and
            e.refs() == [2, 2] and not e.cache, 'Pending lease allowed a late mapping or mutated ownership')
    row('late-map-refused-before-table-or-cache-work', e)
    e = Execution(raw, facts); submit = e.alloc(facts['submit']['bytes']); items = e.alloc(8); job = e.alloc(facts['job']['bytes'])
    e.m.put(items, struct.pack('<Q', job)); base = submit + facts['submit']['fields']['jobs_']
    e.field('jobs', base, 'items', items); e.field('jobs', base, 'count', 1)
    e.field('job', job, 'active', 1); e.field('job', job, 'ring', 0)
    require(e.m.call(e.functions['disjoint'], [submit, 0, e.output, 1]) == 0 and
            e.m.call(e.functions['disjoint'], [submit, 1, e.output, 1]) == 1, 'Distinct IBs incorrectly proved disjoint resource use')
    row('cross-ring-resource-disjointness-refused', e)
    require(len(rows) == 16, 'Actual mapped-resource case inventory differs')
    return rows


def wait_cases(raw, facts, control=False):
    busy, timeout, error, argument, closed = (0xe0000000 | value for value in (0x2d5, 0x2d6, 0x2ca, 0x2c2, 0x2d8))
    settings = [
        ('pending-then-success', [busy, 0], [True, False], [0, 0], 0, 1000, 4, 0, 2, 1),
        ('repeated-pending-then-success', [busy, busy, 0], [True, True, False], [0, 0, 500], 0, 1000, 4, 0, 3, 2),
        ('deadline', [busy], [True], [0, 0, 1000], 0, 1000, 4, timeout, 2, 1),
        ('idle-failed', [busy], [True], [0, 0], 1, 1000, 4, error, 1, 1),
        ('clock-regressed', [busy], [True], [10, 9], 0, 1000, 4, error, 1, 0),
        ('connection-closed', [busy, closed], [True, False], [0, 0], 0, 1000, 4, closed, 2, 1),
        ('duplicate-map-busy', [busy], [False], [0], 0, 1000, 4, busy, 1, 0),
        ('map-refused', [argument], [False], [0], 0, 1000, 4, argument, 1, 0),
        ('immediate-map', [0], [False], [0], 0, 1000, 4, 0, 1, 0),
        ('frozen-clock-poll-bound', [busy], [True], [0], 0, 1000, 4, timeout, 4, 3),
        ('single-attempt-bound', [busy], [True], [0], 0, 1000, 1, timeout, 1, 0),
        ('null-ops', [], [], [], 0, 1000, 4, argument, 0, 0),
    ]
    rows = []
    for name, statuses, pending, clocks, idle_status, budget, polls, expected, attempts, idles in settings:
        m = Model(raw); layout = facts['map_wait']; ops = m.heap + 0x1000; context = m.heap + 0x2000
        m.put(ops - 16, b'\xa5' * (layout['bytes'] + 32)); m.put(ops, bytes(layout['bytes'])); m.put(context, bytes(16))
        counts = {'attempts': 0, 'idles': 0, 'clocks': 0}; visits = set()
        entry = '_dodge_adreno_wait_map'; require(entry in m.names, 'Production bounded-map helper is absent')
        for key, address in (('attempt', m.stop + 0x40), ('now', m.stop + 0x80), ('idle', m.stop + 0xc0)):
            m.put(ops + layout['fields'][key], struct.pack('<Q', address)); m.names['peer_map_wait_' + key] = address
        m.put(ops + layout['fields']['context'], struct.pack('<Q', context))
        def attempt(args):
            require(args[0] == context and m.stack <= args[1] < m.stack + 0x100000, 'Map attempt escaped callback context/output')
            index = counts['attempts']; counts['attempts'] += 1
            m.put(args[1], bytes([int(pending[min(index, len(pending) - 1)])])); m.returned(statuses[min(index, len(statuses) - 1)])
        def now(args):
            require(args[0] == context, 'Map clock lost callback context')
            index = counts['clocks']; counts['clocks'] += 1; m.returned(clocks[min(index, len(clocks) - 1)])
        def idle(args):
            require(args[0] == context, 'Map idle lost callback context'); counts['idles'] += 1; m.returned(idle_status)
        m.bind('peer_map_wait_attempt', attempt); m.bind('peer_map_wait_now', now); m.bind('peer_map_wait_idle', idle)
        addresses = {m.names[entry], *m.peers}
        def instruction(cpu, address, size, ignored):
            if address in addresses: visits.add(address)
        def access(cpu, kind, address, size, value, ignored):
            require(m.stack <= address and address + size <= m.stack + 0x100000 or
                    ops <= address and address + size <= ops + layout['bytes'], 'Map wait escaped bounded ops/stack')
            if kind == m.u.UC_MEM_WRITE: require(m.stack <= address < m.stack + 0x100000, 'Map wait mutated callback ops')
        m.cpu.hook_add(m.u.UC_HOOK_CODE, instruction)
        m.cpu.hook_add(m.u.UC_HOOK_MEM_READ | m.u.UC_HOOK_MEM_WRITE, access)
        if control: m.put(m.names[entry], struct.pack('<2I', 0x52800000, 0xd65f03c0))
        result = m.call(entry, [0 if name == 'null-ops' else ops, budget, polls])
        require(result == expected and counts['attempts'] == attempts and counts['idles'] == idles,
                'Bounded native map waiting did not honor status/deadline/poll bounds: ' + name)
        require(m.read(ops - 16, 16) == m.read(ops + layout['bytes'], 16) == b'\xa5' * 16,
                'Native map waiting wrote callback-record guards')
        rows.append({'case': name, 'result': 'PASS', 'status': hex(result), **counts,
                     'actual_native_helper_visited': m.names[entry] in visits, 'map_clock_idle_are_explicit_peers': True})
    return rows
