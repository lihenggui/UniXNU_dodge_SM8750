#!/usr/bin/env python3
"""Execute the compiled fresh-health frontend helpers with the real native snapshot."""
import json
from pathlib import Path
import struct
import subprocess

from check_adreno_display_timeline import parse_layout
from check_data_mount_kernel import Model
from native_driver_build import ROOT, require, macho
from prepare_initial_data import sha


def layouts(out):
    out = out.resolve()
    record_path = ROOT / 'build/cph2653-fresh-gpu-source/native/compile-commands.json'
    record, = json.loads(record_path.read_text()); command = record['arguments'][:]
    out.mkdir(parents=True, exist_ok=True); obj = out / 'frontend-layout.o'
    command[command.index('-o') + 1] = str(obj); command += ['-Xclang', '-fdump-record-layouts']
    process = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
    log = out / 'compiler-layouts.log'; log.write_text(process.stdout + process.stderr)
    require(process.returncode == 0, 'Fresh GPU native compiler layout probe failed')
    def text(path):
        raw = path.read_bytes(); image = macho(raw)
        section, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    production = Path(record['arguments'][record['arguments'].index('-o') + 1])
    require(text(obj) == text(production), 'Native layout probe differs from the actual frontend instructions')
    facts = {
        'frontend': parse_layout(log.read_text(), 'DodgeDisplayFrontend', ('requiresAdreno',)),
        'entry': parse_layout(log.read_text(), 'DodgeFrontendEntry',
                             ('gpuEpoch', 'gpuTarget', 'gpuSubmitted', 'gpuRetired', 'gpuCaptured', 'gpuPassed', 'gpuInvalid')),
    }
    return facts, [obj, log], record_path


class Health:
    def __init__(self, raw, layout, backend, trace, control=None):
        self.m = m = Model(raw); self.layout = layout; self.backend = backend; self.trace = trace
        self.regions = []; self.cursor = m.heap + 4096; self.held = False
        self.available = True; self.retired = 7; self.fence_status = 0; self.queries = 0; self.lock_tries = 0
        self.front = self.alloc(layout['frontend']['bytes']); self.entry = self.alloc(layout['entry']['bytes'])
        self.ring = self.alloc(backend['ring']['bytes']); self.submit = self.alloc(backend['submit']['bytes']); self.lock = self.alloc(64)
        self.published = int(trace['published_state'], 16); self.counter = int(trace['recovery_counter'], 16)
        self.field('frontend', 'requiresAdreno', 1)
        self.publish(True); self.p64(self.published + backend['published']['fields']['ring'], self.ring)
        self.p64(self.published + backend['published']['fields']['submit'], self.submit)
        self.p64(self.published + backend['published']['fields']['lock'], self.lock)
        self.p32(self.submit + backend['submit']['fields']['ring_count_'], 1)
        self.fences(7, 7); self.epoch(0)
        for name in ('_IOLockTryLock', '_lck_mtx_try_lock'):
            if name in m.names: m.bind(name, self.try_lock)
        for name in ('_IOLockUnlock', '_lck_mtx_unlock'):
            if name in m.names: m.bind(name, self.unlock)
        m.bind('__ZN16NativeAdrenoRing10fenceValueEPj', self.fence)
        self.ready_name = '__ZL8gpuReadyP20DodgeDisplayFrontendR18DodgeFrontendEntry'
        self.current_name = '__ZL10gpuCurrentPK20DodgeDisplayFrontendRK18DodgeFrontendEntry'
        require(self.ready_name in m.names and self.current_name in m.names, 'Compiled fresh frontend helpers absent')
        self.visits = set()
        for name in (self.ready_name, self.current_name, '_dodge_adreno_display_timeline'):
            require(m.names[name] not in m.peers, 'Peer hides compiled frontend/snapshot algorithm')
        self.m.cpu.hook_add(m.u.UC_HOOK_CODE, self.observe)
        self.m.cpu.hook_add(m.u.UC_HOOK_MEM_READ | m.u.UC_HOOK_MEM_WRITE, self.access)
        if control:
            name, words = control
            m.put(m.names[name], struct.pack('<' + str(len(words)) + 'I', *words))

    def alloc(self, size):
        address = self.cursor + 16; self.cursor += (size + 63) & -32
        self.m.put(address - 16, b'\xa5' * (size + 32)); self.m.put(address, bytes(size))
        self.regions.append((address, size)); return address
    def p64(self, at, value): self.m.put(at, struct.pack('<Q', value))
    def p32(self, at, value): self.m.put(at, struct.pack('<I', value))
    def field(self, record, name, value=None):
        address = (self.front if record == 'frontend' else self.entry) + self.layout[record]['fields'][name]
        size = 1 if name in ('requiresAdreno', 'gpuCaptured', 'gpuPassed', 'gpuInvalid') else 8 if name == 'gpuEpoch' else 4
        if value is not None: self.m.put(address, value.to_bytes(size, 'little'))
        return int.from_bytes(self.m.read(address, size), 'little')
    def publish(self, state): self.m.put(self.published + self.backend['published']['fields']['published'], bytes([int(state)]))
    def epoch(self, generation): self.p32(self.counter, generation)
    def fences(self, submitted, retired):
        self.p32(self.ring + self.backend['ring']['fields']['seqno_'], submitted); self.retired = retired
    def poison(self, state): self.m.put(self.ring + self.backend['ring']['fields']['poisoned_'], bytes([int(state)]))
    def try_lock(self, args):
        require(args[0] == self.lock and not self.held, 'Native fresh health locked the wrong or held mutex')
        self.lock_tries += 1; self.held = self.available; self.m.returned(int(self.held))
    def unlock(self, args):
        require(args[0] == self.lock and self.held, 'Native fresh health unlocked an unowned mutex')
        self.held = False; self.m.returned()
    def fence(self, args):
        require(args[0] == self.ring and self.held and self.m.stack <= args[1] <= self.m.stack + 0x100000 - 4,
                'Native fresh health queried the wrong fence or without its mutex')
        self.queries += 1; self.p32(args[1], self.retired); self.m.returned(self.fence_status)
    def observe(self, cpu, pc, size, ignored):
        for name in (self.ready_name, self.current_name, '_dodge_adreno_display_timeline'):
            if self.m.names[name] == pc: self.visits.add(name)
    def access(self, cpu, kind, address, size, value, ignored):
        stack = self.m.stack <= address and address + size <= self.m.stack + 0x100000
        body = any(a <= address and address + size <= a + n for a, n in self.regions)
        image = any(s['va'] <= address and address + size <= s['va'] + s['size'] for s in self.m.image['segments'])
        require(stack or body or image, 'Native fresh health escaped bounded memory')
        if kind == self.m.u.UC_MEM_WRITE:
            require(stack or self.entry <= address and address + size <= self.entry + self.layout['entry']['bytes'],
                    'Native fresh health wrote backend/frontend state instead of its entry')
    def run(self, current=False):
        before = self.m.read(self.entry, self.layout['entry']['bytes'])
        front = self.m.read(self.front, self.layout['frontend']['bytes'])
        result = self.m.call(self.current_name if current else self.ready_name, [self.front, self.entry])
        require(result in (0, 1) and not self.held, 'Native fresh GPU helper did not return a boolean and release its mutex')
        require(self.m.read(self.front, len(front)) == front, 'Native fresh GPU helper wrote frontend configuration')
        if current: require(self.m.read(self.entry, len(before)) == before, 'Native fresh admission mutated its entry')
        for a, n in self.regions:
            require(self.m.read(a - 16, 16) == self.m.read(a + n, 16) == b'\xa5' * 16, 'Native health object canary changed')
        return result


def cases(raw, layout, backend, trace, control=None):
    rows = []
    for name, change, restore in (
        ('poisoned-ring', lambda h: h.poison(True), lambda h: h.poison(False)),
        ('unpublished-gpu', lambda h: h.publish(False), lambda h: h.publish(True)),
        ('busy-snapshot-lock', lambda h: setattr(h, 'available', False), lambda h: setattr(h, 'available', True)),
        ('fence-read-error', lambda h: setattr(h, 'fence_status', -1), lambda h: setattr(h, 'fence_status', 0)),
        ('retired-beyond-submitted', lambda h: h.fences(7, 8), lambda h: h.fences(7, 7)),
        ('active-multi-ring-preemption', lambda h: (h.m.put(h.submit + backend['submit']['fields']['preempt_on_'], b'\1'),
             h.p32(h.submit + backend['submit']['fields']['ring_count_'], 2)),
             lambda h: h.p32(h.submit + backend['submit']['fields']['ring_count_'], 1)),
    ):
        h = Health(raw, layout, backend, trace, control)
        require(h.run() == h.run(current=True) == 1 and h.field('entry', 'gpuTarget') == 7,
                'Native health did not capture the initial completed target')
        change(h)
        require(h.run(current=True) == h.run() == 0 and h.field('entry', 'gpuPassed') == 1 and
                h.field('entry', 'gpuInvalid') == 0, 'Historical target bypassed fresh backend refusal: ' + name)
        restore(h); require(h.run() == h.run(current=True) == 1, 'Unknown-health retry lost its target: ' + name)
        rows.append({'case': 'passed-target-' + name, 'result': 'PASS', 'native_snapshot_queries': h.queries,
                     'read_only_admission': True, 'original_target': h.field('entry', 'gpuTarget')})
    for name, change in (
        ('recovery-epoch', lambda h: h.epoch(1)),
        ('submitted-and-retired-regression', lambda h: h.fences(6, 6)),
    ):
        h = Health(raw, layout, backend, trace, control); require(h.run() == 1, 'Initial GPU target unavailable')
        change(h); require(h.run(current=True) == h.run() == 0 and h.field('entry', 'gpuInvalid') == 1,
                           'Native historical target survived a new epoch or invalid timeline: ' + name)
        h.epoch(0); h.fences(7, 7); require(h.run() == h.run(current=True) == 0, 'Native invalid request adopted reused fence numbers')
        rows.append({'case': 'passed-target-' + name, 'result': 'PASS', 'refusal_latched': True, 'read_only_admission': True})
    h = Health(raw, layout, backend, trace, control); require(h.run() == 1, 'Initial target unavailable')
    h.fences(100, 7); require(h.run() == h.run(current=True) == 1 and h.field('entry', 'gpuTarget') == 7,
                            'Native fresh-health observation adopted unrelated later work')
    h.fences(100, 90); require(h.run() == 1, 'Advanced actual retirements did not remain eligible')
    h.fences(100, 89); require(h.run(current=True) == h.run() == 0 and h.field('entry', 'gpuInvalid') == 1,
                             'Native fresh-health observations ignored a later retirement regression')
    rows.append({'case': 'first-target-preserved-and-observations-monotonic', 'result': 'PASS', 'original_target': 7})
    h = Health(raw, layout, backend, trace, control); h.fences(7, 6)
    require(h.run() == h.run(current=True) == 0 and h.field('entry', 'gpuCaptured') == 1 and
            h.field('entry', 'gpuPassed') == 0, 'Native pending producer became a completed producer')
    h.fences(100, 7); require(h.run() == h.run(current=True) == 1 and h.field('entry', 'gpuTarget') == 7,
                            'Native pending target did not complete independently of later submissions')
    rows.append({'case': 'pending-target-completes-with-fresh-health', 'result': 'PASS'})
    h = Health(raw, layout, backend, trace, control); h.publish(False)
    require(h.run() == h.run(current=True) == 0 and h.field('entry', 'gpuCaptured') == 0,
            'Native unavailable GPU fabricated an initial epoch or target')
    h.publish(True); require(h.run() == 1 and h.field('entry', 'gpuEpoch') == 1, 'Native first available snapshot not captured')
    rows.append({'case': 'first-valid-snapshot-only', 'result': 'PASS'})
    h = Health(raw, layout, backend, trace, control); h.epoch(0xffffffff)
    require(h.run() == h.run(current=True) == 0 and not h.field('entry', 'gpuCaptured'), 'Saturated native recovery epoch was accepted')
    rows.append({'case': 'saturated-recovery-epoch', 'result': 'PASS'})
    h = Health(raw, layout, backend, trace, control); h.field('frontend', 'requiresAdreno', 0); h.publish(False); h.poison(True)
    require(h.run() == h.run(current=True) == 1 and not h.queries and not h.lock_tries,
            'CpuOnly acquired a GPU dependency')
    rows.append({'case': 'cpu-only-has-no-gpu-query', 'result': 'PASS'})
    return rows
