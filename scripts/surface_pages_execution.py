#!/usr/bin/env python3
"""Run linked surface/import association with real native memory/VM references."""
import json
import hashlib
from pathlib import Path
import struct
import subprocess

from check_adreno_display_timeline import parse_layout
from native_driver_build import ROOT, macho, require
from native_prelink import backed_offset
from prepare_surface_identity import checked as identity_contract
from prepare_surface_memory import checked as memory_contract
from surface_identity_execution import Execution as IdentityExecution


def layouts(out):
    out.mkdir(parents=True, exist_ok=True)
    recipe = ROOT / 'build/cph2653-surface-pages/native/compile-commands.json'
    record, = json.loads(recipe.read_text()); command = record['arguments'][:]
    production = Path(command[command.index('-o') + 1]); obj = out / 'pages-layout.o'; log = out / 'pages-layout.log'
    command[command.index('-o') + 1] = str(obj); command += ['-Xclang', '-fdump-record-layouts']
    result = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    def text(path):
        raw = path.read_bytes(); image = macho(raw)
        section, = [s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__text']
        return raw[section['fileoff']:section['fileoff'] + section['size']]
    require(result.returncode == 0 and text(production) == text(obj), 'Surface page layout probe changed production instructions')
    facts = {key: parse_layout(log.read_text(), name, fields) for key, name, fields in (
        ('association', 'DodgeSurfacePages', ('identity', 'backing', 'memory', 'bytes', 'prepared', 'quarantined')),
        ('memory', 'NativeAdrenoMemory', ('descriptor_', 'imported_', 'read_only_', 'spans_', 'bytes_', 'span_count_',
                                         'device_references_', 'prepared_', 'quarantined_')),
        ('descriptor', 'IOMemoryDescriptor', ()),
        ('object', 'OSObject', ('retainCount',)),
    )}
    baseline = json.loads((ROOT / 'reports/ios16-mapped-lease-kernel.json').read_text())['mapped_resource_layout']
    require(facts['memory']['bytes'] == baseline['memory']['bytes'] and all(offset == baseline['memory']['fields'][name]
        for name, offset in facts['memory']['fields'].items() if name != 'read_only_'), 'Native memory layout no longer matches retained backend')
    facts['vm'] = baseline['vm']; facts['mapping'] = baseline['mapping']
    return facts, [obj, log], recipe


class Execution(IdentityExecution):
    def __init__(self, raw, facts, probe, control=None):
        contract, _ = identity_contract(); super().__init__(raw, contract, probe)
        memory, _ = memory_contract()
        for name, block in memory['blocks'].items():
            address = self.a(int(block['address'],16)); at = backed_offset(self.m.image['segments'],address,block['bytes'],len(raw))
            require(hashlib.sha256(raw[at:at+block['bytes']]).hexdigest()==block['sha256'],'Linked original surface memory instructions changed')
            self.blocks[address]='memory_'+name
        self.facts = facts; self.prepared = False; self.prepare_failed = self.complete_failed = False
        self.prepare_calls = self.complete_calls = self.segments = 0
        self.direction = 3; self.length = 12288; self.run = 4096; self.physical = [0x40000000 + i * 4096 for i in range(3)]
        self.mutation = None; self.cache_failed = False; self.cache = []
        self.backing = self.allocate(facts['descriptor']['bytes'], 'owned-surface-descriptor')
        self.imported = self.allocate(facts['descriptor']['bytes'], 'already-prepared-import-descriptor')
        self.table_md = self.allocate(29 * 8, 'surface-descriptor-vtable'); self.p64(self.backing, self.table_md)
        # OSObject::retain/release dispatch through its tagged/count overloads.
        # Populate the real native base table instead of replacing that chain.
        object_table=self.m.names['__ZTV8OSObject']+16
        descriptor_table=self.m.names['__ZTV18IOMemoryDescriptor']+16
        for slot in (2,3,4,5,9,10,11):
            require(self.u64(object_table+slot*8)==self.u64(descriptor_table+slot*8),
                    'Native descriptor reference override differs from qualified base chain')
        self.m.put(self.table_md,self.m.read(descriptor_table,16*8))
        self.p32(self.backing + facts['object']['fields']['retainCount'], 1)
        self.p64(self.surface + 56, self.backing); self.p32(self.surface + 172, 12288)
        self.p32(self.surface + 1000, 2) # external owner plus the input identity's owned original reference
        self.identity = self.allocate(16, 'owned-input-identity'); self.p64(self.identity, self.surface); self.p32(self.identity + 8, self.id)
        self.association = self.allocate(facts['association']['bytes'], 'source-page-association')
        self.memory_object = self.allocate(facts['memory']['bytes'], 'native-imported-memory')
        self.span = self.allocate(3 * 24, 'native-import-spans'); self.m.put(self.span, struct.pack('<3Q', 0, 0x40000000, 12288))
        for name, value in (('imported_', self.imported), ('spans_', self.span), ('bytes_', 12288), ('span_count_', 1), ('prepared_', 1)):
            self.field('memory', name, value)
        for slot, name in ((4, '__ZNK8OSObject6retainEv'), (5, '__ZNK8OSObject7releaseEv')):
            require(name in self.m.names, 'Missing real native OSObject reference function'); self.p64(self.table_md + slot * 8, self.m.names[name])
        for slot, fn in ((21, lambda a: self.m.returned(self.direction)), (22, lambda a: self.m.returned(self.length)),
                         (19, self.segment), (27, self.prepare), (28, self.complete)):
            self.p64(self.table_md + slot * 8, self.peer('descriptor-primitive-' + str(slot), fn))
        self.peer('source-metacast', self.meta_cast, self.m.names['__ZNK15OSMetaClassBase8metaCastEPKc'])
        for part, fn in (('NativeAdrenoMaintainPhysicalPages', self.physical_cache), ('NativeAdrenoNotePhase', lambda a: self.m.returned())):
            self.peer('source-primitive-' + part, fn, self.function(part))
        self.p32(self.m.names['_native_adreno_io_coherent'], 0)
        self.source_visits = set(); self.source_entries = {self.m.names[n]: n for n in self.m.names if n.startswith('_dodge_surface_pages_')}
        self.source_entries.update({self.function('NativeAdrenoMemory13holdForDevice'): 'native-memory-hold',
                                    self.function('NativeAdrenoMemory21retireAfterQuiescence'): 'native-memory-retire',
                                    self.m.names['__ZNK8OSObject6retainEv']: 'native-descriptor-retain',
                                    self.m.names['__ZNK8OSObject7releaseEv']: 'native-descriptor-release'})
        for name in ('__ZNK8OSObject12taggedRetainEPKv','__ZNK8OSObject13taggedReleaseEPKv','__ZNK8OSObject13taggedReleaseEPKvi'):
            self.source_entries[self.m.names[name]]=name
        self.m.cpu.hook_add(self.m.u.UC_HOOK_CODE, self.source_observe)
        if control:
            name, words = control; self.m.put(self.m.names[name], struct.pack('<' + str(len(words)) + 'I', *words))
    def function(self, part):
        names = [name for name in self.m.names if part in name]; require(len(names) == 1, 'Missing/ambiguous linked function: ' + part)
        return self.m.names[names[0]]
    def call_part(self, part, args):
        self.m.names['call_part'] = self.function(part); return self.m.call('call_part', args)
    def field(self, record, name, value=None):
        obj = self.memory_object if record == 'memory' else self.association
        at = obj + self.facts[record]['fields'][name]
        size = 1 if name in ('prepared_', 'quarantined_', 'read_only_', 'prepared', 'quarantined') else 4 if name == 'device_references_' else 8
        if value is not None: self.m.put(at, value.to_bytes(size, 'little'))
        return int.from_bytes(self.m.read(at, size), 'little')
    def meta_cast(self, args):
        require((args[0], self.m.string(args[1])) in ((self.surface, 'IOSurface'), (self.backing, 'IOMemoryDescriptor')),
                'Surface page source type check changed')
        self.m.returned(args[0])
    def prepare(self, args):
        require(args[:2] == [self.backing, 0] and not self.prepared, 'Unexpected descriptor prepare')
        self.prepare_calls += 1
        if self.mutation == 'prepare-replacement': self.p64(self.surface + 56, 0xdeadbeef)
        if self.prepare_failed: self.m.returned(0xe00002ca); return
        self.prepared = True; self.m.returned()
    def complete(self, args):
        require(args[:2] == [self.backing, 0] and self.prepared, 'Unprepare without a successful prepare')
        require(self.field('memory', 'device_references_') == 1, 'Source unprepared backing while VM/job references remain')
        self.complete_calls += 1
        if self.complete_failed: self.m.returned(0xe00002ca); return
        self.prepared = False; self.m.returned()
    def segment(self, args):
        require(args[0] == self.backing and self.prepared and args[1] < self.length and args[1] % 4096 == 0 and args[3] == 0x800,
                'Source physical walk escaped exact prepared descriptor')
        self.segments += 1
        if self.segments == 3:
            if self.mutation == 'walk-replacement': self.p64(self.surface + 56, 0xdeadbeef)
            elif self.mutation == 'walk-resize': self.p32(self.surface + 172, 16384)
        self.p64(args[2], self.run); self.m.returned(self.physical[args[1] // 4096])
    def physical_cache(self, args):
        require(args[:3] == [0x40000000, 12288, 1], 'Native VM lease changed the association page range')
        self.cache.append({'references': self.field('memory', 'device_references_'), 'descriptor_prepared': self.prepared})
        self.m.returned(0xe00002ca if self.cache_failed else 0)
    def source_observe(self, cpu, pc, size, ignored):
        if pc in self.source_entries: self.source_visits.add(self.source_entries[pc])
    def bind(self): return self.m.call('_dodge_surface_pages_bind', [self.identity, self.backing, self.memory_object, self.association])
    def current(self): return self.m.call('_dodge_surface_pages_current', [self.association])
    def release(self): return self.m.call('_dodge_surface_pages_release', [self.association])
    def balanced(self, consumed=True):
        require(self.field('memory', 'device_references_') == 0 and self.u32(self.backing + self.facts['object']['fields']['retainCount']) == 1 and
            self.u32(self.surface + 1000) == (1 if consumed else 2) and not self.prepared and
            self.m.read(self.association, self.facts['association']['bytes']) == bytes(self.facts['association']['bytes']),
            'Source page association did not balance its actual native/original references')
    def retained(self):
        require(self.field('memory', 'device_references_') >= 1 and self.u32(self.backing + self.facts['object']['fields']['retainCount']) == 2 and
                self.u32(self.surface + 1000) == 2 and self.prepared, 'Source association lost prepared or retained backing')
    def result(self, name):
        for at, (size, _) in self.objects.items():
            require(self.m.read(at - 16, 16) == self.m.read(at + size, 16) == b'\xa5' * 16, 'Surface page source corrupted bounded object guard')
        return {'case': name, 'result': 'PASS', 'instructions': self.instructions, 'source_entries': sorted(self.source_visits),
                'original_entries': sorted(self.executed), 'physical_segments_checked': self.segments,
                'prepare_calls': self.prepare_calls, 'complete_calls': self.complete_calls,
                'native_memory_references': self.field('memory', 'device_references_')}


def cases(raw, facts, probe, control=None):
    rows = []
    def new(): return Execution(raw, facts, probe, control)
    e = new(); require(not e.bind(), 'Actual source page bind refused matching import'); e.retained()
    require(not e.current() and not e.release() and not e.release(), 'Actual source page release/current failed'); e.balanced()
    rows.append(e.result('matching-full-descriptor-and-native-original-balanced-lifetime'))
    e = new(); e.field('memory', 'span_count_', 3)
    for i in range(3):
        pa = 0x40000000 + i * 8192; e.m.put(e.span + i * 24, struct.pack('<3Q', i * 4096, pa, 4096)); e.physical[i] = pa
    require(not e.bind() and not e.release(), 'Actual fragmented page association failed'); e.balanced(); rows.append(e.result('fragmented-physical-pages'))
    for page in range(3):
        e = new(); e.physical[page] += 0x100000
        require(e.bind() == 0xe00002e2, 'Actual source accepted a mismatched physical page'); e.balanced(); rows.append(e.result('mismatched-page-' + str(page)))
    for name in ('zero-PA', 'gap', 'truncated', 'overflow', 'overlong', 'empty-count'):
        e = new()
        if name == 'zero-PA': e.p64(e.span + 8, 0)
        elif name == 'gap': e.p64(e.span, 4096)
        elif name == 'truncated': e.p64(e.span + 16, 8192)
        elif name == 'overflow': e.p64(e.span + 8, 0xfffffffffffff000)
        elif name == 'overlong': e.p64(e.span + 16, 16384)
        else: e.field('memory', 'span_count_', 0)
        expected = 0xe00002d8 if name == 'empty-count' else 0xe00002c2
        require(e.bind() == expected, 'Actual source accepted malformed import metadata: ' + name)
        e.balanced(consumed=name != 'empty-count'); rows.append(e.result('malformed-span-' + name))
    for name, expected in (('short-run', 0xe00002e2), ('prepare-failure', 0xe00002ca),
                            ('prepare-replacement', 0xe00002d8), ('walk-replacement', 0xe00002d8), ('walk-resize', 0xe00002d8)):
        e = new()
        if name == 'short-run': e.run = 4095
        elif name == 'prepare-failure': e.prepare_failed = True
        else: e.mutation = name
        require(e.bind() == expected, 'Actual page association missed capture failure: ' + name); e.balanced(); rows.append(e.result(name))
    for name in ('rollback-complete-failure', 'release-complete-failure'):
        e = new()
        if name.startswith('rollback'): e.physical[1] += 4096; e.complete_failed = True; status = e.bind()
        else: require(not e.bind(), 'Page association could not start'); e.complete_failed = True; status = e.release()
        require(status == 0xe00002ca and e.field('association', 'quarantined') and e.field('memory', 'quarantined_') and
                e.release() == 0xe00002d8 and e.current() == 0xe00002d8, 'Actual complete failure did not quarantine ownership')
        e.retained(); rows.append(e.result(name))
    for readonly, expected in ((False, 0xe00002e2), (True, 0)):
        e = new(); e.direction = 2; e.field('memory', 'read_only_', int(readonly))
        require(e.bind() == expected, 'Actual surface descriptor write permissions changed')
        if not expected: require(not e.release(), 'Read-only association release failed')
        e.balanced(consumed=not expected); rows.append(e.result('descriptor-direction-readonly-' + str(readonly)))
    e = new(); e.p32(e.surface + 172, 8193); require(not e.bind() and not e.release(), 'Actual allocation rounding failed'); e.balanced()
    rows.append(e.result('allocation-rounded-within-exact-import'))
    e = new(); e.p64(e.surface + 56, 0xdeadbeef)
    require(e.bind() == 0xe00002e2 and not e.prepare_calls, 'Borrowed unowned descriptor was dereferenced or accepted'); e.balanced(False)
    rows.append(e.result('unowned-borrowed-pointer-compared-only'))
    e = new(); require(not e.bind(), 'Association start failed'); e.field('memory', 'device_references_', 2)
    require(e.release() == 0xe00002d5 and not e.complete_calls, 'Source unprepared backing with outstanding native resource hold')
    e.field('memory', 'device_references_', 1); require(not e.release(), 'Association release after fixture quiescence failed'); e.balanced()
    rows.append(e.result('extra-device-reference-defers-unprepare'))
    for jobs in (1,2):
        e=new();require(not e.bind(),'Association start failed before native VM holds')
        # Mapping installation and its eventual TLB unmap are explicit fixture
        # operations. Actual VM job holds/acquisition/retirement execute here.
        require(not e.call_part('NativeAdrenoMemory13holdForDevice',[e.memory_object]),'Mapping fixture reference failed')
        vm=e.allocate(facts['vm']['bytes'],'native-VM');mapping=e.allocate(facts['mapping']['bytes'],'native-mapping')
        output=e.allocate(16,'VM-snapshot-output')
        def field(record,obj,name,value,width=8):e.m.put(obj+facts[record]['fields'][name],value.to_bytes(width,'little'))
        for name,value in (('mappings_',mapping),('high_',1),('next_handle_',2)):field('vm',vm,name,value)
        field('vm',vm,'attached_',1,1)
        for name,value in (('memory',e.memory_object),('handle',1),('iova',0x800000)):field('mapping',mapping,name,value)
        field('mapping',mapping,'permissions',3,4)
        for _ in range(jobs):
            require(not e.call_part('NativeAdrenoVm10holdMapped',[vm,output,output+8]) and
                    (e.u64(output),e.u64(output+8))==(2,1),'Actual native VM did not capture associated resource')
        require(e.release()==0xe00002d5 and not e.complete_calls,'Association backing unprepared with actual VM job holds')
        for index in range(jobs):
            require(not e.call_part('NativeAdrenoVm12retireMapped',[vm,2,1,1]),'Actual native VM job retirement failed')
            require(e.field('memory','device_references_')==1+jobs-index,'Native VM retired another owner reference')
            require(e.release()==0xe00002d5 and not e.complete_calls,'Mapping/other job reference did not protect backing')
        require(len(e.cache)==jobs and all(row['descriptor_prepared'] for row in e.cache),'Native VM cache acquisition lacked pinned backing')
        require(not e.call_part('NativeAdrenoMemory21retireAfterQuiescence',[e.memory_object]),'Mapping fixture reference retirement failed')
        require(not e.release(),'Association release after native holds retired failed');e.balanced()
        rows.append(e.result('association-through-native-VM-'+str(jobs)+'-job-holds'))
    return rows


def controls(raw,facts,probe):
    e=Execution(raw,facts,probe);rows=[]
    def name(part):return next(n for n in e.m.names if part in n)
    for label,function in (
        ('page-and-current-check-always-success','_dodge_surface_pages_current'),
        ('association-release-skipped','_dodge_surface_pages_release'),
        ('native-memory-hold-skipped',name('NativeAdrenoMemory13holdForDevice')),
        ('native-memory-retirement-skipped',name('NativeAdrenoMemory21retireAfterQuiescence')),
        ('original-descriptor-getter-null','_native_iphone_surface_memory'),
    ):
        try:cases(raw,facts,probe,(function,(0x52800000,0xd65f03c0)))
        except ValueError as error:rows.append({'case':label,'result':'REJECTED','function':function,'reason':str(error)})
        else:raise ValueError('Surface page instruction control accepted: '+label)
    return rows
