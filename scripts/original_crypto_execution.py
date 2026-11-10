#!/usr/bin/env python3
"""Execute original crypto and native consumers; only platform services are peers."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time

from check_data_mount_kernel import Model
from native_driver_build import ROOT, require


class Execution:
    def __init__(self, candidate, contract, owner, scenario):
        self.model = Model(candidate.read_bytes()); self.contract, self.owner, self.scenario = contract, owner, scenario
        self.names = self.model.names; self.slide = int(owner['slide'], 0)
        self.allocations, self.locks, self.events, self.formats = {}, {}, [], set()
        self.cursor, self.clock = self.model.heap + 0x400000, 100000
        self.logs, self.post_returns, self.panics = [], [], []
        self.request, self.api_generator_calls = None, []
        self.mutex_operations = 0
        self.counts = {name: 0 for name in ('original_entry', 'original_wrapper', 'post_entry', 'native_prng', 'native_table', 'entropy_init', 'entropy_callbacks')}
        self.install_peers(); self.install_observers(); self.mutate()
        # A trusted boot-seed input fixture, not the target bootloader's
        # collection/health tests. Never serialize or print these bytes.
        self.model.put(self.names['_bootseed'], os.urandom(32))

    def allocate(self, count):
        require(0 < count <= 16 << 20, 'Crypto platform allocation exceeds bound')
        address = (self.cursor + 4095) & -4096; self.cursor = address + count + 8192
        self.model.map(address - 64, count + 128); self.model.put(address - 64, bytes([0xa5]) * (count + 128))
        self.model.put(address, bytes(count)); self.allocations[address] = count
        return address

    def writes(self, address, count):
        if self.request:
            start, end = self.request['buffer'], self.request['buffer'] + self.request['bytes']
            first, last = max(start, address), min(end, address + count)
            if first < last: self.request['coverage'][first - start:last - start] = bytes([1]) * (last - first)

    def put(self, address, data):
        self.writes(address, len(data)); self.model.put(address, data)

    def install_peers(self):
        m = self.model
        def free(args):
            require(args[0] in self.allocations and self.allocations[args[0]] == args[1], 'Original crypto free size differs')
            self.check_buffer(args[0], args[1]); del self.allocations[args[0]]; m.returned()
        m.bind('_IOMallocData', lambda args: m.returned(self.allocate(args[0]))); m.bind('_IOFreeData', free)
        def copy(args):
            require(args[2] <= 16 << 20, 'Original crypto copy exceeds bound')
            self.put(args[0], m.read(args[1], args[2])); m.returned(args[0])
        def fill(args):
            require(args[2] <= 16 << 20, 'Original crypto fill exceeds bound')
            self.put(args[0], bytes([args[1] & 255]) * args[2]); m.returned(args[0])
        m.bind('_memcpy', copy); m.bind('_memset', fill)
        def zero(args):
            require(args[1] <= 16 << 20, 'Original crypto zero exceeds bound')
            self.put(args[0], bytes(args[1])); m.returned()
        m.bind('_bzero', zero)
        def checked_copy(args): require(args[2] <= args[3], 'Checked crypto copy exceeds destination'); copy(args)
        def checked_fill(args): require(args[2] <= args[3], 'Checked crypto fill exceeds destination'); fill(args)
        m.bind('___memcpy_chk', checked_copy); m.bind('___memset_chk', checked_fill)
        def memset_s(args):
            require(args[3] <= args[1] and args[3] <= 16 << 20, 'Crypto memset_s exceeds destination')
            self.put(args[0], bytes([args[2] & 255]) * args[3]); m.returned()
        m.bind('_memset_s', memset_s)
        def compare(args):
            require(args[2] <= 16 << 20, 'Crypto memcmp exceeds bound')
            a, b = m.read(args[0], args[2]), m.read(args[1], args[2]); m.returned((a > b) - (a < b))
        m.bind('_memcmp', compare)
        def str_compare(args, bound=4096):
            require(bound <= 4096, 'Crypto string comparison exceeds bound')
            for index in range(bound):
                a, b = m.read(args[0] + index, 1), m.read(args[1] + index, 1)
                if a != b or not any(a): m.returned((a > b) - (a < b)); return
            m.returned()
        m.bind('_strcmp', lambda args: str_compare(args)); m.bind('_strncmp', lambda args: str_compare(args, args[2]))
        def strlcpy(args):
            require(0 < args[2] <= args[3] and args[2] <= 4096, 'Crypto strlcpy exceeds destination')
            data = m.string(args[1]).encode(); self.put(args[0], data[:args[2] - 1] + b'\0'); m.returned(len(data))
        m.bind('___strlcpy_chk', strlcpy)
        def logging(args): self.logs.append(m.string(args[0])); m.returned()
        m.bind('_kprintf', logging)
        def parse(args):
            require(m.string(args[0]) == 'fips_mode' and args[2] == 4, 'Original crypto requested another boot option')
            m.returned()  # Absent: both actual callers select full default mode zero.
        m.bind('_PE_parse_boot_argn', parse)
        def now(args): self.clock += 10000; m.returned(self.clock)
        m.bind('_mach_absolute_time', now); m.bind('_ml_get_timebase', now)
        m.bind('_clock_timebase_info', lambda args: (m.put(args[0], struct.pack('<II', 1, 1)), m.returned()))
        def group(args):
            require(len(m.string(args[0])) < 128, 'Crypto lock group name exceeds bound'); m.returned(self.allocate(128))
        def mutex(args):
            require(args[0] in self.allocations, 'Crypto mutex used an unknown lock group')
            address = self.allocate(128); self.locks[address] = 0; m.returned(address)
        m.bind('_lck_grp_alloc_init', group); m.bind('_lck_mtx_alloc_init', mutex)
        def lock(args):
            require(args[0] in self.locks and self.locks[args[0]] == 0, 'Crypto peer mutex is already owned')
            self.mutex_operations += 1; self.locks[args[0]] = 1; m.returned()
        def unlock(args):
            require(self.locks.get(args[0]) == 1, 'Crypto peer mutex is not owned')
            self.mutex_operations += 1; self.locks[args[0]] = 0; m.returned()
        def try_lock(args):
            require(args[0] in self.locks, 'Unknown crypto peer mutex')
            self.mutex_operations += 1; got = self.locks[args[0]] == 0; self.locks[args[0]] = 1; m.returned(got)
        def assert_lock(args):
            require(args[0] in self.locks and args[1] in (1, 2) and self.locks[args[0]] == (args[1] == 1),
                    'Actual original mutex ownership assertion failed'); m.returned()
        m.bind('_lck_mtx_lock', lock); m.bind('_lck_mtx_unlock', unlock); m.bind('_lck_mtx_try_lock', try_lock); m.bind('_lck_mtx_assert', assert_lock)
        m.bind('_pmap_in_ppl', lambda args: m.returned())
        def forbidden_ppl(args): raise ValueError('Ordinary kernel fixture reached a PPL page operation')
        m.bind('_pmap_claim_reserved_ppl_page', forbidden_ppl); m.bind('_pmap_free_reserved_ppl_page', forbidden_ppl)
        m.bind('_cpu_number', lambda args: m.returned())
        def entropy_init(args): self.counts['entropy_init'] += 1; m.returned()
        def entropy(args):
            capacity, = struct.unpack('<Q', m.read(args[0], 8)); require(capacity <= 4096, 'Entropy fixture exceeds callback bound')
            self.counts['entropy_callbacks'] += 1; m.put(args[0], bytes(8)); m.returned()
        # No collected interrupt samples in this early-boot fixture. The PRNG
        # uses the provided 32-byte boot seed; no positive entropy score is supplied.
        m.bind('_entropy_init', entropy_init); m.bind('_entropy_provide', entropy)
        m.bind('_sysctl_register_oid', lambda args: m.returned())
        def snprintf(args):
            require(args[1] <= 4096, 'Crypto name formatting exceeds bound')
            fmt = m.string(args[2]); self.formats.add(fmt); sp = m.cpu.reg_read(m.arm.UC_ARM64_REG_SP); offset = 0
            def conversion(match):
                nonlocal offset
                token = match.group(0)
                if token == '%%': return '%'
                value, = struct.unpack('<Q', m.read(sp + offset, 8)); offset += 8; kind = token[-1]
                if kind == 's': return m.string(value)
                if kind == 'c': return chr(value & 255)
                if kind in 'xXp': return ('0x' if kind == 'p' else '') + format(value, 'X' if kind == 'X' else 'x')
                if kind in 'di':
                    bits = 64 if 'l' in token or 'z' in token else 32; value &= (1 << bits) - 1
                    if value & (1 << (bits - 1)): value -= 1 << bits
                return str(value)
            output = re.sub(r'%(?:%|(?:ll|l|z)?[cdiuxXsp])', conversion, fmt).encode()
            require(b'%' not in output, 'Unmodeled original crypto name format: ' + fmt)
            if args[1]: self.put(args[0], output[:args[1] - 1] + b'\0')
            m.returned(len(output))
        m.bind('_snprintf', snprintf)
        def panic(args): self.panics.append(m.string(args[0])); m.cpu.reg_write(m.arm.UC_ARM64_REG_PC, m.stop)
        m.bind('_panic', panic)
        m.bind('___stack_chk_fail', lambda args: (_ for _ in ()).throw(ValueError('Original crypto stack guard failed')))

    def observe(self, address, callback):
        self.model.cpu.hook_add(self.model.u.UC_HOOK_CODE, callback, begin=address, end=address)

    def install_observers(self):
        m, n = self.model, self.names
        for key, address in (('original_entry', n['_dodge_original_crypto_real_entry']), ('original_wrapper', n['_dodge_original_crypto_entry']),
                             ('native_prng', n['_register_and_init_prng']), ('native_table', n['_register_crypto_functions'])):
            def observed(cpu, pc, size, ignored, label=key): self.counts[label] += 1; self.events.append(label)
            self.observe(address, observed)
        def post_entry(cpu, pc, size, ignored):
            require(m.register(0) == 0 and m.register(1) == n['_dodge_original_crypto_header'], 'Original POST mode/header argument differs')
            self.counts['post_entry'] += 1; self.events.append('post_entry')
        self.observe(int(self.contract['post_entry'], 16) + self.slide, post_entry)
        def post_return(cpu, pc, size, ignored): self.post_returns.append(m.register(0) & 0xffffffff); self.events.append('post_return')
        self.observe(int(self.contract['after_post_call'], 16) + self.slide, post_return)
        generate = int(self.owner['prng_functions']['pointers'][4], 16) + self.slide
        def generator(cpu, pc, size, ignored):
            if not self.request: return
            args = [m.register(i) for i in range(4)]; request = self.request
            require(args[0] == n['_dodge_original_crypto_prng_context'] and args[1] == 0 and
                    0 < args[2] <= request['bytes'] - request['offset'] and args[3] == request['buffer'] + request['offset'],
                    'Native PRNG callback crossed its context/generator/output request')
            request['offset'] += args[2]; self.api_generator_calls.append(args[2])
        self.observe(generate, generator)
        m.cpu.hook_add(m.u.UC_HOOK_MEM_WRITE, lambda cpu, kind, address, size, value, ignored: self.writes(address, size))
        protected = ['_dodge_original_crypto_entry', '_dodge_original_crypto_real_entry', '_register_and_init_prng',
                     '_register_crypto_functions', '_dodge_crypto_prng_ready', '_dodge_crypto_prng_matches', '_read_random',
                     '_crypto_random_generate', '_crypto_random_uniform', '_crypto_random_kmem_ctx_size', '_crypto_random_kmem_init',
                     '_cc_rand_generate', '_random_buf', '_kmem_crypto_init', '_zpercpu_count']
        protected += ['_' + algorithm + '_' + part for algorithm in ('SHA256', 'SHA384', 'SHA512') for part in ('Init', 'Update', 'Final')]
        protected += [int(self.contract['post_entry'], 16) + self.slide,
                      *[int(value, 16) + self.slide for value in self.owner['prng_functions']['pointers']]]
        for name in protected:
            address = n[name] if isinstance(name, str) else name
            require(address not in m.peers, 'Crypto/registration/PRNG was replaced with a peer: ' + str(name))

    def mutate(self):
        m, scenario = self.model, self.scenario
        if scenario == 'bad-stop-code':
            wrapper, = struct.unpack('<Q', m.read(self.names['_dodge_original_crypto_kmod'] + 188, 8))
            a, b = struct.unpack('<2I', m.read(wrapper, 8)); delta = ((a >> 5) & 0x7ffff) * 4 + ((a >> 29) & 3)
            require(a & 0x9f00001f == 0x90000008 and b & 0xffc003ff == 0x91000108, 'Original stop slot address changed')
            slot = (wrapper & -4096) + ((delta - (1 << 21) if delta & (1 << 20) else delta) << 12) + ((b >> 10) & 4095)
            body, = struct.unpack('<Q', m.read(slot, 8)); old = m.read(body + 4, 1); m.put(body + 4, bytes([old[0] ^ 1]))
        elif scenario == 'bad-hmac-answer':
            at = int(self.contract['first_hmac_answer'], 16) + self.slide
            old = m.read(at, 1); m.put(at, bytes([old[0] ^ 1]))
        elif scenario == 'post-RET': m.put(int(self.contract['post_entry'], 16) + self.slide, struct.pack('<I', 0xd65f03c0))
        elif scenario == 'ready-store-NOP':
            start = self.names['_register_and_init_prng']; code = m.read(start, 240)
            words = struct.unpack('<60I', code); found = []
            for index in range(59):
                if words[index] == 0x52800028 and words[index + 1] & 0xffc0001f == 0xb9000008: found.append(start + (index + 1) * 4)
            require(len(found) == 1, 'Native PRNG ready publication instruction is ambiguous')
            m.put(found[0], struct.pack('<I', 0xd503201f))
        else: require(scenario == 'normal', 'Unknown original crypto execution scenario')

    def bootstrap(self):
        m = self.model; m.cpu.reg_write(m.arm.UC_ARM64_REG_SP, m.stack + 0xff000); m.cpu.reg_write(m.arm.UC_ARM64_REG_LR, m.stop)
        pc, started = self.names['_source_corecrypto14_bootstrap'], time.monotonic()
        for chunk in range(100):
            m.cpu.emu_start(pc, m.stop, count=5000000); pc = m.cpu.reg_read(m.arm.UC_ARM64_REG_PC)
            if pc == m.stop: break
            if chunk % 5 == 4: print(self.scenario + ': actual crypto execution ' + str((chunk + 1) * 5) + 'M instructions', flush=True)
        else: raise ValueError('Original crypto execution exhausted its bounded instruction budget')
        self.elapsed = time.monotonic() - started

    def check_buffer(self, address, count):
        require(self.model.read(address - 64, 64) == self.model.read(address + count, 64) == bytes([0xa5]) * 64,
                'Original crypto/native consumer escaped an allocation')

    def consumers(self, context_sizes):
        m = self.model; rows = []
        for name, context_bytes, digest_bytes in zip(('SHA256', 'SHA384', 'SHA512'), context_sizes[:3], context_sizes[3:]):
            for value in (b'', b'abc', b'a' * 127, b'a' * 128, b'a' * 129, b'abc' * 1000):
                context, output, data = self.allocate(context_bytes), self.allocate(digest_bytes), self.allocate(max(1, len(value)))
                m.put(data, value); m.call('_' + name + '_Init', [context])
                cut = min(17, len(value)); m.call('_' + name + '_Update', [context, data, cut], limit=2000000)
                m.call('_' + name + '_Update', [context, data + cut, len(value) - cut], limit=2000000)
                m.call('_' + name + '_Final', [output, context], limit=2000000)
                require(m.read(output, digest_bytes) == hashlib.new(name.lower(), value).digest(), 'Native/original SHA consumer differs')
                rows.append({'algorithm': name, 'input_bytes': len(value), 'split_at': cut, 'result': 'PASS'})
        random_rows = []
        for count in (1, 32, 4096, 65536):
            output = self.allocate(count)
            self.request = {'buffer': output, 'bytes': count, 'offset': 0, 'coverage': bytearray(count)}
            before = len(self.api_generator_calls); m.call('_read_random', [output, count], limit=3000000)
            require(self.request['offset'] == count and all(self.request['coverage']), 'Native/original PRNG did not write every requested byte')
            random_rows.append({'bytes': count, 'generator_chunks': self.api_generator_calls[before:], 'all_output_bytes_written': True, 'result': 'PASS'})
            self.request = None
        return rows, random_rows

    def cached_loader_span(self):
        m = self.model; source = json.loads((ROOT / 'reports/ios16-crypto-source.json').read_text()); hooks = source['actual_crypto_hooks']
        module = self.names['_dodge_original_crypto_kmod']; m.put(module + 80, b'12.0\0')
        begin = int(hooks['original_cpp_call'], 16) + 4; branch, load = struct.unpack('<2I', m.read(begin, 8))
        require(branch & 0xff00001f == 0x35000000 and load & 0xffc003ff == 0xf9400260, 'Actual post-C++ loader fragment changed')
        delta = (branch >> 5) & 0x7ffff; end = begin + 4 * (delta - (1 << 19) if delta & (1 << 18) else delta)
        kext = self.allocate(512); m.put(kext + ((load >> 10) & 4095) * 8, struct.pack('<Q', module))
        m.cpu.reg_write(m.arm.UC_ARM64_REG_X19, kext); boundary = []
        m.names['_real_crypto_cached_span'] = begin; m.names['_real_crypto_cached_boundary'] = end
        def reached(args): boundary.append(m.register(0) & 0xffffffff); m.cpu.reg_write(m.arm.UC_ARM64_REG_PC, m.stop)
        m.bind('_real_crypto_cached_boundary', reached); m.call('_real_crypto_cached_span', [0])
        require(boundary == [0] and self.counts['original_entry'] == self.counts['post_entry'] == 1, 'Actual cached loader repeated original initialization/POST')
        return {'result': 'PASS', 'loader_stamped_version': '12.0', 'original_initializer_calls': self.counts['original_entry'],
                'original_post_calls': self.counts['post_entry'], 'full_oskext_start_executed': False}

    def memory_consumers(self, geometry):
        m = self.model; size = m.call('_crypto_random_kmem_ctx_size')
        require(0 < size <= geometry['maximum_context_bytes'], 'Original kmem random context exceeds the native API bound')
        context = self.allocate(size); m.call('_crypto_random_kmem_init', [context]); rows = []
        def request(count):
            output = self.allocate(count); self.request = {'buffer': output, 'bytes': count, 'offset': 0, 'coverage': bytearray(count)}
            return output
        def written():
            require(all(self.request['coverage']), 'Native random consumer did not write the full result'); self.request = None
        for count in (1, 32, 4096):
            output = request(count); before = self.mutex_operations
            m.call('_crypto_random_generate', [context, output, count], limit=3000000); written()
            require(self.mutex_operations == before, 'Initialized kmem random generator acquired a mutex')
            rows.append({'api': 'crypto_random_generate', 'bytes': count, 'all_output_bytes_written': True,
                         'no_mutex_acquired': True, 'cryptographic_randomness_qualified': False, 'result': 'PASS'})
        for bound in (1, 2, 3, 17, 1 << 32, 1 << 63, (1 << 64) - 1):
            output = request(8); before = self.mutex_operations
            m.call('_crypto_random_uniform', [context, bound, output], limit=3000000); written()
            value, = struct.unpack('<Q', m.read(output, 8))
            require(value < bound and self.mutex_operations == before, 'Native kmem uniform result exceeded the bound or acquired a mutex')
            rows.append({'api': 'crypto_random_uniform', 'bound': bound, 'result_within_bound': True,
                         'all_output_bytes_written': True, 'no_mutex_acquired': True, 'result': 'PASS'})
        for api in ('_cc_rand_generate', '_random_buf'):
            for count in (1, 32, 4096):
                output = request(count); result = m.call(api, [output, count], limit=3000000); written()
                require(result == 0, 'Native ccrng/random_buf consumer failed')
                rows.append({'api': api[1:], 'bytes': count, 'api_return': result, 'all_output_bytes_written': True, 'result': 'PASS'})
        # Run the real EARLY_BOOT callback. Only allocation is a peer. Read
        # private array geometry from the actual compiled MOV/STR/CMP, then
        # read back each published pointer rather than reconstructing the array.
        start = self.names['_kmem_crypto_init']
        stride, = struct.unpack('<I', m.read(start + 0x28, 4))
        store, = struct.unpack('<I', m.read(start + 0x54, 4))
        bound, = struct.unpack('<I', m.read(start + 0x94, 4))
        require(stride & 0xffe0001f == 0x52800016 and store & 0xffc003ff == 0xf9000280 and
                bound & 0xffc003ff == 0xf10002bf, 'Actual kmem random startup array geometry changed')
        stride = (stride >> 5) & 65535; field = ((store >> 10) & 4095) * 8; classes = (bound >> 10) & 4095
        require(stride == 168 and field == 16 and classes == 14, 'Actual kmem random startup extent differs')
        mask = geometry['percpu_mangle_mask']; physical = mask | 0x660000000; allocations, initialized = [], []
        # This bounded run begins after VM/platform initialization. Its static
        # image still contains the zero-initialized page-shift variable, so
        # supply the selected 4 KiB platform value explicitly; VM is not run.
        page_shift = self.names['_PAGE_SHIFT_CONST']
        require(struct.unpack('<I', m.read(page_shift, 4))[0] in (0, 12), 'Native per-CPU page-shift fixture conflicts with the candidate')
        m.put(page_shift, struct.pack('<I', 12))
        m.put(self.names['_zpercpu_early_count'], struct.pack('<I', 1))
        require(m.call('_zpercpu_count') == 1, 'Actual native per-CPU allocation count differs from the CPU0 fixture')
        def percpu(args):
            require(args[0] == size and args[1] == geometry['percpu_alignment_mask'] and len(allocations) < classes,
                    'Actual kmem random startup per-CPU allocation shape differs')
            address = physical + len(allocations) * 0x10000; m.map(address - 64, size + 128)
            m.put(address - 64, bytes([0xa5]) * (size + 128)); m.put(address, bytes(size))
            self.allocations[address] = size; allocations.append(address); m.returned(address & ~mask)
        m.bind('_zalloc_percpu_permanent', percpu)
        self.observe(self.names['_crypto_random_kmem_init'], lambda cpu, pc, count, ignored: initialized.append(m.register(0)))
        m.call('_kmem_crypto_init', limit=3000000)
        require(initialized == allocations and len(allocations) == classes and not self.panics,
                'Actual EARLY_BOOT kmem random startup did not initialize every size class')
        array = self.names['_kmem_size_array']
        for index, address in enumerate(allocations):
            require(struct.unpack('<Q', m.read(array + index * stride + field, 8))[0] == address & ~mask,
                    'Actual kmem random startup did not publish its allocated context')
        return {'result': 'PASS', 'original_context_bytes': size, 'direct_case_count': len(rows), 'direct_cases': rows,
                'actual_early_boot_kmem': {'result': 'PASS', 'native_size_classes_initialized': classes, 'percpu_fixture_count': 1,
                    'native_array_stride': stride, 'native_context_field': field, 'all_published_pointers_read_back': True,
                    'page_shift_supplied_as_platform_fixture': 12,
                    'percpu_allocator_is_explicit_peer': True, 'full_allocator_or_smp_qualified': False}}


def run_case(candidate, contract, owner, contexts, scenario, random_geometry=None):
    run = Execution(Path(candidate), contract, owner, scenario); run.bootstrap()
    m, n = run.model, run.names
    passed = [message.rsplit(' - ', 1)[-1].strip() for message in run.logs if 'PASSED:' in message]
    required = contract['required_passed_tests']
    table, = struct.unpack('<Q', m.read(n['_g_crypto_funcs'], 8))
    ready, matches = m.call('_dodge_crypto_prng_ready'), m.call('_dodge_crypto_prng_matches', [n['_dodge_original_crypto_prng_context']])
    rows, random_rows, cached, memory = [], [], None, None
    if scenario == 'normal':
        require(not run.panics and run.post_returns == [0] and passed == required and
                all(run.counts[key] == 1 for key in ('original_entry', 'original_wrapper', 'post_entry', 'native_prng', 'native_table', 'entropy_init')) and
                ready == matches == 1 and table == n['_dodge_original_crypto_functions'] and m.read(n['_bootseed'], 32) == bytes(32),
                'Actual original crypto initialization/POST/PRNG/table ownership did not complete')
        require(run.events == ['original_wrapper', 'original_entry', 'post_entry', 'post_return', 'native_prng', 'native_table'],
                'Actual original POST/PRNG/table registration order differs')
        rows, random_rows = run.consumers(contexts); cached = run.cached_loader_span()
        require(random_geometry is not None, 'Native memory random layout probe is required')
        memory = run.memory_consumers(random_geometry)
    elif scenario in ('bad-stop-code', 'bad-hmac-answer'):
        failure = 'fipspost_post_integrity' if scenario == 'bad-stop-code' else 'fipspost_post_hmac'
        require(len(run.post_returns) == 1 and run.post_returns[0] != 0 and run.panics and
                all('FIPS Kernel POST Failed' in text for text in run.panics) and failure not in passed and
                run.counts['native_prng'] == run.counts['native_table'] == 0 and ready == matches == table == 0,
                'Altered original code/known-answer input did not fail actual POST before registration')
    elif scenario == 'post-RET':
        require(not run.panics and run.post_returns == [0] and not passed and ready == matches == 1,
                'POST-RET control did not demonstrate missing real selftests')
    elif scenario == 'ready-store-NOP':
        require(run.panics and all('original corecrypto initialization failed' in text for text in run.panics) and
                run.post_returns == [0] and passed == required and ready == matches == 0 and table == n['_dodge_original_crypto_functions'],
                'Real owner guard accepted incomplete native PRNG publication')
    if scenario != 'normal':
        result = m.call('_dodge_crypto_start_once', [n['_dodge_original_crypto_kmod'], 0])
        require(result == (0 if scenario == 'post-RET' else 5) and run.counts['original_entry'] == 1, 'Failed/cached execution attempted original initialization again')
    require(not any(run.locks.values()), 'Original execution left a platform peer mutex owned')
    for address, count in run.allocations.items(): run.check_buffer(address, count)
    return {'case': scenario, 'result': 'PASS' if scenario == 'normal' else 'REJECTED', 'actual_post_return': run.post_returns,
            'actual_passed_post_tests': passed, 'actual_original_entry_and_registration_counts': run.counts,
            'actual_original_panic_formats': run.panics, 'native_sha_vectors': rows, 'native_prng_transfers': random_rows,
            'actual_cached_loader_span': cached, 'actual_registered_table_matches_original': table == n['_dodge_original_crypto_functions'],
            'native_memory_random_consumers': memory,
            'actual_native_prng_ready': bool(ready), 'actual_native_prng_context_matches_original': bool(matches),
            'seed_fixture_cleared': m.read(n['_bootseed'], 32) == bytes(32), 'execution_event_order': run.events,
            'explicit_platform_peers_visited': sorted(m.visited), 'name_format_shapes': sorted(run.formats),
            'no_positive_interrupt_entropy_estimate_supplied': True, 'private_seed_or_random_bytes_disclosed': False,
            'physical_entropy_or_hardware_qualified': False}
