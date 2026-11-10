#!/usr/bin/env python3
"""Execute the built DarwinBoot C boot route with explicit firmware, memory and console peers."""
import os
from pathlib import Path
import re
import struct

from check_data_mount_kernel import Model
from native_driver_build import require

ERROR = 1 << 63


class Firmware(Model):
    def __init__(self, raw, mapping, layout, files, ramdisk, scenario):
        import unicorn as u
        import unicorn.arm64_const as arm
        self.u, self.arm = u, arm; self.cpu = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
        self.pages, self.peers, self.visited = set(), {}, set(); self.names = {}
        for line in Path(mapping).read_text().splitlines():
            match = re.fullmatch(r'([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+\d+\s+(\w+)', line)
            if match:
                address, name = int(match[1], 16), match[2]
                require(name not in self.names or self.names[name] == address, 'Conflicting firmware symbol')
                self.names[name] = address
        pe, = struct.unpack_from('<I', raw, 60); sections, = struct.unpack_from('<H', raw, pe + 6)
        optional, = struct.unpack_from('<H', raw, pe + 20); base, = struct.unpack_from('<Q', raw, pe + 24 + 24)
        require(base == 0, 'Firmware CPU fixture needs the linked preferred base zero')
        extent, = struct.unpack_from('<I', raw, pe + 24 + 56); self.map(0, extent)
        for index in range(sections):
            section = pe + 24 + optional + index * 40
            va, count, offset = struct.unpack_from('<3I', raw, section + 12)
            if count: self.put(va, raw[offset:offset + count])
        self.heap, self.stack, self.stop, self.scratch = 0x600000000, 0x700000000, 0x800000000, 0x100000000
        self.map(self.heap, 0x200000); self.map(self.stack, 0x100000); self.map(self.stop, 4096); self.map(self.scratch, 65536)
        self.cpu.hook_add(u.UC_HOOK_CODE, self.hook)
        self.layout, self.files, self.ramdisk, self.scenario = layout, files, ramdisk, scenario
        self.cursor, self.allocations = self.heap + 0x400000, {}
        self.file_protocols, self.closed, self.events, self.logs = {}, [], [], []
        self.window, self.window_freed, self.exited, self.handoff = None, False, False, None
        self.seed, self.seed_writes = os.urandom(256), 0
        self.seed_erases, self.exit_calls = [], 0
        self.firmware_peers(); self.request = self.request_fixture()

    def allocate(self, size):
        require(0 < size <= 512 << 20, 'Firmware fixture allocation exceeds bound')
        address = (self.cursor + 4095) & -4096; self.cursor = address + size + 8192
        self.map(address - 64, size + 128); self.put(address - 64, bytes([0xa5]) * (size + 128)); self.put(address, bytes(size))
        self.allocations[address] = size; return address

    def free(self, address):
        require(address in self.allocations, 'Firmware freed an unknown allocation')
        self.canary(address, self.allocations[address]); del self.allocations[address]

    def canary(self, address, size):
        require(self.read(address - 64, 64) == self.read(address + size, 64) == bytes([0xa5]) * 64, 'Firmware escaped its allocated buffer')

    def value(self, address, offset, value, width=8): self.put(address + offset, value.to_bytes(width, 'little'))

    def peer(self, label, callback):
        address = self.stop + 0x100 + len(self.peers) * 4; self.names[label] = address; self.bind(label, callback); return address

    def utf16(self, address):
        result = bytearray()
        for index in range(1024):
            unit = self.read(address + index * 2, 2)
            if unit == b'\0\0': return result.decode('utf-16-le')
            result += unit
        raise ValueError('Firmware string exceeded bound')

    def firmware_peers(self):
        a = self.layout
        self.services = self.allocate(a['boot_services_size']); self.value(self.names['gBS'], 0, self.services)
        self.system = self.allocate(a['system_table_size']); self.value(self.names['gST'], 0, self.system)
        self.value(self.names['mImage'], 0, 0x1111)
        self.fs = self.allocate(a['filesystem_size']); self.root = self.allocate(a['file_protocol_size']); self.rng = self.allocate(a['rng_size'])
        def protocol(args):
            require(not self.exited, 'Firmware protocol called after ExitBootServices')
            if args[0] == 0x2222:
                require(self.read(args[1], 16) == self.read(self.names['gEfiSimpleFileSystemProtocolGuid'], 16), 'Volume used a different protocol GUID')
                self.value(args[2], 0, self.fs); self.returned()
            else: self.returned(ERROR | 14)
        self.value(self.services, a['bs_handle_protocol'], self.peer('firmware_handle_protocol', protocol))
        def volume(args): require(args[0] == self.fs, 'Different volume fixture'); self.value(args[1], 0, self.root); self.returned()
        self.value(self.fs, a['fs_open_volume'], self.peer('firmware_open_volume', volume))
        def open_file(args):
            require(args[0] == self.root and args[3] == 1 and args[4] == 0, 'Firmware opened a file for another operation')
            name = self.utf16(args[2]); self.events.append('open:' + name.rsplit('\\', 1)[-1])
            if name not in self.files: self.returned(ERROR | 14); return
            file = self.allocate(a['file_protocol_size']); self.file_protocols[file] = name
            for field, address in self.file_methods.items(): self.value(file, a[field], address)
            self.value(args[1], 0, file); self.returned()
        def info(args):
            require(args[0] in self.file_protocols, 'Unknown firmware file info')
            size, = struct.unpack('<Q', self.read(args[2], 8))
            needed = a['file_info_size'] + 32
            self.value(args[2], 0, needed)
            if size < needed: self.returned(ERROR | 5); return
            require(args[3] in self.allocations and self.allocations[args[3]] >= needed, 'Firmware file info lacks allocation')
            self.value(args[3], 0, needed); self.value(args[3], a['info_file_size'], len(self.files[self.file_protocols[args[0]]]))
            self.value(args[3], a['info_attributes'], 0); self.returned()
        def read(args):
            data = self.files[self.file_protocols[args[0]]]; wanted, = struct.unpack('<Q', self.read(args[1], 8))
            require(wanted == len(data) and self.allocations.get(args[2]) == wanted, 'Firmware file read size differs')
            self.put(args[2], data); self.value(args[1], 0, len(data)); self.returned()
        def close(args): self.closed.append(args[0]); self.returned()
        self.file_methods = {'file_get_info': self.peer('firmware_file_info', info), 'file_read': self.peer('firmware_file_read', read),
                             'file_close': self.peer('firmware_file_close', close)}
        self.value(self.root, a['file_open'], self.peer('firmware_file_open', open_file)); self.value(self.root, a['file_close'], self.file_methods['file_close'])
        def locate(args):
            require(not self.exited, 'RNG discovery after ExitBootServices')
            guid = self.read(args[0], 16)
            if guid == self.read(self.names['gEfiRngProtocolGuid'], 16):
                self.events.append('locate-rng')
                if self.scenario == 'rng-missing': self.returned(ERROR | 14); return
                self.value(args[2], 0, self.rng); self.returned()
            else: self.returned(ERROR | 14)
        def rng(args):
            raw_guid = struct.pack('<IHH8B', 0xe43176d7, 0xb6e8, 0x4827, 0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61)
            require(not self.exited and args[0] == self.rng and self.read(args[1], 16) == raw_guid and args[2] == 256,
                    'Actual firmware entropy call differs from RAW/256-byte contract')
            require(self.read(args[3], 256) == bytes(256), 'Actual loader did not erase the payload seed before RNG')
            self.events.append('raw-rng'); self.seed_writes += 1
            self.seed_address = args[3]
            count = 37 if self.scenario == 'rng-partial-error' else 256
            self.put(args[3], bytes(count) if self.scenario == 'rng-zero' else self.seed[:count])
            self.returned(ERROR | 7 if self.scenario == 'rng-partial-error' else ERROR | 3 if self.scenario == 'rng-unsupported' else 0)
        self.value(self.services, a['bs_locate_protocol'], self.peer('firmware_locate_protocol', locate))
        self.value(self.rng, a['rng_get'], self.peer('firmware_raw_rng', rng))
        def memory_map(args):
            require(not self.exited, 'GetMemoryMap after ExitBootServices')
            if self.scenario == 'late-map-failure' and self.seed_writes:
                self.events.append('late-map-failure'); self.returned(ERROR | 7); return
            size, = struct.unpack('<Q', self.read(args[0], 8)); needed = a['memory_descriptor_size']
            self.value(args[0], 0, needed); self.value(args[2], 0, 99); self.value(args[3], 0, needed); self.value(args[4], 0, 1, 4)
            if size < needed: self.returned(ERROR | 5); return
            descriptor = bytearray(needed); struct.pack_into('<I', descriptor, 0, 7)
            struct.pack_into('<Q', descriptor, a['descriptor_physical'], 0x200000000)
            struct.pack_into('<Q', descriptor, a['descriptor_pages'], (5 << 30) // 4096)
            self.put(args[1], bytes(descriptor)); self.events.append('get-memory-map'); self.returned()
        self.value(self.services, a['bs_memory_map'], self.peer('firmware_get_memory_map', memory_map))
        def pages(args):
            require(args[0] == 2 and args[1] == 1 and args[2] == (4 << 30) // 4096, 'Actual firmware window allocation shape differs')
            address, = struct.unpack('<Q', self.read(args[3], 8)); require(0x200000000 <= address < 0x200200000, 'Actual window address left its fixture')
            self.window = (address, args[2] * 4096); self.events.append('allocate-window'); self.returned()
        self.value(self.services, a['bs_allocate_pages'], self.peer('firmware_allocate_pages', pages))
        def free_pages(args):
            require(self.window == (args[0], args[1] * 4096), 'Firmware freed a different window')
            self.window_freed = True; self.events.append('free-window'); self.returned()
        self.value(self.services, a['bs_free_pages'], self.peer('firmware_free_pages', free_pages))
        def alloc_pool(args): self.value(args[2], 0, self.allocate(args[1])); self.returned()
        def free_pool(args): self.free(args[0]); self.returned()
        self.value(self.services, a['bs_allocate_pool'], self.peer('firmware_allocate_pool', alloc_pool))
        self.value(self.services, a['bs_free_pool'], self.peer('firmware_free_pool', free_pool))
        def exit_services(args):
            require(args[0] == 0x1111 and args[1] == 99 and self.seed_writes == 1 and not self.exited, 'ExitBootServices preceded fresh entropy')
            self.exit_calls += 1
            if self.scenario == 'exit-stale-key-once' and self.exit_calls == 1:
                self.events.append('exit-stale-key'); self.returned(ERROR | 2); return
            self.exited = True; self.events.append('exit-boot-services'); self.returned()
        self.value(self.services, a['bs_exit_services'], self.peer('firmware_exit_boot_services', exit_services))
        self.bind('AllocatePool', lambda args: self.returned(self.allocate(args[0])))
        def native_free(args): self.free(args[0]); self.returned()
        self.bind('FreePool', native_free)
        def copy(args):
            require(args[2] <= 128 << 20, 'Firmware copy exceeds bound'); self.map(args[0], args[2]); self.put(args[0], self.read(args[1], args[2])); self.returned(args[0])
        def zero(args):
            require(args[1] <= 512 << 20, 'Firmware zero exceeds bound'); self.map(args[0], args[1]); self.put(args[0], bytes(args[1])); self.returned(args[0])
        self.bind('CopyMem', copy); self.bind('ZeroMem', zero)
        self.bind('Print', lambda args: self.returned()); self.bind('DebugPrint', lambda args: self.returned())
        self.bind('DebugAssert', lambda args: (_ for _ in ()).throw(ValueError('Actual firmware assertion failed')))
        self.bind('CpuDeadLoop', lambda args: (_ for _ in ()).throw(ValueError('Actual firmware dead loop reached')))
        self.bind('DarwinCurrentEl', lambda args: self.returned(4))
        def handoff(args): self.handoff = args[:4]; self.events.append('darwin-enter-boundary'); self.cpu.reg_write(self.arm.UC_ARM64_REG_PC, self.stop)
        self.bind('DarwinEnter', handoff)
        def erase(cpu, pc, count, ignored):
            # LTO specializes the private helper's constant 256-byte length
            # and removes its second argument. Check the actual written range
            # at the RNG boundary and after failure, not a dead argument.
            self.seed_erases.append(self.register(0))
        self.cpu.hook_add(self.u.UC_HOOK_CODE, erase, begin=self.names['DodgeBootEntropyErase'], end=self.names['DodgeBootEntropyErase'])

    def request_fixture(self):
        a = self.layout; request = self.allocate(a['request_size']); path = self.allocate(128)
        self.put(path, '\\kernel.macho'.encode('utf-16-le') + b'\0\0'); self.value(request, a['request_volume'], 0x2222)
        self.value(request, a['request_path'], path)
        ramdisk = self.allocate(len(self.ramdisk)); self.put(ramdisk, self.ramdisk)
        self.value(request, a['request_ramdisk'], ramdisk); self.value(request, a['request_ramdisk_size'], len(self.ramdisk))
        return request

    def run(self):
        self.call('Boot', [0, self.request], limit=5000000)
        for address, size in self.allocations.items(): self.canary(address, size)
        if self.handoff:
            require(self.scenario in ('normal', 'exit-stale-key-once') and self.exited and not self.window_freed, 'Firmware handed off on an invalid fixture')
            require(len(self.seed_erases) == 1 and self.exit_calls == (2 if self.scenario == 'exit-stale-key-once' else 1), 'Actual entropy erase/exit retry count differs')
            require(self.events.index('raw-rng') < self.events.index('exit-boot-services') < self.events.index('darwin-enter-boundary'), 'Entropy/exit/handoff order differs')
            args, _, base, _ = self.handoff; a = self.layout
            tree_va, = struct.unpack('<Q', self.read(args + a['args_tree'], 8)); virtual, = struct.unpack('<Q', self.read(args + a['args_virtual_base'], 8))
            count, = struct.unpack('<I', self.read(args + a['args_tree_size'], 4)); physical = base + tree_va - virtual
            tree = self.read(physical, count)
            require(self.read(self.seed_address, 256) == self.seed, 'Firmware did not carry the new seed into the final ADT')
            return {'case': self.scenario, 'result': 'PASS', 'raw_rng_calls': self.seed_writes, 'actual_boot_c_function_executed': True,
                    'actual_inlined_entropy_code_executed': True, 'exit_boot_services_is_explicit_peer': True, 'exit_calls': self.exit_calls,
                    'actual_seed_erase_calls': len(self.seed_erases), 'events': self.events,
                    'explicit_platform_peers_visited': sorted(self.visited), 'handoff_assembly_or_kernel_entered': False}, tree, self.seed
        result = self.register(0)
        require(self.scenario != 'normal' and result & ERROR and not self.exited and self.window_freed, 'Firmware did not refuse/clean up the failed handoff')
        require(self.seed_erases or self.scenario == 'missing-seed', 'Failed entropy attempt did not erase the payload seed')
        for address in self.seed_erases: require(self.read(address, 256) == bytes(256), 'Firmware retained a partial/rejected entropy result')
        return {'case': self.scenario, 'result': 'REJECTED', 'actual_boot_c_function_executed': True, 'actual_status': hex(result),
                'raw_rng_calls': self.seed_writes, 'allocated_window_freed': True, 'exit_boot_services_called': False, 'events': self.events,
                'explicit_platform_peers_visited': sorted(self.visited)}, None, None
