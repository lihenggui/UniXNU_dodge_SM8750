#!/usr/bin/env python3
"""Check compiled init-context Data mounting and the bounded original APFS copyin prefix."""
import hashlib
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, build_objects, inspect_object, macho, require, symbols
from native_prelink import backed_offset
from prepare_initial_data import sha
from prepare_apfs_mount_abi import KERNEL, PROFILE

OUT = ROOT / 'build/ios16-apfs-mount-kernel'


def layout():
    directory = OUT / 'abi'; directory.mkdir(parents=True, exist_ok=True)
    pairs = [('status_bytes', 'sizeof(DodgeDataMountStatus)'), ('status_phase', 'offsetof(DodgeDataMountStatus,phase)'),
             ('status_last', 'offsetof(DodgeDataMountStatus,last)'), ('status_entered', 'offsetof(DodgeDataMountStatus,syscallEntered)'),
             ('status_mounted', 'offsetof(DodgeDataMountStatus,filesystemMounted)'), ('status_verified', 'offsetof(DodgeDataMountStatus,resultVerified)'),
             ('cold', 'unsigned(DodgeDataMountPhase::Cold)'), ('mounted', 'unsigned(DodgeDataMountPhase::Mounted)'),
             ('failed', 'unsigned(DodgeDataMountPhase::Failed)'),
             ('ram_bytes', 'sizeof(DodgeRamBlockStatus)'), ('ram_start', 'offsetof(DodgeRamBlockStatus,start)'),
             ('ram_pin', 'offsetof(DodgeRamBlockStatus,instancePinned)'), ('ram_retained', 'offsetof(DodgeRamBlockStatus,driverRetained)'),
             ('ram_started', 'unsigned(DodgeRamBlockStartPhase::Started)'),
             ('attr_bytes', 'sizeof(vnode_attr)'), ('attr_supported', 'offsetof(vnode_attr,va_supported)'),
             ('attr_active', 'offsetof(vnode_attr,va_active)'), ('attr_uid', 'offsetof(vnode_attr,va_uid)'),
             ('attr_gid', 'offsetof(vnode_attr,va_gid)'), ('want_uid', 'VNODE_ATTR_va_uid'), ('want_gid', 'VNODE_ATTR_va_gid'),
             ('statfs_bytes', 'sizeof(vfsstatfs)'), ('statfs_name', 'offsetof(vfsstatfs,f_fstypename)'),
             ('rootfs', 'MNT_ROOTFS'), ('readonly', 'MNT_RDONLY'), ('vdir', 'VDIR'), ('vreg', 'VREG'),
             ('user_max', 'MACH_VM_MAX_ADDRESS'), *[(name, name) for name in
              ('EPERM', 'EINVAL', 'EAGAIN', 'EBUSY', 'EALREADY', 'EAUTH', 'ENOENT', 'ENOTSUP', 'EFAULT', 'EIO')]]
    source = directory / 'DataMountLayout.cpp'
    source.write_text('#include "DodgeDataMount.h"\n#include "DodgeRamBlockLifecycle.h"\n#include <sys/mount.h>\n'
                      '#include <sys/vnode.h>\n#include <sys/errno.h>\n#include <mach/vm_param.h>\n'
                      'extern "C" const uint64_t dodge_data_mount_layout[]={' + ','.join('uint64_t(' + value + ')' for _, value in pairs) + '};\n')
    obj, = build_objects([source], directory, [ROOT / 'drivers/DodgeStorage'])
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_data_mount_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(pairs)) + 'Q', raw, section['fileoff'] + symbol['value'] - section['va'])
    return dict(zip((name for name, _ in pairs), values)), obj


class Model:
    def __init__(self, raw):
        import unicorn as u
        import unicorn.arm64_const as arm
        require(u.__version__ == '2.1.4', 'Use pinned Unicorn')
        self.u, self.arm = u, arm
        self.cpu = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
        self.pages, self.peers, self.visited = set(), {}, set()
        self.image = macho(raw)
        self.names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0}
        for segment in self.image['segments']:
            if segment['name'] == '__PAGEZERO': continue
            self.map(segment['va'], segment['size'])
            if segment['filesize']:
                self.cpu.mem_write(segment['va'], raw[segment['fileoff']:segment['fileoff'] + segment['filesize']])
        self.heap, self.stack, self.stop, self.scratch = 0x600000000, 0x700000000, 0x800000000, 0x100000000
        self.map(self.heap, 0x200000); self.map(self.stack, 0x100000); self.map(self.stop, 4096); self.map(self.scratch, 0x10000)
        self.cpu.hook_add(u.UC_HOOK_CODE, self.hook)
    def map(self, address, count):
        start = end = None
        for page in range(address & -4096, (address + count + 4095) & -4096, 4096):
            if page not in self.pages:
                if start is None: start = page
                end = page + 4096
                self.pages.add(page)
            elif start is not None:
                self.cpu.mem_map(start, end - start); start = end = None
        if start is not None: self.cpu.mem_map(start, end - start)
    def put(self, address, value): self.cpu.mem_write(address, value)
    def read(self, address, count): return bytes(self.cpu.mem_read(address, count))
    def register(self, index): return self.cpu.reg_read(getattr(self.arm, 'UC_ARM64_REG_X' + str(index)))
    def string(self, address):
        for count in range(4096):
            if self.read(address + count, 1) == b'\0': return self.read(address, count).decode()
        raise ValueError('Unbounded mount peer string')
    def bind(self, name, peer):
        require(name in self.names, 'Missing mount peer: ' + name)
        self.peers[self.names[name]] = (name, peer)
    def returned(self, value=0):
        self.cpu.reg_write(self.arm.UC_ARM64_REG_X0, value & ((1 << 64) - 1))
        self.cpu.reg_write(self.arm.UC_ARM64_REG_PC, self.cpu.reg_read(self.arm.UC_ARM64_REG_LR))
    def hook(self, cpu, pc, size, ignored):
        if pc in self.peers:
            name, peer = self.peers[pc]; self.visited.add(name)
            peer([self.register(i) for i in range(8)])
    def call(self, name, args=(), limit=200000):
        for index, value in enumerate(args):
            self.cpu.reg_write(getattr(self.arm, 'UC_ARM64_REG_X' + str(index)), value)
        self.cpu.reg_write(self.arm.UC_ARM64_REG_SP, self.stack + 0xff000)
        self.cpu.reg_write(self.arm.UC_ARM64_REG_LR, self.stop)
        self.cpu.emu_start(self.names[name], self.stop, count=limit)
        require(self.cpu.reg_read(self.arm.UC_ARM64_REG_PC) == self.stop, 'Mount code failed to return')
        return self.register(0) & 0xffffffff


def request_cases(path):
    raw = path.read_bytes(); model = Model(raw)
    captures = json.loads((ROOT / 'build/ios16-apfs-mount-program/captures.json').read_text())
    rows = []
    for capture in captures:
        if capture['outcome'] != 'mount-boundary' or not capture['user_device_pointer'] or capture['flags'] & ~0x200001:
            continue
        output = model.heap + 0x1000
        model.put(output - 16, bytes([0xa5]) * 368)
        result = model.call('_dodge_apfs_ordinary_mount_args', [output, 336, capture['user_device_pointer'], capture['flags'], capture['uid'], capture['gid']])
        require(result == 1 and model.read(output, 336).hex() == capture['payload_hex'] and
                model.read(output - 16, 16) == model.read(output + 336, 16) == bytes([0xa5]) * 16, 'Native helper differs from original request')
        rows.append({'case': capture['case'], 'result': 'PASS', 'all_336_bytes_match_original': True})
    require(len(rows) == 12, 'Native request comparison count changed')
    return rows


def original_prefix():
    contract = json.loads(PROFILE.read_text())
    raw = KERNEL.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == contract['original_kernelcache_sha256'], 'Original APFS prefix identity differs')
    rows = []
    captures = json.loads((ROOT / 'build/ios16-apfs-mount-program/captures.json').read_text())
    for name in ('root-owners', 'noowners', 'copyin-error', 'null-data'):
        model = Model(raw)
        capture = next(row for row in captures if row['case'] == ('noowners' if name == 'noowners' else 'root-owners'))
        payload = bytes.fromhex(capture['payload_hex'])
        data = model.scratch + 0x100
        model.put(data - 16, bytes([0xa5]) * 368)
        model.put(data, payload)
        model.names['_original_apfs_prefix'] = int(contract['apfs_mount_entry'], 16)
        model.names['_original_statfs_stub'] = int(contract['statfs_stub'], 16)
        model.names['_original_copyin_stub'] = int(contract['copyin_stub'], 16)
        model.names['_original_memset_stub'] = 0xfffffff00625ed30
        copied, destination, boundary = [], [], []
        model.bind('_original_statfs_stub', lambda args: model.returned(model.heap))
        def copyin(args):
            require(args[0] == data + 8 and args[2] == 324, 'Original APFS did not consume the VFS-adjusted bounded pointer')
            require(model.stack <= args[1] <= model.stack + 0x100000 - 324, 'Original copyin destination is outside its stack')
            copied.append(args[2]); destination.append(args[1])
            if name != 'copyin-error': model.put(args[1], model.read(args[0], args[2]))
            model.returned(14 if name == 'copyin-error' else 0)
        model.bind('_original_copyin_stub', copyin)
        def memset(args):
            require(name == 'null-data' and args[1] == 0 and args[2] == 324, 'Unexpected original APFS null-data initializer')
            destination.append(args[0]); model.put(args[0], bytes(324)); model.returned(args[0])
        model.bind('_original_memset_stub', memset)
        def stop(label):
            def reached(args):
                boundary.append(label)
                model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
            return reached
        model.names['_normal'] = int(contract['normal_after_copyin'], 16)
        model.names['_copyin_failure'] = int(contract['error_after_copyin'], 16)
        model.bind('_normal', stop('normal-after-copyin'))
        model.bind('_copyin_failure', stop('copyin-failure'))
        model.call('_original_apfs_prefix', [model.heap + 0x1000, model.heap + 0x2000,
                                            0 if name == 'null-data' else data + 8, model.heap + 0x3000])
        expected = 'copyin-failure' if name == 'copyin-error' else 'normal-after-copyin'
        require(boundary == [expected] and copied == ([] if name == 'null-data' else [324]), 'Original APFS copyin result branch differs')
        if name == 'null-data':
            expected_bytes = bytearray(324); expected_bytes[316:324] = bytes([255]) * 8
            require(model.read(destination[0], 324) == expected_bytes, 'Original null-data defaults differ')
        elif name != 'copyin-error':
            require(model.read(destination[0], 324) == payload[8:332], 'Original APFS copyin payload differs')
        require(model.read(data - 16, 16) == model.read(data + 336, 16) == bytes([0xa5]) * 16,
                'Original APFS prefix wrote outside the request')
        rows.append({'case': name, 'result': 'PASS', 'original_copyin_bytes': copied,
                     'boundary': boundary[0], 'full_mount_executed': False})
    return rows


ADAPTER_CASES = (
    ('default-disabled', 'EPERM'), ('data-disabled', 'EPERM'), ('null-process', 'EINVAL'), ('wrong-current', 'EINVAL'),
    ('wrong-pid', 'EINVAL'), ('process-32bit', 'EINVAL'), ('short-scratch', 'EINVAL'), ('null-scratch', 'EINVAL'),
    ('high-scratch', 'EINVAL'), ('update-flags', 'EINVAL'), ('not-started', 'EAGAIN'), ('not-pinned', 'EAGAIN'),
    ('not-retained', 'EAGAIN'), ('missing-root', 'EAGAIN'), ('root-changed-before', 'EAUTH'), ('root-writable', 'EAUTH'),
    ('root-wrong-filesystem', 'EAUTH'), ('lookup-before-failed', 'ENOENT'), ('not-directory', 'EBUSY'),
    ('already-mounted', 'EBUSY'), ('different-covered-filesystem', 'EBUSY'), ('getattr-failed', 'EIO'),
    ('uid-unsupported', 'ENOTSUP'), ('gid-unsupported', 'ENOTSUP'), ('media-not-ready', 'EAGAIN'),
    ('wrong-seed-size', 'EINVAL'), ('wrong-seed-hash', 'EINVAL'), ('no-device', 'EINVAL'), ('raw-device-path', 'EINVAL'),
    ('traversal-device-path', 'EINVAL'), ('unterminated-device-path', 'EINVAL'),
    ('copyout-type-failed', 'EFAULT'), ('copyout-path-failed', 'EFAULT'), ('copyout-device-failed', 'EFAULT'),
    ('copyout-payload-failed', 'EFAULT'), ('mount-failed', 'EIO'), ('mount-eagain', 'EAGAIN'), ('mount-ebusy', 'EBUSY'),
    ('lookup-after-failed', 'ENOENT'),
    ('wrong-mounted-device', 'EAUTH'), ('missing-mounted-device', 'EAUTH'), ('mounted-wrong-filesystem', 'EAUTH'),
    ('mounted-readonly-mismatch', 'EAUTH'), ('mounted-owner-policy-mismatch', 'EAUTH'),
    ('root-changed-after', 'EAUTH'), ('mounted-not-vfs-root', 'EAUTH'),
    ('ordinary-success', None), ('readonly-success', None), ('noowners-success', None), ('readonly-noowners-success', None),
    ('success-repeat', None), ('preflight-retry', None),
)


def adapter(path, case, expected, facts, mutation=False, init=False):
    raw = bytearray(path.read_bytes())
    if mutation:
        names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0}
        if mutation == 'init-call-NOP':
            report = json.loads((ROOT / 'reports/ios16-data-mount-native.json').read_text())
            address, word = int(report['actual_init_hook']['data_boot_call'], 16), 0xd503201f
        else:
            address, word = names['_dodge_apfs_mount_syscall' if mutation == 'bridge-RET' else '_dodge_data_mount_for_init'], 0xd65f03c0
        at = backed_offset(macho(raw)['segments'], address, 4, len(raw)); struct.pack_into('<I', raw, at, word)
    model = Model(bytes(raw))
    h = model.heap
    process, root, other_root, covered, data_root, device_node = [h + x for x in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000)]
    root_fs, data_fs, context = [h + x for x in (0x7000, 0x8000, 0x9000)]
    stat_root, stat_data = h + 0x10000, h + 0x12000
    for at, name in ((stat_root, 'wrongfs' if case == 'root-wrong-filesystem' else 'apfs'),
                     (stat_data, 'wrongfs' if case == 'mounted-wrong-filesystem' else 'apfs')):
        model.put(at, bytes(facts['statfs_bytes']))
        model.put(at + facts['statfs_name'], name.encode() + b'\0')
    flags = (1 if 'readonly-success' in case or case == 'readonly-noowners-success' else 0) | (0x200000 if 'noowners-success' in case else 0)
    if case == 'readonly-noowners-success': flags = 0x200001
    if case == 'update-flags': flags = 0x10000
    holds, counters, requests = {}, {'roots': 0, 'lookups': 0, 'copyouts': 0, 'mounts': 0, 'media': 0, 'sleeps': 0}, []
    launch_paths, panic_codes = [], []
    active = {'mounted': False, 'retry': False}
    seed = json.loads((ROOT / 'reports/ios16-data-volatile-image.json').read_text())
    expected_digest = bytes.fromhex(seed['image_sha256'])
    selected_device = 0x0e000009
    def retain(node):
        if node: holds[node] = holds.get(node, 0) + 1
    def put(args):
        require(holds.get(args[0], 0) > 0, 'Data mount released an unowned vnode')
        holds[args[0]] -= 1; model.returned()
    def flag(args):
        name = model.string(args[0])
        if init and name == 'launchdsuffix': model.returned(0); return
        require(name in ('dodge-data', 'dodge-data-mount') and args[2] == 4, 'Unexpected mount boot flag')
        value = not ((case == 'default-disabled' and name == 'dodge-data-mount') or (case == 'data-disabled' and name == 'dodge-data'))
        model.put(args[1], struct.pack('<I', int(value))); model.returned(int(value))
    model.bind('_PE_parse_boot_argn', flag)
    model.bind('_current_proc', lambda args: model.returned(process + 8 if case == 'wrong-current' else process))
    model.bind('_proc_pid', lambda args: model.returned(2 if case == 'wrong-pid' else 1))
    model.bind('_proc_is64bit', lambda args: model.returned(case != 'process-32bit'))
    def ram_status(args):
        value = bytearray(facts['ram_bytes'])
        struct.pack_into('<I', value, facts['ram_start'], 0 if case == 'not-started' else facts['ram_started'])
        value[facts['ram_pin']] = case != 'not-pinned'; value[facts['ram_retained']] = case != 'not-retained'
        model.put(args[0], bytes(value)); model.returned()
    model.bind('_dodge_ramblock_status', ram_status)
    def get_root(args):
        counters['roots'] += 1
        node = root
        if case == 'missing-root': node = 0
        elif case == 'root-changed-before' and counters['roots'] == 3: node = other_root
        elif case == 'root-changed-after' and active['mounted']: node = other_root
        retain(node); model.returned(node)
    model.bind('_vfs_rootvnode', get_root)
    model.bind('_vnode_put', put)
    model.bind('_vnode_mount', lambda args: model.returned(data_fs if args[0] == data_root or
                (case == 'different-covered-filesystem' and args[0] == covered) else root_fs))
    model.bind('_vnode_isvroot', lambda args: model.returned((args[0] != covered or case == 'already-mounted') and
                not (case == 'mounted-not-vfs-root' and args[0] == data_root)))
    model.bind('_vnode_vtype', lambda args: model.returned(facts['vreg'] if case == 'not-directory' else facts['vdir']))
    model.bind('_vfs_statfs', lambda args: model.returned(stat_data if args[0] == data_fs else stat_root))
    def mount_flags(args):
        if args[0] == root_fs: value = facts['rootfs'] | (0 if case == 'root-writable' else facts['readonly'])
        else:
            value = flags
            if case == 'mounted-readonly-mismatch': value ^= 1
            if case == 'mounted-owner-policy-mismatch': value ^= 0x200000
        model.returned(value)
    model.bind('_vfs_flags', mount_flags)
    model.bind('_vfs_context_current', lambda args: model.returned(context))
    def lookup(args):
        require(model.string(args[0]) == '/private/var' and args[1] == 0 and args[3] == context, 'Wrong Data lookup arguments')
        counters['lookups'] += 1
        error = case == ('lookup-after-failed' if active['mounted'] else 'lookup-before-failed')
        if error: model.returned(facts['ENOENT']); return
        node = data_root if active['mounted'] else covered
        retain(node); model.put(args[2], struct.pack('<Q', node)); model.returned()
    model.bind('_vnode_lookup', lookup)
    def getattr_peer(args):
        require(args[0] == covered and args[2] == context, 'Wrong Data owner context')
        wanted, = struct.unpack('<Q', model.read(args[1] + facts['attr_active'], 8))
        require(wanted == facts['want_uid'] | facts['want_gid'], 'Wrong Data attributes requested')
        if case == 'getattr-failed': model.returned(facts['EIO']); return
        supported = wanted & ~(facts['want_uid'] if case == 'uid-unsupported' else facts['want_gid'] if case == 'gid-unsupported' else 0)
        model.put(args[1] + facts['attr_supported'], struct.pack('<Q', supported))
        model.put(args[1] + facts['attr_uid'], struct.pack('<I', 501)); model.put(args[1] + facts['attr_gid'], struct.pack('<I', 20))
        model.returned()
    model.bind('_vnode_getattr', getattr_peer)
    # The media selector is an explicit IOKit peer; the caller's UUID/size/hash
    # admission and all subsequent copyout/syscall/result code execute normally.
    def media(args):
        counters['media'] += 1
        require(model.string(args[0]) == 'DAF0DD2B-1D90-5A73-A426-9306E1F967B5' and args[3] == 64, 'Wrong selected Data installation')
        if case == 'media-not-ready' or (case == 'preflight-retry' and not active['retry']) or (case == 'media-late' and counters['sleeps'] < 2):
            model.returned(0); return
        path = '/dev/rdisk9s1' if case == 'raw-device-path' else '/dev/disk9s1/../../foo' if case == 'traversal-device-path' else '/dev/disk9s1'
        model.put(args[1], struct.pack('<I', 0xffffffff if case == 'no-device' else selected_device))
        model.put(args[2], b'x' * 64 if case == 'unterminated-device-path' else path.encode() + b'\0')
        model.put(args[4], bytes(8)); model.put(args[5], struct.pack('<Q', (1 << 31) + (4096 if case == 'wrong-seed-size' else 0)))
        model.put(args[6], bytes(32) if case == 'wrong-seed-hash' else expected_digest); model.returned(1)
    model.bind('_native_ram_block_volume_seed', media)
    def copyout(args):
        counters['copyouts'] += 1
        require(model.scratch <= args[1] < args[1] + args[2] <= model.scratch + 0x400, 'Data copyout escaped owned scratch')
        faults = {'copyout-type-failed': 1, 'copyout-path-failed': 2, 'copyout-device-failed': 3, 'copyout-payload-failed': 4}
        if faults.get(case) == counters['copyouts']: model.returned(facts['EFAULT']); return
        model.put(args[1], model.read(args[0], args[2])); model.returned()
    model.bind('_copyout', copyout)
    bridge_layout_at = model.names['_dodge_apfs_mount_syscall_layout']
    bridge_layout = struct.unpack('<5I', model.read(bridge_layout_at, 20))
    require(bridge_layout == (32, 0, 8, 16, 24), 'Actual generated mount syscall layout differs')
    def mount(args):
        counters['mounts'] += 1
        require(args[0] == process and not holds.get(covered), 'Mount has wrong process or still holds covered vnode')
        request = model.read(args[1], bridge_layout[0])
        fstype, point = struct.unpack_from('<QQ', request)
        syscall_flags, = struct.unpack_from('<I', request, bridge_layout[3])
        payload_at, = struct.unpack_from('<Q', request, bridge_layout[4])
        require(model.string(fstype) == 'apfs' and model.string(point) == '/private/var' and syscall_flags == flags and
                payload_at == model.scratch + 0x100, 'Actual C syscall bridge request differs')
        payload = model.read(payload_at, 336)
        pointer, payload_flags = struct.unpack_from('<QQ', payload)
        owners = struct.unpack_from('<II', payload, 0x144)
        require(pointer == model.scratch + 0x80 and model.string(pointer) == '/dev/disk9s1' and payload_flags == flags and
                struct.unpack_from('<H', payload, 16)[0] == 1 and owners == ((99, 99) if flags & 0x200000 else (501, 20)),
                'Actual init-context request ownership or payload differs')
        opaque = bytearray(payload)
        for start, end in ((0, 18), (0x144, 0x14c)): opaque[start:end] = bytes(end - start)
        require(not any(opaque), 'Actual Data request includes an opaque nonzero field')
        requests.append(hashlib.sha256(payload).hexdigest())
        model.put(args[2], bytes(4))
        if case in ('mount-failed', 'mount-eagain', 'mount-ebusy'):
            model.returned(facts[{'mount-failed': 'EIO', 'mount-eagain': 'EAGAIN', 'mount-ebusy': 'EBUSY'}[case]]); return
        active['mounted'] = True; model.returned()
    model.bind('_mount', mount)
    def device(args):
        require(args[0] == data_fs, 'Wrong data filesystem for device readback')
        node = 0 if case == 'missing-mounted-device' else device_node
        retain(node); model.returned(node)
    model.bind('_vfs_devvp', device)
    model.bind('_vnode_specrdev', lambda args: model.returned(selected_device + (1 if case == 'wrong-mounted-device' else 0)))
    def compare(args, operation):
        if operation == 'memory': left, right = model.read(args[0], args[2]), model.read(args[1], args[2])
        else:
            left, right = model.string(args[0]), model.string(args[1])
            if operation == 'bounded': left, right = left[:args[2]], right[:args[2]]
        model.returned((left > right) - (left < right))
    model.bind('_memcmp', lambda args: compare(args, 'memory'))
    model.bind('_strcmp', lambda args: compare(args, 'string'))
    model.bind('_strncmp', lambda args: compare(args, 'bounded'))
    model.bind('_strlen', lambda args: model.returned(len(model.string(args[0]))))
    def strnlen(args):
        data = model.read(args[0], args[1]); first = data.find(b'\0'); model.returned(first if first >= 0 else len(data))
    model.bind('_strnlen', strnlen)
    model.bind('_bzero', lambda args: (model.put(args[0], bytes(args[1])), model.returned()))
    def forbidden(args): raise ValueError('Compiled mount adapter reached panic/stack failure')
    model.bind('_panic', forbidden); model.bind('___stack_chk_fail', forbidden)
    if init:
        init_map = h + 0x20000
        model.bind('_current_map', lambda args: model.returned(init_map))
        model.bind('_vm_map_page_size', lambda args: model.returned(4096))
        def allocate(args):
            require(args[0] == init_map and args[2:5] == [4096, 1, 0], 'Init allocation peer arguments differ')
            if case == 'allocation-failed': model.returned(3); return
            model.put(args[1], struct.pack('<Q', model.scratch)); model.returned()
        model.bind('_mach_vm_allocate_kernel', allocate)
        model.bind('_memorystatus_init_at_boot_snapshot', lambda args: model.returned())
        model.bind('_printf', lambda args: model.returned())
        def load_init(args):
            require(args[0] == process and args[1] == model.scratch and
                    (active['mounted'] or case == 'default-disabled'), 'Init loader ran before selected Data preparation')
            launch_paths.append(model.string(args[2])); model.returned()
        model.bind('_load_init_program_at_path', load_init)
        def panic(args):
            require('dodge Data preparation before init failed' in model.string(args[0]), 'Init hit an unrelated panic')
            sp = model.cpu.reg_read(model.arm.UC_ARM64_REG_SP)
            panic_codes.append(struct.unpack('<I', model.read(sp, 4))[0])
            model.cpu.reg_write(model.arm.UC_ARM64_REG_PC, model.stop)
        model.bind('_panic', panic)
        def sleep(args):
            require(args[0] == 10 and counters['sleeps'] < 999, 'Init Data readiness sleep is unbounded')
            counters['sleeps'] += 1; model.returned()
        model.bind('_IOSleep', sleep)
    scratch = 0 if case == 'null-scratch' else facts['user_max'] if case == 'high-scratch' else model.scratch
    count = 0x3ff if case == 'short-scratch' else 0x400
    arguments = [0 if case == 'null-process' else process, scratch, count, flags]
    if init:
        model.call('_load_init_program', [process], limit=2000000)
        require(len(panic_codes) <= 1 and not (panic_codes and launch_paths), 'Init failure continued to launchd')
        first = panic_codes[0] if panic_codes else 0
        require(bool(launch_paths) == (expected is None), 'Actual init did not stop/continue as selected')
        expected_sleeps = 999 if case in ('not-started', 'media-not-ready') else 2 if case == 'media-late' else 0
        require(counters['sleeps'] == expected_sleeps, 'Init Data retry budget differs')
    else:
        first = model.call('_dodge_data_mount_for_init', arguments)
    if case == 'preflight-retry':
        require(first == facts['EAGAIN'] and not counters['mounts'], 'Media preflight did not remain retryable')
        active['retry'] = True
        first = model.call('_dodge_data_mount_for_init', arguments)
    expected_value = facts[expected] if expected else 0
    require(first == expected_value, 'Wrong compiled Data mount result for ' + case + ': ' + str(first) + ', expected ' + str(expected_value))
    status_at = h + 0x18000
    model.call('_dodge_data_mount_status', [status_at])
    data = model.read(status_at, facts['status_bytes'])
    phase, = struct.unpack_from('<I', data, facts['status_phase'])
    entered, mounted, verified = [bool(data[facts['status_' + key]]) for key in ('entered', 'mounted', 'verified')]
    require(entered == bool(counters['mounts']) and mounted == active['mounted'] and
            verified == (expected is None and case != 'default-disabled'), 'Compiled mount status differs')
    require(phase == (facts['mounted'] if verified else facts['failed'] if entered else facts['cold']), 'Compiled mount failure was not latched correctly')
    if entered and not init:
        snapshot = counters.copy()
        again = model.call('_dodge_data_mount_for_init', arguments)
        require(again == facts['EALREADY'] and counters == snapshot and counters['mounts'] == 1, 'Completed or failed mount was implicitly retried')
    require(all(value == 0 for value in holds.values()), 'Data mount leaked a vnode iocount for ' + case)
    return {'case': case, 'result': 'PASS', 'errno': first, 'phase': phase, 'actual_init_function_executed': init,
            'readiness_sleeps': counters['sleeps'], 'launch_paths': launch_paths, 'init_panic_errno': panic_codes,
            'mount_peer_calls': counters['mounts'], 'copyout_peer_calls': counters['copyouts'],
            'vnode_iocount_balance_verified': True, 'post_mount_verified': verified,
            'actual_C_generated_syscall_bridge_executed': bool(counters['mounts']),
            'explicit_peers': sorted(model.visited), 'filesystem_mounted_in_host_or_phone': False}


INIT_CASES = (('default-disabled', None), ('data-disabled', 'EPERM'), ('ordinary-success', None), ('media-late', None),
              ('media-not-ready', 'EAGAIN'), ('not-started', 'EAGAIN'), ('allocation-failed', 'EINVAL'),
              ('mount-failed', 'EIO'), ('mount-eagain', 'EAGAIN'), ('mount-ebusy', 'EBUSY'),
              ('lookup-after-failed', 'ENOENT'), ('root-changed-after', 'EAUTH'))


def main():
    path = ROOT / 'reports/ios16-data-mount-prelink.json'
    prelink = json.loads(path.read_text())
    require(prelink['builder_sha256'] == sha(ROOT / 'scripts/build_data_mount_prelink.py') and
            prelink['combined_source_objects'] == 87 and prelink['init_boot_call_site_wired'], 'Data mount prelink is stale')
    for filename, value in {**prelink['source_sha256'], **prelink['dependency_report_sha256'], **prelink['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Data mount CPU input changed: ' + filename)
    candidate = ROOT / prelink['candidate']
    facts, obj = layout()
    request_rows = request_cases(candidate)
    original_rows = original_prefix()
    adapter_rows = [adapter(candidate, name, error, facts) for name, error in ADAPTER_CASES]
    init_rows = [adapter(candidate, name, error, facts, init=True) for name, error in INIT_CASES]
    require((len(request_rows), len(original_rows), len(adapter_rows), len(init_rows)) == (12, 4, 52, 12), 'Data mount CPU case counts differ')
    controls = []
    for name in ('api-RET', 'bridge-RET', 'init-call-NOP'):
        try:
            adapter(candidate, 'ordinary-success', None, facts, mutation=name, init=name == 'init-call-NOP')
        except ValueError as error:
            controls.append({'case': name, 'result': 'REJECTED', 'reason': str(error)})
        else:
            raise ValueError('Corrupted Data mount native code was accepted: ' + name)
    evidence = OUT / 'cpu-cases.json'
    evidence.write_text(json.dumps({'layout': facts, 'source_requests': request_rows, 'original_apfs_prefix': original_rows,
                                   'source_adapter': adapter_rows, 'actual_init_function': init_rows}, indent=2) + '\n')
    sources = [Path(__file__), ROOT / 'scripts/prepare_apfs_mount_abi.py', ROOT / 'scripts/build_data_mount_source.py',
               ROOT / 'drivers/DodgeStorage/DodgeDataMount.h', ROOT / 'drivers/DodgeStorage/DodgeRamBlockLifecycle.h', PROFILE]
    report = {'result': 'IOS16_INIT_DATA_MOUNT_SOURCE_AND_ORIGINAL_COPYIN_CPU_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'dependency_report_sha256': {str(path.relative_to(ROOT)): sha(path),
                                         'reports/ios16-apfs-mount-program.json': sha(ROOT / 'reports/ios16-apfs-mount-program.json')},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, evidence)}, 'compiler_layout': facts,
              'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate),
              'case_count': 80, 'request_cases': request_rows, 'original_copyin_cases': original_rows,
              'mount_coordinator_cases': adapter_rows, 'actual_init_function_cases': init_rows, 'negative_controls': controls,
              'source_data_mount_default_enabled': False, 'original_apfs_copyin_prefix_executed': True,
              'original_apfs_data_mount_qualified': False, 'original_root_authentication_qualified': False,
              'mount_and_vfs_iokit_process_vm_libraries_are_explicit_peers': True,
              'filesystem_mounted_in_host_or_phone': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False,
              'scope': 'Twelve native request paths match the original program byte-for-byte. Four bounded original APFS paths verify the 324-byte copyin '
                       'and failure/null-data boundaries. Fifty-two actual compiled mount coordinator paths verify admission, ownership and result identity; '
                       'twelve paths execute actual load_init_program and the Data readiness gate before the init-loader peer. '
                       'The generated C syscall bridge executes; mount/VFS/IOKit/process/VM/library peers do not authenticate or mount a real filesystem.'}
    (ROOT / 'reports/ios16-data-mount-kernel.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 80 ARM64 Data mount paths (12 request / 4 original copyin / 52 coordinator / 12 actual init), 3 code-corruption controls')


if __name__ == '__main__':
    main()
