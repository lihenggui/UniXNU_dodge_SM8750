#!/usr/bin/env python3
"""Execute native seed-close instructions and connect the unchanged iPhone saver to them."""
import argparse
import json
from pathlib import Path
import struct

from build_native_system import REPORT as KERNEL_REPORT, check_report as check_kernel
from check_data_mount_kernel import Model
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols

OUT = ROOT / 'build/cph2653-seed-sync-kernel'
REPORT = ROOT / 'reports/ios16-seed-close-kernel.json'


def layout():
    pairs = [('fg_bytes', 'sizeof(struct fileglob)'), *[('fg_' + name, 'offsetof(struct fileglob, fg_' + name + ')')
        for name in ('flag', 'ops', 'data')], ('attr_bytes', 'sizeof(struct vnode_attr)'),
        ('attr_supported', 'offsetof(struct vnode_attr, va_supported)'), ('statfs_bytes', 'sizeof(struct vfsstatfs)'),
        ('statfs_type', 'offsetof(struct vfsstatfs, f_fstypename)'), ('data_bytes', 'sizeof(DodgeDataMountStatus)'),
        ('data_phase', 'offsetof(DodgeDataMountStatus, phase)'), ('data_mounted', 'offsetof(DodgeDataMountStatus, filesystemMounted)'),
        ('data_verified', 'offsetof(DodgeDataMountStatus, resultVerified)'), ('data_ready', 'unsigned(DodgeDataMountPhase::Mounted)'),
        ('req_bytes', 'sizeof(struct sysctl_req)'), ('req_oldfunc', 'offsetof(struct sysctl_req, oldfunc)')]
    for name in ('uid', 'gid', 'mode', 'nlink', 'data_size'):
        pairs += [('attr_' + name, 'offsetof(struct vnode_attr, va_' + name + ')'),
            ('width_' + name, 'sizeof(((struct vnode_attr *)0)->va_' + name + ')'),
            ('want_' + name, 'VNODE_ATTR_va_' + name)]
    pairs += [(name, name) for name in ('FWRITE', 'FREAD', 'VREG', 'VDIR', 'MNT_WAIT', 'F_FULLFSYNC', 'EIO', 'EAUTH', 'ENOTSUP', 'ENXIO')]
    source = OUT / 'SeedSyncLayout.cpp'
    source.write_text('#include <sys/file_internal.h>\n#include <sys/vnode.h>\n#include <sys/fcntl.h>\n#include <sys/mount.h>\n'
        '#include <sys/errno.h>\n#include <sys/sysctl.h>\n#include "DodgeDataMount.h"\nextern "C" const uint64_t dodge_seed_sync_layout[]={' +
        ','.join('uint64_t(' + value + ')' for _, value in pairs) + '};\n')
    obj, = build_objects([source], OUT, [ROOT / 'drivers/DodgeStorage'])
    raw = obj.read_bytes();meta = inspect_object(raw)
    symbol, = [row for row in symbols(raw) if row['name'] == '_dodge_seed_sync_layout']
    section, = [s for segment in meta['segments'] for s in segment['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(pairs)) + 'Q', raw, section['fileoff'] + symbol['value'] - section['va'])
    return dict(zip((name for name, _ in pairs), values)), [source, obj, OUT / 'compile-commands.json']


class NativeClose:
    def __init__(self, candidate, abi):
        self.m = m = Model(candidate.read_bytes());self.abi = a = abi;self.events = [];self.references = {}
        self.owner = True;self.full_error = self.close_error = self.seed_error = 0;self.bytes = 32
        self.path = '/private/var/db/prng.seed';self.flag = a['FWRITE']
        self.seed, self.data, self.directory, self.mount = [m.heap + value for value in (0x1000, 0x2000, 0x3000, 0x4000)]
        self.fg, self.context, self.type = [m.heap + value for value in (0x5000, 0x6000, 0x7000)]
        self.references = {self.seed: 1, self.data: 0, self.directory: 0}
        m.put(self.fg, bytes(a['fg_bytes']));m.put(self.fg + a['fg_ops'], struct.pack('<Q', m.names['_vnops']))
        m.put(self.fg + a['fg_data'], struct.pack('<Q', self.seed))
        m.put(self.type, bytes(a['statfs_bytes']));m.put(self.type + a['statfs_type'], b'apfs\0')
        self.name = m.heap + 0x8000;m.put(self.name, b'prng.seed\0')
        def getref(args):self.references[args[0]] += 1;m.returned()
        def putref(args):
            require(self.references.get(args[0], 0) > 0, 'Native close released an unowned vnode')
            self.references[args[0]] -= 1;m.returned()
        m.bind('_vnode_getwithref', getref);m.bind('_vnode_put', putref)
        m.bind('_vnode_vtype', lambda args: m.returned(a['VREG'] if args[0] == self.seed else a['VDIR']))
        m.bind('_vnode_getname', lambda args: m.returned(self.name));m.bind('_vnode_putname', lambda args: m.returned())
        m.bind('_vnode_mount', lambda args: m.returned(self.mount))
        m.bind('_vnode_isvroot', lambda args: m.returned(args[0] == self.data))
        m.bind('_vfs_statfs', lambda args: m.returned(self.type));m.bind('_vfs_flags', lambda args: m.returned())
        m.bind('_dodge_owner_security_ready', lambda args: m.returned(self.owner))
        def option(args):
            require(m.string(args[0]) == 'dodge-seed-sync' and args[2] == 4, 'Unexpected seed boot option')
            m.put(args[1], struct.pack('<I', 1));m.returned(1)
        m.bind('_PE_parse_boot_argn', option)
        def state(args):
            output = bytearray(a['data_bytes']);struct.pack_into('<I', output, a['data_phase'], a['data_ready'])
            output[a['data_mounted']] = output[a['data_verified']] = 1;m.put(args[0], bytes(output));m.returned()
        m.bind('_dodge_data_mount_status', state)
        def lookup(args):
            path = m.string(args[0]);require(path in ('/private/var', '/private/var/db') and args[1] == 0 and args[3] == self.context,
                'Unexpected native seed lookup')
            node = self.data if path == '/private/var' else self.directory
            self.references[node] += 1;m.put(args[2], struct.pack('<Q', node));m.returned()
        m.bind('_vnode_lookup', lookup)
        def path(args):
            capacity, = struct.unpack('<I', m.read(args[2], 4));value = self.path.encode() + b'\0'
            require(len(value) <= capacity, 'Native path buffer too small');m.put(args[1], value)
            m.put(args[2], struct.pack('<I', len(value)));m.returned()
        m.bind('_vn_getpath', path)
        def attributes(args):
            require(args[0] == self.seed and args[2] == self.context, 'Unexpected native seed attributes')
            output = bytearray(a['attr_bytes']);wanted = 0
            for name, value in (('uid', 0), ('gid', 0), ('mode', 0o600), ('nlink', 1), ('data_size', self.bytes)):
                wanted |= a['want_' + name]
                output[a['attr_' + name]:a['attr_' + name] + a['width_' + name]] = value.to_bytes(a['width_' + name], 'little')
            struct.pack_into('<Q', output, a['attr_supported'], wanted);m.put(args[1], bytes(output));m.returned()
        m.bind('_vnode_getattr', attributes)
        def synchronize(args):
            require(args[0] in (self.seed, self.directory) and args[1] == a['MNT_WAIT'] and args[2] == self.context,
                'Unexpected native fsync request')
            self.events.append('seed-sync' if args[0] == self.seed else 'directory-sync')
            m.returned(self.seed_error if args[0] == self.seed else 0)
        m.bind('_VNOP_FSYNC', synchronize)
        def full(args):
            require(args[:5] == [self.seed, a['F_FULLFSYNC'], 0, 0, self.context], 'Unexpected full synchronization request')
            self.events.append('full-sync');m.returned(self.full_error)
        m.bind('_VNOP_IOCTL', full)
        def close(args):
            require(args[:3] == [self.seed, self.flag, self.context], 'Native close changed vnode/flags/context')
            self.events.append('close');m.returned(self.close_error)
        m.bind('_vn_close', close)
        m.bind('_strcmp', lambda args: m.returned((m.string(args[0]) > m.string(args[1])) - (m.string(args[0]) < m.string(args[1]))))
        def zero(args):require(args[1] <= 4096, 'Unbounded native seed zero');m.put(args[0], bytes(args[1]));m.returned()
        m.bind('_bzero', zero)

    def call(self):
        m, a = self.m, self.abi;m.put(self.fg + a['fg_flag'], struct.pack('<I', self.flag))
        result = m.call('_vn_closefile', [self.fg, self.context], limit=1000000)
        require(self.references == {self.seed: 1, self.data: 0, self.directory: 0}, 'Native close leaked vnode references')
        require('_dodge_seed_close_sync' not in m.peers and '_vn_closefile' not in m.peers, 'Seed close replaced with a peer')
        return result

    def counters(self):
        m, a = self.m, self.abi;request = m.heap + 0x9000;peer = m.scratch + 0xf000;captured = []
        def output(args):
            require(args[0] == request and args[2] == 4, 'Seed diagnostic width changed')
            captured.append(int.from_bytes(m.read(args[1], 4), 'little'));m.returned()
        m.peers[peer] = ('seed-sysctl-output', output)
        result = []
        for index in range(4):
            m.put(request, bytes(a['req_bytes']));m.put(request + a['req_oldfunc'], struct.pack('<Q', peer));captured.clear()
            require(m.call('_dodge_seed_sync_sysctl', [0, 0, index, request]) == 0 and len(captured) == 1,
                'Actual source seed sysctl failed')
            result.append(captured[0])
        return result


def cpu_cases(candidate, abi):
    rows = []
    for name in ('normal', 'foreign-owner', 'readonly-close', 'outside-path', 'short-seed', 'file-sync-error', 'full-sync-error',
        'full-sync-unsupported', 'ordinary-close-error', 'both-errors'):
        close = NativeClose(candidate, abi)
        if name == 'foreign-owner':close.owner = False
        if name == 'readonly-close':close.flag = abi['FREAD']
        if name == 'outside-path':close.path = '/elsewhere/prng.seed'
        if name == 'short-seed':close.bytes = 31
        if name == 'file-sync-error':close.seed_error = abi['EIO']
        if name in ('full-sync-error', 'both-errors'):close.full_error = abi['EIO']
        if name == 'full-sync-unsupported':close.full_error = abi['ENOTSUP']
        if name in ('ordinary-close-error', 'both-errors'):close.close_error = abi['ENXIO']
        result = close.call();expected = close.close_error or close.seed_error or close.full_error or (abi['EAUTH'] if name == 'short-seed' else 0)
        wanted = ['close'] if name in ('foreign-owner', 'readonly-close', 'outside-path', 'short-seed') else (
            ['seed-sync', 'close'] if name == 'file-sync-error' else ['seed-sync', 'directory-sync', 'full-sync', 'close'])
        require(result == expected and close.events == wanted, 'Wrong native seed-close result/order: ' + name)
        counters = close.counters();ignored = name in ('foreign-owner', 'readonly-close', 'outside-path')
        error = close.seed_error or close.full_error or (abi['EAUTH'] if name == 'short-seed' else 0)
        require(counters == ([0, 0, 0, 0] if ignored else [1, int(not error), int(bool(error)), error]),
            'Actual source seed diagnostic counters differ')
        rows.append({'case': name, 'result': 'PASS', 'errno': result, 'calls': close.events, 'source_sysctl_values': counters})
    return rows


def user_imports(raw):
    m = Model(raw);meta = m.image;nlist = symbols(raw)
    dynamic, = [at for kind, at, _ in meta['commands'] if kind == 11]
    offset, count = struct.unpack_from('<II', raw, dynamic + 56);indices = struct.unpack_from('<' + str(count) + 'I', raw, offset)
    stubs, got = {}, {}
    for kind, at, _ in meta['commands']:
        if kind != 25:continue
        sections, = struct.unpack_from('<I', raw, at + 64)
        for i in range(sections):
            section = at + 72 + 80 * i;name = raw[section:section + 16].split(b'\0')[0]
            if name not in (b'__stubs', b'__got'):continue
            address, size = struct.unpack_from('<QQ', raw, section + 32);first, stride = struct.unpack_from('<II', raw, section + 68)
            if name == b'__got':stride = 8
            for index in range(size // stride):
                symbol = indices[first + index];require(symbol < len(nlist), 'Invalid original seedctl import')
                (stubs if name == b'__stubs' else got)[nlist[symbol]['name']] = address + index * stride
    return m, stubs, got


def original_saver(candidate, abi):
    path = ROOT / 'build/cph2653-native-entropy/prng_seedctl.original'
    consumer = json.loads((ROOT / 'hardware/dodge-entropy.json').read_text())['iPhone_consumer']
    require(sha(path) == consumer['sha256'], 'Need exact original iPhone saver')
    rows = []
    for failing_flush in (False, True):
        kernel = NativeClose(candidate, abi);kernel.full_error = abi['EIO'] if failing_flush else 0
        m, stubs, got = user_imports(path.read_bytes());guard = m.heap + 0x1000
        m.put(got['___stack_chk_guard'], struct.pack('<Q', guard));m.put(guard, bytes(8))
        events = [];written = bytearray();cleared = []
        def bind(name, function):m.peers[stubs[name]] = (name, function)
        def entropy(args):
            require(args[1] == 32, 'Original seed width changed');m.put(args[0], bytes(range(32)));events.append('getentropy');m.returned()
        bind('_getentropy', entropy)
        def opened(args):
            sp = m.cpu.reg_read(m.arm.UC_ARM64_REG_SP);mode, = struct.unpack('<Q', m.read(sp, 8))
            require(m.string(args[0]) == '/var/db/prng.seed' and args[1] == 1537 and mode == 0o600, 'Original seed open flags changed')
            events.append('open-create-truncate');m.returned(100)
        bind('_open', opened)
        def chmod(args):require(args[:2] == [100, 0o600], 'Original seed mode changed');events.append('chmod');m.returned()
        def chown(args):require(args[:3] == [100, 0, 0], 'Original seed owner changed');events.append('chown');m.returned()
        bind('_fchmod', chmod);bind('_fchown', chown)
        def write(args):
            require(args[0] == 100 and args[2] == 32 - len(written), 'Original partial-write loop changed')
            count = min(args[2], 7);written.extend(m.read(args[1], count));events.append('write');m.returned(count)
        bind('_write', write)
        def close(args):
            require(args[0] == 100 and written == bytes(range(32)), 'Original close preceded complete seed write')
            result = kernel.call();events.append('close');m.returned(-1 if result else 0)
        bind('_close', close)
        def clear(args):
            require(args[0] == 32, 'Original clear width changed');m.put(args[1], bytes(32));cleared.append(args[1]);m.returned()
        bind('_cc_clear', clear)
        bind('___stack_chk_fail', lambda args: (_ for _ in ()).throw(ValueError('Original seed saver stack guard failed')))
        m.names['_original_seed_saver'] = int(consumer['blocks']['save_new_seed']['address'], 16)
        result = m.call('_original_seed_saver', limit=1000000)
        require(result == 0 and len(written) == 32 and len(cleared) == 1 and m.read(cleared[0], 32) == bytes(32) and
            events[:4] == ['getentropy', 'open-create-truncate', 'chmod', 'chown'] and events.count('write') == 5 and events[-1] == 'close',
            'Original seed saver did not complete and clear its temporary bytes')
        last, = struct.unpack('<I', kernel.m.read(kernel.m.names['_dodge_seed_sync_last_error'], 4))
        require(last == kernel.full_error, 'Native seed failure was not retained')
        rows.append({'case': 'original-save-full-sync-error' if failing_flush else 'original-save', 'result': 'PASS',
            'original_return': result, 'native_sync_errno': last, 'partial_writes': 5, 'temporary_seed_cleared': True,
            'original_ignores_close_error': failing_flush, 'kernel_calls': kernel.events})
    return rows, path


def check_report(report):
    require(report['result'] == 'IOS16_NATIVE_SEED_CLOSE_AND_ORIGINAL_SAVER_CPU_PASS' and len(report['native_cases']) == 10 and
        len(report['original_saver_cases']) == 2 and not report['hardware_tested'], 'Incomplete native seed-close evidence')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Seed-close CPU input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual native close and unchanged original seed save instructions');return
    kernel = json.loads(KERNEL_REPORT.read_text());check_kernel(kernel);OUT.mkdir(parents=True, exist_ok=True)
    abi, artifacts = layout();candidate = ROOT / kernel['candidate'];cases = cpu_cases(candidate, abi);saved, original = original_saver(candidate, abi)
    files = [Path(__file__), ROOT / 'scripts/check_data_mount_kernel.py', ROOT / 'hardware/dodge-entropy.json']
    report = {'result': 'IOS16_NATIVE_SEED_CLOSE_AND_ORIGINAL_SAVER_CPU_PASS', 'compiler_layout': abi,
        'native_cases': cases, 'original_saver_cases': saved,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(KERNEL_REPORT.relative_to(ROOT)): sha(KERNEL_REPORT)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in [*artifacts, candidate, original]},
        'hardware_tested': False, 'phone_operations': 'none', 'scope': 'Actual native VFS close and source synchronization '
        'instructions run with explicit VFS/registry peers and compiler-derived layouts. The unchanged original iPhone saver '
        'executes creation, ownership, five partial writes, close and temporary clearing; close enters the native kernel model. '
        'An injected full-sync failure stays visible in the kernel even though the original utility ignores close errors and '
        'returns zero. No device flush, filesystem crash consistency or physical entropy quality is qualified.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: ten actual native close cases and two complete original iPhone save paths')


if __name__ == '__main__':main()
