#!/usr/bin/env python3
"""Execute actual IOBSD/Data scheduling and existing Data paths in the 84-object candidate."""
import json
from pathlib import Path
import struct

from native_driver_build import ROOT, build_objects, inspect_object, require, symbols, macho
from prepare_initial_data import sha
from check_data_kernel import CASES as IO_CASES, emulate as data_io, lifetime

OUT = ROOT / 'build/cph2653-data-startup-kernel'
CASES = ('default-disabled', 'data-success', 'thread-failure', 'thread-retry', 'missing-root', 'wait-storage',
         'wait-graphics', 'busy-then-success', 'sticky-init-failure', 'error-owned-driver', 'success-null-driver',
         'start-timeout', 'earlier-timeout')


def layout():
    out = OUT / 'abi'; out.mkdir(parents=True, exist_ok=True)
    source = out / 'DataLateLayout.cpp'
    pairs = [('data_bytes', 'sizeof(DodgeDataLateStatus)'), ('data_phase', 'offsetof(DodgeDataLateStatus,phase)'),
             ('data_last', 'offsetof(DodgeDataLateStatus,last)'), ('data_attempts', 'offsetof(DodgeDataLateStatus,attempts)'),
             ('data_started', 'offsetof(DodgeDataLateStatus,driverStarted)'),
             ('system_bytes', 'sizeof(DodgeSystemLateStatus)'), ('system_phase', 'offsetof(DodgeSystemLateStatus,phase)'),
             ('graphics_bytes', 'sizeof(DodgeGraphicsLateStatus)'), ('graphics_phase', 'offsetof(DodgeGraphicsLateStatus,phase)'),
             ('ram_bytes', 'sizeof(DodgeRamBlockStatus)'), ('ram_phase', 'offsetof(DodgeRamBlockStatus,phase)'),
             ('ram_start', 'offsetof(DodgeRamBlockStatus,start)'), ('ram_pin', 'offsetof(DodgeRamBlockStatus,instancePinned)'),
             ('ram_retained', 'offsetof(DodgeRamBlockStatus,driverRetained)'),
             ('data_cold', 'unsigned(DodgeDataLatePhase::Cold)'), ('data_queued', 'unsigned(DodgeDataLatePhase::Queued)'),
             ('data_finished', 'unsigned(DodgeDataLatePhase::Finished)'), ('system_finished', 'unsigned(DodgeSystemLatePhase::Finished)'),
             ('graphics_finished', 'unsigned(DodgeGraphicsLatePhase::Finished)'), ('ram_ready', 'unsigned(DodgeRamBlockPhase::Ready)'),
             ('ram_start_failed', 'unsigned(DodgeRamBlockStartPhase::Failed)'),
             *[(name, code) for name, code in [('success', 'kIOReturnSuccess'), ('not_ready', 'kIOReturnNotReady'), ('busy', 'kIOReturnBusy'),
                ('error', 'kIOReturnError'), ('not_permitted', 'kIOReturnNotPermitted')]]]
    source.write_text('#include "DodgeDataLate.h"\n#include "DodgeRamBlockLifecycle.h"\n#include "DodgeSystemLate.h"\n#include "DodgeGraphicsLate.h"\n'
                      'extern "C" const unsigned dodge_data_late_layout[]={' + ','.join('unsigned(' + value + ')' for _, value in pairs) + '};\n')
    obj, = build_objects([source], out, [ROOT / 'drivers/DodgeStorage', ROOT / 'drivers/DodgeDisplay'])
    raw = obj.read_bytes(); image = inspect_object(raw)
    symbol, = [s for s in symbols(raw) if not s['kind'] & 0xe0 and s['name'] == '_dodge_data_late_layout']
    section, = [s for seg in image['segments'] for s in seg['sections'] if s['va'] <= symbol['value'] < s['va'] + s['size']]
    values = struct.unpack_from('<' + str(len(pairs)) + 'I', raw, section['fileoff'] + symbol['value'] - section['va'])
    return dict(zip((name for name, _ in pairs), values)), obj


def emulate(path, case, facts, control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__ == '2.1.4', 'Use pinned Unicorn 2.1.4')
    raw = path.read_bytes(); image = macho(raw)
    names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0 and s['kind'] & 14}
    own_raw = (ROOT / 'build/cph2653-data-startup/DodgeDataLate.o').read_bytes()
    own_text, = [s for seg in inspect_object(own_raw)['segments'] for s in seg['sections'] if s['name'] == '__text']
    own = [s['name'] for s in symbols(own_raw) if not s['kind'] & 0xe0 and s['kind'] & 14 and
           own_text['va'] <= s['value'] < own_text['va'] + own_text['size'] and not s['name'].startswith('ltmp')]
    code_addresses = sorted({s['value'] for s in symbols(raw) if not s['kind'] & 0xe0 and s['kind'] & 14 and
                             any(t['va'] <= s['value'] < t['va'] + t['size'] for seg in image['segments'] for t in seg['sections'] if t['name'] == '__text')})
    ranges = [(names[name], next(a for a in code_addresses if a > names[name])) for name in own if name in names]
    ranges.append((names['_IOKitBSDInit'], names['_IOKitBSDInit'] + 80))
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    for segment in image['segments']:
        if segment['size'] and segment['initprot']:
            uc.mem_map(segment['va'], (segment['size'] + 4095) & ~4095)
            uc.mem_write(segment['va'], raw[segment['fileoff']:segment['fileoff'] + segment['filesize']])
    root, platform, driver, out, thread, stack, halt = 0x100040, 0x110040, 0x120040, 0x130040, 0x140040, 0x200000, 0x300000
    for address in (root, platform, driver, out, thread): uc.mem_map(address & ~4095, 4096)
    uc.mem_map(stack, 65536); uc.mem_map(halt, 4096)
    for address in (root, platform, driver): uc.mem_write(address, struct.pack('<Q', names['__ZTV9IOService'] + 16))
    events, queue, peers, completed = [], [], {}, []
    calls = sleeps = released = deallocated = terminated = queue_attempts = 0
    def put(address, value): uc.mem_write(address, value)
    def arguments(n=8): return [uc.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i))) for i in range(n)]
    def returned(value=0):
        uc.reg_write(arm.UC_ARM64_REG_X0, value & ((1 << 64) - 1)); uc.reg_write(arm.UC_ARM64_REG_PC, uc.reg_read(arm.UC_ARM64_REG_LR))
    def cstring(address):
        result = bytearray()
        for i in range(256):
            byte = bytes(uc.mem_read(address + i, 1))
            if byte == b'\0': return result.decode()
            result += byte
        raise ValueError('Unbounded Data scheduling string')
    def bind(name, fn):
        require(name in names, 'Missing Data scheduler peer: ' + name); peers[names[name]] = (name, fn)
    def publish(a):
        require(cstring(a[0]) == 'IOBSD' and not a[1], 'Wrong Data IOBSD resource'); events.append('IOBSD'); returned()
    bind('__ZN9IOService15publishResourceEPKcP8OSObject', publish)
    bind('_dodge_system_schedule', lambda a: (events.append('system-peer'), returned()))
    bind('_dodge_input_schedule', lambda a: (events.append('input-peer'), returned()))
    def flag(a):
        require(a[2] == 4, 'Data boot flag has wrong width')
        name = cstring(a[0]); require(name in ('dodge-data', 'native-ufs-root', 'dodge-graphics'), 'Unexpected Data startup flag')
        enabled = case != 'default-disabled' if name == 'dodge-data' else case in ('wait-storage', 'earlier-timeout') if name == 'native-ufs-root' else case == 'wait-graphics'
        put(a[1], struct.pack('<I', int(enabled))); returned(int(enabled))
    bind('_PE_parse_boot_argn', flag)
    def queued(a):
        nonlocal queue_attempts
        queue_attempts += 1
        require(a[0] and not a[1] and a[2], 'Data kernel thread arguments changed')
        if case == 'thread-failure' or case == 'thread-retry' and queue_attempts == 1: returned(1); return
        queue.append(a[0]); put(a[2], struct.pack('<Q', thread)); returned()
    bind('_kernel_thread_start', queued)
    def deallocate(a):
        nonlocal deallocated
        require(a[0] == thread and not deallocated, 'Data thread reference released twice'); deallocated += 1; returned()
    bind('_thread_deallocate', deallocate)
    bind('_current_thread', lambda a: returned(thread))
    def terminate(a):
        nonlocal terminated
        require(a[0] == thread and not terminated, 'Data worker termination repeated'); terminated += 1; returned()
    bind('_thread_terminate', terminate)
    # Existing optional BSD deferred work is outside this Data route.
    bind('_thread_call_allocate_with_options', lambda a: returned(0))
    def sleep(a):
        nonlocal sleeps
        require(a[0] == 10, 'Data worker sleep interval changed'); sleeps += 1; returned()
    bind('_IOSleep', sleep)
    bind('__ZN9IOService11getPlatformEv', lambda a: returned(0 if case == 'missing-root' else platform))
    bind('__ZNK9IOService10isInactiveEv', lambda a: returned(0))
    bind('__ZNK9IOService11getProviderEv', lambda a: returned(root if a[0] == platform else 0))
    def earlier(a, kind):
        count = facts[kind + '_bytes']; value = bytearray(count)
        finished = sleeps >= (3 if kind == 'graphics' else 2) and case != 'earlier-timeout'
        if finished: struct.pack_into('<I', value, facts[kind + '_phase'], facts[kind + '_finished'])
        put(a[0], bytes(value)); returned()
    bind('_dodge_system_late_status', lambda a: earlier(a, 'system'))
    bind('_dodge_graphics_late_status', lambda a: earlier(a, 'graphics'))
    def started(a):
        nonlocal calls
        require(a[0] == root and a[1] and bytes(uc.mem_read(a[1], 8)) == bytes(8), 'Data starter changed provider/owned output')
        calls += 1
        if case == 'wait-storage': require(sleeps >= 2, 'Data raced storage')
        if case == 'wait-graphics': require(sleeps >= 3, 'Data raced graphics')
        if case == 'busy-then-success' and calls < 3: returned(facts['busy']); return
        if case in ('sticky-init-failure', 'start-timeout'): returned(facts['not_ready']); return
        if case != 'success-null-driver': put(a[1], struct.pack('<Q', driver))
        returned(facts['error'] if case == 'error-owned-driver' else 0)
    bind('_dodge_ramblock_start', started)
    def state(a):
        value = bytearray(facts['ram_bytes']); struct.pack_into('<I', value, facts['ram_phase'], facts['ram_ready'])
        if case == 'sticky-init-failure':
            value[facts['ram_pin']] = value[facts['ram_retained']] = 1
            struct.pack_into('<I', value, facts['ram_start'], facts['ram_start_failed'])
        put(a[0], bytes(value)); returned()
    bind('_dodge_ramblock_status', state)
    def release(a):
        nonlocal released
        require(a[0] == driver and not released, 'Data worker released the wrong or duplicate owned driver'); released += 1; returned()
    bind('__ZNK8OSObject7releaseEv', release)
    if control:
        source = json.loads((ROOT / 'reports/ios16-data-startup.json').read_text())
        put(int(source['actual_iobsd_hook']['queue_call_order'][2], 16), struct.pack('<I', 0xd503201f))
    def hook(engine, address, size, user):
        if address in peers:
            name, fn = peers[address]; completed.append(name); fn(arguments()); return
        require(any(start <= address < end for start, end in ranges), 'Data scheduler escaped source code: ' + hex(address))
        if address == names['_dodge_data_schedule']: events.append('data-source')
    uc.hook_add(unicorn.UC_HOOK_CODE, hook)
    def execute(name, *args):
        for i, value in enumerate(args): uc.reg_write(getattr(arm, 'UC_ARM64_REG_X' + str(i)), value)
        uc.reg_write(arm.UC_ARM64_REG_SP, stack + 0xff00); uc.reg_write(arm.UC_ARM64_REG_LR, halt)
        uc.emu_start(names[name] if isinstance(name, str) else name, halt, timeout=5000000, count=1000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC) == halt, 'Data scheduler did not return')
        return uc.reg_read(arm.UC_ARM64_REG_X0) & 0xffffffff
    require(execute('_IOKitBSDInit') == 0 and events == ['IOBSD', 'system-peer', 'data-source', 'input-peer'], 'Actual IOBSD Data queue ordering changed')
    if case == 'thread-retry': require(execute('_dodge_data_schedule') == 0, 'Data failed to retry thread creation')
    if case in ('default-disabled', 'thread-failure'):
        require(not queue and not calls and not deallocated, 'Disabled/failed Data schedule started work')
    else:
        require(len(queue) == deallocated == 1 and not calls, 'Data starter ran synchronously on IOBSD')
        execute(queue[0], 0, 0)
        require(terminated == 1, 'Data worker did not terminate')
    put(out, b'\xa5' * 64); execute('_dodge_data_late_status', out)
    status = bytes(uc.mem_read(out, facts['data_bytes']))
    phase, last, attempts = (struct.unpack_from('<I', status, facts['data_' + name])[0] for name in ('phase', 'last', 'attempts'))
    success = case not in ('default-disabled', 'thread-failure', 'missing-root', 'earlier-timeout', 'start-timeout', 'sticky-init-failure', 'error-owned-driver', 'success-null-driver')
    require(status[facts['data_started']] == int(success), 'Data worker startup result changed')
    if case in ('default-disabled', 'thread-failure'):
        require(phase == facts['data_cold'] and not attempts, 'Disabled/failed Data phase changed')
    else:
        require(phase == facts['data_finished'] and execute('_dodge_data_schedule') == facts['not_permitted'], 'Data worker was not final or restarted')
        if case in ('missing-root', 'earlier-timeout'): require(attempts == 1000 and sleeps == 999 and not calls, 'Data wait is not bounded')
        elif case == 'start-timeout': require(attempts == calls == 1000 and sleeps == 999, 'Data prestart retry bound changed')
        else:
            expected_calls = 3 if case == 'busy-then-success' else 1
            require(calls == expected_calls and released == int(success or case == 'error-owned-driver'), 'Data owned-reference or retry count changed')
        require(last == (0 if success else facts['error'] if case in ('error-owned-driver', 'success-null-driver') else facts['not_ready']), 'Data status lost the actual error')
    require(bytes(uc.mem_read(out + facts['data_bytes'], 64 - facts['data_bytes'])) == b'\xa5' * (64 - facts['data_bytes']), 'Data status overran its caller buffer')
    return {'case': case, 'result': 'PASS', 'starter_calls': calls, 'sleeps': sleeps, 'owned_releases': released,
            'phase': phase, 'attempts': attempts, 'explicit_peers': sorted(set(completed))}


def main():
    OUT.mkdir(exist_ok=True)
    path = ROOT / 'reports/ios16-data-startup-prelink.json'; prelink = json.loads(path.read_text())
    require(prelink['builder_sha256'] == sha(ROOT / 'scripts/build_data_startup_prelink.py'), 'Data startup prelink is stale')
    candidate = ROOT / prelink['candidate']; require(sha(candidate) == prelink['candidate_sha256'], 'Data startup candidate changed')
    old_path = ROOT / 'reports/ios16-data-kernel.json'; old = json.loads(old_path.read_text())
    require(old['builder_sha256'] == sha(ROOT / 'scripts/check_data_kernel.py') and old['case_count'] == 30, 'Base Data CPU evidence is stale')
    facts, obj = layout()
    cases = [emulate(candidate, case, facts) for case in CASES]
    try: emulate(candidate, 'data-success', facts, control=True)
    except ValueError as error: control = {'case': 'actual-BSD-Data-call-NOP', 'result': 'REJECTED', 'reason': str(error)}
    else: raise ValueError('Removing actual BSD Data scheduling was accepted')
    inputs = {variant: json.loads((ROOT / ('reports/ios16-data' + variant + '-image.json')).read_text()) for variant in ('', '-volatile')}
    io = [data_io(candidate, case, old['instance_layout'], inputs) for case in IO_CASES]
    io.append(lifetime(candidate, old['instance_layout']))
    io.extend(lifetime(candidate, old['instance_layout'], init_case=case) for case in ('init-parent-failure', 'init-property-failure', 'init-success'))
    output = OUT / 'cpu-cases.json'; output.write_text(json.dumps({'scheduling': cases, 'data_paths': io}, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/check_data_kernel.py', ROOT / 'drivers/DodgeStorage/DodgeDataLate.cpp', ROOT / 'drivers/DodgeStorage/DodgeDataLate.h']
    report = {'result': 'IOS16_ACTUAL_DATA_STARTUP_AND_DATA_PATHS_ARM64_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
              'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (path, old_path, ROOT / 'reports/ios16-data-startup.json')},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (obj, output)}, 'candidate': prelink['candidate'], 'candidate_sha256': sha(candidate),
              'case_count': len(cases) + len(io), 'scheduler_case_count': len(cases), 'data_case_count': len(io),
              'scheduling_cases': cases, 'data_cases': io, 'native_status_layout': facts, 'negative_controls': [control],
              'actual_iobsd_and_data_scheduler_executed': True, 'data_starter_implementation_is_a_peer_in_scheduler_cases': True,
              'original_apfs_data_mount_qualified': False, 'hardware_tested': False, 'ready_for_ios_boot': False,
              'all_ios_port_code_complete': False, 'phone_operations': 'none',
              'scope': 'Actual 84-object prelinked IOBSD/Data scheduler and bounded worker, with explicit system/input scheduler, IOKit/thread and Data-starter peers. '
                       'The existing 30 Data I/O/C1/D1/original-init CPU paths are rerun against this exact new candidate. No complete registry/APFS/phone runtime qualification.'}
    (ROOT / 'reports/ios16-data-startup-kernel.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', len(cases), 'actual Data scheduling +', len(io), 'Data CPU paths in the 84-object candidate; removed-call control rejected')


if __name__ == '__main__':
    main()
