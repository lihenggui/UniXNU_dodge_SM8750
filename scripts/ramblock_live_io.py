#!/usr/bin/env python3
"""Exercise the real I/O method on the object produced by the real start method."""
import struct

from native_driver_build import require


def exercise(model, obj, facts, logical, initial, allocations, control=False):
    descriptor, completion = model.heap + 0x30000, model.heap + 0x31000
    callback, target, parameter = model.stop + 0x300, 0x12340000, 0x56780000
    model.put(descriptor, struct.pack('<Q', model.names['__ZTV18IOMemoryDescriptor'] + 16))
    model.put(completion, bytes(facts['completion_bytes']))
    for name, value in (('completion_target', target), ('completion_action', callback), ('completion_parameter', parameter)):
        model.put(completion + facts[name], struct.pack('<Q', value))
    gate, = struct.unpack('<Q', model.read(obj + facts['gate'], 8))
    oracle, rows, locks = dict(initial), [], [0, 0]
    active = {}
    allocator = model.peers[model.names['_IOMalloc_internal']][1]
    def lock(args):
        require(args[0] == gate and locks[0] == locks[1], 'Live I/O lock is unbalanced')
        locks[0] += 1; model.returned()
    def unlock(args):
        require(args[0] == gate and locks[0] == locks[1] + 1, 'Live I/O unlock is unbalanced')
        locks[1] += 1; model.returned()
    model.bind('_lck_mtx_lock', lock); model.bind('_lck_mtx_unlock', unlock)
    def descriptor_value(args, value):
        require(args[0] == descriptor, 'Live I/O inspected another descriptor')
        model.returned(value)
    model.bind('__ZNK18IOMemoryDescriptor9getLengthEv', lambda args: descriptor_value(args, len(active['buffer'])))
    model.bind('__ZNK18IOMemoryDescriptor12getDirectionEv',
               lambda args: descriptor_value(args, facts['direction_out'] if active['write'] else facts['direction_in']))
    def transfer(args, write):
        buffer = active['buffer']
        require(args[0] == descriptor and write == active['write'] and locks[0] == locks[1] + 1 and
                args[1] <= len(buffer) and args[3] <= len(buffer) - args[1], 'Live descriptor transfer escaped its request/lock')
        count = min(args[3], active['short']) if active['short'] else args[3]
        if write: model.put(args[2], bytes(buffer[args[1]:args[1] + count]))
        else: buffer[args[1]:args[1] + count] = model.read(args[2], count)
        model.returned(count)
    model.bind('__ZN18IOMemoryDescriptor9readBytesEyPvy', lambda args: transfer(args, True))
    model.bind('__ZN18IOMemoryDescriptor10writeBytesEyPKvy', lambda args: transfer(args, False))
    def allocate(args):
        limit = active['budget']
        if limit is not None and len(allocations) - active['before'] >= limit:
            model.returned(); return
        allocator(args)
    model.bind('_IOMalloc_internal', allocate)
    def completed(args):
        require(args[:2] == [target, parameter] and locks[0] == locks[1], 'Live I/O completed under the lock or changed context')
        active['completions'].append([args[2] & 0xffffffff, args[3]]); model.returned()
    model.names['_live_storage_completion'] = callback
    model.bind('_live_storage_completion', completed)
    entry = '__ZN14NativeRamBlock16doAsyncReadWriteEP18IOMemoryDescriptoryyP19IOStorageAttributesP19IOStorageCompletion'
    if control: model.put(model.names[entry], struct.pack('<I', 0xd65f03c0))
    def expected(offset, length):
        output = bytearray()
        while len(output) < length:
            index, skip = divmod(offset + len(output), 4096)
            count = min(4096 - skip, length - len(output))
            output += oracle.get(index, bytes(4096))[skip:skip + count]
        return bytes(output)
    def request(name, block, sectors, write=False, budget=None, short=None, actual=None, status=None, unavailable=False):
        length = sectors * 512
        source = bytes((index * 31 + len(rows) * 7 + 1) & 255 for index in range(length))
        buffer = bytearray(source if write else bytes([0xcd]) * length)
        active.update(buffer=buffer, write=write, budget=budget, short=short, before=len(allocations), completions=[])
        before_locks = locks[0]
        result = model.call(entry, [obj, descriptor, block, sectors, 0, completion], limit=1000000)
        want_actual = length if actual is None else actual
        want_status = facts['success'] if status is None else facts[status]
        require(locks[0] == locks[1] == before_locks + 1, 'Started disk did not balance the I/O gate')
        if unavailable:
            require(result == facts['not_ready'] and not active['completions'] and len(allocations) == active['before'],
                    'Storeless large disk accepted a write')
            require(buffer == source, 'Unavailable live write changed its descriptor')
        else:
            require(result == facts['success'] and active['completions'] == [[want_status, want_actual]],
                    'Started disk I/O completion differs: ' + name)
            if write:
                require(buffer == source, 'Live write changed caller-owned input')
                done = 0
                while done < want_actual:
                    index, skip = divmod(block * 512 + done, 4096)
                    count = min(4096 - skip, want_actual - done)
                    page = bytearray(oracle.get(index, bytes(4096)))
                    page[skip:skip + count] = source[done:done + count]; oracle[index] = bytes(page); done += count
            else:
                require(buffer == expected(block * 512, want_actual) + bytes([0xcd]) * (length - want_actual),
                        'Started disk read differs from independent seed/write oracle: ' + name)
        rows.append({'case': name, 'result': 'PASS', 'return': hex(result), 'completions': active['completions'],
                     'new_allocated_pages': len(allocations) - active['before'], 'balanced_lock_pairs': 1})
    hole = next(index for index in range(logical // 4096 - 16) if all(index + delta not in initial for delta in range(16)))
    volume = next(index for index, page in initial.items() if page[32:36] == b'APSB')
    request('container-superblock-from-started-disk', 0, 8)
    request('volume-superblock-from-started-disk', volume * 8, 8)
    request('zero-hole-from-started-disk', hole * 8, 8)
    request('cross-page-from-started-disk', 7, 10)
    request('last-sector-from-started-disk', logical // 512 - 1, 1)
    if logical > 1 << 31:
        request('large-disk-write-without-store-refused', hole * 8, 1, write=True, unavailable=True)
    else:
        request('write-imported-page', 2, 1, write=True)
        request('read-modified-imported-page', 0, 8)
        request('write-new-hole-page', hole * 8, 1, write=True)
        request('read-new-page-and-zero-remainder', hole * 8, 8)
        request('write-across-two-new-pages', (hole + 2) * 8 + 7, 3, write=True)
        request('read-both-new-pages', (hole + 2) * 8, 16)
        request('allocation-failure', (hole + 4) * 8, 8, write=True, budget=0, actual=0, status='no_memory')
        request('read-unallocated-page-after-failure', (hole + 4) * 8, 8)
        request('partial-allocation-failure', (hole + 6) * 8, 16, write=True, budget=1, actual=4096, status='no_memory')
        request('read-partially-completed-write', (hole + 6) * 8, 16)
        request('short-descriptor-read', 0, 1, short=29, actual=29, status='io_error')
        request('short-descriptor-write', (hole + 6) * 8, 1, write=True, short=29, actual=29, status='io_error')
        request('read-after-short-write', (hole + 6) * 8, 8)
        request('write-last-sector', logical // 512 - 1, 1, write=True)
        request('read-last-page-and-zero-prefix', logical // 512 - 8, 8)
    require(locks[0] == locks[1] == len(rows), 'Live I/O left the disk gate locked')
    require(model.read(obj + facts['seed_hash'], 32) == model.read(model.names['_native_ram_block_seed_sha256'], 32),
            'Live I/O changed the startup seed identity')
    return {'result': 'PASS', 'case_count': len(rows), 'cases': rows, 'actual_start_object_reused_without_field_reconstruction': True,
            'descriptor_allocation_lock_and_completion_are_explicit_peers': True,
            'volatile_writes_only': logical <= 1 << 31, 'persistent_store_or_original_apfs_execution': False}
