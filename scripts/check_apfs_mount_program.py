#!/usr/bin/env python3
"""Execute the exact original iPhone mount program to the mount boundary with explicit libc/IOKit peers."""
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from native_driver_build import ROOT, macho, require, pinned_sources
from native_prelink import backed_offset
from prepare_initial_data import sha
from prepare_apfs_mount_abi import PROFILE, PROGRAM, imports

OUT = ROOT / 'build/ios16-apfs-mount-program'
OPTIONS_LIBRARY = None


class MntOption(ctypes.Structure):
    _fields_ = [('name', ctypes.c_char_p), ('inverse', ctypes.c_int), ('flag', ctypes.c_int), ('alternate', ctypes.c_int)]


def options_library():
    global OPTIONS_LIBRARY
    if OPTIONS_LIBRARY is None:
        source = pinned_sources(('apfs_mount_options_reference',))['apfs_mount_options_reference']
        OUT.mkdir(parents=True, exist_ok=True)
        library = OUT / 'libAppleMountOptions.so'
        subprocess.run(['/usr/bin/clang-14', '-std=c11', '-D_DEFAULT_SOURCE', '-Dlint', '-O2', '-fPIC', '-shared',
                        '-Wall', '-Wextra', '-Werror', '-I' + str(source), source / 'getmntopts.c', '-o', library], check=True)
        require(ctypes.sizeof(MntOption) == 24 and [getattr(MntOption, name).offset for name, _ in MntOption._fields_] == [0, 8, 12, 16],
                'Host parser option structure differs')
        OPTIONS_LIBRARY = ctypes.CDLL(str(library))
        OPTIONS_LIBRARY.getmntopts.argtypes = [ctypes.c_char_p, ctypes.POINTER(MntOption), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        OPTIONS_LIBRARY.getmntopts.restype = ctypes.c_void_p
        OPTIONS_LIBRARY.freemntopts.argtypes = [ctypes.c_void_p]; OPTIONS_LIBRARY.freemntopts.restype = None
        OPTIONS_LIBRARY.getmntoptnum.argtypes = [ctypes.c_void_p, ctypes.c_char_p]; OPTIONS_LIBRARY.getmntoptnum.restype = ctypes.c_long
    return OPTIONS_LIBRARY
CASES = (
    {'name': 'root-owners', 'owners': (0, 0)},
    {'name': 'mountpoint-owners', 'owners': (501, 20)},
    {'name': 'stat-failure', 'owners': (501, 20), 'stat_error': True, 'expected_owners': (0, 0)},
    {'name': 'explicit-uid', 'options': ['-u', '42'], 'expected_owners': (42, 20)},
    {'name': 'explicit-gid', 'options': ['-g', '77'], 'expected_owners': (501, 77)},
    {'name': 'explicit-both', 'options': ['-u', '42', '-g', '77'], 'expected_owners': (42, 77)},
    {'name': 'raw-device', 'device': '/dev/rdisk9s1', 'expected_device': '/dev/disk9s1'},
    {'name': 'unprefixed-device', 'device': 'disk9s1', 'expected_device': '/dev/disk9s1'},
    {'name': 'root-mountpoint', 'mountpoint': '/', 'expected_owners': (0, 0), 'no_device': True},
    {'name': 'noowners', 'options': ['-o', 'noowners'], 'flags': 0x200000, 'expected_owners': (99, 99)},
    {'name': 'noowners-explicit', 'options': ['-o', 'noowners', '-u', '42', '-g', '77'],
     'flags': 0x200000, 'expected_owners': (42, 77)},
    {'name': 'readonly', 'options': ['-o', 'ro'], 'flags': 1},
    {'name': 'readonly-noowners', 'options': ['-o', 'ro,noowners'], 'flags': 0x200001, 'expected_owners': (99, 99)},
    {'name': 'update-clears-device', 'options': ['-o', 'update'], 'flags': 0x10000,
     'expected_owners': (0xffffffff, 0xffffffff), 'no_device': True, 'mode': 0},
    {'name': 'realpath-failure', 'realpath_error': True, 'error': True},
    {'name': 'missing-argument', 'missing_argument': True, 'error': True},
    {'name': 'unresolved-uid', 'options': ['-u', '-1'], 'error': True},
    {'name': 'unresolved-gid', 'options': ['-g', '-1'], 'error': True},
    {'name': 'unsupported-option', 'options': ['-o', 'dodge-unknown'], 'error': True},
)


def chains(raw, image):
    """Decode only the original's ordinary format-6 chains, using Apple's pinned header layout."""
    command, = [at for cmd, at, size in image['commands'] if cmd == 0x80000034]
    offset, size = struct.unpack_from('<II', raw, command + 8)
    require(offset + size <= len(raw), 'Original chained fixups exceed file')
    version, starts, import_offset, strings, count, fmt, compression = struct.unpack_from('<7I', raw, offset)
    require((version, count, fmt, compression) == (0, 77, 1, 0), 'Original chained fixups header changed')
    names = []
    for index in range(count):
        record, = struct.unpack_from('<I', raw, offset + import_offset + index * 4)
        at = offset + strings + (record >> 9)
        end = raw.index(b'\0', at, offset + size)
        names.append(raw[at:end].decode())
    start_base = offset + starts
    segments, = struct.unpack_from('<I', raw, start_base)
    require(segments == len(image['segments']) == 5, 'Original chained segment count differs')
    records = struct.unpack_from('<' + str(segments) + 'I', raw, start_base + 4)
    patches, counts = {}, {'binds': 0, 'rebases': 0}
    base = 0x100000000
    for index, relative in enumerate(records):
        if not relative:
            continue
        at = start_base + relative
        extent, page_size, pointer_format, segment_offset, max_pointer, pages = struct.unpack_from('<IHHQIH', raw, at)
        segment = image['segments'][index]
        require(extent == 22 + 2 * pages and pointer_format == 6 and page_size == 0x4000 and pages == 1 and
                max_pointer == 0 and segment['va'] == base + segment_offset, 'Unsupported original chain segment')
        for page in range(pages):
            first, = struct.unpack_from('<H', raw, at + 22 + page * 2)
            if first == 0xffff:
                continue
            require(first < 0x8000, 'Original multi-start chains are outside this profile')
            cursor = segment['va'] + page * page_size + first
            page_end = segment['va'] + (page + 1) * page_size
            while True:
                require(cursor not in patches and segment['va'] <= cursor <= page_end - 8, 'Original chain loop or page overflow')
                fileoff = backed_offset(image['segments'], cursor, 8, len(raw))
                value, = struct.unpack_from('<Q', raw, fileoff)
                following = (value >> 51) & 0xfff
                if value >> 63:
                    ordinal = value & 0xffffff
                    require(ordinal < len(names) and (value >> 24) & 0x7ffffff == 0, 'Original chained bind has addend/reserved bits')
                    patches[cursor] = names[ordinal]
                    counts['binds'] += 1
                else:
                    require((value >> 36) & 0x7fff == 0, 'Original chained rebase has unexpected top/reserved bits')
                    target = base + (value & ((1 << 36) - 1))
                    require(any(s['va'] <= target < s['va'] + s['size'] for s in image['segments'] if s['name'] != '__PAGEZERO'),
                            'Original chained rebase leaves image')
                    patches[cursor] = target
                    counts['rebases'] += 1
                if not following:
                    break
                cursor += following * 4
    return patches, counts


def emulate(case, mutation=False):
    import unicorn as u
    import unicorn.arm64_const as arm
    require(u.__version__ == '2.1.4', 'Use pinned Unicorn')
    library = options_library()
    host_parsers = {}
    raw = PROGRAM.read_bytes()
    image = macho(raw)
    contract = json.loads(PROFILE.read_text())
    require(hashlib.sha256(raw).hexdigest() == contract['original_program_sha256'], 'Original mount program changed')
    cpu = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
    for segment in image['segments']:
        if segment['name'] == '__PAGEZERO':
            continue
        cpu.mem_map(segment['va'], (segment['size'] + 4095) & -4096)
        cpu.mem_write(segment['va'], raw[segment['fileoff']:segment['fileoff'] + segment['filesize']])
    cpu.mem_map(0x200000000, 0x200000)
    cpu.mem_map(0x300000000, 0x200000)
    calls, pointer_imports = imports(raw, image)
    patches, chain_counts = chains(raw, image)
    require(all(patches.get(at) == name for at, name in pointer_imports.items()), 'Chained and indirect import names disagree')
    globals, peers = {}, {}
    global_names = {'___stack_chk_guard', '_getmnt_silent', '_optarg', '_optind', '_optopt',
                    '_kCFAllocatorDefault', '_kCFBooleanTrue', '_kIOMasterPortDefault'}
    for at, value in patches.items():
        if isinstance(value, str):
            if value not in peers:
                peers[value] = 0x300100000 + len(peers) * 0x100
            target = peers[value]
            (globals if value in global_names else calls)[value if value in global_names else target] = target if value in global_names else value
        else:
            target = value
        cpu.mem_write(at, struct.pack('<Q', target))
    argv = 0x300000000
    arguments = ['mount_apfs', *case.get('options', []), case.get('device', '/dev/disk9s1')]
    if not case.get('missing_argument'):
        arguments.append(case.get('mountpoint', '/private/var'))
    values = []
    for index, value in enumerate(arguments):
        at = argv + 0x1000 + index * 0x1000
        cpu.mem_write(at, value.encode() + b'\0')
        cpu.mem_write(argv + index * 8, struct.pack('<Q', at))
        values.append(at)
    cpu.mem_write(globals['_optind'], struct.pack('<I', 1))
    allocated = 0x300050000
    option_index, instructions = 1, 0
    visited, result = set(), None

    def x(index):
        return cpu.reg_read(arm.UC_ARM64_REG_X0 + index)
    def string(ptr):
        if not ptr:
            raise ValueError('Null peer string')
        data = bytearray()
        for index in range(4096):
            value = bytes(cpu.mem_read(ptr + index, 1))
            if value == b'\0':
                return bytes(data)
            data += value
        raise ValueError('Unterminated peer string')
    def allocate(data):
        nonlocal allocated
        require(len(data) < 65536, 'Peer allocation exceeds bound')
        at = allocated
        allocated += (len(data) + 31) & -16
        require(allocated < 0x3000f0000, 'Peer heap exceeds bound')
        cpu.mem_write(at, data)
        return at
    def hook(cpu, pc, size, ignored):
        nonlocal option_index, instructions, result
        instructions += 1
        name = calls.get(pc)
        if name is None:
            return
        visited.add(name)
        args = [x(i) for i in range(8)]
        answer = 0
        if name == '___chkstk_darwin':
            answer = args[0]  # Special probe convention preserves incoming registers.
        elif name in ('_err_set_exit', '_free'):
            pass
        elif name == '_getopt':
            require(args[0] == len(arguments), 'Original argc changed before getopt')
            if option_index < len(arguments) and arguments[option_index].startswith('-'):
                token = arguments[option_index]
                require(len(token) == 2, 'Fixture uses a non-single-letter option')
                letter = token[1]
                option_string = string(args[2]).decode()
                position = option_string.find(letter)
                require(position >= 0, 'Fixture option is absent from original getopt spec')
                option_index += 1
                if position + 1 < len(option_string) and option_string[position + 1] == ':':
                    require(option_index < len(arguments), 'Fixture option argument missing')
                    cpu.mem_write(globals['_optarg'], struct.pack('<Q', values[option_index]))
                    option_index += 1
                answer = ord(letter)
            else:
                answer = -1
            cpu.mem_write(globals['_optind'], struct.pack('<I', option_index))
        elif name == '_memset':
            require(args[2] <= 8192, 'Original memset exceeds peer bound')
            cpu.mem_write(args[0], bytes([args[1] & 255]) * args[2])
            answer = args[0]
        elif name in ('_strlcpy', '___strlcpy_chk'):
            value = string(args[1])
            count = args[2]
            require(0 < count <= 4096 and (name != '___strlcpy_chk' or count <= args[3]), 'Original string copy bound invalid')
            cpu.mem_write(args[0], value[:count - 1] + b'\0')
            answer = len(value)
        elif name in ('_strncmp', '_strncasecmp', '_strcmp', '_strcasecmp'):
            left, right = string(args[0]), string(args[1])
            if name in ('_strncmp', '_strncasecmp'):
                left, right = left[:args[2]], right[:args[2]]
            if name in ('_strncasecmp', '_strcasecmp'):
                left, right = left.lower(), right.lower()
            answer = (left > right) - (left < right)
        elif name == '_realpath$DARWIN_EXTSN':
            if case.get('realpath_error'):
                answer = 0
            else:
                cpu.mem_write(args[1], string(args[0]) + b'\0')
                answer = args[1]
        elif name == '_stat':
            data = bytearray(144)
            struct.pack_into('<II', data, 16, *case.get('owners', (501, 20)))
            cpu.mem_write(args[1], bytes(data))
            answer = -1 if case.get('stat_error') else 0
        elif name == '_getmntinfo':
            cpu.mem_write(args[0], bytes(8))
        elif name == '_snprintf':
            require(string(args[2]) == b'%s%s', 'Unqualified snprintf peer format')
            sp = cpu.reg_read(arm.UC_ARM64_REG_SP)
            pointers = struct.unpack('<QQ', bytes(cpu.mem_read(sp, 16)))
            value = b''.join(string(p) for p in pointers)
            require(0 < args[1] <= 4096, 'snprintf peer bound invalid')
            cpu.mem_write(args[0], value[:args[1] - 1] + b'\0')
            answer = len(value)
        elif name == '_strtol':
            value = string(args[0])
            answer = int(value, 10)
            if args[1]:
                cpu.mem_write(args[1], struct.pack('<Q', args[0] + len(value)))
        elif name == '_strlen':
            answer = len(string(args[0]))
        elif name == '_strdup':
            answer = allocate(string(args[0]) + b'\0')
        elif name == '_strchr':
            value = string(args[0]) + b'\0'
            found = value.find(bytes([args[1] & 255]))
            answer = args[0] + found if found >= 0 else 0
        elif name == '_strtok_r':
            start = args[0] or struct.unpack('<Q', bytes(cpu.mem_read(args[2], 8)))[0]
            if start:
                value = string(start)
                separators = set(string(args[1]))
                first = 0
                while first < len(value) and value[first] in separators:
                    first += 1
                end = first
                while end < len(value) and value[end] not in separators:
                    end += 1
                answer = start + first if first < len(value) else 0
                if end < len(value):
                    cpu.mem_write(start + end, b'\0')
                    following = start + end + 1
                else:
                    following = 0
                cpu.mem_write(args[2], struct.pack('<Q', following))
        elif name == '_freemntopts':
            require(args[0] in host_parsers, 'Original program freed an unknown option parser')
            parser, table = host_parsers.pop(args[0]); library.freemntopts(parser)
        elif name == '_getmntoptnum':
            require(args[0] in host_parsers, 'Original numeric option uses an unknown parser')
            answer = library.getmntoptnum(host_parsers[args[0]][0], string(args[1]))
        elif name == '_getmntopts':
            # The pinned Apple C parser operates on a copy of the original
            # relocated mntopt table. Its opaque allocation stays host-side.
            entries = []
            for index in range(128):
                pointer, inverse, flag, alternate = struct.unpack('<Qiii4x', bytes(cpu.mem_read(args[1] + index * 24, 24)))
                if not pointer:
                    break
                entries.append((string(pointer), inverse, flag, alternate))
            else:
                raise ValueError('Original option table exceeds bound')
            table = (MntOption * (len(entries) + 1))()
            for index, option_record in enumerate(entries):
                table[index] = MntOption(*option_record)
            normal = ctypes.c_int(struct.unpack('<i', bytes(cpu.mem_read(args[2], 4)))[0])
            alternate = ctypes.c_int(struct.unpack('<i', bytes(cpu.mem_read(args[3], 4)))[0])
            silent, = struct.unpack('<I', bytes(cpu.mem_read(globals['_getmnt_silent'], 4)))
            require(silent == 1, 'Original parser did not select silent admission')
            ctypes.c_int.in_dll(library, 'getmnt_silent').value = silent
            parser = library.getmntopts(string(args[0]), table, ctypes.byref(normal), ctypes.byref(alternate))
            require(parser, 'Pinned Apple option parser allocation failed')
            cpu.mem_write(args[2], struct.pack('<i', normal.value)); cpu.mem_write(args[3], struct.pack('<i', alternate.value))
            answer = allocate(bytes(32)); host_parsers[answer] = (parser, table)
        elif name in ('_IOBSDNameMatching', '_IOServiceGetMatchingService'):
            answer = 0
        elif name in ('_err', '_errx', '_errc'):
            result = {'outcome': 'error-before-mount', 'exit_code': args[0], 'error_peer': name}
            cpu.emu_stop()
            return
        elif name == '_mount':
            payload = bytes(cpu.mem_read(args[3], 336))
            if mutation:
                payload = payload[:16] + b'\x08\0' + payload[18:]
            pointer, flags = struct.unpack_from('<QQ', payload)
            result = {'outcome': 'mount-boundary', 'fsname': string(args[0]).decode(), 'mountpoint': string(args[1]).decode(),
                      'flags': args[2], 'payload_flags': flags, 'mode': struct.unpack_from('<H', payload, 16)[0],
                      'uid': struct.unpack_from('<I', payload, 0x144)[0], 'gid': struct.unpack_from('<I', payload, 0x148)[0],
                      'device': string(pointer).decode() if pointer else None, 'user_device_pointer': pointer,
                      'payload_hex': payload.hex()}
            cpu.emu_stop()
            return
        else:
            raise ValueError('Unqualified original-program peer: ' + name)
        cpu.reg_write(arm.UC_ARM64_REG_X0, answer & ((1 << 64) - 1))
        cpu.reg_write(arm.UC_ARM64_REG_PC, cpu.reg_read(arm.UC_ARM64_REG_LR))

    cpu.hook_add(u.UC_HOOK_CODE, hook)
    cpu.reg_write(arm.UC_ARM64_REG_SP, 0x2001ff000)
    cpu.reg_write(arm.UC_ARM64_REG_X0, len(arguments))
    cpu.reg_write(arm.UC_ARM64_REG_X1, argv)
    cpu.reg_write(arm.UC_ARM64_REG_LR, 0x300080000)
    cpu.emu_start(int(contract['program_entry'], 16), 0x300080000, count=200000)
    require(result is not None, 'Original program did not reach a classified boundary for ' + case['name'] +
            ' at ' + hex(cpu.reg_read(arm.UC_ARM64_REG_PC)) + ', peers=' + repr(sorted(visited)))
    require(not host_parsers, 'Original program leaked a host option-parser allocation')
    if case.get('error'):
        require(result['outcome'] == 'error-before-mount', 'Original rejected invocation reached mount')
    else:
        require(result['outcome'] == 'mount-boundary', 'Original valid invocation failed before mount')
        uid, gid = case.get('expected_owners', case.get('owners', (501, 20)))
        require(result['fsname'] == 'apfs' and result['mountpoint'] == case.get('mountpoint', '/private/var') and
                result['flags'] == result['payload_flags'] == case.get('flags', 0) and result['mode'] == case.get('mode', 1) and
                (result['uid'], result['gid']) == (uid, gid), 'Original APFS request differs for ' + case['name'] + ': ' +
                repr({key: result[key] for key in ('flags', 'payload_flags', 'mode', 'uid', 'gid')}))
        require(result['device'] == (None if case.get('no_device') else case.get('expected_device', '/dev/disk9s1')), 'Original device canonicalization differs')
        payload = bytes.fromhex(result['payload_hex'])
        mask = bytearray(payload)
        for start, end in ((0, 18), (0x144, 0x14c)):
            mask[start:end] = bytes(end - start)
        require(not any(mask), 'Unqualified nonzero opaque original request field')
    return {'case': case['name'], 'result': 'PASS', 'original_instructions': instructions, 'explicit_peers': sorted(visited),
            'chained_fixups': chain_counts, **result}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = [emulate(case) for case in CASES]
    try:
        emulate(CASES[0], mutation=True)
    except ValueError as error:
        controls = [{'case': 'wrong-ordinary-mode-8', 'result': 'REJECTED', 'reason': str(error)}]
    else:
        raise ValueError('A wrong ordinary-volume mode was accepted')
    fixture = OUT / 'captures.json'
    fixture.write_text(json.dumps(rows, indent=2) + '\n')
    public = [{key: value for key, value in row.items() if key not in ('payload_hex', 'user_device_pointer')} for row in rows]
    reference = ROOT / 'sources/libutil-mount-reference'
    sources = [Path(__file__), ROOT / 'scripts/prepare_apfs_mount_abi.py', PROFILE, reference / 'getmntopts.c', reference / 'mntopts.h',
               ROOT / 'sources/xnu-ios16/EXTERNAL_HEADERS/mach-o/fixup-chains.h']
    report = {'result': 'IOS16_ORIGINAL_MOUNT_APFS_ORDINARY_REQUEST_CPU_PASS', 'builder_sha256': sha(Path(__file__)),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sources},
              'dependency_report_sha256': {'reports/ios16-apfs-mount-abi.json': sha(ROOT / 'reports/ios16-apfs-mount-abi.json')},
              'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in (fixture, OUT / 'libAppleMountOptions.so')},
              'option_library_reference': json.loads((ROOT / 'upstream.lock.json').read_text())['apfs_mount_options_reference'],
              'pinned_original_apple_getmntopts_source_executed_in_host_peer': True, 'case_count': len(rows), 'cases': public,
              'original_program_executed_from_main_to_boundary': True, 'libc_and_iokit_are_explicit_peers': True,
              'mount_syscall_executed': False, 'full_apfs_mount_qualified': False, 'hardware_tested': False,
              'ready_for_ios_boot': False, 'all_ios_port_code_complete': False, 'negative_controls': controls,
              'scope': 'Exact original main and its internal option/device/request helpers execute on ARM64 with bounded explicit library and IOKit peers. '
                       'Format-6 chained fixups relocate the original option tables; the pinned Apple C getmntopts peer parses those tables. '
                       'Requests stop at mount; early failures stop at err. No original APFS mount or host/phone filesystem operation occurs.'}
    (ROOT / 'reports/ios16-apfs-mount-program.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', len(rows), 'original iPhone mount_apfs CPU paths to mount/error boundaries with explicit peers')


if __name__ == '__main__':
    main()
