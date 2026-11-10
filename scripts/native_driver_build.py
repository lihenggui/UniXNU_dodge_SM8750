#!/usr/bin/env python3
"""Shared native-source compilation and Mach-O inspection for local driver builds."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree'
OBJDIR = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
NATIVE = OBJDIR / 'mach.development.bcm2837.unstripped'
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from native_prelink import macho, exports


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ios_userspace_linker():
    """Expose the real pinned LLVM Mach-O frontend under its dispatch name."""
    binary = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld'
    require(binary.is_file(), 'Install the pinned Rust LLVM tools first')
    linker = ROOT / 'build/gpu-link-tools/ld64.lld'
    linker.parent.mkdir(parents=True, exist_ok=True)
    if not linker.exists():
        linker.symlink_to(binary)
    require(linker.is_symlink() and linker.resolve() == binary.resolve(), 'Unexpected userspace Mach-O linker')
    return linker


def pinned_sources(names):
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    result = {}
    for name in names:
        spec = lock[name]
        directory = ROOT / spec['path']
        head = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == spec['revision'], 'Source revision mismatch: ' + name)
        require(not subprocess.check_output(['git', '-C', str(directory), 'status', '--porcelain'], text=True),
                'Reference has unrecorded source edits: ' + name)
        result[name] = directory
    return result


def compile_command(source, destination, includes=(), extra=()):
    relative = 'bsd/DEVELOPMENT/vfs_conf.o.json' if source.suffix == '.c' else 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe = OBJDIR / relative
    record = json.loads(recipe.read_text().strip().rstrip(','))
    args, command, index = record['arguments'], [], 0
    while index < len(args):
        value = args[index]
        if value == record['file']:
            command.append(str(source))
        elif value in ('-o', '-MF', '-MJ'):
            index += 1
        elif value == '-Xclang' and args[index + 1].startswith('-W'):
            index += 1
        elif value not in ('-MD', '-MP') and not value.startswith('-W'):
            command.append(value)
        index += 1
    # Match the consuming driver's warning policy while retaining the real
    # kernel target, headers, code generation and signed-overflow instrumentation.
    command += ['-o', str(destination), '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-parameter', '-Wno-unnecessary-virtual-specifier',
                '-Wno-missing-designated-field-initializers', '-Wno-c99-designator',
                '-Wno-reorder-init-list', '-Wno-deprecated-enum-enum-conversion', *extra]
    for directory in includes:
        command += ['-I', str(directory)]
    require(not any('HOST_TEST' in arg for arg in command), 'Host-test macro in native driver compile')
    return {'arguments': command, 'directory': record['directory'], 'source': str(source),
            'recipe': str(recipe.relative_to(TREE)), 'recipe_sha256': sha(recipe)}


def inspect_object(data):
    require(struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 1),
            'Expected an ordinary ARM64 relocatable Mach-O')
    image = macho(data)
    version, = [at for cmd, at, _ in image['commands'] if cmd == 0x32]
    require(struct.unpack_from('<II', data, version + 8) == (2, 0x100000), 'Expected an iOS 16.0 object')
    return image


def symbols(data):
    image = macho(data)
    command, = [at for cmd, at, _ in image['commands'] if cmd == 2]
    offset, count, strings, size = struct.unpack_from('<4I', data, command + 8)
    require(offset + count * 16 <= len(data) and strings + size <= len(data), 'Invalid Mach-O symbols')
    result = []
    for index in range(count):
        strx, kind, section, description, value = struct.unpack_from('<IBBHQ', data, offset + 16 * index)
        require(strx < size, 'Invalid Mach-O symbol string')
        end = data.index(b'\0', strings + strx, strings + size)
        result.append({'name': data[strings + strx:end].decode(), 'kind': kind,
                       'section': section, 'description': description, 'value': value})
    return result


def build_objects(files, out, includes=(), extra=()):
    out.mkdir(parents=True, exist_ok=True)
    objects = [out / (source.stem + '.o') for source in files]
    require(len(set(objects)) == len(objects), 'Driver sources have colliding object names')
    commands = [compile_command(source, obj, includes, extra) for source, obj in zip(files, objects)]
    (out / 'compile-commands.json').write_text(json.dumps(commands, indent=2) + '\n')

    def compile_one(item):
        command, obj = item
        with obj.with_suffix('.log').open('w') as stream:
            process = subprocess.run(command['arguments'], cwd=command['directory'], timeout=120,
                                     stdout=stream, stderr=subprocess.STDOUT)
        if process.returncode == 0:
            inspect_object(obj.read_bytes())
        return obj.name, process.returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(pool.map(compile_one, zip(commands, objects)))
    (out / 'compile-results.json').write_text(json.dumps(results, indent=2) + '\n')
    failed = [name for name, code in results.items() if code]
    require(not failed, 'Driver compilation failed; inspect per-object logs in ' + str(out) + ': ' + ', '.join(failed))
    return objects


def archive_imports(objects):
    defined, undefined, weak, strong = {}, set(), set(), set()
    for obj in objects:
        for symbol in symbols(obj.read_bytes()):
            kind, name = symbol['kind'], symbol['name']
            if kind & 0xe0 or not kind & 1:
                continue
            if kind & 0xe:
                defined.setdefault(name, []).append((obj.name, bool(symbol['description'] & 0x80)))
            else:
                undefined.add(name)
                if symbol['description'] & 0x40:
                    weak.add(name)
                else:
                    strong.add(name)
    collisions = {name: values for name, values in defined.items() if sum(not weak for _, weak in values) > 1}
    require(not collisions, 'Duplicate strong driver definitions: ' + repr(collisions))
    undefined -= defined.keys()
    # An import is optional only when every unresolved reference is weak.
    # One strong consumer must not disappear behind another weak consumer.
    weak -= strong
    native = NATIVE.read_bytes()
    public = {name for names in exports(native, macho(native)).values() for name in names}
    internal = {s['name'] for s in symbols(native) if not s['kind'] & 0xe0 and s['kind'] & 0xe}
    return {'defined': sorted(defined), 'native_public_imports': sorted(undefined & public),
            'native_static_link_only_imports': sorted((undefined - public) & internal),
            'required_board_or_original_imports': sorted(undefined - public - internal - weak),
            'optional_weak_imports': sorted((undefined - public - internal) & weak)}
