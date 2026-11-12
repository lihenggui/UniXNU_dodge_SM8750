#!/usr/bin/env python3
"""Bind SoftwareAES to the original iPhone class in a separate QEMU kernel."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_native_a830_kernel import REPORT as BASE_REPORT
from build_qemu_owner_root import OUT as OWNER_OUT, REPORT as OWNER_REPORT, check_report as check_owner
from build_qemu_storage import OUT as STORAGE_OUT
from build_qemu_exec import MODULE, validate_extension
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from check_gpu_link import assemble, run
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import ROOT, TREE, OBJDIR, build_objects, inspect_object, pinned_sources, require, sha, symbols, macho
from native_prelink import backed_offset
from prepare_ios16_pmgr import original
from prepare_surface_backing import checked as backing_checked, apply_hooks

OUT = ROOT / 'build/cph2653-qemu-aes'
REPORT = ROOT / 'reports/ios16-qemu-aes.json'
INIT = '__GLOBAL__sub_I_DodgeSoftwareAES.cpp'
VTABLE = '__ZTV9NativeAES'


def concrete_methods(path):
    raw = path.read_bytes();image = inspect_object(raw);table = symbols(raw)
    vtable, = [row for row in table if row['name'] == VTABLE]
    section, = [section for segment in image['segments'] for section in segment['sections']
        if section['va'] <= vtable['value'] < section['va'] + section['size']]
    offset, count = struct.unpack_from('<2I', raw, section['command_offset'] + 56);slots = {}
    for index in range(count):
        address, bits = struct.unpack_from('<2I', raw, offset + index * 8)
        slot = section['va'] + address - vtable['value'] - 16
        if slot < 0 or slot > 181 * 8:continue
        require(bits >> 24 == 14 and slot % 8 == 0, 'AES vtable relocation changed')
        slots[slot // 8] = table[bits & 0xffffff]['name']
    require(set(slots) == set(range(181)), 'Expected complete iPhone AES dispatch table')
    return [slots[index] for index in range(181)]


def derive_abi(methods):
    raw, image, read, entries, names = original()
    module_name = 'com.apple.iokit.IOCryptoAcceleratorFamily';entry = entries[module_name]
    module = macho(raw, backed_offset(image['segments'], entry['_PrelinkExecutableLoadAddr'], 32, len(raw)))
    def words(address, count):return struct.unpack('<' + str(count) + 'I', read(address, count * 4))
    def adrp(pc, word):
        require(word & 0x9f000000 == 0x90000000, 'AES ADRP changed')
        delta = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3)
        return (pc & -4096) + ((delta - (1 << 21) if delta & (1 << 20) else delta) << 12)
    def branch(pc, call=True):
        word, = words(pc, 1);require(word & 0xfc000000 == (0x94000000 if call else 0x14000000), 'AES branch changed')
        delta = word & 0x3ffffff
        return pc + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
    def stub(pc):
        a, b, c = words(pc, 3)
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200, 'AES import stub changed')
        return struct.unpack('<Q', read(adrp(pc, a) + ((b >> 10) & 4095) * 8, 8))[0]
    setup = 0xfffffff0056db438;w = words(setup, 14)
    require(w[:2] == (0xa9bf7bfd, 0x910003fd) and w[8] == 0x52802403 and
        stub(branch(setup + 36)) == names['__ZN11OSMetaClassC2EPKcPKS_j'], 'Original AES metadata constructor changed')
    meta = adrp(setup + 8, w[2]) + ((w[3] >> 10) & 4095)
    label = adrp(setup + 16, w[4]) + ((w[5] >> 10) & 4095)
    parent = adrp(setup + 24, w[6]) + ((w[7] >> 10) & 4095)
    require(meta == 0xfffffff007a11050 and parent == 0xfffffff007a110d8 and
        read(label, 17) == b'IOAESAccelerator\0', 'Original AES class identity changed')
    parent_setup = 0xfffffff0056db724;p = words(parent_setup, 14)
    require(p[8] == 0x52801103 and adrp(parent_setup + 8, p[2]) + ((p[3] >> 10) & 4095) == parent and
        struct.unpack('<Q', read(adrp(parent_setup + 24, p[6]) + ((p[7] >> 10) & 4095) * 8, 8))[0] == names['__ZN9IOService10gMetaClassE'],
        'Original crypto parent size or IOService identity changed')
    constructor = 0xfffffff0056d9038;c = words(constructor, 8)
    require(c[:2] == (0xa9bf7bfd, 0x910003fd) and c[5:] == (0xf9000008, 0xa8c17bfd, 0xd65f03c0) and
        branch(constructor + 8) == 0xfffffff0056db540, 'AES protected constructor changed')
    crypto_constructor = branch(constructor + 8)
    require(stub(branch(crypto_constructor + 8)) == names['__ZN9IOServiceC2EPK11OSMetaClass'], 'Crypto parent constructor changed')
    vptr = adrp(constructor + 12, c[3]) + ((c[4] >> 10) & 4095)
    table = struct.unpack('<181Q', read(vptr, 181 * 8))
    require(read(vptr + 181 * 8, 8) == bytes(8), 'AES table extent changed')
    destructor = table[0] - 4
    require(branch(destructor, False) == branch(table[0], False) == 0xfffffff0056db580 and
        stub(branch(0xfffffff0056db580, False)) == names['__ZN9IOServiceD2Ev'], 'AES protected destructor changed')
    a, b, c = words(table[7], 3)
    require(c == 0xd65f03c0 and adrp(table[7], a) + ((b >> 10) & 4095) == meta, 'AES virtual metadata changed')
    bindings, rows = {}, []
    overridden = {0, 1, 7, 86, 111, 117, 168, 169, 170, 171, 172}
    executable, = [segment for segment in module['segments'] if segment['name'] == '__TEXT_EXEC']
    for slot, (name, address) in enumerate(zip(methods, table)):
        own = name.startswith(('__ZN9NativeAES', '__ZNK9NativeAES'))
        require(own == (slot in overridden), 'Unexpected AES subclass override at slot ' + str(slot))
        if name in names:
            require(names[name] == address, 'AES inherited native dispatch changed at slot ' + str(slot));kind = 'native'
        else:
            require(executable['va'] <= address < executable['va'] + executable['filesize'], 'AES method escaped original component')
            kind = 'overridden' if own else 'original'
            if not own:
                require(name.startswith('__ZN16IOAESAccelerator'), 'Unexpected private AES parent method')
                bindings[name] = address
        rows.append({'slot': slot, 'compiled_method': name, 'original_address': hex(address), 'kind': kind})
    bindings.update({'__ZN16IOAESAcceleratorC2EPK11OSMetaClass': constructor,
        '__ZN16IOAESAcceleratorD2Ev': destructor, '__ZN16IOAESAccelerator10gMetaClassE': meta,
        '_dodge_original_aes_meta': meta})
    blocks = [('metadata_constructor', setup, 56), ('crypto_metadata_constructor', parent_setup, 56),
        ('protected_constructor', constructor, 64), ('protected_destructor', destructor, 8), ('vtable', vptr, 181 * 8)]
    return {'product': 'iPhone10,3', 'build': '20H392', 'module': module_name, 'version': entry['CFBundleVersion'],
        'original_kernelcache_sha256': hashlib.sha256(raw).hexdigest(), 'instance_bytes': 288, 'parent_bytes': 136,
        'metaclass': hex(meta), 'vptr': hex(vptr), 'methods': rows,
        'blocks': {name: {'address': hex(address), 'bytes': count, 'sha256': hashlib.sha256(read(address, count)).hexdigest()}
                   for name, address, count in blocks},
        'bindings': {name: hex(address - 0x1000000) for name, address in bindings.items()}}


def readback(raw, methods, abi):
    image = macho(raw);names = {row['name']: row for row in symbols(raw) if not row['kind'] & 0xe0}
    def read(address, count):
        at = backed_offset(image['segments'], address, count, len(raw));return raw[at:at + count]
    require(not any(row['kind'] == 1 for row in names.values()), 'AES kernel has unresolved symbols')
    require(struct.unpack('<181Q', read(names[VTABLE]['value'] + 16, 181 * 8)) ==
        tuple(names[name]['value'] for name in methods), 'AES concrete dispatch changed')
    for name, address in abi['bindings'].items():
        require(names[name]['kind'] == 3 and names[name]['value'] == int(address, 0), 'AES original alias changed')
    for segment in image['segments']:
        for section in segment['sections']:
            if section['name'] != '__mod_init_func' or not section['size']:continue
            values = struct.unpack('<' + str(section['size'] // 8) + 'Q', read(section['va'], section['size']))
            require(names[INIT]['value'] not in values, 'AES class initializes before its original parent')
    return {'class_bytes': 288, 'vtable_entries': 181, 'original_aliases': len(abi['bindings']),
        'deferred_initializer': hex(names[INIT]['value'])}


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_SOFTWARE_AES_KERNEL_PASS' and report['abi']['instance_bytes'] == 288 and
        report['source_reference'] == json.loads((ROOT / 'upstream.lock.json').read_text())['software_aes_reference'] and
        not report['hardware_tested'], 'Invalid iPhone AES build')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'AES build input changed: ' + name)
    require(readback((ROOT / report['candidate']).read_bytes(), report['concrete_methods'], report['abi']) == report['class_readback'],
        'AES linked readback changed')


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true');parser.add_argument('--negative-kat', action='store_true');args = parser.parse_args()
    if args.negative_kat:
        OUT = OUT.with_name(OUT.name + '-negative');REPORT = REPORT.with_name(REPORT.stem + '-negative.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original iPhone AES binding and QEMU kernel');return
    owner = json.loads(OWNER_REPORT.read_text());check_owner(owner)
    base = json.loads(BASE_REPORT.read_text());lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reference = pinned_sources(('software_aes_reference',))['software_aes_reference'];include = reference
    OUT.mkdir(parents=True, exist_ok=True)
    if args.negative_kat:
        include = OUT / 'wrong-answer';include.mkdir(exist_ok=True)
        text = (reference / 'NativeAES.cpp').read_text();marker = '0x76,0x49,0xab,0xac'
        require(text.count(marker) == 1, 'AES known-answer marker changed')
        (include / 'NativeAES.cpp').write_text(text.replace(marker, '0x77,0x49,0xab,0xac'))
        (include / 'OriginalAESABI.h').write_bytes((reference / 'OriginalAESABI.h').read_bytes())
    cpp = [ROOT / 'drivers/DodgeSecurity/DodgeSoftwareAES.cpp', ROOT / 'drivers/DodgeSecurity/DodgeQemuAES.cpp']
    obj, lifecycle = build_objects(cpp, OUT, [include])
    methods = concrete_methods(obj);abi = derive_abi(methods)
    late = OUT / 'DodgeSoftwareAES.late.o'
    objcopy = ROOT / '.toolchains/rust-gpu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy'
    subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + INIT, obj, late], check=True)
    bindings = assemble(OUT, 'aes-original-bindings', ''.join('.globl ' + name + '\n.set ' + name + ',' + address + '\n'
        for name, address in sorted(abi['bindings'].items())))
    archive = OUT / 'libDodgeQemuAES.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, late, lifecycle, bindings], check=True)
    pin = lock['dodge_qemu_aes_overlay'];patch = ROOT / pin['path'];old_bsd = STORAGE_OUT / 'IOKitBSDInit.cpp'
    require(sha(patch) == pin['sha256'] and sha(old_bsd) == pin['base_source_sha256'], 'AES source overlay changed')
    bsd = OUT / 'IOKitBSDInit.cpp';bsd.write_bytes(old_bsd.read_bytes())
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)], cwd=OUT, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(bsd) == pin['output_source_sha256'],
        'AES source hook did not apply exactly')
    recipe = json.loads((OBJDIR / 'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json').read_text().strip().rstrip(','))
    command, index = [], 0
    while index < len(recipe['arguments']):
        value = recipe['arguments'][index]
        if value == recipe['file']:command.append(str(bsd))
        elif value in ('-o', '-MF', '-MJ'):index += 1
        elif value not in ('-MD', '-MP'):command.append(value)
        index += 1
    bsd_obj = OUT / 'IOKitBSDInit.aes.cpo';run([*command, '-o', bsd_obj], OUT / 'bsd-compile.log', recipe['directory'])
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_arg, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = (OWNER_OUT / 'native.filelist').read_text().splitlines();old_obj = str(STORAGE_OUT / 'IOKitBSDInit.qemu.cpo')
    require(rows.count(old_obj) == 1, 'Ambiguous AES IOBSD replacement')
    filelist = OUT / 'native.filelist';filelist.write_text(''.join((str(bsd_obj) if row == old_obj else row) + '\n' for row in rows))
    command[command.index(old_arg)] = '-Wl,-filelist,' + str(filelist)
    native = OUT / 'mach.aes'
    command += ['-Wl,-force_load,' + str(OWNER_OUT / 'libDodgeQemuOwnerRoot.a'), '-Wl,-force_load,' + str(archive), '-o', str(native)]
    run(command, OUT / 'link.log', OBJDIR)
    data = native.read_bytes();facts = readback(data, methods, abi)
    names = {row['name']: row for row in symbols(data) if not row['kind'] & 0xe0}
    source = {**base, 'actual_crypto_hooks': hook_readbacks(data), 'actual_iobsd_hook': hook_readback(data),
        'actual_init_hook': init_hook_readback(data),
        'combined_original_bindings': {**base['combined_original_bindings'], **abi['bindings']},
        'combined_native_entries': {name: hex(names[name]['value']) for name in [*base['combined_native_entries'],
            '_native_owner_root_checkpoint', '_native_owner_root_accepted_checkpoint', '_native_virtio_read_checkpoint',
            '_native_verified_block_root_authorized', '_dodge_qemu_aes_start', '_dodge_qemu_aes_checkpoint', '_dodge_aes_allocate']}}
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots'];original_raw = ORIGINAL.read_bytes()
    base_context = original_context(original_raw, roots, config)
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE])
    context = original_context(original_raw, [*roots, MODULE], config)
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    security_path = OUT / 'security-init.json';security_path.write_text(json.dumps(security, indent=2) + '\n')
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in [*roots, MODULE]:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', security_path]
        process = subprocess.run(command, env=env, capture_output=True, text=True);(OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'AES prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and record['native_sha256'] == sha(native) and
        record['original_sha256'] == hashlib.sha256(original_raw).hexdigest(), 'AES prelink inputs changed')
    checked = validate_extension(raw, record, data, original_raw, context, base_context, config, source, security)
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    require(readback(candidate.read_bytes(), methods, abi) == facts, 'AES prelink changed original bindings')
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    files = [Path(__file__), *cpp, reference / 'NativeAES.cpp', reference / 'OriginalAESABI.h', reference / 'LICENSE',
        ROOT / 'scripts/build_qemu_exec.py', ROOT / 'scripts/prepare_ios16_pmgr.py', patch, bsd]
    artifacts = [obj, lifecycle, late, bindings, archive, bsd_obj, filelist, native, candidate, emission, security_path,
        OUT / 'compile-commands.json']
    if args.negative_kat:artifacts += [include / 'NativeAES.cpp', include / 'OriginalAESABI.h']
    report = {'result': 'IOS16_QEMU_SOFTWARE_AES_KERNEL_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'dependency_report_sha256': {str(OWNER_REPORT.relative_to(ROOT)): sha(OWNER_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'source_reference': lock['software_aes_reference'], 'abi': abi, 'candidate': str(candidate.relative_to(ROOT)),
        'candidate_sha256': sha(candidate), 'concrete_methods': methods, 'class_readback': facts,
        'negative_kat': args.negative_kat, 'security_start_readback': security_readback, **checked, 'hardware_tested': False,
        'scope': 'Separate iPhone QEMU fixture with SoftwareAES and original 20H392 constructor, destructor, metadata and inherited methods. '
                 'All 181 concrete slots and 64,635 prelink pointers are read back. The class initializes only after its original parent loads. '
                 'Original component instructions remain unchanged. CBC known answers and service registration require runtime checks.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: iPhone 288-byte / 181-slot AES, original bindings and strict 29-component QEMU kernel')


if __name__ == '__main__':main()
