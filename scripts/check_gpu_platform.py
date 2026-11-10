#!/usr/bin/env python3
"""Record captured A830 inputs and check pinned software peers without device IO."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from unixnu.devicetree import read_fdt, registers
from native_prelink import backed_offset, macho, unserialize_xml


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def path(node):
    return '/' if node.parent is None else path(node.parent).rstrip('/') + '/' + node.name


def find(tree, name):
    node, = [node for node in tree.walk() if node.name == name]
    return node


def build_native_platform(soc, fw, backend):
    """Compile portable helpers, with the real ARM64 barriers/SMC path enabled."""
    tree = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree'
    objdir = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    recipes = {
        '.c': objdir / 'bsd/DEVELOPMENT/vfs_conf.o.json',
        '.cpp': objdir / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'}
    out = ROOT / 'build/cph2653-gpu-platform'
    out.mkdir(parents=True, exist_ok=True)
    files = [fw / name for name in ('AdrenoFirmware.c', 'AdrenoHfi.c',
             'AdrenoHfiStartup.c', 'AdrenoHfiVotes.c')]
    files += [soc / name for name in ('Sm8750Gmu.c', 'Sm8750GmuCommandDb.c',
              'Sm8750SocInfo.c', 'Sm8750GpuZap.c', 'Sm8750GpuPower.c', 'Sm8750GpuSmmu.c')]
    files.append(backend / 'NativeAdrenoA830HwInit.cpp')
    support = {}
    for name in ('ArmSmmu4K', 'AdrenoPM4'):
        relative = 'kits/' + name
        pin = subprocess.check_output(['git', '-C', str(ROOT / 'sources/UniXNU'),
                                       'ls-tree', 'HEAD', relative], text=True).split()[2]
        directory = ROOT / 'sources/UniXNU' / relative
        head = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == pin, 'Native GPU support header revision mismatch: ' + name)
        require(not subprocess.check_output(['git', '-C', str(directory), 'status', '--porcelain'], text=True),
                'Native GPU support headers contain working changes: ' + name)
        support[name] = head
    objects, commands = [], []
    with (out / 'compile.log').open('w') as stream:
        for source in files:
            recipe = recipes[source.suffix]
            record = json.loads(recipe.read_text().strip().rstrip(','))
            args, command, index = record['arguments'], [], 0
            obj = out / (source.stem + '.o')
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
            command += ['-o', str(obj), '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror']
            # Darwin 22 kernel headers use partially initialized designated
            # aggregates and C array designators in C++ translation units.
            command += ['-Wno-missing-designated-field-initializers', '-Wno-c99-designator']
            if source.suffix == '.c':
                command += ['-std=gnu11']
            for directory in (soc, fw, backend, ROOT / 'sources/UniXNU/kits/ArmSmmu4K',
                              ROOT / 'sources/UniXNU/kits/AdrenoPM4'):
                command += ['-I', str(directory)]
            require(not any('HOST_TEST' in arg for arg in command), 'Host test macro in native GPU build')
            commands.append(command)
            process = subprocess.run(command, cwd=record['directory'], timeout=60,
                                     stdout=stream, stderr=subprocess.STDOUT)
            require(process.returncode == 0, 'Native GPU compile failed; see build/cph2653-gpu-platform/compile.log')
            data = obj.read_bytes()
            image = macho(data)
            require(image['kind'] == 1, 'Native GPU helper is not an ARM64 relocatable object')
            version, = [at for cmd, at, _ in image['commands'] if cmd == 0x32]
            require(struct.unpack_from('<II', data, version + 8) == (2, 0x100000),
                    'Native GPU helper is not targeted at iOS 16.0')
            objects.append(obj)
    archive = out / 'libSm8750GpuPlatform.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', str(archive), *map(str, objects)], check=True)
    (out / 'compile-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    result = {'result': 'PASS', 'target': 'arm64-apple-ios16.0',
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': digest(archive.read_bytes()),
              'object_sha256': {obj.name: digest(obj.read_bytes()) for obj in objects},
              'source_sha256': {str(f.relative_to(ROOT)): digest(f.read_bytes()) for f in files},
              'compiler_recipe_sha256': {str(f.relative_to(tree)): digest(f.read_bytes()) for f in recipes.values()},
              'support_header_revisions': support, 'host_test_macros': False,
              'linked_into_target_kernel': False,
              'scope': 'Eleven native source objects, including A830 hardware-init and ARM64 HFI/SMC paths. '
                       'An independent archive, without IOGPU publication, a Metal frontend or a runnable GPU driver.'}
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtb', type=Path, help='Existing captured CPH2653 DTB; no phone access')
    parser.add_argument('--native-archive', action='store_true',
                        help='Also compile independent GPU platform helpers with the native iOS 16 kernel recipes')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    names = ('sm8750', 'oneplus13t_reference', 'a830_backend_reference',
             'a830_metal_reference', 'a830_firmware_reference')
    sources = {}
    for name in names:
        spec = lock[name]
        source = ROOT / spec['path']
        head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == spec['revision'], 'GPU reference revision mismatch: ' + name)
        require(not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True),
                'GPU reference contains working changes: ' + name)
        sources[name] = source

    hardware = json.loads((ROOT / 'hardware/cph2653.json').read_text())
    dtb = args.dtb
    if dtb is None:
        capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
        dtb = Path(capture['source_directory']) / 'device-tree.dtb'
    raw = dtb.read_bytes()
    require(digest(raw) == hardware['source']['dtb_sha256'], 'Captured target DTB hash mismatch')
    tree = read_fdt(raw)
    gpu = find(tree, 'qcom,kgsl-3d0@3d00000')
    gmu = find(tree, 'qcom,gmu@3d37000')
    smmu = find(tree, 'kgsl-smmu@3da0000')
    require(gpu.scalar('qcom,chipid') == 0x44050001, 'Target is not the reviewed A830v2 revision')
    handles = {n.scalar('phandle'): n for n in tree.walk() if 'phandle' in n.properties}
    windows = {}
    for node in (gpu, gmu, smmu):
        regions = registers(node)
        labels = node.strings('reg-names') if 'reg-names' in node.properties else [None] * len(regions)
        require(len(labels) == len(regions), 'Register names/ranges differ: ' + node.name)
        windows[path(node)] = [{'name': name, 'start': hex(start), 'bytes': size}
                               for name, (start, size) in zip(labels, regions)]

    policies = []
    for node in find(gpu, 'qcom,gpu-pwrlevel-bins').children:
        levels = sorted(node.children, key=lambda child: child.scalar('reg'))
        initial = node.scalar('qcom,initial-pwrlevel')
        require(initial in [n.scalar('reg') for n in levels], 'Initial GPU level is absent')
        policies.append({
            'node': node.name,
            'speed_bin': node.scalar('qcom,speed-bin') if 'qcom,speed-bin' in node.properties else None,
            'sku_codes': node.cells('qcom,sku-codes') if 'qcom,sku-codes' in node.properties else None,
            'initial_index': initial,
            'levels': [[n.scalar(key) for key in ('reg', 'qcom,gpu-freq', 'qcom,level',
                        'qcom,bus-freq', 'qcom,bus-min', 'qcom,bus-max')] for n in levels]})
    require(len(policies) == 6, 'Captured GPU power-bin count changed')
    firmware_verified = False
    firmware_report = ROOT / 'reports/gpu-firmware.json'
    if firmware_report.exists():
        evidence = json.loads(firmware_report.read_text())
        pins = lock['oneplus13_gpu_firmware']
        manifest = ROOT / pins['path']
        firmware_verified = (digest(manifest.read_bytes()) == pins['sha256'] and
            evidence['result'] == 'CPH2653_GPU_FIRMWARE_STATIC_BUILD_PASS' and
            evidence['pin_sha256'] == pins['sha256'] and
            digest((ROOT / evidence['archive']).read_bytes()) == evidence['archive_sha256'])
    inputs = {
        'device': 'OnePlus 13 CPH2653 / dodge / SM8750',
        'captured_dtb_sha256': digest(raw), 'chip_id': hex(gpu.scalar('qcom,chipid')),
        'gpu_model': gpu.strings('qcom,gpu-model')[0], 'compatible': gpu.strings('compatible'),
        'register_windows': windows,
        'interrupt_specifiers': {path(n): n.cells('interrupts') for n in (gpu, gmu, smmu)},
        'gpu_clock_names': gpu.strings('clock-names'),
        'gmu_clock_names': gmu.strings('clock-names'),
        'gmu_power_domain_names': gmu.strings('power-domain-names'),
        'gmu_iommu_specifier': gmu.cells('iommus'),
        'gmu_iommu_controller': path(handles[gmu.cells('iommus')[0]]),
        'level_columns': ['index', 'hz', 'corner_level', 'bus_index', 'bus_min', 'bus_max'],
        'power_bins': policies, 'ddr_bus_table': gpu.cells('qcom,bus-table-ddr'),
        'gmu_frequency_corner_pairs': gmu.cells('qcom,gmu-freq-table'),
        'active_speed_bin': None, 'active_sku': None, 'command_db_rail_tables_available': False,
        'target_firmware_hashes_verified': firmware_verified, 'firmware_validation_report': 'reports/gpu-firmware.json',
        'runtime_selected': False, 'hardware_tested': False,
        'scope': 'Observed target declarations only. Corner levels and bus indices are not voltages. '
                 'The active fused bin, command-db rail mapping, firmware execution and power sequence are unqualified.'}

    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    kc = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    require(digest(kc) == profile['kernel']['prelink']['kernelcache_sha256'], 'Original iPhone KC changed')
    image = macho(kc)
    info, = [s for s in image['segments'] if s['name'] == '__PRELINK_INFO']
    offset = backed_offset(image['segments'], info['va'], info['filesize'], len(kc))
    entries = unserialize_xml(kc[offset:offset + info['filesize']])['_PrelinkInfoDictionary']
    families = ('com.apple.iokit.IOGPUFamily', 'com.apple.iokit.IOSurface',
                'com.apple.iokit.IOMobileGraphicsFamily')
    graphics = {e['CFBundleIdentifier']: {'version': e['CFBundleVersion'],
                'declared_dependencies': e.get('OSBundleLibraries', {})}
                for e in entries if e['CFBundleIdentifier'] in families}
    require(set(graphics) == set(families), 'Original iPhone graphics families are missing')
    by_name = {entry['CFBundleIdentifier']: entry for entry in entries}
    selected, pending = set(), list(profile['kernel']['prelink']['roots'])
    while pending:
        name = pending.pop()
        if name not in selected:
            selected.add(name)
            pending.extend(by_name[name].get('OSBundleLibraries', {}))

    soc = sources['sm8750'] / 'kits/Sm8750Platform'
    fw = sources['a830_firmware_reference']
    board = sources['oneplus13t_reference'] / 'package'
    plans = [
        ('gpu-probe', [soc / 'Test/gpu-probe.c']),
        ('gpu-power', [soc / 'Test/gpu-power.c', soc / 'Sm8750GpuPower.c', fw / 'AdrenoHfiVotes.c']),
        ('gpu-zap', [soc / 'Test/gpu-zap.c', soc / 'Sm8750GpuZap.c']),
        ('socinfo', [soc / 'Test/socinfo.c', soc / 'Sm8750SocInfo.c']),
        ('hfi', [fw / 'test_hfi.c', fw / 'AdrenoHfi.c']),
        ('hfi-startup', [fw / 'test_startup.c', fw / 'AdrenoHfiStartup.c', fw / 'AdrenoHfi.c']),
        ('gen8-votes', [soc / 'Test/gpu-votes.c', soc / 'Sm8750GmuCommandDb.c',
                        soc / 'Sm8750GpuPower.c', board / 'PaganiGpuVotes.c',
                        fw / 'AdrenoHfiVotes.c', fw / 'AdrenoHfiStartup.c', fw / 'AdrenoHfi.c'])]
    log = ROOT / 'analysis/sm8750-gpu-platform-tests.log'
    log.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cph2653-gpu-') as directory, log.open('w') as stream:
        flags = ['cc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-D_POSIX_C_SOURCE=200809L', '-fsanitize=address,undefined', '-DADRENO_HFI_HOST_TEST',
                 '-I', str(soc), '-I', str(fw), '-I', str(board)]
        for name, files in plans:
            binary = Path(directory) / name
            subprocess.run([*flags, *map(str, files), '-o', str(binary)], check=True, timeout=60,
                           stdout=stream, stderr=subprocess.STDOUT)
            subprocess.run([str(binary)], check=True, timeout=30, stdout=stream, stderr=subprocess.STDOUT,
                           env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
            stream.write('PASS: ' + name + '\n')
            stream.flush()

    inspected = {file for _, files in plans for file in files}
    inspected.update(board / file for file in ('PaganiGpuOpps.h', 'PaganiGpuVotes.h'))
    for base in (soc, fw):
        inspected.update(base.glob('*.h'))
    backend = sources['a830_backend_reference']
    inspected.update(backend / name for name in ('NativeAdrenoA830HwInit.cpp', 'README.md'))
    inspected.add(sources['a830_metal_reference'] / 'README.md')
    donor = json.loads((sources['oneplus13t_reference'] / 'scripts/data/sm8750-gpu-inputs.json').read_text())
    report = {
        'result': 'CAPTURED_INPUTS_AND_SOFTWARE_PEERS_PASS', 'device': inputs['device'],
        'chip_id': inputs['chip_id'], 'source_revisions': {n: lock[n]['revision'] for n in names},
        'source_sha256': {str(f.relative_to(ROOT)): digest(f.read_bytes()) for f in sorted(inspected)},
        'captured_inputs': 'hardware/dodge-gpu.json', 'captured_dtb_sha256': digest(raw),
        'observed_power_bin_count': len(policies),
        'iphone_target': 'iPhone10,3 / iOS 16.7.16 / 20H392', 'original_kernelcache_sha256': digest(kc),
        'original_graphics_family_versions': graphics,
        'original_graphics_selected_for_prelink': any(n in selected for n in families),
        'host_suites_passed': [name for name, _ in plans], 'sanitizers': ['address', 'undefined'],
        'host_log_sha256': digest(log.read_bytes()),
        'gen8_votes_test_uses_reference_policy_and_synthetic_command_db': True,
        'reference_firmware_names': sorted(donor['firmware']['files']),
        'reference_firmware_is_target_qualified': False,
        'remaining': [
            'Identify the matching target GMU/SQE/AQE/ZAP files and verify their full hashes.',
            'Resolve target command-db rail tables and active fused bin/SKU; qualify clocks, RPMh and ZAP authentication.',
            'Build the A830 backend against exact iPhone graphics ABI; do not reuse iPadOS 17 binary bindings.',
            'Qualify SMMU/DMA/cache ownership, BO lifetime, fences and fault/reset recovery.',
            'Build matching Turnip/metal2vulkan/Metal userspace and qualify known shader pixels and IOSurface scanout.'],
        'a830_target_backend_built': False, 'metal_frontend_built': False,
        'iphone_graphics_abi_qualified': False, 'selected_in_default_kernel': False,
        'firmware_executed': False, 'mmio_executed': False, 'hardware_tested': False,
        'scope': 'Seven existing production tests with software register/SMC/HFI peers, including '
                 '13T policy with synthetic rail tables. No actual GPU, firmware, shader or iPhone graphics execution.'}
    if args.native_archive:
        report['native_platform_archive'] = build_native_platform(soc, fw, backend)
    (ROOT / 'hardware/dodge-gpu.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (ROOT / 'reports/gpu-adaptation.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: captured A830 inputs, six power-bin declarations, original iPhone graphics versions and '
          'seven sanitized software-peer suites; target driver and runtime remain unqualified')


if __name__ == '__main__':
    main()
