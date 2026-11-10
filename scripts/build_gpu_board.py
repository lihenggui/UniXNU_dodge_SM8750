#!/usr/bin/env python3
"""Build an unselected CPH2653 GPU connection/presenter candidate from captured inputs."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

from native_driver_build import ROOT, archive_imports, build_objects, pinned_sources, require, sha
from optional_gpu_calls import stage_optional_calls
from check_gpu_metal_host import check as check_metal

sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu.devicetree import read_fdt, registers


def main():
    sources = pinned_sources(('oneplus13t_reference', 'pagani_reference', 'a830_backend_reference',
                              'a830_firmware_reference', 'sm8750'))
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
    raw = Path(capture['source_directory']) / 'device-tree.dtb'
    require(sha(raw) == json.loads((ROOT / 'hardware/dodge-gpu.json').read_text())['captured_dtb_sha256'],
            'Captured device tree differs from the reviewed GPU inputs')
    tree = read_fdt(raw.read_bytes())
    nodes = list(tree.walk())

    def node(name):
        result, = [n for n in nodes if n.name == name]
        return result

    handles = {n.scalar('phandle'): n for n in nodes if 'phandle' in n.properties}
    gpu = node('qcom,kgsl-3d0@3d00000')
    cell = handles[gpu.cells('nvmem-cells')[0]]
    require(cell.name == 'gpu_speed_bin@138' and cell.cells('reg') == [0x138, 2] and cell.cells('bits') == [0, 9],
            'Target speed-bin fuse is not the reviewed two-byte/nine-bit field')
    zap = handles[node('zap-shader').scalar('memory-region')]
    rsc = node('rsc@16500000')
    rsc_ranges = dict(zip(rsc.strings('reg-names'), registers(rsc)))
    windows = {'Gcc': registers(node('clock-controller@100000'))[0],
               'GpuCc': registers(node('clock-controller@3d90000'))[0], 'Rsc': rsc_ranges['drv-2'],
               'Qfprom': registers(cell.parent)[0], 'CommandDb': registers(node('aop_cmd_db_region@81c60000'))[0],
               'Smem': registers(node('smem_region@81d00000'))[0], 'Zap': registers(zap)[0],
               'Smmu': registers(node('kgsl-smmu@3da0000'))[0]}
    gpu_ranges = dict(zip(gpu.strings('reg-names'), registers(gpu)))
    windows['CxMisc'] = gpu_ranges['cx_misc']
    # The unchanged shared GMU binder has three windows. Prove that each one
    # corresponds to this target's captured GMU/GPU/RSCC declarations.
    require(registers(node('qcom,gmu@3d37000'))[0] == (0x3d37000, 0x68000) and
            gpu_ranges['rscc'] == (0x3d50000, 0x10000) and
            gpu_ranges['kgsl_3d0_reg_memory'] == (0x3d00000, 0x40000), 'Shared GMU windows differ from target')
    out = ROOT / 'build/cph2653-gpu-board'
    stage = out / 'source'
    stage.mkdir(parents=True, exist_ok=True)
    header = ['/* Generated only from hash-pinned CPH2653 DT declarations. */', '#pragma once',
              '#include <stdint.h>', 'namespace DodgeGpuBoard {']
    contract = {}
    for name, (start, extent) in windows.items():
        require(start % 4096 == 0 and extent > 0, 'Unaligned target resource: ' + name)
        mapped = (extent + 4095) & ~4095
        header += [f'static constexpr uint64_t {name}Base={start:#x};', f'static constexpr uint64_t {name}Bytes={mapped:#x};']
        contract[name] = {'physical': hex(start), 'declared_bytes': extent, 'mapped_bytes': mapped}
    header += ['static constexpr uint32_t SpeedBinOffset=0x138,SpeedBinMask=0x1ff;', '}']
    (stage / 'DodgeGpuBoard.h').write_text('\n'.join(header) + '\n')
    original = sources['oneplus13t_reference'] / 'package/PaganiGpu.cpp'
    source = stage / original.name
    shutil.copyfile(original, source)
    patch = lock['dodge_gpu_board_patch']
    patch_path = ROOT / patch['path']
    require(sha(patch_path) == patch['sha256'] and patch['source_revision'] == lock['oneplus13t_reference']['revision'],
            'Target board overlay changed after review')
    subprocess.run(['git', 'apply', '--check', '--directory=' + str(stage.relative_to(ROOT)), patch_path], cwd=ROOT, check=True)
    subprocess.run(['git', 'apply', '--directory=' + str(stage.relative_to(ROOT)), patch_path], cwd=ROOT, check=True)
    helper = ROOT / 'drivers/DodgeDisplay/DodgeOptionalCalls.h'
    shutil.copyfile(helper, stage / helper.name)
    driver, optional_overlay = stage_optional_calls('presenter', sources['pagani_reference'] / 'drivers/NativeMobileDisplay')
    presenter = driver / 'NativeGOPPresenter.cpp'
    soc = sources['sm8750'] / 'kits/Sm8750Platform'
    includes = (sources['a830_backend_reference'], sources['a830_firmware_reference'], soc, driver,
                sources['pagani_reference'] / 'drivers/BootProgress', ROOT / 'sources/UniXNU/kits/ArmSmmu4K',
                ROOT / 'sources/UniXNU/kits/AdrenoPM4', ROOT / 'build/cph2653-gpu-firmware',
                ROOT / 'build/cph2653-gpu-policy/source', stage)
    objects = build_objects([source, presenter], out, includes, ['-Wno-overloaded-virtual'])
    metal_tests=check_metal(out,source)
    imports = archive_imports(objects)
    archive = out / 'libDodgeGpuConnection.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, *objects], check=True)
    report = {'result': 'CPH2653_GPU_BOARD_SOURCE_CANDIDATE_PASS', 'target': 'arm64-apple-ios16.0',
              'captured_dtb_sha256': sha(raw), 'resource_windows': contract,
              'speed_bin': {'offset': 312, 'cell_bytes': 2, 'bit_shift': 0, 'bit_width': 9, 'observed_value': None},
              'board_reference_revision': lock['oneplus13t_reference']['revision'], 'board_patch': patch,
              'board_source_sha256': sha(source), 'generated_header_sha256': sha(stage / 'DodgeGpuBoard.h'),
              'presenter_reference_revision': lock['pagani_reference']['revision'], 'presenter_sha256': sha(presenter),
              'optional_call_overlay': optional_overlay, 'optional_call_helper_sha256': sha(helper),
              'metal_registration_host_tests':metal_tests,'metal_registration_builder_sha256':sha(ROOT/'scripts/check_gpu_metal_host.py'),
              'metal_registration_init_property_attach_failure_releases_service':True,
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive), 'imports': imports,
              'reference_shared_max_rail_vote_policy_retained': True, 'power_policy_hardware_qualified': False,
              'reference_memory_topology_constants_hardware_qualified': False,
              'default_kernel_selected': False, 'startup_invoked': False, 'hardware_tested': False,
              'scope': 'Real board startup/presenter objects with target MMIO/fuse/ZAP declarations and target firmware/OPP headers. '
                       'Display callbacks, complete original-family lifecycle, resource ownership and physical operation remain unqualified.'}
    (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'reports/gpu-board-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: target GPU board connection and real GOP presenter compile; no startup or hardware access')


if __name__ == '__main__':
    main()
