#!/usr/bin/env python3
"""Derive standalone A830 board inputs from the pinned CPH2653 runtime FDT."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

from native_driver_build import ROOT, pinned_sources, require, sha

sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu.devicetree import read_fdt, registers

INPUTS = ROOT / 'hardware/dodge-native-a830.json'
FIRMWARE = ROOT / 'hardware/dodge-gpu-firmware.json'
FILES = ('gen80000_gmu.bin', 'gen80000_sqe.fw', 'gen80000_aqe.fw', 'gen80000_zap.mbn')


def level_recipe(source):
    path = source / 'scripts/gen-sm8750-gpu-levels.py'
    spec = importlib.util.spec_from_file_location('native_a830_levels', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def extract(path, source):
    pin = json.loads((ROOT / 'hardware/dodge-gpu.json').read_text())['captured_dtb_sha256']
    require(sha(path) == pin, 'Native A830 requires the pinned CPH2653 runtime DTB')
    recipe, script = level_recipe(source)
    raw = path.read_bytes()
    parsed = recipe.parse(recipe.decompile(raw))
    # Linux dtc can emit an entire string list as one NUL-separated literal.
    for n in parsed.walk():
        for key, values in n.props.items():
            n.props[key] = [(kind, part) for kind, value in values
                            for part in (value.split('\0') if kind == 'str' else [value])]
    data = recipe.extract(parsed)
    nodes = list(read_fdt(raw).walk())
    handles = {n.scalar('phandle'): n for n in nodes if 'phandle' in n.properties}

    def node(name):
        found = [n for n in nodes if n.name == name]
        require(len(found) == 1, 'Ambiguous or missing CPH2653 node: ' + name)
        return found[0]

    def named_ranges(n):
        names, ranges = n.strings('reg-names'), registers(n)
        require(len(names) == len(ranges) and len(set(names)) == len(names), 'Invalid named register ranges')
        return dict(zip(names, ranges))

    def irqs(n):
        cells = n.cells('interrupts')
        require(cells and len(cells) % 3 == 0, 'Expected GIC interrupt triples')
        triples = [cells[i:i + 3] for i in range(0, len(cells), 3)]
        require(all(t[0] == 0 and t[2] in (1, 4) and t[1] < 988 for t in triples), 'Unsupported GIC SPI')
        return [t[1] + 32 for t in triples]

    gpu, gmu, smmu = (node(n) for n in ('qcom,kgsl-3d0@3d00000', 'qcom,gmu@3d37000', 'kgsl-smmu@3da0000'))
    gr, mr = named_ranges(gpu), named_ranges(gmu)
    windows = {name: gr[key] for name, key in (('gpu', 'kgsl_3d0_reg_memory'), ('rscc', 'rscc'),
               ('cx_dbgc', 'cx_dbgc'), ('cx_misc', 'cx_misc'))}
    windows.update(gmu=mr['gmu'], gmu_ao=mr['gmu_ao_blk_dec0'], smmu=registers(smmu)[0],
                   gpucc=registers(node('clock-controller@3d90000'))[0],
                   gcc=registers(node('clock-controller@100000'))[0],
                   cmd_db=registers(node('aop_cmd_db_region@81c60000'))[0],
                   smem=registers(node('smem_region@81d00000'))[0],
                   zap=registers(handles[node('zap-shader').scalar('memory-region')])[0],
                   qfprom=(data['speed_bin']['qfprom'], data['speed_bin']['qfprom_bytes']),
                   rsc_drv2=named_ranges(node('rsc@16500000'))['drv-2'],
                   aoss_msgram=registers(node('power-controller@c300000'))[0],
                   ipcc=registers(node('qcom,ipcc@406000'))[0])
    sensors = [node('gpuss-' + str(i)).cells('thermal-sensors') for i in range(8)]
    require(all(len(row) == 2 and row[0] == sensors[0][0] and row[1] == i + 1
                for i, row in enumerate(sensors)), 'GPU TSENS sensors differ from the driver layout')
    tsens = handles[sensors[0][0]]
    require(tsens.name == 'tsens2@c22a000', 'Unexpected GPU temperature controller')
    windows['tsens_tm'] = registers(tsens)[0]
    llcc = node('cache-controller@24800000')
    require(llcc.strings('reg-names') == ['llcc0_base', 'llcc1_base', 'llcc2_base', 'llcc3_base',
                'llcc_broadcast_or_base', 'llcc_broadcast_and_base'], 'LLCC window order changed')
    streams = {}
    for name, n in (('gpu', node('gfx3d_user')), ('lpac', node('gfx3d_lpac')), ('gmu', gmu)):
        controller, sid, flags = n.cells('iommus')
        require(handles[controller] is smmu and flags == 0, 'Unexpected GPU IOMMU controller or flags')
        streams[name] = sid
    actlr = smmu.cells('qcom,actlr')
    require(actlr[:2] == [0, 0x3ff] and len(actlr) == 3, 'Unsupported SMMU ACTLR match declaration')
    gpu_irqs, gmu_irqs, smmu_irqs = irqs(gpu), irqs(gmu), irqs(smmu)
    require(len(gpu_irqs) == len(gmu_irqs) == 2 and smmu.scalar('#global-interrupts') == 1,
            'GPU/GMU interrupt or SMMU bank layout changed')
    require(len(data['gpu']['bins']) == 6 and data['speed_bin']['shift'] == 0 and
            len(data['gpu']['cnoc']) == len(data['gmu']) == 2 and len(registers(llcc)) == 6,
            'Unsupported power-bin count or shifted speed-bin fuse')
    return json.loads(json.dumps({
        'device': 'OnePlus 13 CPH2653 / dodge / SM8750', 'captured_dtb_sha256': pin,
        'level_parser_sha256': sha(script), 'windows': windows, 'llcc': registers(llcc),
        'chip_id': gpu.scalar('qcom,chipid'), 'allowed_soc_ids': data['soc_ids'],
        'irqs': dict(gpu=gpu_irqs[0], cx_host=gpu_irqs[1], hfi=gmu_irqs[0], gmu=gmu_irqs[1],
                     smmu_global=smmu_irqs[0], smmu_cb=smmu_irqs[1:5], scm_waitq=data['scm_waitq']['intid']),
        'sids': streams, 'smmu_actlr_dt': actlr[2], 'speed_bin': data['speed_bin'],
        'gpu': data['gpu'], 'gmu': data['gmu'],
        'common_level_count': len(recipe.common_levels(data['gpu']['bins'])),
        'ubwc_mode': gpu.scalar('qcom,ubwc-mode'), 'min_access_length': gpu.scalar('qcom,min-access-length'),
        'thermal_sensors': [row[1] for row in sensors],
        'policy': {'slots': [0, 3, 1], 'context_banks': [0, 2], 'pool_mib': 512, 'highest_bank_bit': 16},
        'scope': 'DT declarations and explicit allocation policy. Live SoC/SKU/fuse, ACTLR readback, '
                 'power, thermal calibration and GPU execution require runtime validation.'}))


def render(data):
    lines = ['/* SPDX-License-Identifier: MIT */',
             '/* Generated from CPH2653 DT declarations and the recorded allocation policy. */',
             '#pragma once', 'namespace {']
    for i, group in enumerate(data['gpu']['bins']):
        lines.append(f'static const Adreno830Level dodgeA830Bin{i}[]={{')
        for row in group['levels']:
            values = [row[key] for key in ('khz', 'vlvl', 'bus_min', 'bus', 'bus_max')] + [0, row['acd']]
            lines.append('    {' + ','.join(f'{v}u' for v in values) + '},')
        lines.append('};')
    lines += ['static const uint32_t dodgeA830Ddr[]={' + ','.join(f'{v}u' for v in data['gpu']['ddr_kbps']) + '};',
              'static bool dodgeA830Soc(uint32_t soc) {return ' +
              ' || '.join(f'soc=={v}u' for v in data['allowed_soc_ids']) + ';}',
              'static void dodgeA830Hardware(Adreno830Board *b) {',
              '    b->magic=Adreno830BoardMagic;b->version=Adreno830BoardVersion;']
    for name, (phys, size) in data['windows'].items():
        lines.append(f'    b->{name}={{{phys:#x}ull,{size:#x}ull}};')
    for i, (phys, size) in enumerate(data['llcc']):
        lines.append(f'    b->llcc[{i}]={{{phys:#x}ull,{size:#x}ull}};')
    lines.append(f'    b->chip_id={data["chip_id"]:#x}u;')
    for name, value in data['irqs'].items():
        if name == 'smmu_cb':
            lines += [f'    b->irq_smmu_cb[{i}]={v}u;' for i, v in enumerate(value)]
        else:
            lines.append(f'    b->irq_{name}={value}u;')
    lines += [f'    b->sid_{name}={value}u;' for name, value in data['sids'].items()]
    for name, value in zip(('gpu', 'lpac', 'gmu'), data['policy']['slots']):
        lines.append(f'    b->slot_{name}={value}u;')
    for name, value in zip(('gpu', 'gmu'), data['policy']['context_banks']):
        lines.append(f'    b->cb_{name}={value}u;')
    values = {'smmu_actlr': data['smmu_actlr_dt'], 'pool_mib': data['policy']['pool_mib'],
              'qfprom_speedbin_offset': data['speed_bin']['offset'], 'speedbin_bits': data['speed_bin']['bits'],
              'common_level_count': data['common_level_count'], 'ubwc_mode': data['ubwc_mode'],
              'min_access_length': data['min_access_length'], 'highest_bank_bit': data['policy']['highest_bank_bit']}
    lines += [f'    b->{name}={value}u;' for name, value in values.items()]
    for i, group in enumerate(data['gpu']['bins']):
        lines += [f'    b->levels[{i}]=dodgeA830Bin{i};b->level_count[{i}]={len(group["levels"])}u;',
                  f'    b->initial_level[{i}]={group["initial"]}u;b->bin_speed[{i}]={group["speed_bin"] or 0}u;']
        skus = group['sku_codes'] or []
        lines.append(f'    b->bin_sku_count[{i}]={len(skus)}u;')
        lines += [f'    b->bin_sku[{i}][{k}]={sku}u;' for k, sku in enumerate(skus)]
    lines += ['    b->ddr_kbps=dodgeA830Ddr;b->ddr_levels=sizeof dodgeA830Ddr/sizeof *dodgeA830Ddr;']
    for i, value in enumerate(data['gpu']['cnoc']):
        lines.append(f'    b->cnoc_levels[{i}]={value}u;')
    for i, row in enumerate(data['gmu']):
        lines.append(f'    b->gmu_khz[{i}]={row["khz"]}u;b->gmu_vlvl[{i}]={row["vlvl"]}u;')
    lines += ['}', '}']
    return '\n'.join(lines) + '\n'


def prepare(out):
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    spec = lock['native_a830_board_inputs']
    require(sha(INPUTS) == spec['sha256'], 'Native A830 board inputs changed after review')
    require(sha(FIRMWARE) == lock['oneplus13_gpu_firmware']['sha256'], 'GPU firmware pins changed')
    data = json.loads(INPUTS.read_text())
    firmware = json.loads(FIRMWARE.read_text())['firmware']['files']
    out.mkdir(parents=True, exist_ok=True)
    header = out / 'DodgeNativeA830Inputs.inc'
    header.write_text(render(data))
    pins = out / 'DodgeNativeA830FirmwarePins.inc'
    lines = ['/* Generated from hardware/dodge-gpu-firmware.json. */',
             'const NativeAdrenoFirmwarePin pins[NativeAdrenoFirmwareCount]={']
    for i, name in enumerate(FILES):
        pin = firmware[name]
        digest = ','.join(f'0x{byte:02x}' for byte in bytes.fromhex(pin['sha256']))
        lines.append(f'    {{"{name}",{pin["bytes"]}u,{{{digest}}},{4 if i in (1, 2) else 0}u}},')
    lines.append('};')
    pins.write_text('\n'.join(lines) + '\n')
    return data, [header, pins]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtb', type=Path)
    parser.add_argument('--record', action='store_true', help='record inputs from the pinned local DTB')
    args = parser.parse_args()
    source = pinned_sources(('native_a830_reference',))['native_a830_reference']
    path = args.dtb
    if path is None:
        capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
        path = Path(capture['source_directory']) / 'device-tree.dtb'
    data = extract(path, source)
    if args.record:
        INPUTS.write_text(json.dumps(data, indent=2) + '\n')
    else:
        require(data == json.loads(INPUTS.read_text()), 'Recorded native A830 inputs differ from captured hardware')
        prepare(ROOT / 'build/cph2653-native-a830-board/generated')
    print('PASS: CPH2653 native A830 windows, IRQs, streams, six bins, ACD and eight GPU sensors')


if __name__ == '__main__':
    main()
