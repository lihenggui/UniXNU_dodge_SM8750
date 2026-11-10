#!/usr/bin/env python3
"""Compare a pinned 13T reference with the captured dodge DTB, without device IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu.devicetree import read_fdt, registers, number


def require(condition, message):
    if not condition:
        raise ValueError(message)


def node_path(node):
    return '/' if node.parent is None else node_path(node.parent).rstrip('/') + '/' + node.name


def find(root, name):
    result, = [n for n in root.walk() if n.name == name]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dtb', type=Path, help='Existing captured CPH2653 DTB; never fetched from the phone')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    reference = ROOT / lock['oneplus13t_reference']['path']
    for name in ('oneplus13t_reference', 'pagani_reference', 'sm8750'):
        spec = lock[name]
        actual = subprocess.check_output(['git', '-C', str(ROOT / spec['path']), 'rev-parse', 'HEAD'], text=True).strip()
        require(actual == spec['revision'], 'Reference source revision mismatch: ' + name)
    paths = ('AGENTS.md', 'README.md', 'board.toml', 'porting.toml', 'dts/oneplus13t.dts',
             'package/PaganiPeripherals.h', 'scripts/test-peripherals.py')
    hashes = {}
    for name in paths:
        blob = (reference / name).read_bytes()
        pinned = subprocess.check_output(['git', '-C', str(reference), 'show', 'HEAD:' + name])
        require(blob == pinned, 'Reference file changed after pinning: ' + name)
        hashes[name] = hashlib.sha256(blob).hexdigest()
    hardware = json.loads((ROOT / 'hardware/cph2653.json').read_text())
    dtb = args.dtb
    if dtb is None:
        capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
        dtb = Path(capture['source_directory']) / 'device-tree.dtb'
    data = dtb.read_bytes()
    expected = 'f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11'
    require(hashlib.sha256(data).hexdigest() == expected, 'Captured OnePlus 13 DTB hash mismatch')
    target = read_fdt(data)
    handles = {n.scalar('phandle'): n for n in target.walk() if 'phandle' in n.properties}
    touch = find(target, 'synaptics_tcm_hbp@0')
    require(touch.enabled() and touch.strings('compatible') == ['synaptics,tcm-spi-hbp'], 'Target HBP node changed')
    se, wrapper = touch.parent, touch.parent.parent
    iommu = wrapper.cells('iommus')
    require(len(iommu) == 3 and handles[iommu[0]].scalar('#iommu-cells') == 2, 'Unsupported QUP IOMMU binding')
    reset, attn, avdd = (touch.cells(key) for key in ('synaptics,reset-gpio', 'synaptics,irq-gpio', 'synaptics,avdd-gpio'))
    require(len(reset) == len(attn) == len(avdd) == 3, 'Unsupported target GPIO binding')
    supply = handles[touch.scalar('vdd-supply')]
    pin_states = []
    for phandle in se.cells('pinctrl-0') + touch.cells('pinctrl-0'):
        state = handles[phandle]
        mux = find(state, 'mux')
        config = find(state, 'config')
        pin_states.append({'pins': mux.strings('pins'), 'function': mux.strings('function'),
                           'drive_ma': config.scalar('drive-strength')})
    facts = {
        'device': 'OnePlus 13 CPH2653 / dodge', 'captured_dtb_sha256': expected,
        'touch': {'chip': 'S3910', 'stock_protocol': 'HBP', 'firmware_name': touch.strings('firmware_name'),
                  'se_base': hex(registers(se)[0][0]), 'se_bytes': registers(se)[0][1],
                  'wrapper_base': hex(registers(wrapper)[0][0]),
                  'smmu_base': hex(registers(handles[iommu[0]])[0][0]), 'stream_id': hex(iommu[1]),
                  'max_spi_hz': touch.scalar('spi-max-frequency'),
                  'reset_gpio': reset[1], 'reset_flags': hex(reset[2]),
                  'attn_gpio': attn[1], 'attn_flags': hex(attn[2]),
                  'pin_states': pin_states, 'advertised_panel_coordinates': touch.cells('touchpanel,panel-coords'),
                  'vdd': {'path': node_path(supply), 'name': supply.strings('regulator-name')[0],
                          'min_uv': supply.scalar('regulator-min-microvolt'),
                          'max_uv': supply.scalar('regulator-max-microvolt')},
                  'avdd_gpio': {'controller': node_path(handles[avdd[0]]), 'pin': avdd[1], 'flags': hex(avdd[2])}},
        'panel': hardware['observations']['selected_panel_from_bootargs'],
        'runtime_enabled': False, 'power_sequence_qualified': False, 'iphone_hid_abi_qualified': False,
        'hardware_tested': False,
        'scope': 'Observed board inputs only. GPIO flags and power declarations are preserved, not interpreted as an implemented rail sequence.'}
    header = (reference / 'package/PaganiPeripherals.h').read_text()

    def macro(name):
        value, = re.findall(r'^#define ' + re.escape(name) + r' (0x[0-9a-fA-F]+|[0-9]+)(?:ULL)?$', header, re.M)
        return int(value, 0)

    matched = {
        'touch_se': registers(se)[0][0] == macro('PAGANI_TOUCH_SE'),
        'touch_wrapper': registers(wrapper)[0][0] == macro('PAGANI_TOUCH_WRAPPER'),
        'touch_smmu': registers(handles[iommu[0]])[0][0] == macro('PAGANI_TOUCH_SMMU'),
        'touch_stream': iommu[1] == macro('PAGANI_TOUCH_SMMU_SID'),
        'touch_reset_gpio': reset[1] == macro('PAGANI_TOUCH_RESET'),
        'touch_attn_gpio': attn[1] == macro('PAGANI_TOUCH_ATTN'),
        'touch_spi_limit': touch.scalar('spi-max-frequency') == macro('PAGANI_TOUCH_HZ'),
    }
    with tempfile.TemporaryDirectory(prefix='oneplus13t-reference-', dir=ROOT / 'build') as directory:
        work = Path(directory)
        compiled = work / 'reference.dtb'
        result = subprocess.run(['dtc', '-I', 'dts', '-O', 'dtb', '-i', str(ROOT / lock['sm8750']['path'] / 'dts'),
                                 '-o', str(compiled), str(reference / 'dts/oneplus13t.dts')], capture_output=True, text=True)
        require(result.returncode == 0, result.stderr[-2000:])
        donor = read_fdt(compiled.read_bytes())
        cpu_values = lambda tree: [number(n.cells('reg')) for n in find(tree, 'cpus').children
                                   if n.strings('device_type') == ['cpu']]
        matched['cpu_mpidrs'] = cpu_values(target) == cpu_values(donor)
        matched['architectural_timer_hz'] = find(target, 'timer').scalar('clock-frequency') == find(donor, 'cpus').scalar('timebase-frequency')
        matched['gic_registers'] = registers(find(target, 'interrupt-controller@16000000')) == registers(find(donor, 'interrupt-controller@16000000'))
        matched['ufs_controller'] = registers(find(target, 'ufshc@1d84000'))[0] == registers(find(donor, 'ufs@1d84000'))[0]
        matched['gic_redistributor_stride'] = (number(find(target, 'interrupt-controller@16000000').cells('redistributor-stride'))
                                             == number(find(donor, 'interrupt-controller@16000000').cells('redistributor-stride')))
        matched['gpu_chip_id'] = find(target, 'qcom,kgsl-3d0@3d00000').scalar('qcom,chipid') == find(donor, 'gpu@3d00000').scalar('qcom,chipid')
        tree = work / 'tree'
        for name in ('drivers', 'kits'):
            (tree / name).mkdir(parents=True)
        links = {'drivers/PaganiInput': ROOT / lock['pagani_reference']['path'] / 'drivers/PaganiInput',
                 'drivers/QcomGeniSpi': ROOT / 'sources/UniXNU/drivers/QcomGeniSpi',
                 'kits/Sm8750Platform': ROOT / lock['sm8750']['path'] / 'kits/Sm8750Platform',
                 'kits/oneplus13t': reference / 'package'}
        for name, path in links.items():
            (tree / name).symlink_to(path, target_is_directory=True)
        log = ROOT / 'analysis/oneplus13t-peripherals.log'
        with log.open('w') as stream:
            result = subprocess.run([sys.executable, str(reference / 'scripts/test-peripherals.py'), '--tree', str(tree)],
                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'), stdout=stream, stderr=subprocess.STDOUT)
        require(result.returncode == 0, 'Portable reference tests failed; see analysis/oneplus13t-peripherals.log')
    require(all(matched.values()), 'A presumed shared controller fact differs: ' + repr(matched))
    record = tomllib.loads((reference / 'porting.toml').read_text())
    board = tomllib.loads((reference / 'board.toml').read_text())
    report = {
        'result': 'REFERENCE_COMPARISON_PASS', 'reference_revision': lock['oneplus13t_reference']['revision'],
        'reference_url': lock['oneplus13t_reference']['source_record'],
        'reference_os_profile': board['board']['os_profile'], 'reference_file_sha256': hashes,
        'reference_reported_state': {a['id']: a['status'] for a in record['area']},
        'captured_target_dtb_sha256': expected, 'shared_controller_facts': matched,
        'target_touch_inputs': facts['touch'],
        'separate_board_policy': {
            'touch_power': 'Target declares pm_humu_l4 at 1.8 V and PM8550VS SID9 GPIO3 for AVDD; the 13T LDO16 3.1 V sequence is not selected.',
            'display': 'Target panel is AA569 / 1440x3168 from boot arguments; donor is AA594 with documented 1216x2640 GOP. Actual target GOP is unmeasured.',
            'memory': 'Target runtime DTB and UEFI map own reservations; donor high-RAM base and memory map are not imported.',
            'storage': 'Target GPT/LUN/window geometry must be derived separately; donor unixnu partition LBAs are not imported.',
            'os_abi': 'The reference binds iPadOS 17; iPhone iOS 16 and arm64e iOS 27 require separate binary interfaces.'},
        'portable_peripheral_tests': {'result': 'PASS', 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
            'component_revision': lock['pagani_reference']['revision'], 'reference_board_wiring': True,
            'checks': log.read_text().splitlines(),
            'scope': 'Existing production protocol/register-model tests with reference wiring; no target MMIO, rails or iPhone HID execution.'},
        'target_driver_selected': False, 'hardware_tested': False,
        'scope': 'Reusable source candidates and exact board differences. Donor device observations are not OnePlus 13 qualification.'}
    (ROOT / 'hardware/dodge-peripherals.json').write_text(json.dumps(facts, indent=2) + '\n')
    (ROOT / 'reports/oneplus13t-reference.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(matched)} shared controller facts, target power/pin inputs and portable protocol tests; board/OS adaptation remains separate')


if __name__ == '__main__':
    main()
