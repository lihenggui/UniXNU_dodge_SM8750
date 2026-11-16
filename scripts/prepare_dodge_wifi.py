#!/usr/bin/env python3
"""Derive OnePlus 13 WLAN/PCIe facts from its already captured device tree."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from compare_oneplus13t import node_path, read_fdt, registers
from native_driver_build import ROOT, require, sha

HARDWARE = ROOT / 'hardware/dodge-wifi.json'
CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/wifi-source.json'
CAPTURE_SHA = 'f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11'


def reference():
    spec = json.loads(CONTRACT.read_text())
    for directory in (ROOT / '.cache/upstream-review/pagani-drivers', ROOT / '.cache/dodge-wifi/reference.git'):
        process = subprocess.run(['git', '-C', directory, 'cat-file', '-e', spec['revision'] + '^{commit}'], capture_output=True)
        if not process.returncode:return directory, spec
    directory = ROOT / '.cache/dodge-wifi/reference.git';directory.mkdir(parents=True, exist_ok=True)
    if not (directory / 'HEAD').exists():subprocess.run(['git', 'init', '--bare', '-q', directory], check=True)
    subprocess.run(['git', '-C', directory, 'fetch', '--depth', '1', spec['repository'], spec['revision']], check=True)
    return directory, spec


def blob(directory, spec, name):
    return subprocess.check_output(['git', '-C', directory, 'show', spec['revision'] + ':' + spec['source_directory'] + '/' + name])


def derive():
    capture = json.loads((ROOT / 'analysis/oneplus13-hardware-info.json').read_text())
    dtb = Path(capture['source_directory']) / 'device-tree.dtb';require(sha(dtb) == CAPTURE_SHA, 'Wrong captured dodge DTB')
    tree = read_fdt(dtb.read_bytes());handles = {n.scalar('phandle'): n for n in tree.walk() if 'phandle' in n.properties}
    wlan, = [n for n in tree.walk() if n.strings('compatible') == ['qcom,cnss-peach']]
    pcie, = [n for n in tree.walk() if n.name == 'pcie@1c00000' and n.strings('compatible') == ['qcom,pci-msm']]
    require(wlan.enabled() and pcie.enabled() and wlan.scalar('qcom,wlan-rc-num') == 0 and wlan.cells('supported-ids') == [0x110e],
        'Captured WLAN/PCI selection differs')
    gpio = {name: wlan.cells(prop)[1] for name, prop in (('wlan_en', 'wlan-en-gpio'), ('sw_ctrl', 'qcom,sw-ctrl-gpio'),
        ('wlan_sw_ctrl', 'qcom,wlan-sw-ctrl-gpio'), ('host_sol', 'wlan-host-sol-gpio'), ('dev_sol', 'wlan-dev-sol-gpio'))}
    gpio.update(perst=pcie.cells('perst-gpio')[1], wake=pcie.cells('wake-gpio')[1])
    clkreq = [n for handle in pcie.cells('pinctrl-0') for n in handles[handle].walk()
        if n.strings('function') == ['pcie0_clk_req_n']]
    require(len(clkreq) == 1 and clkreq[0].strings('pins') == ['gpio103'], 'Captured PCIe CLKREQ selection differs')
    gpio['clkreq'] = 103
    require(gpio == {'wlan_en': 16, 'sw_ctrl': 18, 'wlan_sw_ctrl': 19, 'host_sol': 202, 'dev_sol': 203,
        'perst': 102, 'wake': 104, 'clkreq': 103},
        'Captured WLAN GPIO selection differs')
    require(all(wlan.cells(prop)[0] == pcie.cells('perst-gpio')[0] for prop in
        ('wlan-en-gpio', 'qcom,sw-ctrl-gpio', 'qcom,wlan-sw-ctrl-gpio', 'wlan-host-sol-gpio', 'wlan-dev-sol-gpio')),
        'WLAN GPIOs do not share the expected TLMM controller')
    iommu = pcie.cells('iommu-map')
    require(len(iommu) == 8 and iommu[0] == 0 and iommu[2:5] == [0x1400, 1, 0x100] and iommu[6:] == [0x1401, 1],
        'Captured WLAN IOMMU map differs')
    rail_names = ['io', 'io12', 'aon', 'dig', 'rfa1', 'rfa2'];rails = []
    require(sorted(key for key in wlan.properties if key.endswith('-supply')) ==
        sorted('vdd-wlan-' + name + '-supply' for name in rail_names), 'Unreviewed or missing WLAN supply')
    for name in rail_names:
        supply = 'vdd-wlan-' + name;node = handles[wlan.scalar(supply + '-supply')]
        config = wlan.cells('qcom,' + supply + '-config')
        require(len(config) == 5 and config[-1] == 1 and not config[0] % 1000 and not config[1] % 1000,
            'Unreviewed WLAN regulator configuration')
        rails.append({'supply': supply, 'resource': node.parent.name.removeprefix('rpmh-regulator-'),
            'regulator': node.strings('regulator-name')[0], 'minimum_mv': config[0] // 1000, 'maximum_mv': config[1] // 1000,
            'load_ma': config[2] // 1000})
    phy = pcie.cells('qcom,phy-sequence')
    require(len(phy) == 384 and not any(phy[2::3]), 'Unreviewed WLAN PHY sequence/delays')
    names = pcie.strings('reg-names');regions = registers(pcie)
    require(len(names) == len(regions) == 7, 'Unreviewed PCIe register windows')
    return {'schema_version': 1, 'device': 'OnePlus 13 CPH2653 / dodge / SM8750', 'captured_dtb_sha256': CAPTURE_SHA,
        'wlan_node': node_path(wlan), 'pcie_node': node_path(pcie), 'compatible': 'qcom,cnss-peach', 'supported_pci_device': '17cb:110e',
        'pci_identity_observed_on_hardware': False, 'controller': 0, 'gpio': gpio,
        'registers': [{'name': name, 'physical': hex(address), 'bytes': size} for name, (address, size) in zip(names, regions)],
        'iommu_streams': {'root': hex(iommu[2]), 'endpoint': hex(iommu[6])},
        'phy_writes': 128, 'phy_sequence_sha256': hashlib.sha256(struct.pack('>384I', *phy)).hexdigest(),
        'rails': rails, 'antenna_share_supply_present': False, 'hardware_tested': False,
        'scope': 'Offline captured board facts. PCI identity is the supported DT selection, not a live enumeration. '
        'No MSI delivery, firmware, DMA ownership, interface ABI or working radio is established.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--write', action='store_true');args = parser.parse_args()
    facts = derive()
    if args.write:
        require(not HARDWARE.exists(), 'Refuse to replace reviewed WLAN inputs');HARDWARE.write_text(json.dumps(facts, indent=2) + '\n')
    require(json.loads(HARDWARE.read_text()) == facts, 'Reviewed WLAN facts changed')
    print('PASS: captured PCIe0/peach, six supplies, eight pin selections and 128 PHY writes; no phone operation')


if __name__ == '__main__':main()
