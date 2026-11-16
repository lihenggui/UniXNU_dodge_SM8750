#!/usr/bin/env python3
"""Build the six-rail dodge WLAN transport source for Darwin 22, without a foreign wireless ABI."""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from check_gpu_link import run
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols
from prepare_dodge_wifi import CONTRACT, HARDWARE, blob, derive, reference

OUT = ROOT / 'build/cph2653-wifi-transport'
REPORT = ROOT / 'reports/ios16-wifi-transport.json'
C_SOURCES = ('MhiBoot.c', 'WifiFat.c', 'WifiFirmware.c', 'WifiDma.c', 'WifiPmic.c', 'WifiMhiLoad.c', 'WifiRddm.c')
HEADERS = ('PaganiWifiTables.h', 'WifiBringup.h', 'WifiFirmware.h', 'WifiFat.h', 'FatVolume.h', 'FatVolume.c',
    'WifiDma.h', 'WifiPmic.h', 'WifiMhiLoad.h', 'MhiBoot.h', 'WifiUtil.h', 'WifiRddm.h')
TESTS = {'mhi_boot': ('MhiBoot.c',), 'mhi_load': ('WifiMhiLoad.c', 'MhiBoot.c', 'WifiDma.c'),
    'dma': ('WifiDma.c',), 'pmic': ('WifiPmic.c',), 'rddm': ('WifiRddm.c',)}


def stage(directory):
    repo, spec = reference();require(sha(ROOT / spec['patch']) == spec['patch_sha256'], 'WLAN source patch changed')
    names = [*C_SOURCES, *HEADERS, 'WifiBringup.cpp', 'Test/bringup.cpp', 'Test/check-pagani-wifi-host.py',
        'Test/firmware.c', *['Test/' + name + '.c' for name in TESTS]]
    inventory = {}
    for name in sorted(set(names)):
        path = directory / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(blob(repo, spec, name))
        inventory[name] = sha(path)
    for name, digest in spec['before_sha256'].items():require(inventory[name] == digest, 'WLAN reference source changed: ' + name)
    result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', ROOT / spec['patch']],
        cwd=directory, capture_output=True, text=True)
    require(not result.returncode and 'offset' not in result.stdout.lower(), 'WLAN six-rail patch is not exact')
    for name, digest in spec['after_sha256'].items():require(sha(directory / name) == digest, 'WLAN source patch readback differs: ' + name)
    return inventory, spec


def check_tables(directory, facts):
    text = (directory / 'PaganiWifiTables.h').read_text()
    sequence = text.split('constexpr Write kSequence[] = {', 1)[1].split('};', 1)[0]
    pairs = re.findall(r'\{\s*(0x[\da-fA-F]+|\d+)\s*,\s*(0x[\da-fA-F]+|\d+)\s*\}', sequence)
    values = [value for a, b in pairs for value in (int(a, 0), int(b, 0), 0)]
    require(len(pairs) == facts['phy_writes'] == 128 and hashlib.sha256(struct.pack('>384I', *values)).hexdigest() ==
        facts['phy_sequence_sha256'], 'Compiled WLAN PHY sequence differs from captured dodge')
    rail_block = text.split('constexpr Rail kRails[] = {', 1)[1].split('};', 1)[0]
    rails = re.findall(r'\{"(vdd-wlan-[^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*0x[\da-fA-F]+,\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),', rail_block)
    require(len(rails) == len(facts['rails']) == 6 and 'ant-share' not in rail_block, 'Unsafe donor antenna-share rail survived')
    for row, expected in zip(rails, facts['rails']):
        name, resource, regulator, low, high, chosen, load = row
        require((name, resource, regulator, int(low), int(high), int(load)) ==
            tuple(expected[key] for key in ('supply', 'resource', 'regulator', 'minimum_mv', 'maximum_mv', 'load_ma')) and
            int(chosen) == expected['minimum_mv'], 'WLAN rail does not match captured dodge: ' + name)
    require(facts['gpio'] == {'wlan_en': 16, 'sw_ctrl': 18, 'wlan_sw_ctrl': 19, 'host_sol': 202,
        'dev_sol': 203, 'perst': 102, 'wake': 104, 'clkreq': 103}, 'Compiled WLAN pin selection differs')
    pin_block = text.split('constexpr Pin kPins[] = {', 1)[1].split('};', 1)[0]
    pins = {name: int(gpio) for name, gpio in re.findall(r'\{"([^"]+)",\s*(\d+),', pin_block)}
    require(all(pins.get(name) == gpio for name, gpio in facts['gpio'].items()), 'WLAN source GPIOs differ from the capture')
    windows = text.split('constexpr Window kPcie0Windows[] = {', 1)[1].split('};', 1)[0]
    parsed = {name: (int(address, 0), int(size, 0)) for name, address, size in
        re.findall(r'\{"([^"]+)",\s*(0x[\da-fA-F]+),\s*(0x[\da-fA-F]+),', windows)}
    aliases = {'dm_core': 'dbi', 'iatu': 'atu', 'conf': 'config'}
    for region in facts['registers']:
        require(parsed.get(aliases.get(region['name'], region['name'])) == (int(region['physical'], 16), region['bytes']),
            'WLAN source register window differs: ' + region['name'])


def host_checks(directory, output):
    compiler = shutil.which('clang-14') or shutil.which('clang');cxx = shutil.which('clang++-14') or shutil.which('clang++')
    require(compiler and cxx, 'Need Clang with sanitizers')
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
    def compile_one(row):
        name, sources = row;binary = output / name
        run([compiler, '-std=c11', *flags, directory / 'Test' / (name + '.c'),
            *[directory / source for source in sources], '-o', binary], output / (name + '.compile.log'))
        arguments = [binary, output / 'synthetic-rddm.bin'] if name == 'rddm' else [binary]
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
        log = output / (name + '.log');log.write_text(result.stdout + result.stderr)
        require(not result.returncode and result.stdout.strip().splitlines()[-1].startswith('PASS'), 'WLAN protocol check failed: ' + name)
        return name, result.stdout.strip().splitlines()[-1], binary, log
    rows = {};artifacts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for name, line, binary, log in pool.map(compile_one, TESTS.items()):rows[name] = line;artifacts += [binary, log]
    include = output / 'WifiBringupChecks.inc'
    # Relative includes in the unchanged fixture resolve to its staged parent.
    include.write_text((directory / 'Test/bringup.cpp').read_text().replace('"../WifiBringup.h"', '"WifiBringup.h"')
        .replace('"../WifiUtil.h"', '"WifiUtil.h"'))
    source = ROOT / 'drivers/DodgeWifi/DodgeWifi.cpp';test = ROOT / 'tests/DodgeWifiTransportTest.cpp';binary = output / 'dodge-board'
    run([cxx, '-std=c++17', *flags, '-I', directory, '-I', output, '-I', source.parent,
        test, source, directory / 'WifiBringup.cpp', '-o', binary], output / 'board.compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=60)
    log = output / 'board.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.strip().splitlines()[-1].startswith('PASS dodge'), 'dodge WLAN sequence checks failed')
    rows['board'] = result.stdout.strip().splitlines()[-1];artifacts += [include, binary, log]
    cache = output / 'cache-release';cache_source = source.with_name('DodgeWifiFirmware.c')
    run([compiler, '-std=c11', *flags, '-I', directory, '-I', source.parent,
        ROOT / 'tests/DodgeWifiFirmwareTest.c', cache_source, '-o', cache], output / 'cache.compile.log')
    result = subprocess.run([cache], capture_output=True, text=True, timeout=30)
    cache_log = output / 'cache.log';cache_log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'WLAN firmware cache teardown checks failed')
    rows['cache_release'] = result.stdout.strip();artifacts += [cache, cache_log]
    # Exercise the actual firmware/FAT source with public synthetic bytes only.
    spec = importlib.util.spec_from_file_location('dodge_wifi_firmware_checks', directory / 'Test/check-pagani-wifi-host.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.CFLAGS += ['-fno-pie', '-no-pie', '-I', str(source.parent), '-I', str(directory)]
    original_build = module.build
    def build_firmware(out, name, sources, **options):
        return original_build(out, name, [*sources, cache_source], **options)
    module.build = build_firmware
    with tempfile.TemporaryDirectory(prefix='synthetic-firmware-', dir=output) as temporary:
        module.test_firmware(output, Path(temporary))
    artifacts.append(output / 'firmware');rows['firmware'] = 'PASS actual FAT16/FAT32 and seed firmware lookup with synthetic files'
    return rows, artifacts


def check_report(report):
    require(report['result'] == 'IOS16_DODGE_WIFI_TRANSPORT_SOURCE_PASS' and report['supply_count'] == 6 and
        report['phy_writes_match_capture'] == 128 and len(report['host_checks']) == 8 and
        not report['hardware_tested'] and not report['iPad_binary_bindings_used'] and not report['network_service_published'],
        'Incomplete dodge WLAN source checks')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'WLAN source/artifact changed: ' + name)


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--host-only', action='store_true');args = parser.parse_args()
    if args.host_only:OUT = OUT.with_name(OUT.name + '-host');REPORT = REPORT.with_name(REPORT.stem + '-host.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: captured six-rail WLAN source and actual protocol/MMIO-model checks');return
    facts = json.loads(HARDWARE.read_text())
    if not args.host_only:require(derive() == facts, 'Captured WLAN inputs changed')
    OUT.mkdir(parents=True, exist_ok=True);directory = OUT / 'source';inventory, spec = stage(directory);check_tables(directory, facts)
    host = OUT / 'host';host.mkdir(exist_ok=True);checks, artifacts = host_checks(directory, host)
    native = {}
    if not args.host_only:
        objects = build_objects([*[directory / name for name in C_SOURCES], directory / 'WifiBringup.cpp',
            ROOT / 'drivers/DodgeWifi/DodgeWifiFirmware.c', ROOT / 'drivers/DodgeWifi/DodgeWifi.cpp'],
            OUT / 'native', [directory, ROOT / 'drivers/DodgeWifi'])
        for obj in objects:
            require(not any(section['name'] == '__mod_init_func' and section['size']
                for segment in inspect_object(obj.read_bytes())['segments'] for section in segment['sections']), 'WLAN transport has an early initializer')
        archive = OUT / 'libDodgeWifiTransport.a';archive.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, *objects], check=True)
        require(any(row['name'] == '_dodge_wifi_prepare' and row['kind'] & 14 == 14 for row in symbols(objects[-1].read_bytes())),
            'Native dodge WLAN entry missing')
        native = {'archive': str(archive.relative_to(ROOT)), 'native_objects': len(objects)}
        artifacts += [*objects, archive, OUT / 'native/compile-commands.json']
    files = [Path(__file__), ROOT / 'scripts/prepare_dodge_wifi.py', CONTRACT, HARDWARE, ROOT / spec['patch'],
        *[ROOT / 'drivers/DodgeWifi' / name for name in ('DodgeWifi.cpp', 'DodgeWifi.h', 'DodgeWifiFirmware.c', 'DodgeWifiFirmware.h')],
        ROOT / 'tests/DodgeWifiTransportTest.cpp', ROOT / 'tests/DodgeWifiFirmwareTest.c',
        *[directory / name for name in inventory]]
    report = {'result': 'IOS16_DODGE_WIFI_TRANSPORT_SOURCE_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in files},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'reference': {'repository': spec['repository'], 'revision': spec['revision'], 'original_files_sha256': inventory},
        'supply_count': 6, 'phy_writes_match_capture': 128, 'host_checks': checks, **native,
        'iPad_binary_bindings_used': False, 'network_service_published': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Portable source stages survey/power/link for the captured CPH2653 PCIe0/peach selection; '
        'the unsupported donor antenna-share supply is removed. The exact 128-write PHY sequence and six rail configurations '
        'match the capture. Actual MHI, allocator, PMIC, RDDM, FAT/firmware and bring-up sources run with synthetic peers. '
        'A separate explicit cache release API validates ownership and clears buffers after consumers stop; synthetic firmware '
        'fixtures now release their caches before reinitialization and exit. Native objects use the pinned Darwin 22 compiler records. '
        'Kernel registry/worker, DMA/SMMU ownership, real firmware, '
        'MSI and iPhone wireless-framework ABI integration remain open. No foreign wireless frontend or binary binding is imported.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: six-rail dodge WLAN transport source and eight protocol/sequence/lifetime check suites')


if __name__ == '__main__':main()
