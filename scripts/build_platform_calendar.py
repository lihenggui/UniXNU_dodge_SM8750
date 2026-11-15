#!/usr/bin/env python3
"""Backport the reviewed platform calendar changes to the pinned Darwin 22 platform."""
import argparse
import json
from pathlib import Path
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, build_objects, inspect_object, require, sha, symbols

OUT = ROOT / 'build/cph2653-platform-calendar'
REPORT = ROOT / 'reports/ios16-platform-calendar.json'
CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/platform-calendar.json'


def check_report(report):
    require(report['result'] == 'IOS16_PLATFORM_CALENDAR_BACKPORT_PASS' and
        report['source_pin_retained'] and not report['hardware_RTC_implemented'] and not report['hardware_tested'] and
        report['host_cases'] > 500, 'Incomplete platform calendar backport')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Platform calendar input changed: ' + name)
    raw = (ROOT / report['object']).read_bytes();inspect_object(raw)
    defined = {row['name'] for row in symbols(raw) if row['kind'] & 14 == 14}
    require({'_armdt_platform_clock_register', '_armdt_platform_clock_floor',
        '__ZN13ArmDTPlatform15getGMTTimeOfDayEv', '__ZN13ArmDTPlatform15setGMTTimeOfDayEl'} <= defined,
        'Calendar methods missing from the actual platform object')


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: Darwin 22 platform calendar and missing-RTC backport');return
    contract = json.loads(CONTRACT.read_text());reference = ROOT / 'sources/UniXNU/drivers/ArmDTPlatform'
    require(subprocess.check_output(['git', '-C', reference, 'rev-parse', 'HEAD'], text=True).strip() == contract['source_revision'] and
        not subprocess.check_output(['git', '-C', reference, 'status', '--porcelain'], text=True), 'Pinned platform source changed')
    patch = ROOT / contract['patch'];source = reference / 'ArmDTPlatform.cpp'
    require(sha(patch) == contract['patch_sha256'] and sha(source) == contract['before_sha256'], 'Calendar patch/base pin changed')
    OUT.mkdir(parents=True, exist_ok=True)
    staged = OUT / 'source/ArmDTPlatform.cpp';staged.parent.mkdir(exist_ok=True);staged.write_bytes(source.read_bytes())
    process = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch], cwd=staged.parent, capture_output=True, text=True)
    (OUT / 'overlay.log').write_text(process.stdout + process.stderr)
    require(not process.returncode and 'offset' not in process.stdout.lower() and sha(staged) == contract['after_sha256'], 'Calendar patch is not exact')
    directory = ROOT / 'drivers/DodgePlatform'
    obj, = build_objects([staged], OUT, [directory])
    library = OUT / 'libArmDTPlatform.a';library.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', library, obj], check=True)
    binary = OUT / 'calendar-host'
    run(['/usr/bin/clang++-14', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I', directory,
        ROOT / 'tests/DodgeCalendarTest.cpp', '-o', binary], OUT / 'host-compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'Calendar host checks failed; inspect host.log')
    sources = [Path(__file__), CONTRACT, patch, source, directory / 'DodgeCalendar.h', directory / 'DodgePlatformClock.inc',
        ROOT / 'tests/DodgeCalendarTest.cpp', ROOT / 'scripts/native_driver_build.py']
    artifacts = [staged, obj, library, binary, log, OUT / 'compile-commands.json']
    report = {'result': 'IOS16_PLATFORM_CALENDAR_BACKPORT_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in sources},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in artifacts},
        'object': str(obj.relative_to(ROOT)), 'archive': str(library.relative_to(ROOT)),
        'upstream': {key: contract[key] for key in ('repository', 'source_revision', 'reviewed_upstream')},
        'source_pin_retained': True, 'host_cases': int(result.stdout.split()[1]),
        'getGMTTimeOfDay': 'Registered clock when valid, otherwise kernel build date minus one day',
        'IORTC': 'Publish only when /arm-io/rtc is absent; preserve real RTC matching when present',
        'hardware_RTC_implemented': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Actual Darwin 22 ArmDTPlatform object with upstream calendar policy and missing-RTC resource publication. '
        'Bounded parsing, all truncated inputs and real clock callback bodies run under ASan/UBSan. '
        'The fallback is a calendar lower bound; battery-backed time needs an actual board RTC driver.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', report['host_cases'], 'calendar/clock cases and actual iPhone Darwin 22 platform compilation')


if __name__ == '__main__':main()
