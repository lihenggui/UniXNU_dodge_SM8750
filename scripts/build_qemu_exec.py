#!/usr/bin/env python3
"""Add the original iPhone filesystem decompressor to the owner-root fixture."""
from collections import Counter
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_qemu_owner_root import OUT as OWNER_OUT, REPORT as OWNER_REPORT, check_report as check_owner
from build_native_a830_kernel import REPORT as BASE_REPORT
from build_crypto_prelink import validate
from build_crypto_source import hook_readbacks
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback
from build_gpu_graphics_prelink import PROFILE, SECURITY, ORIGINAL, original_context
from build_input_prelink import CONFIG
from image4_boot_policy import security_plan, check_security_starts
from native_driver_build import ROOT, TREE, require, sha, macho, symbols
from native_prelink import backed_offset, exports
from prepare_surface_backing import checked as backing_checked, apply_hooks

OUT = ROOT / 'build/cph2653-qemu-exec'
REPORT = ROOT / 'reports/ios16-qemu-exec.json'
MODULE = 'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib'


def validate_extension(data, record, native, original, context, base_context, config, source, security):
    # Retain the established 63,889-site validator for the unchanged component
    # set. Its metadata/module-entry checks still cover the full new closure.
    base_names = set(base_context['modules'])
    core = copy.deepcopy(record)
    core['bindings'] = [row for row in record['bindings'] if row['module'] in base_names]
    core['pointer_counts'] = dict(Counter(row['kind'] for row in core['bindings']))
    checked = validate(data, core, native, original, base_context, config, source, security)
    require(set(context['modules']) - base_names == {MODULE} and
            len(record['bindings']) == len(context['sites']) == len({row['site'] for row in record['bindings']}) and
            sum(record['pointer_counts'].values()) == len(record['bindings']), 'Unexpected extended pointer inventory')
    image, native_image = macho(data), macho(native)
    def read(raw, parsed, address, count):
        at = backed_offset(parsed['segments'], address, count, len(raw))
        return raw[at:at + count]
    public = {}
    for address, names in exports(native, native_image).items():
        for name in names:public.setdefault(name, set()).add(address)
    slide = record['slide'];added = []
    for row in record['bindings']:
        if row['module'] in base_names:continue
        require(row['module'] == MODULE and context['sites'].get(row['site']) == MODULE and
                row['new_site'] == row['site'] + slide and
                struct.unpack('<Q', read(original, context['image'], row['site'], 8))[0] == row['target'], 'Added pointer provenance changed')
        if row['kind'] == 'component':
            require(context['owner'](row['target']) is not None and row['new_target'] == row['target'] + slide,
                    'Added component pointer changed')
        else:
            choices = {address for name in context['exports'].get(row['target'], []) for address in public.get(name, ())}
            require(row['kind'] == 'kernel' and context['owner'](row['target']) is None and choices == {row['new_target']} and
                    any(seg['va'] <= row['new_target'] < seg['va'] + seg['size'] for seg in native_image['segments']),
                    'Added native pointer has no unique mapped source binding')
        require(struct.unpack('<Q', read(data, image, row['new_site'], 8))[0] == row['new_target'], 'Added pointer readback changed')
        added.append(row)
    require(added, 'Decompressor has no checked pointer sites')
    segments = []
    for segment in context['modules'][MODULE]['segments']:
        if segment['name'] != '__TEXT_EXEC' or not segment['filesize']:continue
        before = read(original, context['image'], segment['va'], segment['filesize'])
        after = read(data, image, segment['va'] + slide, segment['filesize'])
        require(before == after and hashlib.sha256(before).hexdigest() == record['original_executable_sha256'][MODULE],
                'Original decompressor instructions changed')
        segments.append({'address': hex(segment['va'] + slide), 'bytes': len(before), 'sha256': hashlib.sha256(before).hexdigest()})
    checked.update(pointer_sites_read_back=len(record['bindings']), added_pointer_sites=len(added),
        original_decompressor_segments=segments, native_source_entries_preserved=len(source['combined_native_entries']),
        original_aliases_preserved=len(source['combined_original_bindings']))
    return checked


def check_report(report):
    require(report['result'] == 'IOS16_QEMU_ORIGINAL_DECOMPRESSOR_PRELINK_PASS' and report['added_module'] == MODULE and
            len(report['components']) == 29 and MODULE in report['components'] and
            report['pointer_sites_read_back'] == 63889 + report['added_pointer_sites'] and report['added_pointer_sites'] > 0 and
            report['original_decompressor_segments'] and not report['hardware_tested'], 'Invalid decompressor fixture')
    for name, digest in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Decompressor fixture input changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true');args = parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: original iPhone decompressor prelink');return
    owner = json.loads(OWNER_REPORT.read_text());check_owner(owner)
    base = json.loads(BASE_REPORT.read_text());native_path = OWNER_OUT / 'mach.owner-root'
    native, original = native_path.read_bytes(), ORIGINAL.read_bytes()
    profile, config = tomllib.loads(PROFILE.read_text()), json.loads(CONFIG.read_text())
    roots = profile['kernel']['prelink']['roots'] + config['additional_roots']
    base_context = original_context(original, roots, config)
    require(MODULE not in config['expected_executables'], 'Decompressor is already selected')
    config['expected_executables'] = sorted([*config['expected_executables'], MODULE])
    context = original_context(original, [*roots, MODULE], config)
    security, requests, normal = security_plan(profile, json.loads(SECURITY.read_text()))
    OUT.mkdir(parents=True, exist_ok=True)
    fixture = OUT / 'security-init.json';fixture.write_text(json.dumps(security, indent=2) + '\n')
    names = {row['name']: row for row in symbols(native) if not row['kind'] & 0xe0}
    source = {**base, 'actual_crypto_hooks': hook_readbacks(native), 'actual_iobsd_hook': hook_readback(native),
        'actual_init_hook': init_hook_readback(native),
        'combined_native_entries': {name: hex(names[name]['value']) for name in base['combined_native_entries']}}
    emitter = TREE / 'kits/XnuPrelink/emit_prelink.py'
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64', UNIXNU_IOS_VERSION='16.0', PATH='/usr/lib/llvm-14/bin' + os.pathsep + os.environ['PATH'])
    with tempfile.TemporaryDirectory(prefix='emit-', dir=OUT) as temporary:
        pending = Path(temporary) / 'kernel.macho'
        command = [sys.executable, emitter, '--kernel', native_path, '--prelinked', ORIGINAL, '--slide=' + config['slide'], '--output', pending]
        for name in [*roots, MODULE]:command += ['--root', name]
        for request in requests:command += ['--early-security-init', request]
        command += ['--early-security-fixture', fixture]
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        (OUT / 'emission.log').write_text(process.stdout + process.stderr)
        require(not process.returncode, 'Decompressor prelink failed; inspect emission.log')
        raw = pending.read_bytes();record = json.loads(pending.with_suffix('.json').read_text())
    require(record['candidate_sha256'] == hashlib.sha256(raw).hexdigest() and
            record['native_sha256'] == hashlib.sha256(native).hexdigest() and
            record['original_sha256'] == hashlib.sha256(original).hexdigest(), 'Decompressor emission inputs changed')
    checked = validate_extension(raw, record, native, original, context, base_context, config, source, security)
    security_readback = check_security_starts(raw, record, normal)
    backing, _ = backing_checked();candidate = OUT / 'kernel.macho';candidate.write_bytes(apply_hooks(raw, backing))
    emission = OUT / 'emission.json';emission.write_text(json.dumps(record, indent=2) + '\n')
    report = {'result': 'IOS16_QEMU_ORIGINAL_DECOMPRESSOR_PRELINK_PASS',
        'source_sha256': {str(path.relative_to(ROOT)): sha(path) for path in (Path(__file__), ROOT / 'scripts/build_crypto_prelink.py',
            ROOT / 'scripts/build_gpu_graphics_prelink.py', ROOT / 'scripts/image4_boot_policy.py', PROFILE, CONFIG, SECURITY, emitter)},
        'dependency_report_sha256': {str(OWNER_REPORT.relative_to(ROOT)): sha(OWNER_REPORT)},
        'artifacts': {str(path.relative_to(ROOT)): sha(path) for path in (candidate, native_path, emission, fixture)},
        'candidate': str(candidate.relative_to(ROOT)), 'candidate_sha256': sha(candidate), 'added_module': MODULE,
        'components': record['components'], 'kernel_interfaces': record['kernel_interfaces'], **checked,
        'security_start_readback': security_readback, 'hardware_tested': False,
        'scope': 'Original iPhone filesystem decompressor added to the separate owner-root VM fixture. '
                 'The existing 63,889 pointer sites and every added site are independently read back. '
                 'Original component instructions and normal security startup are retained. Runtime loading is a separate check.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: 29 original components and', checked['pointer_sites_read_back'], 'pointer readbacks, including the original decompressor')


if __name__ == '__main__':main()
