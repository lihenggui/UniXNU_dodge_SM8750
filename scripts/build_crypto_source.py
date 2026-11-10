#!/usr/bin/env python3
"""Link an isolated Darwin 22 candidate with a single original crypto/PRNG owner."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from check_crypto_once_host import check as check_host
from check_gpu_link import assemble, run
from crypto_bootstrap_overlay import sources as overlay_sources, patch as overlay_patch
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, require, symbols, macho
from native_prelink import backed_offset
from prepare_initial_data import sha
from prepare_ios16_crypto import FIXTURE, HEADER, header
from build_data_startup import hook_readback
from build_data_mount_source import init_hook_readback

OUT = ROOT / 'build/cph2653-crypto-source'
ENTRIES = ('_dodge_crypto_is_original', '_dodge_crypto_start_once', '_dodge_crypto_bootstrap',
           '_dodge_crypto_status', '_dodge_crypto_prng_ready', '_dodge_crypto_prng_matches')


def hook_readbacks(raw):
    image = macho(raw); names = {s['name']: s['value'] for s in symbols(raw) if not s['kind'] & 0xe0}
    bootstrap = names['_source_corecrypto14_bootstrap']
    starts = sorted(set(names.values()))
    def calls(name):
        start = names[name]; end = next(value for value in starts if value > start)
        offset = backed_offset(image['segments'], start, end - start, len(raw))
        result = {}
        for index, (word,) in enumerate(struct.iter_unpack('<I', raw[offset:offset + end - start])):
            if word & 0xfc000000 == 0x94000000:
                delta = word & 0x3ffffff; pc = start + index * 4
                target = pc + 4 * (delta - (1 << 26) if delta & (1 << 25) else delta)
                result.setdefault(target, []).append(pc)
        return result
    early = calls('_source_corecrypto14_bootstrap')
    require(names['_dodge_crypto_bootstrap'] in early and names.get('_corecrypto_kext_start') not in early,
            'Early crypto still starts the independent source provider or misses the original owner')
    kext_name, = [name for name in names if name == '__ZN6OSKext5startEb']
    later = calls(kext_name)
    cpp_name, = [name for name in names if name.endswith('OSRuntimeInitializeCPP') or name == '__Z22OSRuntimeInitializeCPPP6OSKext']
    require(all(names[name] in later and len(later[names[name]]) == 1 for name in
                ('_dodge_crypto_is_original', '_dodge_crypto_start_once')) and names[cpp_name] in later and
            max(later[names[cpp_name]]) < later[names['_dodge_crypto_is_original']][0] < later[names['_dodge_crypto_start_once']][0],
            'Actual OSKext does not reuse original crypto after its C++ initialization')
    startup = []
    for section in (s for seg in image['segments'] for s in seg['sections'] if s['name'] == '__init_entry_set'):
        offset = backed_offset(image['segments'], section['va'], section['size'], len(raw))
        require(section['size'] % 24 == 0, 'Startup entry record size changed')
        for index in range(0, section['size'], 24):
            stage, rank, function, argument = struct.unpack_from('<IIQQ', raw, offset + index)
            if function == bootstrap: startup.append((stage, rank, argument))
    require(startup == [(15, 0xffffffff, 0)], 'Original crypto must register at SYSCTL LAST, before early IOKit hashing')
    return {'early_bootstrap': hex(bootstrap), 'early_owner_call': hex(early[names['_dodge_crypto_bootstrap']][0]),
            'startup_subsystem': 15, 'startup_rank': 'LAST', 'original_provider_only': True,
            'actual_oskext_start': hex(names[kext_name]), 'original_cpp_call': hex(max(later[names[cpp_name]])),
            'actual_oskext_owner_check': hex(later[names['_dodge_crypto_is_original']][0]),
            'actual_oskext_owner_reuse': hex(later[names['_dodge_crypto_start_once']][0])}


def check_report(report):
    require(report['builder_sha256'] == sha(Path(__file__)) and report['result'] == 'IOS16_SINGLE_ORIGINAL_CRYPTO_OWNER_SOURCE_LINK_PASS',
            'Original crypto source report is stale')
    for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / filename) == value, 'Crypto source input/artifact changed: ' + filename)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    require(report['source_overlay'] == lock['dodge_crypto_owner_overlay'] and report['original_crypto_pin'] == lock['iphone_crypto_contract'],
            'Original crypto pins changed')
    raw = (ROOT / report['candidate']).read_bytes()
    require(hook_readbacks(raw) == report['actual_crypto_hooks'] and report['combined_source_objects'] == 89 and
            report['combined_original_aliases'] == 339 and len(report['combined_native_entries']) == 97 and
            report['host_tests']['case_count'] == 18 and all(row['result'] == 'PASS' for row in report['host_tests']['cases']),
            'Original crypto link/hooks or case counts differ')
    require(not any(report[key] for key in ('hardware_tested', 'ready_for_ios_boot', 'all_ios_port_code_complete',
                'original_crypto_post_executed', 'original_crypto_runtime_qualified')), 'Crypto source report overstates runtime')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    report_path = ROOT / 'reports/ios16-crypto-source.json'
    if args.check_only:
        check_report(json.loads(report_path.read_text())); print('PASS: preserved isolated original-crypto source/link evidence'); return
    OUT.mkdir(exist_ok=True)
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pin = lock['iphone_crypto_contract']; overlay = lock['dodge_crypto_owner_overlay']
    fixture = json.loads(FIXTURE.read_text()); abi_report = ROOT / 'reports/ios16-crypto-contract.json'
    abi = json.loads(abi_report.read_text())
    require(pin['sha256'] == sha(FIXTURE) and pin['header_sha256'] == sha(HEADER) and HEADER.read_text() == header(fixture) and
            abi['contract_facts'] == fixture, 'Need the measured original crypto owner contract')
    base_path = ROOT / 'reports/ios16-data-mount-native.json'; base = json.loads(base_path.read_text())
    for report in (base, abi):
        for filename, value in {**report['source_sha256'], **report['dependency_report_sha256'], **report['artifacts']}.items():
            require(sha(ROOT / filename) == value, 'Original crypto dependency changed: ' + filename)
    require(base['combined_source_objects'] == 87 and base['combined_original_aliases'] == 332, 'Wrong original crypto candidate base')
    records, before, after = overlay_sources(); patch = ROOT / overlay['path']
    require(patch.read_text() == overlay_patch(before, after) and sha(patch) == overlay['sha256'], 'Reviewed crypto overlay changed')
    overlays, compilation = {}, []
    for name in ('prng', 'kext'):
        recipe = records[name]; original_source = Path(recipe['file']); checks = overlay['files'][name]
        require(str(original_source.relative_to(ROOT)) == checks['path'] and sha(original_source) == checks['base_sha256'] and
                hashlib.sha256(after[name].encode()).hexdigest() == checks['output_sha256'], 'Crypto overlay source/output identity differs')
        source = OUT / ('prng_random.crypto.c' if name == 'prng' else 'OSKext.crypto.cpp')
        source.write_text(after[name]); obj = source.with_suffix('.o'); command, index = [], 0
        while index < len(recipe['arguments']):
            value = recipe['arguments'][index]
            if value == recipe['file']: command.append(str(source))
            elif value in ('-o', '-MF', '-MJ'): index += 1
            elif value not in ('-MD', '-MP'): command.append(value)
            index += 1
        command += ['-iquote', str(original_source.parent), '-I', str(ROOT / 'drivers/DodgeSecurity'), '-o', str(obj)]
        run(command, obj.with_suffix('.log'), recipe['directory']); inspect_object(obj.read_bytes())
        overlays[name] = obj; compilation.append({'directory': recipe['directory'], 'source': str(source), 'arguments': command})
    host = check_host(OUT)
    bridge, = build_objects([ROOT / 'drivers/DodgeSecurity/DodgeCryptoBootstrap.c'], OUT,
                           [ROOT / 'drivers/DodgeSecurity', HEADER.parent])
    aliases = {name: int(value, 16) for name, value in fixture['linked_bindings'].items()}
    absolute = assemble(OUT, 'original-crypto-inputs', ''.join('.globl ' + name + '\n.set ' + name + ',' + hex(value) + '\n' for name, value in aliases.items()))
    require({s['name']: s['value'] for s in symbols(absolute.read_bytes()) if s['kind'] == 3} == aliases and
            all(not s['size'] for seg in inspect_object(absolute.read_bytes())['segments'] for s in seg['sections']), 'Crypto aliases contain substituted code')
    archive = OUT / 'libDodgeCryptoOwner.a'
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, bridge, absolute], check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14', 't', archive], text=True).splitlines() == [bridge.name, absolute.name], 'Crypto archive members differ')
    command = json.loads((ROOT / base['link_command']).read_text())[:-2]
    old_filelist, = [value for value in command if value.startswith('-Wl,-filelist,')]
    rows = Path(old_filelist.removeprefix('-Wl,-filelist,')).read_text().splitlines()
    for name, suffix in (('prng', '/osfmk/DEVELOPMENT/prng_random.o'), ('kext', '/libkern/DEVELOPMENT/OSKext.cpo')):
        found, = [row for row in rows if row.endswith(suffix)]; rows[rows.index(found)] = str(overlays[name])
    filelist = OUT / 'combined-native.filelist'; filelist.write_text(''.join(row + '\n' for row in rows))
    command[command.index(old_filelist)] = '-Wl,-filelist,' + str(filelist)
    candidate = OUT / 'mach.crypto-owner'; command += ['-Wl,-force_load,' + str(archive), '-o', str(candidate)]
    run(command, OUT / 'link.log', OBJDIR)
    raw = candidate.read_bytes(); names = {s['name']: s for s in symbols(raw) if not s['kind'] & 0xe0}
    require(macho(raw)['kind'] == 2 and not any(s['kind'] == 1 for s in names.values()), 'Crypto candidate has unresolved imports')
    bindings = {**base['combined_original_bindings'], **fixture['linked_bindings']}
    for name, value in bindings.items(): require(names[name]['kind'] == 3 and names[name]['value'] == int(value, 16), 'Crypto/original alias changed: ' + name)
    entries = [*base['combined_native_entries'], *ENTRIES]
    require(len(entries) == 97 and all(names[name]['kind'] & 0xe == 14 for name in entries), 'Crypto native entry is absent')
    hooks = hook_readbacks(raw)
    controls = []
    at = backed_offset(macho(raw)['segments'], int(hooks['actual_oskext_owner_reuse'], 16), 4, len(raw))
    bad = bytearray(raw); struct.pack_into('<I', bad, at, 0xd503201f)
    try: hook_readbacks(bad)
    except ValueError as error: controls.append({'case': 'OSKext-owner-call-NOP', 'result': 'REJECTED', 'reason': str(error)})
    else: raise ValueError('Missing actual OSKext owner call was accepted')
    link_path = OUT / 'link-command.json'; link_path.write_text(json.dumps(command, indent=2) + '\n')
    compile_path = OUT / 'overlay-compile-commands.json'; compile_path.write_text(json.dumps(compilation, indent=2) + '\n')
    files = [Path(__file__), ROOT / 'scripts/crypto_bootstrap_overlay.py', ROOT / 'scripts/check_crypto_once_host.py',
             ROOT / 'scripts/prepare_ios16_crypto.py', *[ROOT / 'drivers/DodgeSecurity' / name for name in
             ('DodgeCryptoBootstrap.c', 'DodgeCryptoBootstrap.h', 'DodgeCryptoOnce.h')], ROOT / 'tests/DodgeCryptoOnceTest.cpp',
             FIXTURE, HEADER, patch, *[Path(row['file']) for row in records.values()]]
    artifacts = [bridge, absolute, archive, candidate, filelist, link_path, compile_path, OUT / 'compile-commands.json',
                 *overlays.values(), *[OUT / name for name in ('prng_random.crypto.c', 'OSKext.crypto.cpp')], ROOT / host['binary']]
    report = {'result': 'IOS16_SINGLE_ORIGINAL_CRYPTO_OWNER_SOURCE_LINK_PASS', 'builder_sha256': sha(Path(__file__)),
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'dependency_report_sha256': {str(p.relative_to(ROOT)): sha(p) for p in (base_path, abi_report)},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts}, 'candidate': str(candidate.relative_to(ROOT)),
        'candidate_sha256': sha(candidate), 'link_command': str(link_path.relative_to(ROOT)),
        'combined_source_objects': 89, 'combined_original_aliases': len(bindings), 'combined_original_bindings': bindings,
        'combined_native_entries': {name: hex(names[name]['value']) for name in entries},
        'actual_crypto_hooks': hooks, 'actual_iobsd_hook': hook_readback(raw), 'actual_init_hook': init_hook_readback(raw),
        'source_overlay': overlay, 'original_crypto_pin': pin, 'host_tests': host, 'negative_controls': controls,
        'single_original_crypto_owner_wired': True, 'source_provider_fallback_after_original_attempt': False,
        'original_crypto_post_executed': False, 'original_crypto_runtime_qualified': False,
        'hardware_tested': False, 'ready_for_ios_boot': False, 'all_ios_port_code_complete': False,
        'scope': 'Separate 89-object/97-entry source candidate replaces only copied prng/OSKext objects and adds a real original-provider '
                 'single-owner coordinator. Both actual early SYSCTL and OSKext call sites share the same result and reject conflicting '
                 'crypto/PRNG ownership. Original start/POST code is called without replacement callbacks in production. Eighteen host '
                 'sanitizer cases use explicit metadata/provider/entry peers. Seven measured original inputs and all old aliases survive strict '
                 'source linking. No original POST/runtime execution, complete crypto ABI, original-component prelink or boot success is claimed.'}
    report_path.write_text(json.dumps(report, indent=2) + '\n'); check_report(report)
    print('PASS: separate 89-object/97-entry original-crypto owner, actual SYSCTL/OSKext hooks, 18 sanitizer cases and 339 original aliases')


if __name__ == '__main__': main()
