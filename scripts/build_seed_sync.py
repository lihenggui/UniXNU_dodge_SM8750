#!/usr/bin/env python3
"""Compile the selected native seed-close synchronization hook and check original close ownership."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from check_gpu_link import run
from native_driver_build import ROOT, OBJDIR, build_objects, inspect_object, require, sha, symbols

OUT = ROOT / 'build/cph2653-seed-sync'
REPORT = ROOT / 'reports/ios16-seed-close-sync.json'
CONTRACT = ROOT / 'profiles/os/ios-16.7.16-20H392/seed-close-sync.json'


def patch_source(path, patch):
    process = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', patch], cwd=path, capture_output=True, text=True)
    require(not process.returncode and 'offset' not in process.stdout.lower(), 'Seed-close patch is not exact')


def check_report(report):
    require(report['result'] == 'IOS16_SEED_CLOSE_SYNC_SOURCE_PASS' and report['host_cases'] >= 40 and
        report['old_close_control_rejected'] and report['ordinary_close_preserved'] and
        not report['atomic_replacement_added'] and not report['hardware_tested'], 'Incomplete seed-close checks')
    for name, digest in {**report['source_sha256'], **report['artifacts']}.items():
        require(sha(ROOT / name) == digest, 'Seed-close source/artifact changed: ' + name)


def main():
    global OUT, REPORT
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--host-only', action='store_true');args = parser.parse_args()
    if args.host_only:
        OUT = OUT.with_name(OUT.name + '-host');REPORT = REPORT.with_name(REPORT.stem + '-host.json')
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: actual seed-close synchronization, failures and original close ownership');return
    facts = json.loads(CONTRACT.read_text());patch = ROOT / facts['patch'];OUT.mkdir(parents=True, exist_ok=True)
    require(sha(patch) == facts['patch_sha256'], 'Seed-close patch digest changed')
    source = subprocess.check_output(['git', '-C', ROOT / 'sources/xnu-ios16', 'show', facts['source_revision'] + ':' + facts['target']])
    require(hashlib.sha256(source).hexdigest() == facts['before_sha256'], 'Wrong Darwin 22 VFS source')
    reference = OUT / 'reference';path = reference / facts['target'];path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(source)
    patch_source(reference, patch);require(sha(path) == facts['after_sha256'], 'Pinned close patch readback differs')
    driver = ROOT / 'drivers/DodgeStorage/DodgeSeedSync.cpp'
    native_files = [];native_artifacts = [];native_outputs = {};adapted = path
    if not args.host_only:
        recipe = OBJDIR / 'bsd/DEVELOPMENT/vfs_vnops.o.json';record = json.loads(recipe.read_text().strip().rstrip(','))
        original = Path(record['file']);work = OUT / 'tree';adapted = work / facts['target'];adapted.parent.mkdir(parents=True, exist_ok=True)
        # Preserve the already pinned Darwin 22 iovec-alignment adaptation.
        require(original.read_text() == source.decode().replace('uio_stackbuf_t uio_buf[UIO_SIZEOF(1)];',
            '_Alignas(union iovecs) uio_stackbuf_t uio_buf[UIO_SIZEOF(1)];'), 'Unexpected existing VFS adaptation')
        adapted.write_bytes(original.read_bytes());patch_source(work, patch)
        native = OUT / 'vfs_vnops.seed.o';command = [];index = 0
        while index < len(record['arguments']):
            value = record['arguments'][index]
            if value == record['file']:command.append(str(adapted))
            elif value in ('-o', '-MF', '-MJ'):index += 1
            elif value not in ('-MD', '-MP'):command.append(value)
            index += 1
        command += ['-DXNU_DODGE_SEED_SYNC=1', '-iquote', str(original.parent), '-o', str(native)]
        run(command, OUT / 'vfs-compile.log', record['directory']);inspect_object(native.read_bytes())
        require(any(row['name'] == '_dodge_seed_close_sync' and row['kind'] == 1 for row in symbols(native.read_bytes())),
            'Actual VFS close does not call the source seed hook')
        obj, = build_objects([driver], OUT / 'driver', [driver.parent, ROOT / 'drivers/DodgeSecurity'])
        archive = OUT / 'libDodgeSeedSync.a';archive.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/llvm-ar-14', 'rcsD', archive, obj], check=True)
        commands = OUT / 'vfs-compile.json';commands.write_text(json.dumps(command, indent=2) + '\n')
        native_files = [original, recipe];native_artifacts = [adapted, obj, archive, native, commands, OUT / 'driver/compile-commands.json']
        native_outputs = {'archive': str(archive.relative_to(ROOT)), 'vfs_object': str(native.relative_to(ROOT))}
    text = adapted.read_text();start = text.index('static int\nvn_closefile(');end = text.index('\n}\n', start) + 3
    include = OUT / 'SeedClose.inc';include.write_text(text[start:end])
    compiler = shutil.which('clang++-14') or shutil.which('clang++');require(compiler, 'Need Clang sanitizers')
    test = ROOT / 'tests/DodgeSeedSyncTest.cpp';peers = ROOT / 'tests/seed_sync_include';binary = OUT / 'seed-close-host'
    flags = [compiler, '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-reorder-init-list',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
        '-I', peers, '-I', driver.parent, '-I', ROOT / 'drivers/DodgeSecurity', '-I', OUT]
    run([*flags, '-DXNU_DODGE_SEED_SYNC=1', test, '-o', binary], OUT / 'host-compile.log')
    result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    log = OUT / 'host.log';log.write_text(result.stdout + result.stderr)
    require(not result.returncode and result.stdout.startswith('PASS:'), 'Seed-close checks failed; inspect host.log')
    control = OUT / 'old-close-host';run([*flags, '-DXNU_DODGE_SEED_SYNC=0', test, '-o', control], OUT / 'control-compile.log')
    old = subprocess.run([control], capture_output=True, text=True, timeout=30)
    require(old.returncode != 0 and 'Assertion' in old.stderr, 'Old close without synchronization was not rejected')
    files = [Path(__file__), CONTRACT, patch, driver, test, *native_files, *sorted(peers.rglob('*.h'))]
    artifacts = [path, include, binary, control, log, *native_artifacts]
    report = {'result': 'IOS16_SEED_CLOSE_SYNC_SOURCE_PASS',
        'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in files},
        'artifacts': {str(p.relative_to(ROOT)): sha(p) for p in artifacts},
        **native_outputs, 'native_compiled': not args.host_only,
        'host_cases': int(result.stdout.split()[1]), 'old_close_control_rejected': True, 'ordinary_close_preserved': True,
        'atomic_replacement_added': False, 'hardware_tested': False, 'phone_operations': 'none',
        'scope': 'Selected owner-development seed closes validate the original private 32-byte file on verified APFS Data, '
        'synchronize the file and directory, then request F_FULLFSYNC without an unsupported fallback. Actual pinned close '
        'source and synchronization code execute under sanitizers with explicit VFS peers. Ordinary close, lock release and '
        'iocount cleanup always remain, including failures. This preserves original PRNG and userspace code. It does not add '
        'atomic seed-file replacement, guarantee a prior seed survives truncation/crash, or qualify physical persistence. '
        'Fresh boot entropy remains independently required; a saved seed is additional input only.'}
    check_report(report);REPORT.write_text(json.dumps(report, indent=2) + '\n');print(result.stdout.strip())


if __name__ == '__main__':main()
