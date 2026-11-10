#!/usr/bin/env python3
"""Build the pinned local LZFSE and unifdef tools with four host jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shlex
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-iig', action='store_true', help='Run the pinned IIG output regression archive')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    env = dict(os.environ, PATH=os.pathsep.join([str(ROOT / '.venv-uefi/bin'), '/usr/bin', '/bin']))
    prefix = ROOT / '.toolchains/host'
    prefix.mkdir(parents=True, exist_ok=True)
    for name, directory in [('unifdef', ROOT / lock['unifdef']['path']), ('lzfse', ROOT / 'sources/lzfse')]:
        revision = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != lock[name]['revision']:
            raise SystemExit('Unexpected host source revision: ' + name)
        subprocess.run(['make', '-C', str(directory), '-j4', 'CC=/usr/bin/cc'], env=env, check=True)
        if name == 'unifdef':
            manual = prefix / 'share/man/man1/unifdefall.1'
            if manual.is_symlink() and os.readlink(manual) == 'unifdef.1':
                manual.unlink()
            elif manual.exists():
                raise SystemExit('Unexpected existing unifdef manual link')
            subprocess.run(['make', '-C', str(directory), f'prefix={prefix}', 'install'], env=env, check=True)
    executable = prefix / 'bin/unifdef'
    iig = ROOT / lock['iig_port']['path']
    if subprocess.check_output(['git', '-C', str(iig), 'rev-parse', 'HEAD'], text=True).strip() != lock['iig_port']['revision']:
        raise SystemExit('Unexpected iig-port revision')
    from prepare_sources import patch_state
    for specification in lock['iig_port']['patches']:
        if patch_state(iig, specification, False) != 'already-applied':
            raise SystemExit('Apply the pinned iig-port patch with prepare_sources.py --apply first')
    config = os.environ.get('LLVM_CONFIG', '/usr/lib/llvm-14/bin/llvm-config')
    bindir = Path(subprocess.check_output([config, '--bindir'], text=True).strip())
    libdir = subprocess.check_output([config, '--libdir'], text=True).strip()
    resource = subprocess.check_output([str(bindir / 'clang'), '-print-resource-dir'], text=True).strip()
    flags = shlex.split(subprocess.check_output([config, '--cxxflags', '--ldflags'], text=True))
    subprocess.run([str(bindir / 'clang++'), *flags, '-std=c++17',
                    f'-DUNIXNU_CLANG_RESOURCE_DIR="{resource}"', str(iig / 'iig.cpp'),
                    f'-Wl,-rpath,{libdir}', '-lclang', '-ldl', '-o', str(prefix / 'bin/iig')], check=True)
    version = subprocess.run([str(executable), '-V'], capture_output=True, text=True, check=True).stderr
    if 'unifdef-2.12' not in version:
        raise SystemExit('The actual unifdef executable must be version 2.12')
    cases = []
    for name in ('libkern/libkern/c++/OSEndianTypes.h', 'bsd/net/pfvar.h'):
        source = ROOT / lock['xnu_ios16']['path'] / name
        result = subprocess.run([str(executable), '-DKERNEL=1', '-UPRIVATE', str(source)], capture_output=True)
        if result.returncode not in (0, 1):
            raise SystemExit(result.stderr.decode())
        cases.append({'source': name, 'result': 'PASS'})
    report = {'result': 'PASS', 'unifdef_revision': lock['unifdef']['revision'],
              'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
              'version': version.splitlines()[0], 'darwin22_header_regressions': cases,
              'scope': 'Actual preprocessing of published XNU headers; host only.'}
    report['iig_port_revision'] = lock['iig_port']['revision']
    report['iig_executable_sha256'] = hashlib.sha256((prefix / 'bin/iig').read_bytes()).hexdigest()
    if args.check_iig:
        test_env = dict(env, IIG_TOOL=str(prefix / 'bin/iig'), LLVM_CONFIG=config)
        test_env.pop('UNIXNU_IIG_LEGACY_RPC', None)
        log = ROOT / 'analysis/iig-regressions.log'
        log.parent.mkdir(exist_ok=True)
        with log.open('w') as stream:
            subprocess.run(['sh', str(iig / 'tests/run.sh')], env=test_env,
                           stdout=stream, stderr=subprocess.STDOUT, check=True)
        summary = re.search(r'CHECKED=(\d+) FAIL=(\d+)', log.read_text())
        if not summary or int(summary[2]) or not int(summary[1]):
            raise SystemExit('IIG regression log did not report passing cases')
        report['iig_default_regressions'] = {'checked': int(summary[1]), 'failed': int(summary[2]),
            'log': str(log.relative_to(ROOT)), 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
    (ROOT / 'reports/host-tools.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: reference LZFSE and unifdef 2.12; original Darwin 22 headers parse')


if __name__ == '__main__':
    main()
