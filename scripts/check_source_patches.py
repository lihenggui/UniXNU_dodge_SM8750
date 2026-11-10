#!/usr/bin/env python3
"""Check locked overlays on disposable clean source copies, preserving all checkouts."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    specs = {name: lock[name] for name in ('unixnu', 'darwinboot', 'iig_port', 'xnuprelink')}
    specs['uefi'] = {'path': 'uefi/Mu-Silicium', 'revision': lock['revision'],
                     'patches': [lock['memory_patch'], lock['menu_patch'], lock['boot_shim_patch']]}
    result = []
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='source-patches-', dir=ROOT / 'build') as temporary:
        directory = Path(temporary)
        for name, spec in specs.items():
            work = directory / name
            subprocess.run(['git', 'clone', '-q', '--shared', '--no-checkout', str(ROOT / spec['path']), str(work)], check=True)
            subprocess.run(['git', '-C', str(work), 'checkout', '-q', '--detach', spec['revision']], check=True)
            patches = []
            for item in spec['patches']:
                path = Path(item['path'])
                patch = directory / 'unixnu' / path.relative_to('sources/UniXNU') if path.is_relative_to('sources/UniXNU') else ROOT / path
                if hashlib.sha256(patch.read_bytes()).hexdigest() != item['sha256']:
                    raise SystemExit('Fresh source patch digest mismatch: ' + str(path))
                for args in (['--check'], []):
                    subprocess.run(['git', '-C', str(work), 'apply', *args, str(patch)], check=True)
                patches.append({'path': str(path), 'sha256': item['sha256']})
            subprocess.run(['git', '-C', str(work), 'diff', '--check'], check=True)
            result.append({'source': name, 'revision': spec['revision'], 'patches': patches, 'result': 'PASS'})
    report = {'result': 'PASS', 'sources': result,
              'scope': 'Strict application on clean pinned copies, including the IIG patch restored by the core overlay; working source edits preserved.'}
    (ROOT / 'reports/source-patches.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: clean core, DarwinBoot, IIG, XnuPrelink and Mu-Silicium overlays; all digests match')


if __name__ == '__main__':
    main()
