#!/usr/bin/env python3
"""Strictly apply the iPhone patch set to a disposable, pinned Apple checkout."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = '1b191cb58250d0705d8a51287127505aa4bc0789'


def main():
    source = ROOT / 'sources/xnu-ios16'
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != REVISION:
        raise SystemExit('Refusing a different XNU source revision: ' + revision)
    base = ROOT / 'profiles/os/ios-16.7.16-20H392/patches'
    selected = []
    for series in (base / 'arch/series', base / 'xnu/series', ROOT / 'patches/xnu/series'):
        for line in series.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                selected.append(series.parent / line.strip())
    if len(set(selected)) != len(selected):
        raise SystemExit('Duplicate patch in selected series')
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ios16-patches-', dir=ROOT / 'build') as temporary:
        checkout = Path(temporary) / 'xnu'
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(source), str(checkout)], check=True)
        subprocess.run(['git', '-C', str(checkout), 'checkout', '--quiet', '--detach', REVISION], check=True)
        for patch in selected:
            subprocess.run(['git', '-C', str(checkout), 'apply', '--check', str(patch)], check=True)
            subprocess.run(['git', '-C', str(checkout), 'apply', str(patch)], check=True)
        subprocess.run(['git', '-C', str(checkout), 'diff', '--check'], check=True)
    report = {
        'result': 'PASS',
        'scope': 'Strict ordered application on a clean pinned source; compilation, binary ABI and hardware are separate.',
        'baseline_tag': 'xnu-8796.141.3', 'baseline_revision': REVISION,
        'upstream_unixnu_revision': json.loads((ROOT / 'upstream.lock.json').read_text())['unixnu']['revision'],
        'rebased_patch_count': len(selected),
        'not_required': {
            'pgz-aligned-validation.patch': 'Darwin 22 has no zone_id_require_aligned implementation; retain its size-aware zone_id_require.',
            'published-freezer-condition.patch': 'The malformed Darwin 23 FREEZE_ENABLED_DEFAULT condition is absent from Darwin 22.'},
        'patches': [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in selected]}
    (ROOT / 'reports/ios16-rebased-patches.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(selected)} patches applied strictly to clean {REVISION[:12]}')


if __name__ == '__main__':
    main()
