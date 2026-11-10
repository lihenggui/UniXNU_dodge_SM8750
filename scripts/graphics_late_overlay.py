#!/usr/bin/env python3
"""Stage the reviewed IOBSD hook in an isolated file, preserving native inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(out,reference_only=False):
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['dodge_graphics_late_overlay'];patch=ROOT/pin['path']
    if sha(patch)!=pin['sha256']:raise ValueError('Reviewed isolated IOBSD hook patch changed')
    relative=Path('iokit/bsddev/IOKitBSDInit.cpp')
    candidates=[(ROOT/'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree/.cache/xnu-work'/relative,pin['base_source_sha256']),
                (ROOT/lock['xnu_ios16']['path']/relative,pin['reference_source_sha256'])]
    if not reference_only and candidates[0][0].is_file() and sha(candidates[0][0])!=candidates[0][1]:
        raise ValueError('Existing native IOBSD source has unreviewed changes')
    if reference_only:candidates=candidates[1:]
    matches=[(p,h) for p,h in candidates if p.is_file() and sha(p)==h]
    if not matches:raise ValueError('Need the pinned actual Darwin 22 IOKitBSDInit source')
    base,expected_hash=matches[0];out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='late-hook-',dir=out) as temp:
        work=Path(temp);source=work/relative;source.parent.mkdir(parents=True);source.write_bytes(base.read_bytes())
        result=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(patch)],cwd=work,capture_output=True,text=True)
        (out/'hook-patch.log').write_text(result.stdout+result.stderr)
        if result.returncode or 'offset' in result.stdout.lower():raise ValueError('Isolated IOBSD hook patch did not apply exactly')
        destination=out/'source'/relative;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(source.read_bytes())
    if sha(base)!=expected_hash:raise ValueError('Staging modified the original IOBSD source')
    return destination,{'patch':pin,'base_source':str(base.relative_to(ROOT)),'base_source_sha256':sha(base),
                       'patched_source':str(destination.relative_to(ROOT)),'patched_source_sha256':sha(destination),
                       'stager_sha256':sha(Path(__file__))}
