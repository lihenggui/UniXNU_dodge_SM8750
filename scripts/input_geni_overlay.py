#!/usr/bin/env python3
"""Verify the exact device-local derivative of the fixed GENI component."""
import difflib
import json
from pathlib import Path
import subprocess
import tempfile
from native_driver_build import ROOT,require,sha

SOURCE=ROOT/'drivers/DodgeInput/geni/GeniSpi.c'
BASE=ROOT/'sources/UniXNU/drivers/QcomGeniSpi/GeniSpi.c'
PATCH=ROOT/'patches/oneplus13/0008-geni-transfer-completion.patch'

def verify():
    pin=json.loads((ROOT/'upstream.lock.json').read_text())['dodge_geni_transfer_overlay']
    require(pin['path']==str(PATCH.relative_to(ROOT)) and sha(PATCH)==pin['sha256'] and
            sha(BASE)==pin['base_source_sha256'] and sha(SOURCE)==pin['output_source_sha256'],'GENI completion overlay/source pin changed')
    expected=''.join(difflib.unified_diff(BASE.read_text().splitlines(True),SOURCE.read_text().splitlines(True),fromfile='a/GeniSpi.c',tofile='b/GeniSpi.c'))
    require(PATCH.read_text()==expected,'GENI overlay does not exactly describe its pinned base/output')
    out=ROOT/'build/cph2653-input-transfer';out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='overlay-',dir=out) as temporary:
        work=Path(temporary);(work/'GeniSpi.c').write_bytes(BASE.read_bytes())
        ran=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(PATCH)],cwd=work,capture_output=True,text=True)
        require(not ran.returncode and 'offset' not in ran.stdout.lower() and (work/'GeniSpi.c').read_bytes()==SOURCE.read_bytes(),'GENI completion overlay fails strict application')
    return SOURCE
