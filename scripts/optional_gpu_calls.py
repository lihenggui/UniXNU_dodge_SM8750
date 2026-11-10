#!/usr/bin/env python3
"""Stage locked optional-call lowering overlays without editing reference trees."""
import json
import shutil
import subprocess

from native_driver_build import ROOT, require, sha


def stage_optional_calls(group,source):
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    pin=lock['dodge_optional_call_overlays'][group]
    patch=ROOT/pin['path'];helper=ROOT/'drivers/DodgeDisplay/DodgeOptionalCalls.h'
    require(sha(patch)==pin['sha256'] and pin['source_revision']==lock[pin['source_key']]['revision'],
            'Reviewed optional-call overlay changed: '+group)
    stage=ROOT/'.cache/gpu-work/kernel-optional'/group
    stage.parent.mkdir(parents=True,exist_ok=True)
    shutil.copytree(source,stage,dirs_exist_ok=True,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
    shutil.copyfile(helper,stage/helper.name)
    subprocess.run(['git','apply','--check','--directory='+str(stage.relative_to(ROOT)),patch],cwd=ROOT,check=True)
    subprocess.run(['git','apply','--directory='+str(stage.relative_to(ROOT)),patch],cwd=ROOT,check=True)
    return stage,{'patch':pin,'helper_sha256':sha(helper),'stage':str(stage.relative_to(ROOT)),
        'patched_source_sha256':{name:sha(stage/name) for name in pin['files']}}
