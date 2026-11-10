#!/usr/bin/env python3
"""Stage the locked A830 display snapshot after the optional-call overlay."""
import json
import shutil
import subprocess

from native_driver_build import ROOT,require,sha


def stage_display_timeline(source):
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['dodge_adreno_display_timeline']
    patch=ROOT/pin['path'];header=ROOT/pin['header']
    require(sha(patch)==pin['sha256'] and sha(header)==pin['header_sha256'] and
        pin['source_revision']==lock['a830_backend_reference']['revision'],'Reviewed Adreno display snapshot patch/header changed')
    stage=ROOT/'.cache/gpu-work/kernel-display-timeline/backend'
    stage.parent.mkdir(parents=True,exist_ok=True)
    shutil.copytree(source,stage,dirs_exist_ok=True,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
    shutil.copyfile(header,stage/header.name)
    subprocess.run(['git','apply','--check','--directory='+str(stage.relative_to(ROOT)),patch],cwd=ROOT,check=True)
    subprocess.run(['git','apply','--directory='+str(stage.relative_to(ROOT)),patch],cwd=ROOT,check=True)
    return stage,{'patch':pin,'stage':str(stage.relative_to(ROOT)),'stager_sha256':sha(ROOT/'scripts/adreno_display_timeline.py'),
        'base_publish_sha256':sha(source/'NativeAdrenoPublish.cpp'),
        'patched_source_sha256':{'NativeAdrenoPublish.cpp':sha(stage/'NativeAdrenoPublish.cpp'),header.name:sha(stage/header.name)}}
