#!/usr/bin/env python3
"""Sanitize actual cold GPIO and bounded GENI parser/programming source."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from native_driver_build import ROOT,require,sha
from input_geni_overlay import verify,BASE,PATCH

OUT=ROOT/'build/cph2653-input-cold'

def check(out=OUT,synthetic=False):
    out.mkdir(parents=True,exist_ok=True);shared=ROOT/'sources/UniXNU-sm8750-common/kits/Sm8750Platform';geni=ROOT/'sources/UniXNU/drivers/QcomGeniSpi';source=verify()
    flags=['-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie']
    common=['/usr/bin/g++','-std=c++17',*flags,'-no-pie','-I',ROOT/'drivers/DodgeInput','-I',shared,'-I',geni]
    cobject=out/'GeniSpi.host.o';subprocess.run(['/usr/bin/gcc','-std=c11',*flags,'-I',geni,'-c',source,'-o',cobject],check=True)
    groups=[('gpio',[ROOT/'tests/DodgePmicGpioTest.cpp'],[]),
            ('geni',[ROOT/'tests/DodgeGeniFirmwareTest.cpp',ROOT/'drivers/DodgeInput/DodgeGeniFirmware.cpp',cobject],
             ['--synthetic'] if synthetic else [ROOT/'build/ios16-touch-firmware/stock-spi-sefw.bin'])]
    records={}
    for name,files,args in groups:
        binary=out/('cold-'+name+'-host');subprocess.run([*common,*files,'-o',binary],check=True)
        ran=subprocess.run([binary,*args],capture_output=True,text=True,timeout=120,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        (out/('cold-'+name+'-host.log')).write_text(ran.stdout+ran.stderr);require(ran.returncode==0,'Cold input '+name+' sanitizer failed; see log')
        record=json.loads(ran.stdout);require(record['result']=='PASS','Invalid cold input host record')
        records[name]={**record,'binary':str(binary.relative_to(ROOT)),'sha256':sha(binary)}
    files=[Path(__file__),ROOT/'drivers/DodgeInput/DodgeGeniFirmware.cpp',ROOT/'drivers/DodgeInput/DodgeGeniFirmware.h',ROOT/'drivers/DodgeInput/DodgePmicGpio.h',
           ROOT/'drivers/DodgeInput/DodgeTouchPower.h',ROOT/'tests/DodgePmicGpioTest.cpp',ROOT/'tests/DodgeGeniFirmwareTest.cpp',source,BASE,PATCH,
           ROOT/'scripts/input_geni_overlay.py',geni/'GeniSpi.h',shared/'PeripheralIO.h']
    report={'result':'CPH2653_COLD_GPIO_AND_STOCK_SPI_FIRMWARE_SOURCE_SANITIZERS_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'tests':records,'case_count':sum(r['case_count'] for r in records.values()),
            'synthetic_firmware':synthetic,'firmware_sha256':None if synthetic else sha(ROOT/'build/ios16-touch-firmware/stock-spi-sefw.bin'),
            'mmio_and_clock_behavior_are_register_model_peers':True,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Production cold GPIO and raw SEFW parser/programmer under ASan/UBSan/LeakSanitizer. Input/output modes, rail electrical-field preservation, write order, ownership/read/write errors, '
                    'every truncated firmware extent and programming-write readback failure are checked. No actual PMIC/GENI/firmware execution or cold hardware qualification.'}
    if not synthetic:(ROOT/'reports/ios16-input-cold-host.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/('synthetic-host-cases.json' if synthetic else 'host-cases.json')).write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(report['case_count'])+' cold GPIO/GENI sanitizer cases; '+str(records['geni']['fault_injections'])+' individual firmware-write failures; '+('synthetic tables' if synthetic else 'exact stock firmware'))
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--synthetic',action='store_true');args=p.parse_args();check(synthetic=args.synthetic)
