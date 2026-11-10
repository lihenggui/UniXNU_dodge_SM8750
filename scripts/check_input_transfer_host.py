#!/usr/bin/env python3
"""Sanitize the actual local GENI transport/terminal guard and original control."""
import json
import os
from pathlib import Path
import subprocess
from native_driver_build import ROOT,require,sha
from input_geni_overlay import verify,BASE,PATCH

OUT=ROOT/'build/cph2653-input-transfer'

def check(out=OUT):
    out.mkdir(parents=True,exist_ok=True);source=verify()
    header=BASE.parent/'GeniSpi.h';guard=ROOT/'drivers/DodgeInput/DodgeGeniTransfer.cpp';test=ROOT/'tests/DodgeGeniTransferTest.cpp'
    flags=['-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
           '-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie']
    results={}
    for kind,csource,argument in (('production',source,'--production'),('original-control',BASE,'--original-control')):
        obj=out/(kind+'-geni.o');binary=out/(kind+'-transfer-host')
        subprocess.run(['/usr/bin/gcc','-std=c11',*flags,'-I',str(header.parent),'-c',str(csource),'-o',str(obj)],check=True)
        subprocess.run(['/usr/bin/g++','-std=c++17',*flags,'-no-pie','-I',str(header.parent),'-I',str(guard.parent),
                        str(test),str(guard),str(obj),'-o',str(binary)],check=True)
        run=subprocess.run([binary,argument],capture_output=True,text=True,timeout=60,
                           env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1','UBSAN_OPTIONS':'halt_on_error=1'})
        (out/(kind+'-transfer-host.log')).write_text(run.stdout+run.stderr)
        require(run.returncode==0,'GENI '+kind+' transfer checks failed; inspect '+str(out/(kind+'-transfer-host.log')))
        results[kind]={**json.loads(run.stdout),'binary':str(binary.relative_to(ROOT)),'sha256':sha(binary)}
    require(results['production']['result']=='PASS' and results['original-control']['result']=='REJECTED','Transfer production/control outcome changed')
    files=[Path(__file__),ROOT/'scripts/input_geni_overlay.py',source,BASE,PATCH,header,guard,guard.with_suffix('.h'),test]
    report={'result':'CPH2653_GENI_TRANSFER_COMPLETION_RECOVERY_AND_TERMINAL_SOURCE_SANITIZERS_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'case_count':results['production']['case_count'],
            'tests':results,'local_overlay':json.loads((ROOT/'upstream.lock.json').read_text())['dodge_geni_transfer_overlay'],
            'original_source_unchanged':True,'dma_command_data_and_idle_all_required':True,'bounded_cancel_abort_and_requested_channel_reset_ack':True,
            'terminal_error_disables_future_io':True,'mmio_slave_dma_cache_and_reset_behavior_are_peers':True,
            'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual local C transport and C++ ownership/terminal guard under ASan/UBSan/LeakSanitizer. '
                    'Original component control demonstrates data-DMA completion returning while command/wire is active and invalidating RX early. '
                    'The local derivative waits data+command+idle, bounds FIFO extents/cancel/abort/channel-reset ACK and never retries a failed device. '
                    'No physical DMA, SMMU, cache, controller-reset or touch functionality is qualified.'}
    (ROOT/'reports/ios16-input-transfer-host.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'transfer-host-cases.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(report['case_count'])+' actual GENI transport/guard sanitizer cases; unchanged original early-DMA completion control rejected')
    return report

if __name__=='__main__':check()
