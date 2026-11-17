#!/usr/bin/env python3
"""Execute full original iPhone EventDriver/EventService init, stop and free with public API peers."""
import argparse
import gc
import hashlib
import json
from pathlib import Path
import struct

from build_hid_lifecycle import REPORT as SOURCE_REPORT, check_report as check_source
from hid_lifecycle_layout import compile_layout
from hid_lifecycle_model import HidModel, BLOCKS, DRIVER_FREE, SERVICE_FREE
from native_driver_build import ROOT, require, sha
from prepare_hid_event_abi import CONTRACT
from check_hid_parser import context

OUT=ROOT/'build/ios16-hid-original-lifecycle'
REPORT=ROOT/'reports/ios16-hid-original-lifecycle.json'
CASES=('normal','init-parent-failure','init-service-allocation-failure','init-driver-allocation-failure',
    'init-dictionary-failure','timers','timers-no-loop','driver-owned-fields','service-owned-fields','gates-and-loops')


def clear_offsets(read,address,length):
    words=struct.unpack('<'+str(length//4)+'I',read(address,length))
    return sorted({((w>>10)&4095)*8 for w in words if w&0xffc003ff==0xf900003f})


def execute_case(raw,facts,name):
    m=HidModel(raw,facts,case=name);ok=m.call('_hid_driver_init',[m.obj,0])
    expected=not name.startswith('init-');require(ok==int(expected),'Original EventDriver init result differs: '+name)
    service,driver=m.qword(m.obj+192),m.qword(m.obj+256)
    require(bool(driver)==expected,'Original EventDriver allocation state differs')
    if not expected:
        m.canaries();return {'case':name,'result':'PASS','initialized':False,
            'quarantined_expansions':[row['bytes'] for row in m.allocations.values() if row['label'].endswith('expansion')],
            'original_instructions':len(m.original_visits),'allocator_failure_is_explicit_injection': 'allocation' in name}
    if name in ('timers','timers-no-loop','gates-and-loops'):
        for offset in (120,136,352):m.putq(service+offset,m.resource('timer-'+str(offset)))
        if name!='timers-no-loop':m.putq(service+8,m.loop);m.refs[m.loop]+=1
    if name=='driver-owned-fields':
        for offset in clear_offsets(m.original_read,DRIVER_FREE,0x4a8):
            if offset not in (496,504):m.putq(driver+offset,m.resource('driver-field-'+str(offset)))
        m.putq(m.obj+232,m.resource('driver-object-field-232'))
    if name=='service-owned-fields':
        for offset in (16,40):m.putq(service+offset,m.resource('service-field-'+str(offset)))
        m.putq(service,m.provider);m.refs[m.provider]+=1
    if name=='gates-and-loops':
        m.putq(driver+496,m.loop);m.refs[m.loop]+=1
        m.putq(driver+504,m.resource('driver-gate'));m.putq(service+24,m.resource('service-gate'))
    m.call('_hid_service_stop',[m.obj,m.provider]);require(m.original_stop_calls==m.native_stops==1,'Original full stop did not reach native parent')
    for offset in (120,136,352):require(not m.qword(service+offset),'Original stop left its timer populated')
    m.call('_hid_driver_free',[m.obj]);m.canaries()
    require(m.native_frees==1 and len(m.freed)==2 and not m.locks,'Original full EventDriver/EventService cleanup incomplete')
    require(all(value==m.initial_refs.get(pointer,0) for pointer,value in m.refs.items()),'Original free leaked or repeated owned releases')
    return {'case':name,'result':'PASS','initialized':True,'original_instructions':len(m.original_visits),
        'original_stop_calls':m.original_stop_calls,'native_parent_stop_calls':m.native_stops,
        'typed_expansion_bytes':[m.allocations[p]['bytes'] for p in m.freed],
        'released_object_fields':sum(1 for p,n in m.refs.items() if p not in m.initial_refs and n==0),
        'canceled_timers':m.events.count('cancel-timer'),'removed_event_sources':m.events.count('remove-source')}


def check_report(report):
    require(report['result']=='IOS16_ORIGINAL_EVENT_DRIVER_INIT_STOP_FREE_CPU_PASS' and len(report['cases'])==len(CASES) and
        report['no_original_lifecycle_body_peers'] and not report['hardware_tested'],'Incomplete original HID lifetime evidence')
    for name,digest in {**report['source_sha256'],**report['dependency_report_sha256'],**report['artifacts']}.items():
        require(sha(ROOT/name)==digest,'Original HID lifetime input changed: '+name)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: full original EventDriver/EventService init, stop and free bodies');return
    source=json.loads(SOURCE_REPORT.read_text());check_source(source);OUT.mkdir(parents=True,exist_ok=True)
    facts,artifacts=compile_layout(OUT/'abi');raw,read,_,_=context()
    contract=json.loads(CONTRACT.read_text());require(hashlib.sha256(raw).hexdigest()==contract['original_kernelcache_sha256'],'Wrong original iPhone HID image')
    cases=[]
    for case in CASES:
        try:cases.append(execute_case(raw,facts,case))
        except Exception as error:raise ValueError('Original HID '+case+': '+str(error)) from error
        gc.collect()
    # This deliberately injected state remains quarantined by production code.
    unsafe=HidModel(raw,facts,case='init-driver-allocation-failure')
    require(unsafe.call('_hid_driver_init',[unsafe.obj,0])==0,'Need the original failed-driver-init state')
    try:unsafe.call('_hid_driver_free',[unsafe.obj])
    except unsafe.u.UcError as error:
        require(error.errno==unsafe.u.UC_ERR_READ_UNMAPPED,'Unexpected original partial-free failure')
    else:raise ValueError('Original null expansion unexpectedly accepted by free')
    files=[Path(__file__),ROOT/'scripts/hid_lifecycle_model.py',ROOT/'scripts/hid_lifecycle_layout.py',
        ROOT/'scripts/check_hid_parser.py',ROOT/'scripts/check_data_mount_kernel.py',CONTRACT]
    report={'result':'IOS16_ORIGINAL_EVENT_DRIVER_INIT_STOP_FREE_CPU_PASS','compiler_layout':facts,
        'cases':cases,'original_kernelcache_sha256':hashlib.sha256(raw).hexdigest(),
        'original_function_blocks':{name:{'address':hex(address),'bytes':size,'sha256':hashlib.sha256(read(address,size)).hexdigest()}
            for name,(address,size) in BLOCKS.items()},'driver_resource_offsets_cleared':clear_offsets(read,DRIVER_FREE,0x4a8),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'dependency_report_sha256':{str(SOURCE_REPORT.relative_to(ROOT)):sha(SOURCE_REPORT)},
        'artifacts':{str(p.relative_to(ROOT)):sha(p) for p in artifacts},
        'unsafe_partial_free_control':{'result':'REJECTED','state':'deliberately injected null driver expansion'},
        'no_original_lifecycle_body_peers':True,'hardware_tested':False,'phone_operations':'none',
        'scope':'Complete unchanged original EventDriver/EventService init, stop and free bodies execute, including '
        'typed 376/512-byte expansion metadata, three timer branches, observed owned fields and gate/workloop cleanup. '
        'Public allocator/lock/dictionary/refcount/registry/log/native-IOService peers are explicit; full original startup, '
        'matching, clients and physical input are not qualified. Failure cases inject unavailable allocations and do not '
        'claim the original no-fail allocator actually fails. Production retains partial-init quarantine.'}
    check_report(report);REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: ten full original HID init/stop/free cases, exact expansion sizes and partial-free rejection')


if __name__=='__main__':main()
