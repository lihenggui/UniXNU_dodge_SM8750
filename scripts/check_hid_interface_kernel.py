#!/usr/bin/env python3
"""Execute unchanged iPhone IOHIDInterface ownership and EventDriver termination."""
import argparse
import gc
import hashlib
import json
from pathlib import Path

from build_hid_lifecycle import REPORT as SOURCE_REPORT, check_report as check_source
from check_hid_parser import context
from hid_interface_model import InterfaceModel
from hid_lifecycle_layout import compile_layout
from native_driver_build import ROOT, build_objects, pinned_sources, require, sha
from prepare_hid_event_abi import CONTRACT, methods

REPORT=ROOT/'reports/ios16-hid-interface-kernel.json'
OUT=ROOT/'build/ios16-hid-interface-kernel'
CASES=('normal','init-parent-failure','init-allocation-failure','interface-open-failure','owner-open-failure',
    'no-owner','with-pool','with-report-action','with-pool-and-action','close-twice','reopen',
    'driver-terminate','driver-terminate-no-interface','driver-terminate-defer')


def compile_reference():
    refs=pinned_sources(('iohid_headers_reference','iphoneos_sdk_reference'))
    source=OUT/'InterfaceHeaderReference.cpp'
    source.write_text('#include <IOKit/hid/IOHIDInterface.h>\nOSDefineMetaClassAndStructors(IOHIDInterface,IOService)\n'
        'static_assert(sizeof(IOHIDInterface)==264,"Original interface extent");\n'
        'static_assert(sizeof(AbsoluteTime)==8 && sizeof(IOHIDReportType)==4 && sizeof(IOOptionBits)==4,"Interface argument widths");\n')
    target=refs['iphoneos_sdk_reference']/'iPhoneOS16.5.sdk/usr/include/TargetConditionals.h'
    obj,=build_objects([source],OUT/'reference',[ROOT/'build/ios16-hid-event-abi/include'],
        ['-include',str(target),'-Wno-macro-redefined','-Wno-deprecated-declarations'])
    names=methods(obj,'IOHIDInterface')
    require(len(names)==187 and names[89]=='__ZN14IOHIDInterface5closeEP9IOServicej' and
        names[168]=='__ZN14IOHIDInterface4openEP9IOServicejPFvP8OSObjectyP18IOMemoryDescriptor15IOHIDReportTypejPvES7_' and
        names[181]=='__ZN14IOHIDInterface12handleReportEyP18IOMemoryDescriptor15IOHIDReportTypejj',
        'Public interface close/report prototypes changed')
    return [source,obj,OUT/'reference/compile-commands.json'],[refs['iohid_headers_reference']/'IOHIDFamily/IOHIDInterface.h',target]


def execute(raw,facts,case):
    m=InterfaceModel(raw,facts,case);f=m.interface
    m.call('_interface_constructor',[m.obj]);require(m.qword(m.obj)==f['vptr'],'Original interface constructor installed another table')
    ok=m.call('_interface_init',[m.obj,0]);failed=case.startswith('init-')
    require(ok==int(not failed),'Original interface init result differs')
    if not failed:
        reserved=m.qword(m.obj+f['reserved']);m.putq(reserved+f['gate'],m.interface_gate)
        if case=='interface-open-failure':m.interface_fail_open=m.obj
        if case=='owner-open-failure':m.interface_fail_open=m.interface_owner
        opened=case not in ('interface-open-failure','owner-open-failure','no-owner','driver-terminate-no-interface')
        if case!='driver-terminate-no-interface':
            require(m.call('_interface_open',[m.obj,m.provider,0x10000002,0x12340000,0x56780000])==int(opened),
                'Original interface open result differs')
        if opened:
            require(m.interface_callbacks()==[0x12340000,0x56780000,m.provider],
                'Original interface changed target/action/refcon publication')
            if case in ('with-pool','with-pool-and-action'):m.putq(reserved+f['pool'],m.resource('report-pool'))
            if case in ('with-report-action','with-pool-and-action'):m.putq(reserved+f['report_action'],m.resource('report-action'))
        else:require(not m.interface_opened and m.interface_callbacks()==[0,0,0],'Failed interface open retained a callback/client')
        if case.startswith('driver-terminate'):
            # Original didTerminate only uses the measured weak interface field;
            # the caller's remaining native IOService state is a public peer.
            client=m.provider;m.put(client-16,b'\xa5'*16+bytes(264)+b'\xa5'*16);m.putq(client,m.driver_vptr)
            m.putq(client+200,0 if case=='driver-terminate-no-interface' else m.obj)
            output=m.heap+0xd000;m.put(output-16,b'\xa5'*33);m.put(output,bytes([case=='driver-terminate-defer']))
            require(m.call('_interface_driver_did_terminate',[client,m.obj,0xa0000002,output])==1,'Original driver termination result differs')
            require(not m.qword(client+200) and len(m.interface_termination_calls)==1,'Original termination left its weak interface or skipped native notification')
            row=m.interface_termination_calls[0]
            require(row=={'object':client,'provider':m.obj,'options':0xa0000002,'defer_on_entry':int(case=='driver-terminate-defer')},
                'Original termination changed native callback arguments')
            require(m.read(output,1)==bytes([case=='driver-terminate-defer']) and
                m.read(output-16,16)==m.read(output+1,16)==b'\xa5'*16,'Original termination overwrote caller output')
        elif opened:
            m.call('_interface_close',[m.obj,m.provider,0x10000002])
            if case=='close-twice':m.call('_interface_close',[m.obj,m.provider,0x10000002])
            if case=='reopen':
                require(m.call('_interface_open',[m.obj,m.provider,0,0x12340004,0x56780004])==1,'Original interface failed to reopen')
                m.call('_interface_close',[m.obj,m.provider,0])
        require(not m.interface_opened and m.interface_callbacks()==[0,0,0],'Original close retained callback/client ownership')
        require(not m.qword(reserved+f['report_action']),'Original close retained report action')
    m.canaries();m.interface_canaries()
    return {'case':case,'result':'PASS','original_instructions_executed':len(m.original_visits),
        'native_open_attempts':m.interface_open_attempts,'original_interface_close_calls':m.interface_close_calls,
        'original_close_block_calls':m.interface_gate_calls,'pool_flushes':m.interface_flushes,
        'native_termination_notifications':len(m.interface_termination_calls)}


def check_report(report):
    require(report['result']=='IOS16_ORIGINAL_HID_INTERFACE_OWNERSHIP_AND_TERMINATION_CPU_PASS' and
        len(report['cases'])==len(CASES) and not report['hardware_tested'],'Incomplete original interface evidence')
    for name,digest in {**report['source_sha256'],**report['dependency_report_sha256'],**report['artifacts']}.items():
        require(sha(ROOT/name)==digest,'Original interface input changed: '+name)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if args.check_only:
        check_report(json.loads(REPORT.read_text()));print('PASS: fourteen original interface ownership/termination cases');return
    check_source(json.loads(SOURCE_REPORT.read_text()));OUT.mkdir(parents=True,exist_ok=True)
    facts,artifacts=compile_layout(OUT/'abi');reference,reference_inputs=compile_reference();artifacts+=reference
    raw,read,_,_=context()
    require(hashlib.sha256(raw).hexdigest()==json.loads(CONTRACT.read_text())['original_kernelcache_sha256'],'Wrong original iPhone interface image')
    cases=[]
    for case in CASES:
        try:cases.append(execute(raw,facts,case))
        except Exception as error:raise ValueError('Original interface '+case+': '+str(error)) from error
        gc.collect()
    f=InterfaceModel(raw,facts,'normal').interface
    files=[Path(__file__),ROOT/'scripts/hid_interface_model.py',ROOT/'scripts/hid_lifecycle_model.py',
        ROOT/'scripts/hid_lifecycle_layout.py',ROOT/'scripts/check_hid_parser.py',CONTRACT,*reference_inputs]
    blocks={'constructor':(f['constructor'],32),'init':(f['init'],0x58),'open':(f['open'],0xa0),
        'close':(f['close'],0xb4),'close_block':(f['close_block'],0x60),'driver_did_terminate':(f['driver_did_terminate'],0x6c),
        'handle_report':(f['handle_report'],48)}
    report={'result':'IOS16_ORIGINAL_HID_INTERFACE_OWNERSHIP_AND_TERMINATION_CPU_PASS','cases':cases,'original_interface':f,
        'original_kernelcache_sha256':hashlib.sha256(raw).hexdigest(),
        'original_function_blocks':{n:{'address':hex(a),'bytes':size,'sha256':hashlib.sha256(read(a,size)).hexdigest()} for n,(a,size) in blocks.items()},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
        'dependency_report_sha256':{str(SOURCE_REPORT.relative_to(ROOT)):sha(SOURCE_REPORT)},
        'artifacts':{str(p.relative_to(ROOT)):sha(p) for p in artifacts},'hardware_tested':False,'phone_operations':'none',
        'scope':'Unchanged original interface constructor/init/open/close and close-block bodies execute, plus original EventDriver '
        'didTerminate. The 264-byte object, 64-byte typed expansion and callback/owner/gate fields are derived from pinned iPhone '
        'instructions and public compiler metadata. Public native IOService arbitration/open/close/termination, command-gate '
        'execution, pool flush and reference primitives are explicit peers. Full interface startup/matching/free, elements, '
        'IOService scheduler/DriverKit clients and physical input lifetime remain unqualified.'}
    check_report(report);REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: fourteen unchanged original interface ownership/termination cases')


if __name__=='__main__':main()
