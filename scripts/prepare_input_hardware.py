#!/usr/bin/env python3
"""Derive a target input header from the hash-pinned captured DTB, offline."""
import argparse
import json
from pathlib import Path
import urllib.request
from compare_oneplus13t import read_fdt, registers, find, node_path
from native_driver_build import ROOT, require, sha

HEADER=ROOT/'drivers/DodgeInput/PaganiPeripherals.h'
FACTS=ROOT/'hardware/dodge-input.json'

def derive():
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    for spec in lock['dodge_input_register_references']['files']:
        p=ROOT/spec['path']
        if not p.exists():
            p.parent.mkdir(parents=True,exist_ok=True)
            with urllib.request.urlopen(spec['url'],timeout=60) as r:p.write_bytes(r.read())
        require(sha(p)==spec['sha256'],'Input register reference changed: '+str(p))
    capture=json.loads((ROOT/'analysis/oneplus13-hardware-info.json').read_text())
    dtb=Path(capture['source_directory'])/'device-tree.dtb'
    expected='f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11'
    require(sha(dtb)==expected,'Original captured DTB changed')
    root=read_fdt(dtb.read_bytes());handles={n.scalar('phandle'):n for n in root.walk() if 'phandle' in n.properties}
    t=find(root,'synaptics_tcm_hbp@0');require(t.strings('compatible')==['synaptics,tcm-spi-hbp'],'Wrong touch driver')
    spmi=find(root,'qcom,spmi@c42d000');spmi_regs=dict(zip(spmi.strings('reg-names'),registers(spmi)))
    avdd=t.cells('synaptics,avdd-gpio');controller=handles[avdd[0]]
    ppid=controller.parent.cells('reg')[0]*256+(controller.cells('reg')[0]+0x100*(avdd[1]-1))//256
    down=find(root,'vol_down');key_gpio=down.cells('gpios');key_controller=handles[key_gpio[0]]
    key_ppid=key_controller.parent.cells('reg')[0]*256+(key_controller.cells('reg')[0]+0x100*(key_gpio[1]-1))//256
    pon=find(root,'pon_hlos@1300');pon_children=[n for n in pon.children if 'linux,code' in n.properties]
    keys={n.scalar('linux,code'):n.cells('interrupts') for n in pon_children}
    require(keys=={0x74:[0,0x13,7,3],0x73:[0,0x13,6,3]} and down.scalar('linux,code')==0x72 and
            key_gpio[1:]==[6,1] and down.scalar('debounce-interval')==32,'Key wiring changed')
    supply=handles[t.scalar('vdd-supply')];rsc=supply.parent.parent.parent
    rsc_regs=dict(zip(rsc.strings('reg-names'),registers(rsc)));db=find(root,'aop_cmd_db_region@81c60000')
    require(supply.strings('regulator-name')==['pm_humu_l4'] and supply.scalar('regulator-min-microvolt')==1800000 and
            supply.scalar('regulator-max-microvolt')==1800000 and supply.parent.strings('qcom,resource-name')==['ldob4'],'VDD changed')
    pin_drives={}
    for ph in t.parent.cells('pinctrl-0')+t.cells('pinctrl-0'):
        state=handles[ph];mux=find(state,'mux');cfg=find(state,'config')
        for pin in mux.strings('pins'):pin_drives[int(pin[4:])]=cfg.scalar('drive-strength')//2-1
    pins=[48,49,50,51,t.cells('synaptics,reset-gpio')[1],t.cells('synaptics,irq-gpio')[1]]
    iommu=t.parent.parent.cells('iommus');smmu=registers(handles[iommu[0]])[0]
    driver=(ROOT/'.cache/input-reference/s3910-platform-spi.c').read_text()
    require('int state = (en) ? pwr->power_on_state : !pwr->power_on_state;' in driver and
            'gpio_direction_output(pwr->avdd_gpio, state)' in driver and
            'pwr->power_on_state = value;' in driver,'Original compatible GPIO level semantics changed')
    reset=t.scalar('synaptics,reset-on-state');on=t.scalar('synaptics,power-on-state')
    require(reset==0 and on==1 and ppid==0x98a and key_ppid==0x18d,'Target pin policy changed')
    v={
        'GCC_BASE':'0x100000ULL','TOUCH_SE':hex(registers(t.parent)[0][0])+'ULL',
        'TOUCH_WRAPPER':hex(registers(t.parent.parent)[0][0])+'ULL','TOUCH_SMMU':hex(smmu[0])+'ULL',
        'TOUCH_SMMU_SIZE':hex(smmu[1]),'TOUCH_SMMU_SID':hex(iommu[1]),
        'TLMM_GPIO(n)':'(0xf100000ULL+0x1000ULL*(n))','TOUCH_RESET':str(pins[4]),'TOUCH_ATTN':str(pins[5]),
        'TOUCH_PINS':'{'+','.join(map(str,pins))+'}','TOUCH_DRIVES':'{'+','.join(str(pin_drives[n]) for n in pins)+'}',
        'TOUCH_RESET_MS':str(t.scalar('synaptics,reset-active-ms')),'TOUCH_STARTUP_MS':str(t.scalar('synaptics,reset-delay-ms')),
        'TOUCH_HZ':str(t.scalar('spi-max-frequency')),'TOUCH_CS_DELAY':'50','TOUCH_WORD_DELAY':'0',
        'TOUCH_RSC':hex(rsc_regs['drv-2'][0])+'ULL','TOUCH_RSC_SIZE':hex(rsc_regs['drv-2'][1]),
        'CMD_DB':hex(registers(db)[0][0])+'ULL','CMD_DB_SIZE':hex(registers(db)[0][1]),
        'TOUCH_VDD':'"ldob4"','TOUCH_VDD_VRM':'0x40800','TOUCH_VDD_MV':'1800',
        'TOUCH_POWER_MS':str(t.scalar('synaptics,power-delay-ms')),'TOUCH_EDGE_PIXELS':'48',
        'SPMI_CORE':hex(spmi_regs['core'][0])+'ULL','SPMI_CNFG':hex(spmi_regs['cnfg'][0])+'ULL',
        'SPMI_OBS':hex(spmi_regs['obsrvr'][0])+'ULL','SPMI_CHANNELS':hex(spmi_regs['chnls'][0])+'ULL',
        'SPMI_CHANNEL_BYTES':hex(spmi_regs['chnls'][1]),'SPMI_EE':str(spmi.scalar('qcom,ee')),
        'AVDD_PPID':hex(ppid),'AVDD_ON':str(on),'PON_PPID':'0x013','GPIO_PPID':hex(key_ppid),
        'PON_POWER':'0x80','PON_VOLUME_UP':'0x40','GPIO_VOLUME_DOWN':'1'}
    header='// SPDX-License-Identifier: BSD-2-Clause-Patent\n// CPH2653 captured DTB + matching original HBP driver semantics.\n// PAGANI names only preserve source include compatibility; no 13T rail policy.\n#pragma once\n'
    header+=''.join('#define PAGANI_'+n+' '+x+'\n' for n,x in v.items())
    facts={'schema_version':1,'device':'OnePlus 13 CPH2653 / dodge','captured_dtb_sha256':expected,
           'compatible':t.strings('compatible')[0],'spmi_registers':{n:{'base':hex(a),'bytes':z} for n,(a,z) in spmi_regs.items()},
           'avdd':{'controller':node_path(controller),'gpio':avdd[1],'raw_gpio_flags':avdd[2],'ppid':hex(ppid),
                   'physical_on_level':on,'level_source':'synaptics,power-on-state consumed by raw gpio_direction_output in the matching HBP driver',
                   'policy':'validate existing VIN/normal mux/CMOS strength/no DTEST, preload output, initialize input or disabled GPIO, preserve input-enable and electrical fields; no invented rail voltage or drive policy'},
           'vdd':{'resource':'ldob4','millivolts':1800,'expected_vrm_address':'0x40800','runtime_cmd_db_match_required':True},
           'reset_active_ms':t.scalar('synaptics,reset-active-ms'),'reset_delay_ms':t.scalar('synaptics,reset-delay-ms'),
           'power_delay_ms':t.scalar('synaptics,power-delay-ms'),'keys':{'pon_ppid':'0x013','power_bit':128,'volume_up_bit':64,
                      'volume_down_ppid':hex(key_ppid),'volume_down_active_low':True,'debounce_ms':32},
           'register_reference_files':lock['dodge_input_register_references']['files'],
           'reference_only_policy':{'cs_delay_units':50,'edge_pixels':48,'vdd_vrm_address_requires_runtime_lookup':True},
           'gpio_cold_initialization_qualified':False,'hardware_tested':False}
    return header,facts

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
    header,facts=derive()
    if a.write:
        require(not HEADER.exists() and not FACTS.exists(),'Refuse to replace reviewed input facts')
        HEADER.write_text(header);FACTS.write_text(json.dumps(facts,indent=2)+'\n')
    require(HEADER.read_text()==header and json.loads(FACTS.read_text())==facts,'Reviewed target input header/facts changed')
    report={'result':'CPH2653_INPUT_WIRING_AND_COMPATIBLE_POWER_POLICY_PASS','builder_sha256':sha(Path(__file__)),'source_sha256':{str(x.relative_to(ROOT)):sha(x) for x in
            (Path(__file__),ROOT/'scripts/compare_oneplus13t.py',HEADER,FACTS)},'header_sha256':sha(HEADER),'facts_sha256':sha(FACTS),
            'captured_dtb_sha256':facts['captured_dtb_sha256'],'raw_gpio_flags_used_as_logical_level':False,
            'vdd_only_rpmh_resource':'ldob4','donor_ldob16_selected':False,'hardware_tested':False,'ready_for_ios_boot':False}
    (ROOT/'reports/ios16-input-hardware.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: target power/key wiring, physical AVDD high, reset 10/80 ms, VDD 1.8 V; no donor LDO16')

if __name__=='__main__':main()
