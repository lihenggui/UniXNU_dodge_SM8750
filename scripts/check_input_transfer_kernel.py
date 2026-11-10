#!/usr/bin/env python3
"""Execute the actual linked ARM64 GENI transport/terminal guard, with bus peers."""
from collections import deque
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,require,sha,symbols,macho
from build_input_native import fresh

SPI_FIELDS=('oversampling','tx_wm','cur_bpw','cur_speed_hz','last_mode','last_cs','poll_limit','poll_only',
            'snap_irq','snap_status','snap_valid','use_dma')
INFO_FIELDS=('fw_revision','protocol','tx_fifo_depth','fifo_width_bits')
DMA_FIELDS=('ctx','clean','clean_inval','inval','tx_virt','rx_virt','tx_phys','rx_phys','size')
CASES=('pio-duplex','pio-rx-maximum','pio-tx-maximum','dma-duplex','dma-rx-maximum','dma-tx-maximum',
       'dma-command-timeout','dma-reset-timeout','dma-abort-success','dma-abort-failure','dma-stale-reset',
       'foreign-descriptor','engine-busy','pio-zero-word-last','pio-overdepth','terminal-reentry',
       'mode-mismatch','firmware-mismatch','invalid-length','post-gpi-intrusion')

def layout():
    out=ROOT/'build/ios16-input-transfer-abi';out.mkdir(parents=True,exist_ok=True)
    source=out/'DodgeTransferLayout.cpp'
    labels=['spi_bytes','io_bytes','spi_se',*SPI_FIELDS,*['info_'+n for n in INFO_FIELDS],*['dma_'+n for n in DMA_FIELDS]]
    values=['sizeof(geni_spi)','sizeof(geni_io)','offsetof(geni_spi,se)',
            *[f'offsetof(geni_spi,{n})' for n in SPI_FIELDS],
            *[f'offsetof(geni_spi,info)+offsetof(geni_spi_info,{n})' for n in INFO_FIELDS],
            *[f'offsetof(geni_spi,dma)+offsetof(decltype(geni_spi::dma),{n})' for n in DMA_FIELDS]]
    source.write_text('#include <stddef.h>\n#include "DodgeGeniTransfer.h"\nextern "C" const unsigned dodge_transfer_layout[]={'+','.join(values)+'};\n')
    obj,=build_objects([source],out,[ROOT/'drivers/DodgeInput',ROOT/'sources/UniXNU/drivers/QcomGeniSpi'])
    raw=obj.read_bytes();im=inspect_object(raw);symbol,=[s for s in symbols(raw) if not s['kind']&0xe0 and s['name']=='_dodge_transfer_layout']
    section=next(s for seg in im['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    at=section['fileoff']+symbol['value']-section['va'];facts=dict(zip(labels,struct.unpack_from('<'+str(len(labels))+'I',raw,at)))
    require(facts['io_bytes']==32 and facts['spi_se']==0,'Native transfer callback layout differs')
    return facts,obj

def emulate(path,case,facts):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();im=macho(raw);table=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14]
    names={s['name']:s['value'] for s in table};addresses={s['value'] for s in table}
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(address,data=b'',size=0):
        start=address&~4095;end=(address+max(size,len(data))+4095)&~4095
        while start<end:
            if start in pages:start+=4096;continue
            stop=start+4096
            while stop<end and stop not in pages:stop+=4096
            uc.mem_map(start,stop-start);pages.update(range(start,stop,4096));start=stop
        if data:uc.mem_write(address,data)
    for s in im['segments']:
        if s['size'] and s['initprot']:put(s['va'],raw[s['fileoff']:s['fileoff']+s['filesize']],s['size'])
    spi,terminal,stack,halt=0x100040,0x110040,0x300000,0x400000
    tx,rx,dtx,drx=0x500040,0x502040,0x600040,0x602040
    length=519 if case.endswith('maximum') or case=='invalid-length' else 5
    for address,size in ((spi,facts['spi_bytes']),(terminal,4),(tx,length),(rx,length),(dtx,4096),(drx,4096)):
        put(address-64,b'\xa5'*(size+128));put(address,bytes(size))
    put(stack,size=65536);put(halt,size=4096)
    rd,wr,delay,clean,prepare,invalidate=[halt+i*0x100 for i in range(1,7)]
    ctx,cachectx=0x6e1c0ffee,0xcacec0ffee
    put(spi,struct.pack('<4Q',ctx,rd,wr,delay))
    dma=not case.startswith('pio-')
    if case in ('terminal-reentry','invalid-length','engine-busy','mode-mismatch','firmware-mismatch'):dma=False
    def u32(label,value):put(spi+facts[label],struct.pack('<I',value&0xffffffff))
    for label,value in {'oversampling':1,'tx_wm':1,'cur_speed_hz':19000000,'poll_limit':8,
                        'poll_only':2 if dma else 1,'use_dma':int(dma),'info_fw_revision':0x102,
                        'info_protocol':1,'info_tx_fifo_depth':32,'info_fifo_width_bits':32}.items():u32(label,value)
    for label,value in {'ctx':cachectx,'clean':clean,'clean_inval':prepare,'inval':invalidate,
                        'tx_virt':dtx,'rx_virt':drx,'tx_phys':dtx,'rx_phys':drx,'size':4096}.items():
        put(spi+facts['dma_'+label],struct.pack('<Q',value))
    sent=bytes((i*7+3)&255 for i in range(length));put(tx,sent);put(rx,b'\xcc'*length)
    has_tx='-rx-' not in case;has_rx='-tx-' not in case
    if case=='invalid-length':length=520
    if case=='terminal-reentry':put(terminal,struct.pack('<i',-110))
    registers={0x68:0x102,0x258:int(dma),0x614:1};received=deque();writes=[];delays=[];cache=[]
    state={'active':False,'done':False,'command_polls':0,'commands':0,'reads':0,'tx_moved':0,'rx_moved':0,
           'tx_total':0,'rx_total':0,'data':False,'resets':[],'reset_acks':0,'last':False,'tx_reset':0,'rx_reset':0}
    if case=='foreign-descriptor':registers[0xc30]=1
    if case=='engine-busy':state['active']=True
    if case=='mode-mismatch':registers[0x258]=1
    if case=='firmware-mismatch':registers[0x68]=0x103
    command_timeout=case in ('dma-command-timeout','dma-reset-timeout','dma-abort-success','dma-abort-failure','dma-stale-reset')
    abort=case in ('dma-abort-success','dma-abort-failure')
    no_reset_ack=case in ('dma-reset-timeout','dma-stale-reset')
    def response(value,index):return ((value^0xa5)+index)&255
    def progress():
        if not state['active']:return
        if dma:
            if state['data']:
                state['command_polls']+=1
                if state['command_polls']>=3 and not command_timeout:
                    state['active']=False;state['done']=True;registers[0x610]=registers.get(0x610,0)|1
            return
        if not has_tx and has_rx:
            count=min(112,state['rx_total']-state['rx_moved'])
            for _ in range(count):received.append(response(0,state['rx_moved']));state['rx_moved']+=1
        value=registers.get(0x610,0)
        if received:value|=1<<26
        if has_tx and state['tx_moved']<state['tx_total']:value|=1<<30
        if (not has_tx or state['tx_moved']==state['tx_total']) and (not has_rx or state['rx_moved']==state['rx_total']):
            if has_rx and not state['last']:value|=1<<27;state['last']=True
            state['active']=False;state['done']=True;value|=1
        registers[0x610]=value
    def dma_data():
        if not state['active'] or state['data']:return
        if (has_tx and not registers.get(0xc3c)) or (has_rx and not registers.get(0xd3c)):return
        n=state['tx_total'] if has_tx else state['rx_total']
        if has_tx:
            address=registers.get(0xc30,0)|(registers.get(0xc34,0)<<32)
            require(address==dtx,'Native DMA TX pointer differs from owned buffer');payload=bytes(uc.mem_read(address,n))
            require(payload==sent[:n],'Actual native DMA staging changed TX bytes')
        else:payload=bytes(n)
        if has_rx:
            address=registers.get(0xd30,0)|(registers.get(0xd34,0)<<32)
            require(address==drx,'Native DMA RX pointer differs from owned buffer')
            put(address,bytes(response(v,i) for i,v in enumerate(payload)))
            registers[0xd40]=registers.get(0xd40,0)|1
        if has_tx:registers[0xc40]=registers.get(0xc40,0)|1
        state['data']=True
    def args():return [uc.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(value=0):uc.reg_write(arm.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(arm.UC_ARM64_REG_PC,uc.reg_read(arm.UC_ARM64_REG_LR))
    def read(a):
        require(a[0]==ctx and a[1]<0x4000 and not a[1]&3,'Native transfer read escaped SE mapping')
        state['reads']+=1
        reg=a[1]
        if reg==0x610:progress()
        if reg in (0xc40,0xd40):
            key='tx_reset' if reg==0xc40 else 'rx_reset'
            if state[key] and not no_reset_ack:
                state[key]-=1
                if not state[key]:registers[reg]=registers.get(reg,0)|8;state['reset_acks']+=1
        value=registers.get(reg,0)
        if reg==0x40:value=(value&~1)|(1 if state['active'] else 0)
        if reg==0x804:
            value=(len(received)+3)//4
            if state['commands'] and has_rx and state['rx_moved']==state['rx_total']:value|=1<<31|(state['rx_total']%4)<<28
            if state['commands'] and case=='pio-zero-word-last':value=1<<31|1<<28
            if state['commands'] and case=='pio-overdepth':value=33
        if reg==0x780:
            require(received,'Native FIFO read exceeded received byte extent');value=0
            for i in range(4):
                if not received:break
                value|=received.popleft()<<(8*i)
        if reg==0xe18 and case=='post-gpi-intrusion' and state['done']:value=1
        ret(value)
    def write(a):
        require(a[0]==ctx and a[1]<0x4000 and not a[1]&3 and a[2]<=0xffffffff,'Native transfer write escaped SE mapping/width')
        reg,value=a[1:3];writes.append((reg,value))
        if reg in (0x618,0xc44,0xd44):
            target={0x618:0x610,0xc44:0xc40,0xd44:0xd40}[reg];registers[target]=registers.get(target,0)&~value;ret();return
        if reg in (0xc4c,0xd4c):registers[reg]=registers.get(reg,0)|value;ret();return
        registers[reg]=value
        if reg==0x600:
            state.update(active=True,done=False,commands=state['commands']+1,tx_total=registers.get(0x26c,0) if has_tx else 0,
                         rx_total=registers.get(0x270,0) if has_rx else 0,data=False,command_polls=0,tx_moved=0,rx_moved=0,last=False)
            registers[0xc3c]=registers[0xd3c]=0
        if reg==0x700:
            n=min(4,state['tx_total']-state['tx_moved'])
            for i in range(n):
                byte=(value>>(8*i))&255
                require(byte==sent[state['tx_moved']],'Actual native FIFO packing changed TX bytes')
                if has_rx:received.append(response(byte,state['rx_moved']));state['rx_moved']+=1
                state['tx_moved']+=1
        if reg in (0xc3c,0xd3c):dma_data()
        if reg==0x604:
            if value&4 and not abort:
                registers[0x610]=registers.get(0x610,0)|16;state['active']=False
                if case=='dma-stale-reset':registers[0xc40]=registers.get(0xc40,0)|8
            if value&2 and case!='dma-abort-failure':registers[0x610]=registers.get(0x610,0)|32;state['active']=False
        if reg in (0xc58,0xd58):
            require(not state['active'],'Native DMA reset ran behind a live command')
            require(registers.get(0xc4c if reg==0xc58 else 0xd4c,0)&8,'Native reset completion source was not enabled')
            state['resets'].append(reg);state['tx_reset' if reg==0xc58 else 'rx_reset']=2
        ret()
    def wait(a):require(a[0]==ctx and a[1]==1,'Native transfer wait changed');delays.append(1);ret()
    def cache_op(kind,a):
        require(a[0]==cachectx and a[1]==(dtx if kind=='clean' else drx) and a[2]<=4096,'Native cache operation escaped owned DMA memory')
        if kind=='invalidate':require(state['done'] and not state['active'],'Native RX invalidated/copied before command/wire completion')
        cache.append(kind);ret()
    def zero(a):
        require(stack<=a[0] and a[0]+a[1]<=stack+65536,'Native transfer bzero escaped stack')
        put(a[0],bytes(a[1]));ret()
    callbacks={rd:read,wr:write,delay:wait,clean:lambda a:cache_op('clean',a),prepare:lambda a:cache_op('prepare',a),
               invalidate:lambda a:cache_op('invalidate',a),names['_bzero']:zero}
    allowed=[];functions=[]
    for filename in ('GeniSpi.o','DodgeGeniTransfer.o'):
        data=(ROOT/'build/cph2653-input-native'/filename).read_bytes();obj=inspect_object(data);sections=[s for seg in obj['segments'] for s in seg['sections']]
        for s in symbols(data):
            if s['kind']&0xe0 or s['kind']&14!=14 or not s['section'] or sections[s['section']-1]['name']!='__text' or s['name'].startswith('ltmp'):continue
            matches=[v['value'] for v in table if v['name']==s['name']];require(len(matches)==1,'Ambiguous native transfer function: '+s['name'])
            a=matches[0];allowed.append((a,min(v for v in addresses if v>a)-a));functions.append(s['name'])
    def hook(engine,address,size,user):
        if address in callbacks:callbacks[address](args());return
        require(any(a<=address<a+n for a,n in allowed),'Unqualified native transfer call: '+hex(address))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook);uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
    for i,value in enumerate((spi,tx if has_tx else 0,rx if has_rx else 0,length,terminal)):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),value)
    uc.emu_start(names['_dodge_geni_transfer'],halt,timeout=5000000,count=2000000)
    require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt,'Native transfer did not return within bound')
    value=uc.reg_read(arm.UC_ARM64_REG_X0)&0xffffffff;rc=value-(1<<32) if value&0x80000000 else value
    expected=-110 if command_timeout or case=='terminal-reentry' else {'foreign-descriptor':-16,'engine-busy':-16,'pio-zero-word-last':-5,
        'pio-overdepth':-5,'mode-mismatch':-16,'firmware-mismatch':-71,'invalid-length':-22,'post-gpi-intrusion':-16}.get(case,0)
    require(rc==expected,'Native transfer status differs: '+case+' '+str(rc));latched=struct.unpack('<i',bytes(uc.mem_read(terminal,4)))[0]
    require(latched==expected,'Native transfer did not latch exactly its first error')
    if not rc:
        require(state['done'] and not state['active'] and state['commands']==1,'Native transfer returned before wire completion')
        if has_rx:require(bytes(uc.mem_read(rx,length))==bytes(response(sent[i] if has_tx else 0,i) for i in range(length)),'Native RX data differs')
        if dma:require(cache==(['clean'] if has_tx else [])+(['prepare','invalidate'] if has_rx else []),'Native DMA cache ordering changed')
    if case in ('foreign-descriptor','engine-busy','mode-mismatch','firmware-mismatch','terminal-reentry','invalid-length'):
        require(not writes and not cache and not state['commands'],'Native refusal/terminal reentry performed I/O')
    if case in ('terminal-reentry','invalid-length'):require(not state['reads'],'Native terminal/argument refusal read hardware')
    if case=='dma-abort-failure':require(not state['resets'] and state['active'],'Failed native abort reset a live channel')
    if case in ('dma-reset-timeout','dma-stale-reset'):require(len(state['resets'])==1 and not state['reset_acks'],'Native reset timeout accepted stale/absent completion')
    if case in ('dma-command-timeout','dma-abort-success'):require(len(state['resets'])==2 and state['reset_acks']==2,'Native requested-channel reset ACK path missing')
    if command_timeout:
        require('invalidate' not in cache and bytes(uc.mem_read(rx,length))==b'\xcc'*length,'Native failed command exposed RX bytes/cache completion')
    if rc:
        before=(state['reads'],len(writes),len(delays),len(cache),state['commands'])
        uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
        for i,value in enumerate((spi,tx if has_tx else 0,rx if has_rx else 0,length,terminal)):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),value)
        uc.emu_start(names['_dodge_geni_transfer'],halt,timeout=5000000,count=2000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt and uc.reg_read(arm.UC_ARM64_REG_X0)&0xffffffff==rc&0xffffffff,'Native terminal reentry did not return original failure')
        require(before==(state['reads'],len(writes),len(delays),len(cache),state['commands']),'Native terminal reentry performed bus/cache I/O')
    for address,size in ((spi,facts['spi_bytes']),(terminal,4),(tx,519 if case=='invalid-length' else length),(rx,519 if case=='invalid-length' else length),(dtx,4096),(drx,4096)):
        require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+size,64))==b'\xa5'*64,'Native transfer memory canary changed: '+case+' '+hex(address))
    return {'case':case,'result':'PASS','return':rc,'commands':state['commands'],'mmio_writes':len(writes),'delay_calls':len(delays),
            'dma_resets':state['resets'],'reset_acknowledgements':state['reset_acks'],'full_native_transport_and_guard':True}

def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json'
    source=fresh(source_path);prelink=fresh(prelink_path)
    require(prelink['input_source_report_sha256']==sha(source_path),'Transfer CPU source/prelink dependency stale')
    path=ROOT/prelink['candidate'];require(sha(path)==prelink['candidate_sha256'],'Transfer CPU candidate changed')
    facts,obj=layout();cases=[emulate(path,name,facts) for name in CASES]
    out=ROOT/'build/cph2653-input-prelink/transfer-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeInput/DodgeGeniTransfer.cpp',ROOT/'drivers/DodgeInput/DodgeGeniTransfer.h',
           ROOT/'drivers/DodgeInput/geni/GeniSpi.c',ROOT/'sources/UniXNU/drivers/QcomGeniSpi/GeniSpi.h']
    report={'result':'IOS16_PRELINKED_GENI_TRANSPORT_COMPLETION_RECOVERY_AND_TERMINAL_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'case_count':len(cases),'cases':cases,'compiler_derived_layout':facts,
            'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),
            'mmio_slave_dma_cache_and_bzero_are_peers':True,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual current prelinked ARM64 terminal guard, full C FIFO/DMA transport, packing, cancel/abort and requested-channel reset loops. '
                    'PIO/DMA byte extents, command/data/idle completion, cache ordering, failed/stale reset, live-abort refusal and terminal reentry use compiler-derived ABI and allocation canaries. '
                    'Register/slave/DMA/cache/clock behavior and bzero are explicit peers, not hardware or serial-engine firmware execution.'}
    (ROOT/'reports/ios16-input-transfer-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(cases))+' actual prelinked ARM64 full GENI transport/terminal cases, byte readback and bounded cancel/abort/reset paths')

if __name__=='__main__':main()
