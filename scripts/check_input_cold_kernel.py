#!/usr/bin/env python3
"""Run the actual linked ARM64 SEFW parser/loader with register callbacks."""
import hashlib
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,require,sha,symbols,macho
from native_prelink import backed_offset
from build_input_native import fresh

LABELS=['spi_bytes','spi_se','spi_wrapper','io_bytes','io_context','io_read','io_write','io_delay',
        'result_bytes','result_phase','result_writes','result_before','result_after','result_loaded',
        'image_bytes','image_data','image_size','image_core','image_words','image_word_offset','image_configurations','image_index_offset','image_value_offset']

def layout():
    out=ROOT/'build/ios16-input-cold-abi';out.mkdir(parents=True,exist_ok=True);source=out/'DodgeColdLayout.cpp'
    values=['sizeof(geni_spi)','offsetof(geni_spi,se)','offsetof(geni_spi,wrapper)','sizeof(geni_io)',
            *['offsetof(geni_io,'+n+')' for n in ('ctx','rd','wr','delay_us')],
            'sizeof(DodgeGeniResult)',*['offsetof(DodgeGeniResult,'+n+')' for n in ('phase','writes','firmwareBefore','firmwareAfter','loaded')],
            'sizeof(DodgeGeniImage)',*['offsetof(DodgeGeniImage,'+n+')' for n in ('bytes','size','core','words','wordOffset','configurations','indexOffset','valueOffset')]]
    source.write_text('#include "DodgeGeniFirmware.h"\nextern "C" const unsigned dodge_cold_layout[]={'+','.join(values)+'};\n')
    obj,=build_objects([source],out,[ROOT/'drivers/DodgeInput',ROOT/'sources/UniXNU/drivers/QcomGeniSpi'])
    raw=obj.read_bytes();image=inspect_object(raw);s,=[s for s in symbols(raw) if s['name']=='_dodge_cold_layout' and not s['kind']&0xe0]
    section=next(sx for seg in image['segments'] for sx in seg['sections'] if sx['va']<=s['value']<sx['va']+sx['size'])
    at=section['fileoff']+s['value']-section['va'];facts=dict(zip(LABELS,struct.unpack_from('<'+str(len(LABELS))+'I',raw,at)))
    require(facts['io_bytes']==32 and facts['spi_se']==0 and facts['spi_wrapper']==32,'Unexpected compiler-derived bus callback layout')
    return facts,obj

def emulate(path,case,facts):
    import unicorn
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    data=path.read_bytes();image=macho(data);ns=[s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14];names={s['name']:s['value'] for s in ns};addresses={s['value'] for s in ns}
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(a,value=b'',size=0):
        p=a&~4095;end=(a+max(size,len(value))+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            stop=p+4096
            while stop<end and stop not in pages:stop+=4096
            uc.mem_map(p,stop-p);pages.update(range(p,stop,4096));p=stop
        if value:uc.mem_write(a,value)
    for s in image['segments']:
        if s['size'] and s['initprot']:put(s['va'],data[s['fileoff']:s['fileoff']+s['filesize']],s['size'])
    spi,out,view,stack,halt=0x100040,0x110040,0x120040,0x300000,0x400000
    for a,n in ((spi-64,4096),(out-64,4096),(view-64,4096),(stack,65536),(halt,4096)):put(a,size=n)
    for a,size in ((spi,facts['spi_bytes']),(out,facts['result_bytes']),(view,facts['image_bytes'])):
        put(a-64,b'\xa5'*(size+128));put(a,bytes(size))
    rd,wr,delay=halt+0x100,halt+0x200,halt+0x300
    for label,ctx in (('spi_se',0x12345678),('spi_wrapper',0x87654321)):
        put(spi+facts[label],struct.pack('<4Q',ctx,rd,wr,delay))
    blob=names['_dodge_touch_spi_firmware'];end=names['_dodge_touch_spi_firmware_end'];n=end-blob;require(n==2141,'Native embedded firmware extent changed')
    stock=bytes(uc.mem_read(blob,n));firmware=json.loads((ROOT/'reports/ios16-touch-firmware.json').read_text());require(hashlib.sha256(stock).hexdigest()==firmware['firmware_sha256'],'Native firmware bytes changed')
    if case=='parse-bad-protocol':put(blob+12,b'\x02\x00')
    if case=='parse-bad-core':put(blob+8,struct.pack('<I',0x30000000))
    if case=='parse-odd-words':put(blob+18,struct.pack('<H',441))
    se={0xe24:32<<24|32<<16,0xe28:32<<24|32<<16};wrapper={4:0x40000000};writes=[];delays=[];visits=[]
    if case=='prepare-adopt':se[0x68]=0x102
    if case=='prepare-adopt-dma':se[0x68]=0x102;se[0x258]=1
    if case=='prepare-adopt-fifo':se[0x68]=0x102;se[0x800]=1
    if case=='prepare-busy':se[0x40]=1
    if case=='prepare-foreign-protocol':se[0x68]=0x200
    if case=='prepare-foreign-dma':se[0xc30]=1
    if case=='prepare-wrong-core':wrapper[4]=0x40010000
    if case=='prepare-rx-depth':se[0xe28]=32<<24|16<<16
    if case=='prepare-rx-width':se[0xe28]=16<<24|32<<16
    fault=300 if case=='prepare-write-failure' else 0
    def arguments():return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def returned(v=0):uc.reg_write(reg.UC_ARM64_REG_X0,v&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def is_wrapper(ctx):require(ctx in (0x12345678,0x87654321),'Native loader changed callback context');return ctx==0x87654321
    def read(a):
        wrap=is_wrapper(a[0]);r=a[1];require(r<(0x1000 if wrap else 0x4000) and not r&3,'Native loader register read escaped its mapping')
        value=(wrapper if wrap else se).get(r,0)
        if fault and len(writes)==fault and writes[-1][:2]==(wrap,r):value^=1
        returned(value)
    def write(a):
        wrap=is_wrapper(a[0]);r,v=a[1:3];require(r<(0x1000 if wrap else 0x4000) and not r&3 and v<=0xffffffff,'Native loader register write escaped mapping/width')
        writes.append((wrap,r,v));(wrapper if wrap else se)[r]=v
        if not wrap and r==0x2008:se[0x64]=v&1
        if not wrap and r==0x2000 and v&1 and case!='prepare-mirror-timeout':se[0x68]=se.get(0x1000,0);se[0x6c]=se.get(0x1004,0)
        returned()
    def wait(a):require(a[0]==0x12345678 and a[1]==1,'Native firmware mirror wait changed');delays.append(1);returned()
    def zero(a):
        require(any(start<=a[0] and a[0]+a[1]<=start+size for start,size in ((stack,65536),(out,facts['result_bytes']),(view,facts['image_bytes']))),'Native loader bzero escaped local/output storage')
        put(a[0],bytes(a[1]));returned()
    handlers={rd:read,wr:write,delay:wait,names['_bzero']:zero}
    obj=ROOT/'build/cph2653-input-native/DodgeGeniFirmware.o';raw=obj.read_bytes();mi=inspect_object(raw);sections=[s for seg in mi['segments'] for s in seg['sections']]
    allowed=[];function_names=[]
    for s in symbols(raw):
        if s['kind']&0xe0 or s['kind']&14!=14 or not s['section'] or sections[s['section']-1]['name']!='__text':continue
        if not s['name'].startswith(('_dodge_geni_','__Z')):continue
        function_names.append(s['name'])
    function_names.append('_geni_spi_read_info')
    for name in function_names:
        matches=[s['value'] for s in ns if s['name']==name];require(len(matches)==1,'Native cold function has ambiguous identity: '+name)
        a=matches[0];allowed.append((a,min(v for v in addresses if v>a)-a))
    def hook(engine,a,size,user):
        if a in handlers:handlers[a](arguments());return
        require(any(start<=a<start+length for start,length in allowed),'Unqualified cold input native call: '+hex(a))
        for name in function_names:
            if a==names[name]:visits.append(name)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook);uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
    parse=case.startswith('parse-');length=27 if case=='parse-short-header' else n-1 if case=='parse-short-tail' else n
    args=(blob,length,view) if parse else (spi,blob,n,out)
    for i,v in enumerate(args):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),v)
    entry=names['_dodge_geni_parse' if parse else '_dodge_geni_prepare'];uc.emu_start(entry,halt,timeout=5000000,count=2000000)
    require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'Native cold loader did not return');value=uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff;rc=value-(1<<32) if value&0x80000000 else value
    if parse:
        expected=0 if case=='parse-stock' else -22 if case=='parse-short-header' else -71
        require(rc==expected and not writes,'Native parser result/MMIO changed')
        actual=struct.unpack('<Q',bytes(uc.mem_read(view+facts['image_data'],8)))[0]
        require(actual==(blob if not rc else 0),'Native parser view pointer changed')
    else:
        expected={'prepare-adopt-dma':-16,'prepare-adopt-fifo':-16,'prepare-busy':-16,'prepare-foreign-protocol':-16,'prepare-foreign-dma':-16,'prepare-wrong-core':-19,'prepare-rx-depth':-19,'prepare-rx-width':-19,'prepare-write-failure':-5,'prepare-mirror-timeout':-110}.get(case,0)
        require(rc==expected,'Native loader status differs: '+str(rc))
        def field(label):return struct.unpack('<I',bytes(uc.mem_read(out+facts['result_'+label],4)))[0]
        loaded=bytes(uc.mem_read(out+facts['result_loaded'],1))!=b'\0'
        require(field('writes')==len(writes) and loaded==(case=='prepare-cold'),'Native loader result/write count changed')
        if case=='prepare-cold':
            require(len(writes)==535 and field('phase')==6,'Native full firmware programming order/extent changed')
            for i in range(442):require(se.get(0x1010+4*i)==struct.unpack_from('<I',stock,28+4*i)[0],'Native programmed RAM differs from original SPI payload')
            require(se.get(0xe1c)==0 and se.get(0xe18)==0 and not se.get(0x258,0)&1,'Native cold programming exposed IRQ/GPI/DMA execution')
        elif case=='prepare-write-failure':require(len(writes)==300 and field('phase')==4,'Native load continued after failed RAM write')
        elif case=='prepare-mirror-timeout':require(len(writes)==535 and len(delays)==99 and field('phase')==5,'Native load timeout changed')
        else:require(not writes,'Native adoption/refusal wrote hardware')
    for a,size in ((spi,facts['spi_bytes']),(out,facts['result_bytes']),(view,facts['image_bytes'])):
        require(bytes(uc.mem_read(a-64,64))==b'\xa5'*64 and bytes(uc.mem_read(a+size,64))==b'\xa5'*64,'Native cold input allocation canary changed')
    return {'case':case,'result':'PASS','return':rc,'register_writes':len(writes),'delay_calls':len(delays),'full_native_loader_body':not parse,'register_operations_and_bzero_are_peers':True}


def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json';source=fresh(source_path);prelink=fresh(prelink_path)
    require(prelink['input_source_report_sha256']==sha(source_path),'Cold CPU source/prelink dependency stale')
    path=ROOT/prelink['candidate'];require(sha(path)==prelink['candidate_sha256'],'Cold CPU candidate changed')
    facts,obj=layout();names=['parse-stock','parse-short-header','parse-short-tail','parse-bad-protocol','parse-bad-core','parse-odd-words',
          'prepare-cold','prepare-adopt','prepare-adopt-dma','prepare-adopt-fifo','prepare-busy','prepare-foreign-protocol','prepare-foreign-dma','prepare-wrong-core','prepare-rx-depth','prepare-rx-width','prepare-write-failure','prepare-mirror-timeout']
    cases=[emulate(path,n,facts) for n in names];out=ROOT/'build/cph2653-input-prelink/cold-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeInput/DodgeGeniFirmware.cpp',ROOT/'drivers/DodgeInput/DodgeGeniFirmware.h']
    report={'result':'IOS16_PRELINKED_STOCK_SPI_FIRMWARE_PARSER_AND_COLD_LOADER_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'case_count':len(cases),'cases':cases,'compiler_derived_layout':facts,
            'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'register_operations_and_bzero_are_peers':True,
            'source_firmware_instruction_words_executed_on_a_serial_engine':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual current prelinked ARM64 parser, full GENI loader and real geni_spi_read_info with compiler-derived structure offsets and canaries. '
                    'All 442 RAM words are checked against embedded stock bytes, early refusals write nothing, failed RAM write stops, mirror timeout remains bounded. '
                    'Callback MMIO/clock behavior and bzero are peers; serial-engine microcode is never executed.'}
    (ROOT/'reports/ios16-input-cold-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 18 actual prelinked ARM64 cold firmware parser/loader cases; full 535-write load, exact 442-word readback, warm/cold ownership refusals and failure stops')
if __name__=='__main__':main()
