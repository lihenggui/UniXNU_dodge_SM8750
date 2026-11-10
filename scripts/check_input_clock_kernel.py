#!/usr/bin/env python3
"""Execute the actual prelinked ARM64 target clock body with explicit MMIO peers."""
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,require,sha,symbols,macho
from build_input_native import fresh

FIELDS=('hz','select','phase','writes','voteBefore','commandBefore','configurationBefore','dfsBefore','programmed')

def layout():
    out=ROOT/'build/ios16-input-clock-abi';out.mkdir(parents=True,exist_ok=True)
    p=out/'DodgeClockLayout.cpp'
    values=['sizeof(peripheral_io)','sizeof(DodgeTouchClockResult)',*[f'offsetof(DodgeTouchClockResult,{n})' for n in FIELDS]]
    p.write_text('#include <stddef.h>\n#include "DodgeTouchClock.h"\nextern "C" const unsigned dodge_clock_layout[]={'+','.join(values)+'};\n')
    obj,=build_objects([p],out,[ROOT/'drivers/DodgeInput',ROOT/'sources/UniXNU-sm8750-common/kits/Sm8750Platform'])
    raw=obj.read_bytes();im=inspect_object(raw);symbol,=[s for s in symbols(raw) if s['name']=='_dodge_clock_layout' and not s['kind']&0xe0]
    section=next(s for seg in im['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    at=section['fileoff']+symbol['value']-section['va'];values=struct.unpack_from('<'+str(len(values))+'I',raw,at)
    facts=dict(zip(('io_bytes','result_bytes',*FIELDS),values));require(facts['io_bytes']==32,'Unexpected native clock callback shape')
    return facts,obj

def emulate(path,case,facts):
    import unicorn
    import unicorn.arm64_const as reg
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    raw=path.read_bytes();im=macho(raw);table=[s for s in symbols(raw) if not s['kind']&0xe0 and s['kind']&14];names={s['name']:s['value'] for s in table};addresses={s['value'] for s in table}
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(a,data=b'',size=0):
        p=a&~4095;end=(a+max(len(data),size)+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            last=p+4096
            while last<end and last not in pages:last+=4096
            uc.mem_map(p,last-p);pages.update(range(p,last,4096));p=last
        if data:uc.mem_write(a,data)
    for s in im['segments']:
        if s['size'] and s['initprot']:put(s['va'],raw[s['fileoff']:s['fileoff']+s['filesize']],s['size'])
    gio,sio,out,stack,halt=0x100040,0x110040,0x120040,0x300000,0x400000
    for a,n in ((gio,32),(sio,32),(out,facts['result_bytes'])):
        put(a-64,b'\xa5'*(n+128));put(a,bytes(n))
    put(stack,size=65536);put(halt,size=4096)
    read_cb,write_cb,delay_cb=halt+0x100,halt+0x200,halt+0x300
    gcc_ctx,se_ctx=0xc10c0ffee,0x5e4c0ffee
    for a,ctx in ((gio,gcc_ctx),(sio,se_ctx)):put(a,struct.pack('<4Q',ctx,read_cb,write_cb,delay_cb))
    vote,root,cfg,dfs=0x52008,0x183dc,0x183e0,0x183f0
    gcc={vote:0x043c0000,cfg:0x100001,0:0x80000005,4:1,0x10:31,0x14:0x4000,0x18:0x400};se={};writes=[];waits=[]
    cold=case not in ('adopt','adopt-fractional','adopt-dfs','bad-parent','unlocked-pll','update-busy')
    if cold:gcc.update({vote:0x80000000,root:0x80000000,cfg:0xa034770f})
    if case=='adopt-fractional':gcc.update({cfg:0x2601,root+8:384,root+12:(~(15625-384))&65535})
    if case=='adopt-dfs':
        gcc[dfs]=1
        for i in range(8):gcc[root+0x1c+4*i]=0x700
        gcc[root+0x1c+4*5]=3
    if case=='bad-parent':gcc[cfg]=0x700
    if case=='unlocked-pll':gcc[cfg]=0x10b;gcc[0]=5
    if case=='update-busy':gcc[root]=1
    if case=='engine-busy':se[0x40]=1
    if case=='foreign-protocol':se[0x68]=0x200
    if case=='foreign-dma':se[0xc30]=0x1234000
    if case=='root-owned':gcc[vote]|=1<<26
    if case=='bus-timeout':gcc[0x2315c]=0x80000002
    if case=='serial-timeout':gcc[0x183cc]=0x80000002
    def args():return [uc.reg_read(getattr(reg,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(value=0):uc.reg_write(reg.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(reg.UC_ARM64_REG_PC,uc.reg_read(reg.UC_ARM64_REG_LR))
    def read(a):
        ctx,r=a[:2];require(ctx in (gcc_ctx,se_ctx) and not r&3 and r<(0x60000 if ctx==gcc_ctx else 0x4000),'Native clock read escaped its mapping')
        value=(gcc if ctx==gcc_ctx else se).get(r,0)
        if ctx==gcc_ctx and case=='cfg-write-failure' and len(writes)==2 and r==cfg:value^=1
        if ctx==gcc_ctx and case=='source-drift' and len(writes)==4 and r==cfg:value^=0x100
        ret(value)
    def write(a):
        ctx,r,v=a[:3];require(ctx==gcc_ctx and r in (vote,root,cfg) and v<=0xffffffff,'Clock setup wrote SE/PLL/other-clock state')
        writes.append((r,v));gcc[r]=v
        if r==root:
            if case!='update-timeout':gcc[r]&=~1
            if case!='root-timeout':gcc[r]&=~(1<<31)
        if r==vote and v&(1<<26) and case=='late-busy':se[0x40]=1
        ret()
    def delay(a):require(a[0]==gcc_ctx and a[1]==1,'Unbounded/foreign native clock delay');waits.append(1);ret()
    def zero(a):
        require(any(base<=a[0] and a[0]+a[1]<=base+n for base,n in ((out,facts['result_bytes']),(stack,65536))),'Clock bzero escaped local/output memory')
        put(a[0],bytes(a[1]));ret()
    callbacks={read_cb:read,write_cb:write,delay_cb:delay,names['_bzero']:zero}
    obj=ROOT/'build/cph2653-input-native/DodgeTouchClock.o';data=obj.read_bytes();image=inspect_object(data);sections=[s for seg in image['segments'] for s in seg['sections']]
    function_names=[s['name'] for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14==14 and s['section'] and
                    sections[s['section']-1]['name']=='__text' and s['name'].startswith(('_dodge_touch_clock_','__Z'))]
    allowed=[]
    for name in function_names:
        matches=[s['value'] for s in table if s['name']==name];require(len(matches)==1,'Ambiguous native clock function: '+name)
        a=matches[0];allowed.append((a,min(v for v in addresses if v>a)-a))
    def hook(engine,a,size,user):
        if a in callbacks:callbacks[a](args());return
        require(any(start<=a<start+n for start,n in allowed),'Unqualified native clock call: '+hex(a))
    uc.hook_add(unicorn.UC_HOOK_CODE,hook);uc.reg_write(reg.UC_ARM64_REG_SP,stack+65024);uc.reg_write(reg.UC_ARM64_REG_LR,halt)
    for i,a in enumerate((gio,sio,out)):uc.reg_write(getattr(reg,'UC_ARM64_REG_X'+str(i)),a)
    uc.emu_start(names['_dodge_touch_clock_prepare'],halt,timeout=5000000,count=2000000)
    require(uc.reg_read(reg.UC_ARM64_REG_PC)==halt,'Native clock body did not return')
    value=uc.reg_read(reg.UC_ARM64_REG_X0)&0xffffffff;rc=value-(1<<32) if value&0x80000000 else value
    expected={'bad-parent':-95,'unlocked-pll':-95,'update-busy':-16,'engine-busy':-16,'foreign-protocol':-71,
              'foreign-dma':-16,'root-owned':-16,'bus-timeout':-110,'serial-timeout':-110,
              'cfg-write-failure':-5,'update-timeout':-110,'root-timeout':-110,'late-busy':-16,'source-drift':-16}.get(case,0)
    require(rc==expected,'Native clock return changed: '+case+' '+str(rc))
    def field(name):return struct.unpack('<I',bytes(uc.mem_read(out+facts[name],4)))[0]
    require(field('writes')==len(writes),'Native clock write accounting changed')
    if not rc:
        hz=7372800 if case=='adopt-fractional' else 9600000 if case=='adopt-dfs' else 19200000
        require(field('hz')==hz and field('select')==(5 if case=='adopt-dfs' else 0) and field('phase')==4,'Native clock source/DFS result changed')
        require(len(writes)==(4 if cold else 0),'Native clock changed live source or omitted cold writes')
    else:
        require(not field('hz'),'Failed clock setup exposed a usable source rate')
        if case in ('bad-parent','unlocked-pll','update-busy'):require(not writes,'Native early clock refusal wrote state')
        if case=='cfg-write-failure':require(len(writes)==2,'Native clock continued after failed CFG write')
    if case in ('bus-timeout','serial-timeout'):require(len(waits)==200,'Native branch wait not bounded')
    if case in ('update-timeout','root-timeout'):require(len(waits)==500 and len(writes)==3,'Native root update wait not bounded')
    for a,n in ((gio,32),(sio,32),(out,facts['result_bytes'])):
        require(bytes(uc.mem_read(a-64,64))==b'\xa5'*64 and bytes(uc.mem_read(a+n,64))==b'\xa5'*64,'Native clock allocation canary changed')
    return {'case':case,'result':'PASS','return':rc,'register_writes':len(writes),'delay_calls':len(waits),'full_native_clock_body':True}

def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json'
    source=fresh(source_path);prelink=fresh(prelink_path)
    require(prelink['input_source_report_sha256']==sha(source_path),'Clock CPU source/prelink dependency stale')
    path=ROOT/prelink['candidate'];require(sha(path)==prelink['candidate_sha256'],'Clock CPU candidate changed')
    facts,obj=layout();cases=[emulate(path,n,facts) for n in ('cold','adopt','adopt-fractional','adopt-dfs','bad-parent','unlocked-pll','update-busy',
        'engine-busy','foreign-protocol','foreign-dma','root-owned','bus-timeout','serial-timeout','cfg-write-failure','update-timeout','root-timeout','late-busy','source-drift')]
    out=ROOT/'build/cph2653-input-prelink/clock-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeInput/DodgeTouchClock.cpp',ROOT/'drivers/DodgeInput/DodgeTouchClock.h']
    report={'result':'IOS16_PRELINKED_TARGET_COLD_CLOCK_AND_OWNERSHIP_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(path.relative_to(ROOT)),'candidate_sha256':sha(path),'case_count':len(cases),'cases':cases,'compiler_derived_layout':facts,
            'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),
            'mmio_clock_pll_and_bzero_are_peers':True,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Actual current prelinked ARM64 clock ownership, XO cold initialization, live PLL/MND/DFS rate adoption, write-error and bounded timeout paths with compiler-derived layout/canaries. '
                    'Only three allowed GCC registers can be written; serial-engine, PLL, voltage and reset registers are not written. Physical clock/rail/interconnect/PLL behavior remains unqualified.'}
    (ROOT/'reports/ios16-input-clock-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 18 actual prelinked ARM64 target clock/ownership cases; cold XO, live fractional/DFS rates, refusals and bounded failures')

if __name__=='__main__':main()
