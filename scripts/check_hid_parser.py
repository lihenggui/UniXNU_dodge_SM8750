#!/usr/bin/env python3
"""Check native input descriptors with the exact original iPhone C HID parser."""
import hashlib
import json
from pathlib import Path
import struct
from native_driver_build import ROOT,build_objects,inspect_object,pinned_sources,require,sha,symbols,macho
from native_prelink import backed_offset,exports,unserialize_xml
from check_ios16_swap import original_input
from build_input_native import fresh

SLIDE=-0x1000000
OPEN=0xfffffff0057301d4
CLOSE=0xfffffff005730164
PARSER=ROOT/'sources/IOHIDFamily-ios16/IOHIDFamily/IOHIDDescriptorParserPrivate.h'
PUBLIC=PARSER.parent.parent/'IOHIDSystem/IOKit/hidsystem'
PREPARSED=('hidTypeIfValid','collections','collectionCount','reportItems','reportItemCount','reports','reportCount',
           'usageItems','usageItemCount','rawMemPtr','flags','numBytesAllocated')
REPORT=('reportID','inputBitCount','outputBitCount','featureBitCount')
ITEM=('reportType','startBit','parent','dataModes','firstUsageItem','usageItemCount')
GLOBAL=('usagePage','logicalMinimum','logicalMaximum','reportSize','reportID','reportCount')
USAGE=('isRange','usagePage','usage','usageMinimum','usageMaximum')
COLLECTION=('data','usagePage','firstUsageItem','usageItemCount','parent','children','firstChild','nextSibling')

def layout():
    refs=pinned_sources(('iohid_headers_reference','pagani_reference','iphoneos_sdk_reference'))
    out=ROOT/'build/ios16-input-hid-parser-abi';out.mkdir(parents=True,exist_ok=True)
    source=out/'DodgeHidParserLayout.cpp';labels=[];values=[]
    def add(label,value):labels.append(label);values.append(value)
    for prefix,typename,fields in (('preparsed','HIDPreparsedData',PREPARSED),('report','HIDReportSizes',REPORT),
                                   ('item','HIDReportItem',ITEM),('usage','HIDP_UsageItem',USAGE),('collection','HIDCollection',COLLECTION)):
        add(prefix+'_bytes','sizeof('+typename+')')
        for field in fields:add(prefix+'_'+field,f'offsetof({typename},{field})')
    for field in GLOBAL:add('global_'+field,'offsetof(HIDReportItem,globals)+offsetof(HIDGlobalItems,'+field+')')
    add('touch_descriptor_bytes','sizeof(touchDescriptor)');add('buttons_descriptor_bytes','sizeof(buttonsDescriptor)')
    add('frame_bytes','sizeof(s3910_frame)');add('contact_bytes','sizeof(s3910_contact)')
    for field in ('x','y','active'):add('contact_'+field,f'offsetof(s3910_contact,{field})')
    source.write_text('#include <stddef.h>\n#include "IOHIDDescriptorParserPrivate.h"\n#include "Reports.h"\n#include "S3910.h"\nextern "C" const unsigned dodge_hid_parser_layout[]={'+','.join(values)+'};\n')
    target=refs['iphoneos_sdk_reference']/'iPhoneOS16.5.sdk/usr/include/TargetConditionals.h'
    include=out/'include';include.mkdir(exist_ok=True);(include/target.name).write_bytes(target.read_bytes())
    require(sha(include/target.name)==sha(target),'Staged real iPhone SDK conditionals differ')
    obj,=build_objects([source],out,[PARSER.parent,PUBLIC,refs['pagani_reference']/'drivers/PaganiInput',include],['-include',str(target),'-Wno-macro-redefined'])
    data=obj.read_bytes();im=inspect_object(data);symbol,=[s for s in symbols(data) if not s['kind']&0xe0 and s['name']=='_dodge_hid_parser_layout']
    section=next(s for seg in im['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    offset=section['fileoff']+symbol['value']-section['va'];facts=dict(zip(labels,struct.unpack_from('<'+str(len(labels))+'I',data,offset)))
    require(facts['preparsed_bytes']==128 and facts['preparsed_flags']==112 and facts['preparsed_rawMemPtr']==104 and facts['preparsed_numBytesAllocated']==120,
            'Public parser data no longer matches observed original allocation/field accesses')
    return facts,obj

def context():
    _,original,image,read=original_input();info=next(s for s in image['segments'] if s['name']=='__PRELINK_INFO')
    entry=next(e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary'] if e['CFBundleIdentifier']=='com.apple.iokit.IOHIDFamily')
    module=macho(original,backed_offset(image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(original)))
    exported=exports(original,image);imports={}
    for segment in module['segments']:
        for section in segment['sections']:
            if section['name']!='__stubs':continue
            for pc in range(section['va'],section['va']+section['size'],12):
                a,b,c=struct.unpack('<3I',read(pc,12))
                require(a&0x9f00001f==0x90000010 and b&0xffc003ff==0xf9400210 and c==0xd61f0200,'Original HID import stub differs')
                delta=((a>>5)&0x7ffff)*4+((a>>29)&3);delta=delta-(1<<21) if delta&(1<<20) else delta
                got=(pc&~4095)+(delta<<12)+((b>>10)&4095)*8;target=struct.unpack('<Q',read(got,8))[0]
                imports[pc+SLIDE]=exported.get(target,[])
    return original,read,module,imports

def emulate(candidate,case,facts,ctx,control=False):
    import unicorn
    import unicorn.arm64_const as arm
    require(unicorn.__version__=='2.1.4','Use pinned Unicorn 2.1.4')
    original,original_read,module,imports=ctx
    data=candidate.read_bytes();image=macho(data);names={s['name']:s['value'] for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
    uc=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);pages=set()
    def put(address,value=b'',size=0):
        p=address&~4095;end=(address+max(len(value),size)+4095)&~4095
        while p<end:
            if p in pages:p+=4096;continue
            stop=p+4096
            while stop<end and stop not in pages:stop+=4096
            uc.mem_map(p,stop-p);pages.update(range(p,stop,4096));p=stop
        if value:uc.mem_write(address,value)
    for s in image['segments']:
        if s['size'] and s['initprot']:put(s['va'],data[s['fileoff']:s['fileoff']+s['filesize']],s['size'])
    touch=not case.startswith('buttons')
    linked_descriptor=names['__ZL15touchDescriptor' if touch else '__ZL17buttonsDescriptor']
    length=facts['touch_descriptor_bytes' if touch else 'buttons_descriptor_bytes']
    descriptor=0x500040;descriptor_bytes=bytes(uc.mem_read(linked_descriptor,length))
    if control:descriptor_bytes=descriptor_bytes[:7]+b'\x04'+descriptor_bytes[8:]
    if case=='touch-truncated-item':descriptor_bytes=b'\x06\x0d'
    length=len(descriptor_bytes)
    stack,result,halt=0x200000,0x300040,0x400000
    put(stack,size=65536);put(result-64,b'\xa5'*136);put(result,bytes(8));put(halt,size=4096)
    put(descriptor-64,b'\xa5'*(length+128));put(descriptor,descriptor_bytes)
    heap={};events=[];visited=set();native_visited=set();next_heap=0x1000000
    regions={result:(8,True),descriptor:(length,False)}
    native_ranges=[]
    obj_data=(ROOT/'build/cph2653-input-native/S3910.o').read_bytes();obj_image=inspect_object(obj_data)
    obj_sections=[s for seg in obj_image['segments'] for s in seg['sections']]
    obj_symbols=symbols(obj_data)
    for symbol in obj_symbols:
        if symbol['kind']&0xe0 or symbol['kind']&14!=14 or not symbol['section'] or obj_sections[symbol['section']-1]['name']!='__text':continue
        if symbol['name'] not in ('_s3910_decode','_s3910_hid_report'):continue
        section=obj_sections[symbol['section']-1]
        ends=[s['value'] for s in obj_symbols if not s['kind']&0xe0 and s['kind']&14==14 and s['section']==symbol['section'] and
              not s['name'].startswith('ltmp') and s['value']>symbol['value']]
        length_bytes=min(ends,default=section['va']+section['size'])-symbol['value']
        start=names[symbol['name']];native_ranges.append((start,start+length_bytes))
    require(len(native_ranges)==2,'Current S3910 report/decode symbols are not unique')
    def bounded(address,size,write=False):
        require(0<=size<1<<20,'Parser memory peer extent escaped bounds')
        if stack<=address and address+size<=stack+65536:return
        for base,(extent,writable) in regions.items():
            if base<=address and address+size<=base+extent and (not write or writable):return
        for base,item in heap.items():
            if not item['freed'] and base<=address and address+size<=base+item['size']:return
        require(False,'Parser memory access escaped live owned extent: '+hex(address)+' '+str(size)+' write='+str(write))
    def args():return [uc.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(8)]
    def ret(value=0):uc.reg_write(arm.UC_ARM64_REG_X0,value&((1<<64)-1));uc.reg_write(arm.UC_ARM64_REG_PC,uc.reg_read(arm.UC_ARM64_REG_LR))
    def allocate(size,kind):
        nonlocal next_heap
        require(0<size<1<<20,'Original HID parser allocation escaped bounds')
        if case=='touch-fail-'+kind+'-allocation':events.append(('allocation-failure',kind,size));return 0
        address=next_heap+64;next_heap+=(size+4095+128)&~4095
        put(address-64,b'\xa5'*(size+128));put(address,bytes(size));heap[address]={'size':size,'kind':kind,'freed':False}
        events.append(('alloc',kind,size));return address
    def release(address,size,kind):
        require(address in heap and heap[address]['size']==size and heap[address]['kind']==kind and not heap[address]['freed'],'Original HID parser free extent/ownership differs')
        heap[address]['freed']=True;events.append(('free',kind,size))
    def typed_alloc(a):
        view=a[0];require(view==0xfffffff006cc56d8+SLIDE,'Original parser typed allocation view changed')
        size=struct.unpack('<I',bytes(uc.mem_read(view+44,4)))[0]
        require(size==facts['preparsed_bytes'],'Original parser typed allocation size differs from compiler facts')
        ret(allocate(size,'typed'))
    def typed_free(a):
        require(a[0] in (0xfffffff006cc5698+SLIDE,0xfffffff006cc5718+SLIDE),'Original parser typed free view changed')
        release(a[1],facts['preparsed_bytes'],'typed');ret()
    def raw_alloc(a):ret(allocate(a[0],'data'))
    def raw_free(a):release(a[0],a[1],'data');ret()
    def zero(a):bounded(a[0],a[1],True);put(a[0],bytes(a[1]));ret()
    def copy(a):bounded(a[0],a[2],True);bounded(a[1],a[2]);put(a[0],bytes(uc.mem_read(a[1],a[2])));ret(a[0])
    def fill(a):bounded(a[0],a[2],True);put(a[0],bytes([a[1]&255])*a[2]);ret(a[0])
    handlers={'_IOMallocTypeImpl':typed_alloc,'_IOFreeTypeImpl':typed_free,'_IOMallocZeroData':raw_alloc,
              '_IOFreeData':raw_free,'_bzero':zero,'_memcpy':copy,'_memmove':copy,'_memset':fill}
    text=[(s['va']+SLIDE,s['va']+SLIDE+s['size']) for s in module['segments'] if s['initprot']&4]
    def hook(engine,address,size,user):
        if address in imports:
            matches=[handlers[n] for n in imports[address] if n in handlers]
            require(matches and all(m==matches[0] for m in matches),'Unqualified original HID parser import: '+hex(address)+' '+repr(imports[address]))
            matches[0](args());return
        if address in (names['_bzero'],names.get('_memset'),names.get('_memcpy'),names.get('_memmove')):
            require(native_visited,'Unexpected source memory peer from original HID parser')
            {'_bzero':zero,'_memset':fill,'_memcpy':copy,'_memmove':copy}[next(n for n in ('_bzero','_memset','_memcpy','_memmove') if names.get(n)==address)](args());return
        if any(a<=address<b for a,b in native_ranges):native_visited.add(address);return
        require(any(a<=address<b for a,b in text),'Original HID parser escaped its original component: '+hex(address))
        if address not in visited:
            require(bytes(uc.mem_read(address,size))==original_read(address-SLIDE,size),'Original parser executable bytes changed during prelink')
            visited.add(address)
    def memory(engine,access,address,size,value,user):
        if access==unicorn.UC_MEM_WRITE:bounded(address,size,True)
        elif address<0x10000000:bounded(address,size)
    uc.hook_add(unicorn.UC_HOOK_CODE,hook)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)
    def execute(entry,values):
        uc.reg_write(arm.UC_ARM64_REG_SP,stack+65024);uc.reg_write(arm.UC_ARM64_REG_LR,halt)
        for i,value in enumerate(values):uc.reg_write(getattr(arm,'UC_ARM64_REG_X'+str(i)),value)
        uc.emu_start(entry,halt,timeout=5000000,count=2000000)
        require(uc.reg_read(arm.UC_ARM64_REG_PC)==halt,'Original parser did not return within bounds')
        value=uc.reg_read(arm.UC_ARM64_REG_X0)&0xffffffff
        return value-(1<<32) if value&0x80000000 else value
    close_only=case in ('touch-close-null','touch-close-invalid')
    if close_only:
        rc=execute(CLOSE+SLIDE,(0 if case.endswith('null') else result,))
        require(rc==(-13939 if case.endswith('null') else -13944) and not events,'Original close invalid-argument contract changed')
        return {'case':case,'result':'PASS','return':rc,'original_instructions_visited':len(visited)}
    rc=execute(OPEN+SLIDE,(0 if case=='touch-null-descriptor' else descriptor,0 if case=='touch-empty' else length,
                         0 if case=='touch-null-result' else result,1 if case.endswith('strict') else 0))
    if case not in ('touch-valid','buttons-valid','touch-strict','buttons-strict'):
        require(rc!=0 and bytes(uc.mem_read(result,8))==bytes(8) and all(v['freed'] for v in heap.values()),
                'Original parser did not reject/clean up bad descriptor or allocation: '+case+' rc='+str(rc))
        for address,item in heap.items():
            require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+item['size'],64))==b'\xa5'*64,'Failed parser allocation canary changed')
        return {'case':case,'result':'PASS','return':rc,'allocations':events,'original_instructions_visited':len(visited),'failure_allocations_freed':True}
    require(rc==0,'Original HID parser rejected native descriptor: '+case+' '+str(rc))
    parsed=struct.unpack('<Q',bytes(uc.mem_read(result,8)))[0]
    require(parsed in heap and heap[parsed]['size']==128,'Original parser did not return its owned typed allocation')
    def field(address,prefix,name,width=4):
        return int.from_bytes(bytes(uc.mem_read(address+facts[prefix+'_'+name],width)),'little')
    count=field(parsed,'preparsed','reportCount');reports=field(parsed,'preparsed','reports',8)
    report_sizes={field(reports+i*facts['report_bytes'],'report','reportID'):field(reports+i*facts['report_bytes'],'report','inputBitCount') for i in range(count)}
    expected={0:0,3:496} if touch else {0:0,1:72,2:16}
    require(report_sizes==expected,'Original parser report IDs/bit extents differ: '+repr(report_sizes))
    def table(label,prefix):
        base=field(parsed,'preparsed',label,8);n=field(parsed,'preparsed',{'usageItems':'usageItemCount','reportItems':'reportItemCount','collections':'collectionCount'}[label])
        bounded(base,n*facts[prefix+'_bytes']);return [base+i*facts[prefix+'_bytes'] for i in range(n)]
    usages=table('usageItems','usage');items=table('reportItems','item');collections=table('collections','collection')
    def item_usages(item):
        first=field(item,'item','firstUsageItem');count=field(item,'item','usageItemCount')
        require(first+count<=len(usages),'Original parser usage table index escaped its count')
        result=[]
        for u in usages[first:first+count]:
            page=field(u,'usage','usagePage')
            values=range(field(u,'usage','usageMinimum'),field(u,'usage','usageMaximum')+1) if field(u,'usage','isRange',1) else (field(u,'usage','usage'),)
            result.extend((page,value) for value in values)
        return result
    metadata=[]
    for item in items:
        row={name:field(item,'item',name) for name in ITEM}
        row.update({name:field(item,'global',name,8 if name=='reportSize' else 4) for name in GLOBAL})
        row['usages']=item_usages(item);metadata.append(row)
        require(row['reportType']==1 and row['startBit']+row['reportSize']*row['reportCount']<=report_sizes[row['reportID']],
                'Original parser item extent exceeds its report')
    report_cases=[]
    if touch:
        require(len(items)==61 and len(collections)==12,'Original touch descriptor hierarchy changed')
        by_usage={}
        for row in metadata:
            if not row['dataModes']&1:
                require(len(row['usages'])==1 and row['reportCount']==1,'Touch element usage is ambiguous')
                by_usage.setdefault(tuple(row['usages'][0]),[]).append(row)
        require({k:len(v) for k,v in by_usage.items()}=={(13,66):10,(13,71):10,(13,81):10,(1,48):10,(1,49):10,(13,84):1},'Original touch parser usage topology changed')
        def read_bits(report,row):
            require(row['logicalMinimum']==0,'Expected unsigned touch logical value')
            value=(int.from_bytes(report,'little')>>row['startBit'])&((1<<row['reportSize'])-1)
            require(value<=row['logicalMaximum'],'Native touch report exceeds original parsed logical bounds');return value
        def normalize(records):return {i:(x*32767//23040,y*32767//50688) for i,kind,x,y in records if kind in (1,2)}
        def payload(records):return bytes([len(records)])+b''.join(struct.pack('<BBHH',*row) for row in records)
        current,previous,wire,output=0x600040,0x610040,0x620040,0x630040
        for address,size in ((current,facts['frame_bytes']),(previous,facts['frame_bytes']),(wire,61),(output,62)):
            regions[address]=(size,True);put(address-64,b'\xa5'*(size+128));put(address,bytes(size))
        empty=bytes(facts['frame_bytes'])
        def decode(records,address):
            message=payload(records);put(wire,message)
            require(execute(names['_s3910_decode'],(wire,len(message),23040,50688,address))==0,'Actual native touch decode rejected valid frame')
        sequences=[('empty',[],[]),('finger-down',[(0,1,100,200)],[]),('nonzero-id',[(9,1,1000,2000)],[]),
                   ('move',[(0,1,200,400)],[(0,1,100,200)]),('maximum',[(5,1,23040,50688)],[]),
                   ('glove',[(3,2,11520,25344)],[]),('palm',[(4,3,100,100)],[]),
                   ('ten-contacts',[(i,1,100*i,1000*i) for i in range(10)],[]),
                   ('lift',[],[(7,1,11520,25344)]),('after-lift',[],[]),
                   ('simultaneous-lift-and-down',[(2,1,12,34)],[(9,1,200,400)]),
                   ('ten-lifts',[],[(i,1,100*i,1000*i) for i in range(10)])]
        for name,records,old in sequences:
            put(current,empty);put(previous,empty);decode(records,current);decode(old,previous)
            execute(names['_s3910_hid_report'],(current,previous,output));report=bytes(uc.mem_read(output,62))
            live=normalize(records);prior=normalize(old);ids=sorted(live.keys()|prior.keys())
            require(report[0]==3 and read_bits(report,by_usage[(13,84)][0])==len(ids),'Original parsed contact count disagrees with actual native report')
            for slot in range(10):
                value=lambda usage:read_bits(report,by_usage[usage][slot])
                if slot>=len(ids):
                    require(all(value(u)==0 for u in ((13,66),(13,71),(13,81),(1,48),(1,49))),'Native report retained an unused contact');continue
                identity=ids[slot];position=live.get(identity,prior.get(identity))
                require(value((13,66))==int(identity in live) and value((13,71))==1 and value((13,81))==identity and
                        (value((1,48)),value((1,49)))==position,'Actual native touch report disagrees with original parsed usage/bit positions: '+name)
            report_cases.append({'case':name,'result':'PASS','active':len(live),'reported_with_lifts':len(ids),'report_sha256':hashlib.sha256(report).hexdigest()})
        for name,message in (('duplicate-id',payload([(1,1,1,1),(1,1,2,2)])),('id-out-of-range',payload([(10,1,1,1)])),
                             ('x-out-of-range',payload([(1,1,23041,1)])),('y-out-of-range',payload([(1,1,1,50689)])),
                             ('short-frame',b'\x01'),('too-many',b'\x0b')):
            put(wire,message);put(current,b'\xcc'*facts['frame_bytes'])
            require(execute(names['_s3910_decode'],(wire,len(message),23040,50688,current))==-71 and
                    bytes(uc.mem_read(current,facts['frame_bytes']))==b'\xcc'*facts['frame_bytes'],'Bad native frame changed output: '+name)
            report_cases.append({'case':name,'result':'PASS','return':-71,'output_unchanged':True})
        for address,(extent,writable) in regions.items():
            require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+extent,64))==b'\xa5'*64,'Parser/native buffer canary changed')
    else:
        consumer=next(row for row in metadata if row['reportID']==2 and not row['dataModes']&1)
        require(consumer['usages']==[(12,64),(12,48),(12,233),(12,234)] and consumer['startBit']==8 and consumer['reportSize']==1 and consumer['reportCount']==4,
                'Original parsed consumer button usages/bit mapping differ from concrete driver')
        for mask in range(0,16,2):
            report=bytes((2,mask));pressed=[usage for bit,usage in enumerate(consumer['usages']) if mask>>bit&1]
            require((12,64) not in pressed and all(usage in ((12,48),(12,233),(12,234)) for usage in pressed),'Physical buttons selected unsupported consumer usage')
            report_cases.append({'case':'consumer-mask-'+str(mask),'result':'PASS','report':report.hex(),'pressed_usages':pressed})
    require(execute(CLOSE+SLIDE,(parsed,))==0 and all(v['freed'] for v in heap.values()),'Original parser leaked descriptor allocations')
    for address,item in heap.items():
        require(bytes(uc.mem_read(address-64,64))==b'\xa5'*64 and bytes(uc.mem_read(address+item['size'],64))==b'\xa5'*64,'Original parser allocation canary changed')
    require(bytes(uc.mem_read(descriptor,length))==descriptor_bytes,'Original HID parser modified its input descriptor')
    return {'case':case,'result':'PASS','descriptor_bytes':length,'report_bits':report_sizes,'allocations':events,
            'report_items':metadata,'report_cases':report_cases,'original_instructions_visited':len(visited),
            'native_instructions_visited':len(native_visited),'close_freed_all_allocations':True}

def main():
    source_path=ROOT/'reports/ios16-input-native.json';prelink_path=ROOT/'reports/ios16-input-prelink.json'
    source=fresh(source_path);prelink=fresh(prelink_path);candidate=ROOT/prelink['candidate'];facts,obj=layout();ctx=context()
    require(prelink['input_source_report_sha256']==sha(source_path) and sha(candidate)==prelink['candidate_sha256'],'HID parser source/prelink candidate changed')
    cases=[emulate(candidate,name,facts,ctx) for name in ('touch-valid','buttons-valid','touch-strict','buttons-strict',
           'touch-null-descriptor','touch-null-result','touch-empty','touch-truncated-item',
           'touch-fail-typed-allocation','touch-fail-data-allocation','touch-close-null','touch-close-invalid')]
    controls=[]
    try:emulate(candidate,'touch-valid',facts,ctx,True)
    except ValueError as error:
        require(str(error).startswith('Original parser report IDs/bit extents differ:'),'HID descriptor control failed for unrelated reason: '+str(error))
        controls.append({'case':'changed-touch-report-id','result':'REJECTED','check':str(error)})
    else:raise ValueError('Changed native touch descriptor ID was accepted')
    out=ROOT/'build/cph2653-input-prelink/hid-parser-cpu-cases.json';out.write_text(json.dumps({'result':'PASS','layout':facts,'cases':cases,'negative_controls':controls},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_ios16_swap.py',PARSER,
           PUBLIC/'IOHIDDescriptorParser.h',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/PaganiInput/Reports.h',
           ROOT/'sources/UniXNU-Pagani-Drivers/drivers/PaganiInput/S3910.h',ROOT/'sources/UniXNU-Pagani-Drivers/drivers/PaganiInput/S3910.c',
           ROOT/'sources/iphoneos-sdk/iPhoneOS16.5.sdk/usr/include/TargetConditionals.h']
    report={'result':'IOS16_ORIGINAL_IPHONE_HID_DESCRIPTOR_PARSER_AND_NATIVE_REPORT_CPU_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'source_report_sha256':sha(source_path),'prelink_report_sha256':sha(prelink_path),
            'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':sha(candidate),'case_count':len(cases),
            'report_case_count':sum(len(c.get('report_cases',[])) for c in cases),'cases':[{k:v for k,v in c.items() if k!='report_items'} for c in cases],'negative_controls':controls,
            'compiler_derived_layout':facts,'reference_object':str(obj.relative_to(ROOT)),'reference_object_sha256':sha(obj),
            'cpu_cases':str(out.relative_to(ROOT)),'cpu_cases_sha256':sha(out),'original_parser_instructions_unchanged':True,
            'original_hid_open_and_close_executed':True,'actual_native_touch_decode_and_hid_report_executed':True,
            'allocation_failures_cleaned_without_leak':True,'strict_owned_memory_bounds_and_canaries':True,
            'full_original_device_start_executed':False,'original_element_report_dispatch_executed':False,'event_driver_matching_qualified':False,
            'allocator_and_memory_imports_are_peers':True,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Unchanged actual iPhone IOHIDFamily C HID open/count/parse/close ARM64 bodies from the current combined prelink, '
                    'with real iPhone-SDK/public-C compiler layouts, original instruction readback, live allocation bounds and explicit allocator/memory peers. '
                    'Native S3910 decode/report bytes checked using original parsed usage/bit/limit metadata; consumer mapping checked from original parser metadata. '
                    'No complete IOHIDDevice start, element report dispatch, private EventDriver, matching, UI or hardware qualification.'}
    (ROOT/'reports/ios16-input-hid-parser.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(cases))+' original iPhone HID parser/cleanup paths and '+str(report['report_case_count'])+' native report/parsed-metadata cases')

if __name__=='__main__':main()
