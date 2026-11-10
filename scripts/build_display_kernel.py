#!/usr/bin/env python3
"""Strictly link the concrete display and module lifecycle into a separate kernel."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from check_gpu_link import ABSENT,assemble,external_relocations,native_link_command,run
from native_driver_build import ROOT,TREE,NATIVE,OBJDIR,archive_imports,inspect_object,macho,require,sha,symbols
from native_prelink import backed_offset

DEPENDENCIES=('gpu-kernel-candidate','gpu-link-probe','ios16-display-service','ios16-graphics-lifecycle','ios16-gop-provider','ios16-graphics-late')


def iobsd_hook(overlay,linked):
    obj=(ROOT/overlay['replacement_object']).read_bytes();table=symbols(obj)
    source,=[s for s in table if s['name']=='_IOKitBSDInit' and not s['kind']&0xe0 and s['kind']&14]
    end=min(s['value'] for s in table if s['section']==source['section'] and s['kind']&14 and not s['kind']&0xe0 and
            s['value']>source['value'] and not s['name'].startswith('ltmp'))
    length=end-source['value'];require(length==72,'Pinned real IOBSD hook function extent changed')
    names={s['name']:s['value'] for s in symbols(linked) if not s['kind']&0xe0 and s['kind']&14}
    address=names['_IOKitBSDInit'];at=backed_offset(macho(linked)['segments'],address,length,len(linked));code=linked[at:at+length]
    calls={}
    for i,word in enumerate(struct.unpack('<'+str(length//4)+'I',code)):
        if word&0xfc000000!=0x94000000:continue
        delta=word&0x3ffffff;target=address+i*4+4*(delta-(1<<26) if delta&(1<<25) else delta)
        require(target not in calls,'IOBSD hook repeats a direct call');calls[target]=address+i*4
    publish=names['__ZN9IOService15publishResourceEPKcP8OSObject'];schedule=names['_dodge_graphics_schedule']
    require(publish in calls and schedule in calls and calls[publish]<calls[schedule],'Actual IOBSD hook does not publish before scheduling')
    return {'address':hex(address),'bytes':length,'sha256':hashlib.sha256(code).hexdigest(),
            'publish_call':hex(calls[publish]),'schedule_call':hex(calls[schedule]),'schedule_target':hex(schedule)}


def concrete_table(late,linked):
    obj=late.read_bytes();image=inspect_object(obj);table=symbols(obj)
    source=next(s for s in table if s['name']=='__ZTV22DodgeIPhoneFramebuffer')
    section=next(s for seg in image['segments'] for s in seg['sections'] if s['name']=='__const')
    offset=source['value']-section['va']+16;reloc,count=struct.unpack_from('<2I',obj,section['command_offset']+56)
    slots={}
    for i in range(count):
        at,bits=struct.unpack_from('<2I',obj,reloc+8*i)
        if offset<=at<offset+338*8:
            require((at-offset)%8==0 and bits>>24==14,'Unexpected concrete vtable relocation')
            slot=(at-offset)//8;require(slot not in slots,'Duplicate concrete vtable relocation');slots[slot]=table[bits&0xffffff]['name']
    require(set(slots)==set(range(338)),'Concrete vtable relocation coverage is incomplete')
    names={s['name']:s for s in symbols(linked) if not s['kind']&0xe0 and s['kind']&14}
    values=[names[slots[i]]['value'] for i in range(338)];address=names[source['name']]['value']+16
    at=backed_offset(macho(linked)['segments'],address,338*8,len(linked))
    require(list(struct.unpack_from('<338Q',linked,at))==values,'Actual full-kernel concrete vtable differs')
    return {'address':hex(address),'entries':338,'symbols':[slots[i] for i in range(338)],'values':[hex(v) for v in values]}


def main():
    reports={n:json.loads((ROOT/'reports'/f'{n}.json').read_text()) for n in DEPENDENCIES}
    require(all('PASS' in r['result'] and r['native_kernel_sha256']==sha(NATIVE) for r in reports.values()),'Display kernel dependencies are not current passing native builds')
    for name in ('ios16-display-service','ios16-graphics-lifecycle','ios16-gop-provider','ios16-graphics-late'):
        for path,h in reports[name]['source_sha256'].items():require(sha(ROOT/path)==h,'Stale display source dependency: '+path)
    life=reports['ios16-graphics-lifecycle'];service=reports['ios16-display-service'];gpu=reports['gpu-kernel-candidate'];gop=reports['ios16-gop-provider']
    late=reports['ios16-graphics-late'];overlay=late['native_object_overlay']
    require(life['service_report_sha256']==sha(ROOT/'reports/ios16-display-service.json'),'Lifecycle uses an older concrete class')
    require(gop['graphics_lifecycle_report_sha256']==sha(ROOT/'reports/ios16-graphics-lifecycle.json'),'GOP provider uses older preparation/boot code')
    out=ROOT/'build/cph2653-display-kernel';objects_dir=out/'objects';objects_dir.mkdir(parents=True,exist_ok=True)
    protected=[NATIVE,TREE.parent/'kernel/kernel.macho',ROOT/'build/cph2653-native-bringup/boot.img',ROOT/reports['gpu-link-probe']['isolated_kernel']]
    protected.extend([ROOT/overlay['original_object'],ROOT/overlay['base_source'],OBJDIR/'link.filelist'])
    before={str(p.relative_to(ROOT)):sha(p) for p in protected};objects=[];aliases={};archives=[]
    expected={**gpu['object_sha256'],**{Path(o['path']).name:o['sha256'] for r in (service,life,gop,late) for o in r['objects']}}
    require(len(expected)==64,'Display source/alias object names collide or expected object count changed')
    for report in (gpu,service,life,gop,late):
        archive=ROOT/report['archive'];require(sha(archive)==report['archive_sha256'],'A display source archive changed');archives.append(archive)
        for name in subprocess.check_output(['/usr/bin/llvm-ar-14','t',archive],text=True).splitlines():
            require(name==Path(name).name and name.endswith('.o') and name in expected,'Unsafe or unexpected display archive member')
            data=subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,name]);p=objects_dir/name;p.write_bytes(data)
            require(sha(p)==expected[name] and p not in objects,'Display archive member differs or is duplicated: '+name);objects.append(p)
            for s in symbols(data):
                if s['kind']==3:
                    require(s['name'] not in aliases,'Duplicate original display alias');aliases[s['name']]=s['value']
                if s['kind']==1 and s['name'] in ABSENT:require(s['description']&0x40,'Strong display import entered optional absence policy')
            require(not any(r['symbol'] in ABSENT and r['type']==2 for r in external_relocations(p)),'Optional display import has a direct branch')
    require(len(objects)==64 and len(aliases)==196,'Full display object or original address count changed')
    imports=archive_imports(objects)
    require(not imports['required_board_or_original_imports'] and set(imports['optional_weak_imports'])==set(ABSENT),'Unresolved concrete display implementation dependency')
    command,inputs,linker=native_link_command(out)
    original_object=ROOT/overlay['original_object'];replacement=ROOT/overlay['replacement_object']
    require(sha(original_object)==overlay['original_object_sha256'] and sha(replacement)==overlay['replacement_object_sha256'],
        'Isolated IOBSD replacement or original object changed')
    rows=[(OBJDIR/line).resolve() for line in (OBJDIR/'link.filelist').read_text().splitlines()]
    require(rows.count(original_object.resolve())==1,'Native filelist does not contain exactly one original IOBSD object')
    native_filelist=out/'display-native.filelist'
    native_filelist.write_text(''.join(str(replacement if p==original_object.resolve() else p)+'\n' for p in rows))
    old_flag='-Wl,-filelist,'+str(OBJDIR/'link.filelist');require(command.count(old_flag)==1,'Unexpected native filelist link argument')
    command[command.index(old_flag)]='-Wl,-filelist,'+str(native_filelist)
    inputs.update([native_filelist,replacement,ROOT/overlay['compile_manifest'],ROOT/overlay['patched_source']])
    partial=out/'DodgeDisplayCombined.o'
    partial_command=[str(linker),'-r','-arch','arm64','-platform_version','ios','16.0','16.0','-all_load',*map(str,archives),'-o',str(partial)]
    run(partial_command,out/'partial-link.log');inspect_object(partial.read_bytes())
    merged=archive_imports([partial]);require(not merged['required_board_or_original_imports'] and set(merged['defined'])>=set(imports['defined']),
        'Relocatable display link lost implementations')
    absent=assemble(out,'absent-weak-imports',''.join(f'.globl {n}\n.set {n},0\n' for n in sorted(ABSENT)))
    require(not any(s['size'] for seg in inspect_object(absent.read_bytes())['segments'] for s in seg['sections']),'Weak absence has data/code')
    output=out/'mach.display';link_command=[*command,*['-Wl,-force_load,'+str(a) for a in archives],str(absent),'-o',str(output)]
    run(link_command,out/'display-link.log',OBJDIR)
    data=output.read_bytes();image=macho(data);table=symbols(data)
    require(image['kind']==2 and struct.unpack_from('<3I',data)==(0xfeedfacf,0x100000c,0),'Display output is not ordinary ARM64 MH_EXECUTE')
    require(not any(s['kind']==1 for s in table),'Strict full display kernel contains undefined imports')
    names={s['name']:s for s in table if not s['kind']&0xe0 and s['kind']&14}
    for name,value in {**aliases,**dict.fromkeys(ABSENT,0)}.items():
        require(names[name]['kind']==3 and names[name]['value']==value,'Original/weak alias changed in full display kernel: '+name)
    late=next(ROOT/o['path'] for o in service['objects'] if Path(o['path']).name=='DodgeIPhoneFramebuffer.late.o')
    vtable=concrete_table(late,data)
    initializer=names[service['initializer']]['value'];early=0
    for section in (s for seg in image['segments'] for s in seg['sections'] if s['name']=='__mod_init_func'):
        require(section['size']%8==0,'Native constructor table is unaligned');at=backed_offset(image['segments'],section['va'],section['size'],len(data))
        pointers=struct.unpack_from('<'+str(section['size']//8)+'Q',data,at);early+=len(pointers)
        require(initializer not in pointers,'Deferred display class remains in the actual early constructor table')
    real=set(reports['gpu-link-probe']['real_linked_entry_points'])|{n for n in imports['defined'] if any(p in n for p in
        ('dodge_display_service_','dodge_iphone_framebuffer_','_dodge_graphics_','_dodge_gop_provider_'))}|{service['initializer']}
    require(all(names[n]['kind']&14==14 and names[n]['value'] and any(seg['va']<=names[n]['value']<seg['va']+seg['size'] and seg['initprot']&4
        for seg in image['segments']) for n in real if n!='_native_gop_vsync'),'Native display/module entry is absent or non-executable')
    firmware=json.loads((ROOT/'reports/gpu-firmware.json').read_text());fw=[]
    for suffix,file in (('gmu','gen80000_gmu.bin'),('sqe','gen80000_sqe.fw'),('aqe','gen80000_aqe.fw'),('zap','gen80000_zap.mbn')):
        symbol='_sm8750_gpu_'+suffix;expected_fw=firmware['files'][file];address=names[symbol]['value']
        at=backed_offset(image['segments'],address,expected_fw['bytes'],len(data));digest=hashlib.sha256(data[at:at+expected_fw['bytes']]).hexdigest()
        size_at=backed_offset(image['segments'],names[symbol+'_size']['value'],8,len(data))
        require(address%4096==0 and digest==expected_fw['sha256'] and struct.unpack_from('<Q',data,size_at)[0]==expected_fw['bytes'],'Display kernel changed stock microcode: '+file)
        fw.append({'file':file,'address':hex(address),'bytes':expected_fw['bytes'],'sha256':digest})
    strong=assemble(out,'missing-display-regression','.data\n.globl _dodge_missing_display_dependency\n.quad _dodge_missing_display_dependency\n')
    run([*link_command[:-2],str(strong),'-o',str(out/'invalid-display')],out/'strong-import-rejected.log',OBJDIR,success=False)
    require('undefined' in (out/'strong-import-rejected.log').read_text().lower(),'Missing display implementation was not refused by real linker')
    require(all(sha(ROOT/p)==h for p,h in before.items()),'Display candidate altered an existing native/default/GPU kernel')
    inputs.update([*archives,absent,NATIVE,linker,ROOT/'.toolchains/xnu-linux/llvm/bin/clang',Path(__file__),
        ROOT/'scripts/native_driver_build.py',ROOT/'scripts/check_gpu_link.py',*[ROOT/'reports'/f'{n}.json' for n in DEPENDENCIES]])
    manifest=out/'link-inputs.json';manifest.write_text(json.dumps({str(p.relative_to(ROOT)):sha(p) for p in sorted(inputs)},indent=2)+'\n')
    commands=out/'link-commands.json';commands.write_text(json.dumps({'partial':partial_command,'display':link_command},indent=2)+'\n')
    report={'result':'IOS16_CONCRETE_DISPLAY_FULL_NATIVE_KERNEL_LINK_PASS','builder_sha256':sha(Path(__file__)),
        'native_kernel_sha256':sha(NATIVE),'dependency_report_sha256':{n:sha(ROOT/'reports'/f'{n}.json') for n in DEPENDENCIES},
        'linked_source_objects':64,'objects':expected,'original_binding_count':196,'original_absolute_bindings_preserved':{n:hex(v) for n,v in aliases.items()},
        'real_linked_entry_points':{n:hex(names[n]['value']) for n in sorted(real)},'imports':imports,
        'strict_no_undefined':True,'strong_missing_import_control':'REJECTED','absence_adapter_contains_code_or_data':False,
        'partial_object':str(partial.relative_to(ROOT)),'partial_object_sha256':sha(partial),'isolated_kernel':str(output.relative_to(ROOT)),
        'isolated_kernel_sha256':sha(output),'bytes':len(data),'concrete_vtable':vtable,'firmware_readback':fw,
        'actual_early_constructor_count':early,'concrete_initializer_removed_from_early_table':True,
        'input_manifest':str(manifest.relative_to(ROOT)),'input_manifest_sha256':sha(manifest),
        'command_manifest':str(commands.relative_to(ROOT)),'command_manifest_sha256':sha(commands),
        'native_filelist':str(native_filelist.relative_to(ROOT)),'native_filelist_sha256':sha(native_filelist),'native_object_overlay':overlay,
        'actual_iobsd_hook':iobsd_hook(overlay,data),
        'opt_in_iobsd_graphics_hook_linked':True,'default_iobsd_source_object_and_filelist_unchanged':True,
        'protected_default_artifact_sha256':before,'default_artifacts_unchanged':True,'concrete_class_and_module_entry_linked':True,
        'original_components_embedded':False,'runtime_entry_invoked':False,'default_kernel_selected':False,'boot_payload_packaged':False,
        'initializer_lifecycle_qualified':False,'hardware_tested':False,'ready_for_ios_boot':False,
        'scope':'Separate actual native kernel link of 54 GPU objects, four concrete-display objects, three original-module/boot orchestration objects, two GOP provider objects and one late worker. '
            'Reads all 338 concrete vtable entries, 196 original addresses and four stock microcodes. No fixture-native N_ABS imports or implementation stubs. '
            'Only this link substitutes an isolated real IOKitBSDInit object that queues a worker when dodge-graphics=1; original source/object/filelist stay untouched. '
            'Original graphics have not yet been embedded into this MH_EXECUTE; explicit prepare/attach has not run in a kernel.'}
    (ROOT/'reports/ios16-display-kernel.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: real 64-object display + module lifecycle/GOP/late kernel, 338 vtable slots, 196 original aliases and four stock microcodes; defaults unchanged')


if __name__=='__main__':main()
