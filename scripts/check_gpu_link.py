#!/usr/bin/env python3
"""Strict isolated kernel/GPU link and weak-import checks; never select a kernel."""
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess

from native_driver_build import ROOT, NATIVE, OBJDIR, archive_imports, build_objects, inspect_object, macho, require, sha, symbols
from native_prelink import backed_offset

# These are absent optional diagnostics, not display implementations. Null
# addresses express Mach-O weak-import absence and contain no code/data object.
# A new missing symbol requires review; strong imports can never enter this set.
ABSENT={
    '_boot_log_export_put':'Unselected UFS-backed cache export',
    '_native_gpu_pixel_put':'Unselected GPU trace pixel capture',
    '_native_gpu_trace_enabled':'Unselected GPU trace switch',
    '_native_gpu_trace_record':'Unselected GPU trace recorder',
    '_native_owner_cache_stage':'Unselected owner-root cache diagnostics',
    '_native_pmap_user_mappings':'Unselected pmap diagnostic query',
    '_native_ufs_block_failures':'Unselected UFS read diagnostics',
    '_native_ufs_block_reads':'Unselected UFS read diagnostics',
    '_pagani_gpu_trace_start':'Unselected reference trace/presenter startup',
}


def run(command,log,cwd=ROOT,success=True):
    with log.open('w') as stream:
        completed=subprocess.run(command,cwd=cwd,stdout=stream,stderr=subprocess.STDOUT,timeout=120)
    require((completed.returncode==0)==success,'Link test returned an unexpected status; see '+str(log))
    return completed.returncode


def external_relocations(path):
    data=path.read_bytes();image=inspect_object(data);table=symbols(data);result=[]
    for section in (s for segment in image['segments'] for s in segment['sections']):
        offset,count=struct.unpack_from('<2I',data,section['command_offset']+56)
        require(offset+count*8<=len(data),'Relocation table exceeds object')
        for index in range(count):
            at,bits=struct.unpack_from('<2I',data,offset+index*8)
            if bits>>27&1:
                require(bits&0xffffff<len(table),'Invalid external relocation symbol')
                result.append({'symbol':table[bits&0xffffff]['name'],'type':bits>>28,'offset':at,'section':section})
    return result


def optional_call_probe(out):
    import unicorn
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC
    require(unicorn.__version__=='2.1.4','Use hash-pinned Unicorn 2.1.4')
    source=out/'optional-call.cpp'
    source.write_text('#include "DodgeOptionalCalls.h"\n'
        'extern "C" uint64_t dodge_test_callback(uint64_t,uint64_t) __attribute__((weak_import));\n'
        'extern "C" uint64_t dodge_optional_probe(uint64_t a,uint64_t b) '
        '{if(!dodge_test_callback)return 0xfeed;return dodge_optional_call(dodge_test_callback,a,b);}\n')
    obj,=build_objects([source],out,[ROOT/'drivers/DodgeDisplay'],['-include','stdint.h'])
    data=obj.read_bytes();image=inspect_object(data);table=symbols(data)
    text,=[s for segment in image['segments'] for s in segment['sections'] if s['name']=='__text']
    code=bytearray(data[text['fileoff']:text['fileoff']+text['size']])
    base,got,peer,stack,stop=0x100000,0x200020,0x210000,0x300000,0x400000
    relocations=external_relocations(obj)
    require(len(relocations)==2 and {entry['type'] for entry in relocations}=={5,6} and
            all(entry['symbol']=='_dodge_test_callback' and entry['section']['name']=='__text' for entry in relocations),
            'Optional function did not lower to a GOT-indirect call')
    for entry in relocations:
        at=entry['offset'];word,=struct.unpack_from('<I',code,at)
        if entry['type']==5:
            require(word&0x9f000000==0x90000000,'Expected optional GOT ADRP')
            immediate=((got&~4095)-((base+at)&~4095))//4096
            word=(word&0x9f00001f)|((immediate&3)<<29)|(((immediate>>2)&0x7ffff)<<5)
        else:
            require(word&0xffc00000==0xf9400000,'Expected optional GOT pointer load')
            word=(word&~(4095<<10))|(((got&4095)//8)<<10)
        struct.pack_into('<I',code,at,word)
    function,=[s for s in table if s['name']=='_dodge_optional_probe' and s['kind']&14]
    cases=[]
    for present,a,b in ((False,7,11),(True,7,11),(True,(1<<64)-1,1)):
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address,length in ((base,4096),(got&~4095,4096),(peer,4096),(stack,16384),(stop,4096)):machine.mem_map(address,length)
        machine.mem_write(base,bytes(code));machine.mem_write(got,struct.pack('<Q',peer if present else 0));calls=[]
        def hook(engine,address,size,user):
            require(base<=address<base+len(code) or address==peer,'Optional call escaped its code/peer')
            if address==peer:
                arguments=(engine.reg_read(UC_ARM64_REG_X0),engine.reg_read(UC_ARM64_REG_X1));calls.append(arguments)
                engine.reg_write(UC_ARM64_REG_X0,sum(arguments)&((1<<64)-1));engine.reg_write(UC_ARM64_REG_PC,engine.reg_read(UC_ARM64_REG_LR))
        def access(engine,kind,address,size,value,user):
            require(stack<=address and address+size<=stack+16384 or kind!=UC_MEM_WRITE and got<=address and address+size<=got+8,
                    'Optional call escaped stack/GOT bounds')
        machine.hook_add(UC_HOOK_CODE,hook);machine.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,access)
        machine.reg_write(UC_ARM64_REG_X0,a);machine.reg_write(UC_ARM64_REG_X1,b)
        machine.reg_write(UC_ARM64_REG_SP,stack+0x3f00);machine.reg_write(UC_ARM64_REG_LR,stop)
        machine.emu_start(base+function['value']-text['va'],stop,timeout=100000,count=256)
        expected=(a+b)&((1<<64)-1) if present else 0xfeed
        require(machine.reg_read(UC_ARM64_REG_PC)==stop and machine.reg_read(UC_ARM64_REG_X0)==expected and
                calls==([(a,b)] if present else []),'Native optional presence/absence/return-value mismatch')
        cases.append({'present':present,'arguments':[a,b],'result':expected,'callback_peer_calls':len(calls)})
    return {'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),'cases':cases,'actual_kernel_callback_executed':False}


def native_link_command(out):
    recorded=shlex.split((OBJDIR/'.LDFLAGS').read_text().replace('\0','').strip())
    libraries=[part for part in recorded[1:] if part.endswith('.a') and not part.startswith('-')]
    require(len(libraries)==1 and libraries[0].endswith('/libcc_kext.a'),'Unexpected recorded native support libraries')
    flags=[part for part in recorded[1:] if part not in libraries]
    native=NATIVE.read_bytes();image=macho(native)
    at,=[at for command,at,_ in image['commands'] if command==0x2a]
    version,=struct.unpack_from('<Q',native,at+8)
    parts=[version>>40,(version>>30)&1023,(version>>20)&1023,(version>>10)&1023,version&1023]
    while len(parts)>1 and not parts[-1]:parts.pop()
    version_text='.'.join(map(str,parts))
    linker=ROOT/'.toolchains/xnu-linux/CommandLineTools/usr/bin/ld'
    command=[ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-fuse-ld='+str(linker),
             *flags,'-Wl,-source_version,'+version_text,'-Wl,-filelist,'+str(OBJDIR/'link.filelist'),
             *(OBJDIR/name for name in ('version.o','lastkerneldataconst.o','lastkernelconstructor.o','nonlto.o')),*libraries]
    record=OBJDIR/'mach.development.bcm2837.link/mach.development.bcm2837.linkarchives'
    command+=shlex.split(record.read_text())
    inputs={OBJDIR/'.LDFLAGS',OBJDIR/'link.filelist',record,OBJDIR/'all-alias.exp',OBJDIR/'symbolsets.plist',
            *(OBJDIR/name for name in ('version.o','lastkerneldataconst.o','lastkernelconstructor.o','nonlto.o'))}
    for line in (OBJDIR/'link.filelist').read_text().splitlines():inputs.add((OBJDIR/line).resolve())
    for argument in command:
        for part in str(argument).split(','):
            if part.endswith('.a') and Path(part).is_file():inputs.add(Path(part).resolve())
    inputs.add(ROOT/'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree/.cache/fakeroot/usr/local/lib/kernel/libfirehose_kernel.a')
    return [str(arg) for arg in command],inputs,linker


def assemble(out,name,source):
    path=out/(name+'.S');path.write_text(source);obj=out/(name+'.o')
    subprocess.run([ROOT/'.toolchains/xnu-linux/llvm/bin/clang','-target','arm64-apple-ios16.0','-c',path,'-o',obj],check=True)
    inspect_object(obj.read_bytes());return obj


def main():
    candidate=json.loads((ROOT/'reports/gpu-kernel-candidate.json').read_text())
    archive=ROOT/candidate['archive'];before=sha(NATIVE)
    require(before==candidate['native_kernel_sha256'] and sha(archive)==candidate['archive_sha256'] and
            not candidate['imports']['required_board_or_original_imports'],'Current complete source-provider archive required')
    out=ROOT/'build/cph2653-gpu-link-probe';objects_dir=out/'objects';objects_dir.mkdir(parents=True,exist_ok=True)
    members=subprocess.check_output(['/usr/bin/llvm-ar-14','t',archive],text=True).splitlines()
    require(len(members)==candidate['object_count']==54 and len(set(members))==54 and
            set(members)==set(candidate['object_sha256']),'Unexpected candidate archive object set')
    objects=[];optional_refs=[];aliases={}
    for name in members:
        require(Path(name).name==name and name.endswith('.o'),'Unsafe archive member name')
        data=subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,name]);path=objects_dir/name;path.write_bytes(data)
        require(sha(path)==candidate['object_sha256'][name],'Candidate member changed: '+name);objects.append(path)
        for symbol in symbols(data):
            if symbol['kind']==3:
                require(symbol['name'] not in aliases,'Duplicate exact original absolute alias')
                aliases[symbol['name']]=symbol['value']
            if symbol['kind']==1 and symbol['name'] in ABSENT:
                require(symbol['description']&0x40,'An absent optional symbol has a strong consumer: '+symbol['name'])
                optional_refs.append({'object':name,'symbol':symbol['name'],'weak_reference':True})
        require(not any(entry['symbol'] in ABSENT and entry['type']==2 for entry in external_relocations(path)),
                'Optional absent address still has a direct ARM64 branch: '+name)
    imports=archive_imports(objects)
    require(imports==candidate['imports'] and set(imports['optional_weak_imports'])==set(ABSENT),
            'Optional absence policy differs from real object references')
    command,inputs,linker=native_link_command(out)
    partial=out/'DodgeA830Combined.o'
    partial_command=[str(linker),'-r','-arch','arm64','-platform_version','ios','16.0','16.0','-all_load',str(archive),'-o',str(partial)]
    run(partial_command,out/'partial-link.log');inspect_object(partial.read_bytes())
    merged=archive_imports([partial])
    require(all(merged[field]==imports[field] for field in ('native_public_imports','native_static_link_only_imports',
                'required_board_or_original_imports','optional_weak_imports')) and set(imports['defined'])<=set(merged['defined']),
            'Real relocatable link lost source definitions or changed imports')
    optional_probe=optional_call_probe(out)
    weak=assemble(out,'weak-regression','.data\n.weak_reference _dodge_negative_missing\n.quad _dodge_negative_missing\n')
    strong=assemble(out,'strong-regression','.data\n.globl _dodge_negative_missing\n.quad _dodge_negative_missing\n')
    mixed=archive_imports([weak,strong])
    require(mixed['required_board_or_original_imports']==['_dodge_negative_missing'] and not mixed['optional_weak_imports'],
            'A strong reference was incorrectly hidden by a weak consumer')
    duplicate=assemble(out,'duplicate-regression','.data\n.globl _native_gop_vsync\n_native_gop_vsync:\n.quad 0,0,0\n')
    duplicate_command=[*partial_command[:-2],str(duplicate),'-o',str(out/'duplicate-invalid.o')]
    run(duplicate_command,out/'duplicate-rejected.log',success=False)
    require('duplicate' in (out/'duplicate-rejected.log').read_text().lower(),'Negative control did not reach duplicate-definition checking')
    absent=assemble(out,'absent-weak-imports','// Absence only: no function bodies or data objects.\n'+
                    ''.join(f'.globl {name}\n.set {name}, 0\n' for name in sorted(ABSENT)))
    require({s['name']:s['value'] for s in symbols(absent.read_bytes()) if s['kind']==3}==dict.fromkeys(ABSENT,0) and
            all(not section['size'] for segment in inspect_object(absent.read_bytes())['segments'] for section in segment['sections']),
            'Weak absence adapter contains code, data or nonzero addresses')
    baseline=out/'mach.baseline';baseline_command=[*command,'-o',str(baseline)]
    run(baseline_command,out/'baseline-link.log',OBJDIR)
    raw=NATIVE.read_bytes();replayed=baseline.read_bytes()
    require(len(raw)==len(replayed),'Native baseline link replay has a different layout')
    canonical_native=bytearray(raw);canonical_replay=bytearray(replayed);image=macho(raw)
    seal=json.loads(NATIVE.with_suffix(NATIVE.suffix+'.crypto-hmac.json').read_text())
    hmac_at=int(seal['hmac_file_offset'],16)
    canonical_native[hmac_at:hmac_at+32]=bytes(32);canonical_replay[hmac_at:hmac_at+32]=bytes(32)
    for kind,at,_ in image['commands']:
        if kind==0x1b:
            canonical_native[at+8:at+24]=bytes(16);canonical_replay[at+8:at+24]=bytes(16)
    require(canonical_native==canonical_replay,'Native baseline replay changed more than UUID/POST seal')
    output=out/'mach.gpu';gpu_command=[*command,'-Wl,-force_load,'+str(archive),str(absent),'-o',str(output)]
    run(gpu_command,out/'gpu-link.log',OBJDIR)
    linked=output.read_bytes();image=macho(linked)
    require(struct.unpack_from('<4I',linked)==(0xfeedfacf,0x100000c,0,2),'Expected ordinary ARM64 MH_EXECUTE isolated link output')
    table=symbols(linked);defined={s['name']:s for s in table if not s['kind']&0xe0 and s['kind']&14}
    require(not any(s['kind']==1 for s in table),'Strict native GPU link retained undefined symbols')
    require(all(name in defined and defined[name]['value']==0 and defined[name]['kind']==3 for name in ABSENT),
            'Absent optional imports were replaced by implementations or data')
    require(all(name in defined and defined[name]['value']==address for name,address in aliases.items()),
            'Real original iPhone absolute bindings changed during final link')
    real=['_native_legacy_gpu_complete','_native_gop_vsync','_dodge_software_refresh_create',
          '_dodge_diagnostic_console_attach','_dodge_gpu_start','_native_gop_handoff_call',
          '_dodge_adreno_display_timeline',
          '___ubsan_handle_negate_overflow_minimal']
    frontend=json.loads((ROOT/'reports/ios16-display-frontend.json').read_text())
    frontend_entries=[name for name in frontend['imports']['defined'] if 'dodge_display_frontend_' in name]
    require(len(frontend_entries)==7 and len(aliases)==20,'Exact frontend/IOSurface source entry or original alias count differs')
    real+=frontend_entries
    require(all(name in defined and defined[name]['value'] for name in real),'A real display/backend/runtime implementation was lost')
    firmware=json.loads((ROOT/'reports/gpu-firmware.json').read_text());firmware_readback=[]
    for suffix,name in (('gmu','gen80000_gmu.bin'),('sqe','gen80000_sqe.fw'),('aqe','gen80000_aqe.fw'),('zap','gen80000_zap.mbn')):
        symbol='_sm8750_gpu_'+suffix;expected=firmware['files'][name];address=defined[symbol]['value']
        at=backed_offset(image['segments'],address,expected['bytes'],len(linked));digest=hashlib.sha256(linked[at:at+expected['bytes']]).hexdigest()
        size_at=backed_offset(image['segments'],defined[symbol+'_size']['value'],8,len(linked))
        require(address%4096==0 and digest==expected['sha256'] and struct.unpack_from('<Q',linked,size_at)[0]==expected['bytes'],
                'Linked target firmware bytes/size/alignment differ: '+name)
        firmware_readback.append({'name':name,'symbol':symbol,'address':hex(address),'bytes':expected['bytes'],'sha256':digest})
    source_files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/optional_gpu_calls.py',ROOT/'drivers/DodgeDisplay/DodgeOptionalCalls.h',
                  *(ROOT/pin['path'] for pin in json.loads((ROOT/'upstream.lock.json').read_text())['dodge_optional_call_overlays'].values())]
    inputs.update(source_files);inputs.update({archive,absent,NATIVE,linker,ROOT/'.toolchains/xnu-linux/llvm/bin/clang'})
    manifest={str(path.relative_to(ROOT)):sha(path) for path in sorted(inputs)}
    manifest_path=out/'link-inputs.json';manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
    commands=out/'validated-commands.json';commands.write_text(json.dumps({'partial':partial_command,'baseline':baseline_command,'gpu':gpu_command},indent=2)+'\n')
    require(sha(NATIVE)==before,'The default native kernel was modified by an isolated link test')
    report={'result':'GPU_ISOLATED_NATIVE_AND_RELOCATABLE_LINK_PASS','native_kernel_sha256':before,'builder_sha256':sha(Path(__file__)),
            'candidate_report_sha256':sha(ROOT/'reports/gpu-kernel-candidate.json'),'candidate_archive_sha256':sha(archive),
            'linked_source_objects':len(objects),'partial_object':str(partial.relative_to(ROOT)),'partial_object_sha256':sha(partial),
            'isolated_kernel':str(output.relative_to(ROOT)),'isolated_kernel_sha256':sha(output),'bytes':len(linked),
            'baseline_replay':str(baseline.relative_to(ROOT)),'baseline_replay_sha256':sha(baseline),
            'baseline_matches_default_except_uuid_and_post_seal':True,'strict_no_undefined':True,
            'optional_weak_absence':ABSENT,'optional_reference_metadata':optional_refs,
            'optional_direct_branch_relocations_absent':True,'absence_adapter_contains_code_or_data':False,
            'optional_call_arm64_probe':optional_probe,'negative_controls':['strong-import-not-hidden-by-weak','duplicate-definition-rejected-by-real-linker'],
            'firmware_binary_readback':firmware_readback,'original_absolute_bindings_preserved':{name:hex(address) for name,address in aliases.items()},
            'real_linked_entry_points':{name:hex(defined[name]['value']) for name in real},
            'static_ubsan_runtime_resolved_from_actual_native_objects':True,
            'input_manifest':str(manifest_path.relative_to(ROOT)),'input_manifest_sha256':sha(manifest_path),
            'command_manifest':str(commands.relative_to(ROOT)),'command_manifest_sha256':sha(commands),
            'default_kernel_unchanged':True,'default_kernel_selected':False,'boot_payload_packaged':False,
            'original_components_embedded':False,'source_crypto_post_sealed':False,'initializer_lifecycle_qualified':False,
            'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Real 54-object relocatable and isolated full native-kernel links with original aliases, bounded packet/queue frontend and stock firmware readback. '
                    'Unselected, guarded weak diagnostics are null addresses; no dummy function/data implementations are linked. '
                    'Default kernel remains byte-for-byte unchanged. Output has no original graphics components, qualified initialization order, '
                    'POST seal or boot packaging and is not a usable iPhone system.'}
    (ROOT/'reports/gpu-link-probe.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: real 54-object and isolated native kernel links; firmware bytes match; default kernel unchanged; no runtime qualification')


if __name__=='__main__':main()
