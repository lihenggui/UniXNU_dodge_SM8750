#!/usr/bin/env python3
"""Embed exact original graphics into the separate concrete-display kernel, offline."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_gpu_graphics_prelink import PROFILE,CONFIG,SECURITY,ORIGINAL,digest,original_context,validate_image,negative_controls,verify_post
from build_display_kernel import concrete_table,iobsd_hook
from native_driver_build import ROOT,TREE,NATIVE,macho,require,sha,symbols
from native_prelink import backed_offset,exports
from prepare_graphics_lifecycle import FIXTURE,derive
from prepare_gop_provider import FIXTURE as GOP_FIXTURE,derive as derive_gop


def check_extra(data,native,original,context,kernel,fixture,late):
    image=macho(data);native_image=macho(native);slide=int(fixture['slide'],0)
    names={s['name']:s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
    aliases=[]
    for name,value in kernel['original_absolute_bindings_preserved'].items():
        address=int(value,16)
        require(names[name]['kind']==3 and names[name]['value']==address,'Display original alias differs: '+name)
        extent=context['owner'](address-slide);require(extent is not None,'Display alias is outside selected original graphics')
        metadata=name.endswith('gMetaClassE') or name.startswith('_dodge_original_graphics_') or name=='_dodge_original_gop_provider_meta'
        table=name=='__ZTV25IOMobileFramebufferLegacy'
        if not metadata and not table:
            require(extent[3]['initprot']&4,'Display method alias is outside original executable storage')
            old=backed_offset(context['image']['segments'],address-slide,16,len(original));new=backed_offset(image['segments'],address,16,len(data))
            require(data[new:new+16]==original[old:old+16],'Display original method instruction bytes differ')
        aliases.append({'symbol':name,'address':hex(address),'component':extent[2],'kind':'vtable' if table else 'metadata' if metadata else 'function'})
    require(len(aliases)==196,'Full display prelink omitted original bindings')
    checked=concrete_table(late,data);require(checked==kernel['concrete_vtable'],'Prelinked full-kernel concrete vtable differs')
    hook=iobsd_hook(kernel['native_object_overlay'],data)
    require(hook==kernel['actual_iobsd_hook'],'Prelinked native IOBSD scheduling hook changed')
    # Qualified base calls use the original Legacy table. Its native-parent
    # pointers must now target this candidate's actual source-kernel exports.
    base=int(kernel['original_absolute_bindings_preserved']['__ZTV25IOMobileFramebufferLegacy'],16)
    at=backed_offset(context['image']['segments'],base-slide,340*8,len(original));old=struct.unpack_from('<340Q',original,at)
    at=backed_offset(image['segments'],base,340*8,len(data));new=struct.unpack_from('<340Q',data,at)
    native_names={n:a for a,group in exports(native,native_image).items() for n in group}
    for index,value in enumerate(old):
        if not value:wanted=0
        elif context['owner'](value):wanted=value+slide
        else:
            choices={native_names[n] for n in context['exports'].get(value,[]) if n in native_names}
            require(len(choices)==1,'Original Legacy table has no unique actual native binding');wanted=next(iter(choices))
        require(new[index]==wanted,'Original Legacy qualified-call vtable target differs')
    gop=derive_gop();require(gop==json.loads(GOP_FIXTURE.read_text()),'GOP provider contract changed')
    require(kernel['original_absolute_bindings_preserved'][gop['alias']]==gop['linked_metaclass'],'GOP provider metadata identity changed')
    for key,count in (('vptr',178),('metadata_vptr',14)):
        address=int(gop[key],16)
        old_at=backed_offset(context['image']['segments'],address,count*8,len(original))
        new_at=backed_offset(image['segments'],address+slide,count*8,len(data))
        before=struct.unpack_from('<'+str(count)+'Q',original,old_at)
        after=struct.unpack_from('<'+str(count)+'Q',data,new_at)
        for value,actual in zip(before,after):
            if not value:wanted=0
            elif context['owner'](value):wanted=value+slide
            else:
                choices={native_names[n] for n in context['exports'].get(value,[]) if n in native_names}
                require(len(choices)==1,'Original GOP provider vtable lacks a unique actual native binding');wanted=next(iter(choices))
            require(actual==wanted,'Original GOP provider vtable differs: '+key)
    constructors=finalizers=0
    entries={}
    for module in fixture['modules']:
        require(int(module['linked_metaclass'],16)==int(kernel['original_absolute_bindings_preserved'][module['alias']],16),'Module identity is not bound to exact original metadata')
        original_address=int(module['kmod_info'],16);at=backed_offset(image['segments'],original_address+slide,196,len(data))
        actual=struct.unpack_from('<2Q',data,at+180)
        require(actual==(int(module['start'],16)+slide,int(module['stop'],16)+slide),'Original lifecycle start/stop addresses differ')
        for section in module['sections'].values():
            at=backed_offset(image['segments'],int(section['address'],16)+slide,section['bytes'],len(data))
            wanted=[int(e['address'],16)+slide for e in section['entries']]
            require(list(struct.unpack_from('<'+str(len(wanted))+'Q',data,at))==wanted,'Original module constructor/finalizer table differs')
            for e in section['entries']:
                a=int(e['address'],16)+slide;p=backed_offset(image['segments'],a,16,len(data))
                require(digest(data[p:p+16])==e['prefix_sha256'],'Original lifecycle function prefix differs')
        constructors+=len(module['sections']['__mod_init_func']['entries']);finalizers+=len(module['sections']['__mod_term_func']['entries'])
        entries[module['bundle']]={'start':hex(actual[0]),'stop':hex(actual[1]),'metadata':module['linked_metaclass'],'instance_bytes':module['instance_bytes']}
    return {'original_display_aliases':aliases,'concrete_vtable_entries_read_back':338,'original_legacy_vtable_words_read_back':340,
        'module_constructor_entries_read_back':constructors,'module_finalizer_entries_read_back':finalizers,'original_graphics_module_entries':entries,
        'original_gop_provider_vtable_entries_read_back':178,'original_gop_metadata_vtable_entries_read_back':14,
        'gop_provider_contract_sha256':sha(GOP_FIXTURE),'actual_iobsd_hook':hook}


def main():
    kernel_path=ROOT/'reports/ios16-display-kernel.json';kernel=json.loads(kernel_path.read_text())
    require(kernel['builder_sha256']==sha(ROOT/'scripts/build_display_kernel.py') and kernel['linked_source_objects']==64 and kernel['strict_no_undefined'],
        'Need a current actual full display kernel link')
    for n,h in kernel['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{n}.json')==h,'Display kernel dependency changed: '+n)
    source=ROOT/kernel['isolated_kernel'];source_bytes=source.read_bytes();require(digest(source_bytes)==kernel['isolated_kernel_sha256'],'Display kernel changed')
    config=json.loads(CONFIG.read_text());profile=tomllib.loads(PROFILE.read_text());original=ORIGINAL.read_bytes()
    fixture=derive();require(fixture==json.loads(FIXTURE.read_text()) and digest(original)==fixture['original_kernelcache_sha256'],'Original module lifecycle contract is stale')
    life=json.loads((ROOT/'reports/ios16-graphics-lifecycle.json').read_text());service=json.loads((ROOT/'reports/ios16-display-service.json').read_text())
    require(life['contract_sha256']==sha(FIXTURE),'Lifecycle contract changed after native compilation')
    old_gpu=json.loads((ROOT/'reports/gpu-link-probe.json').read_text())
    check_link={'original_absolute_bindings_preserved':old_gpu['original_absolute_bindings_preserved'],'real_linked_entry_points':kernel['real_linked_entry_points']}
    require(all(kernel['original_absolute_bindings_preserved'][n]==a for n,a in check_link['original_absolute_bindings_preserved'].items()),'Existing exact GPU aliases changed')
    late=next(ROOT/o['path'] for o in service['objects'] if Path(o['path']).name=='DodgeIPhoneFramebuffer.late.o')
    protected=[NATIVE,TREE.parent/'kernel/kernel.macho',ROOT/'build/cph2653-native-bringup/boot.img',ROOT/old_gpu['isolated_kernel'],
        ROOT/'build/cph2653-gpu-graphics-prelink/kernel.macho',source]
    before={str(p.relative_to(ROOT)):sha(p) for p in protected}
    roots=profile['kernel']['prelink']['roots']+config['additional_roots'];context=original_context(original,roots,config);security=json.loads(SECURITY.read_text())
    out=ROOT/'build/cph2653-display-prelink';out.mkdir(parents=True,exist_ok=True)
    emitter=TREE/'kits/XnuPrelink/emit_prelink.py';sealer=TREE/'scripts/seal-source-crypto-kernel.py';parser=ROOT/'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env={**os.environ,'UNIXNU_XNU_ARCH':'arm64','UNIXNU_IOS_VERSION':'16.0','PATH':'/usr/lib/llvm-14/bin'+os.pathsep+os.environ['PATH']}
    with tempfile.TemporaryDirectory(prefix='checked-',dir=out) as temporary:
        work=Path(temporary);sealed=work/'mach.display.sealed';sealed.write_bytes(source_bytes);candidate=work/'kernel.macho'
        result=subprocess.run([sys.executable,sealer,sealed,'--kernel-args',' '.join(config['boot_arguments'])],capture_output=True,text=True,env=env)
        (out/'seal.log').write_text(result.stdout+result.stderr);require(result.returncode==0,'Display POST sealing failed')
        native=sealed.read_bytes();seal=json.loads(sealed.with_suffix(sealed.suffix+'.crypto-hmac.json').read_text());at=int(seal['hmac_file_offset'],16)
        require(len(native)==len(source_bytes) and native[:at]==source_bytes[:at] and native[at+32:]==source_bytes[at+32:],'Display sealing changed bytes outside POST field')
        verify_post(native,seal)
        command=[sys.executable,emitter,'--kernel',sealed,'--prelinked',ORIGINAL,'--slide='+config['slide'],'--output',candidate]
        for root in roots:command+=['--root',root]
        for request in profile['kernel']['prelink']['early_security_init']:command+=['--early-security-init',request]
        command+=['--early-security-fixture',SECURITY]
        result=subprocess.run(command,capture_output=True,text=True,env=env);(out/'emission.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Strict full display/original graphics prelink failed; see emission.log')
        data=candidate.read_bytes();record=json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256']==digest(data) and record['native_sha256']==digest(native) and record['original_sha256']==digest(original),'Display prelink record hashes differ')
        def validate(value):
            base=validate_image(value,record,native,original,context,config,check_link,seal,security)
            extra=check_extra(value,native,original,context,kernel,fixture,late);return base,extra
        base,extra=validate(data)
        controls=negative_controls(data,record,native,original,context,config,check_link,seal,security)
        image=macho(data);at=backed_offset(image['segments'],int(kernel['concrete_vtable']['address'],16)+109*8,8,len(data))
        symcmd,=[a for kind,a,_ in image['commands'] if kind==2];symoff,=struct.unpack_from('<I',data,symcmd+8);table=symbols(data)
        def symbol_at(name):
            index,=[i for i,s in enumerate(table) if s['name']==name and s['kind']==3];return symoff+index*16+8
        method=next(n for n in kernel['original_absolute_bindings_preserved'] if n.startswith('__ZN25IOMobileFramebufferLegacy') and 'gMetaClass' not in n)
        gop=json.loads(GOP_FIXTURE.read_text());gop_table=backed_offset(image['segments'],int(gop['vptr'],16)+int(gop['slide'],0)+21*8,8,len(data))
        for name,offset in [('concrete-vtable',at),('display-original-alias',symbol_at(method)),('graphics-metadata-alias',symbol_at('_dodge_original_graphics_surface_meta')),
                           ('gop-provider-vtable',gop_table),('gop-provider-metadata-alias',symbol_at(gop['alias']))]:
            bad=bytearray(data);bad[offset]^=1
            try:validate(bad)
            except ValueError as error:
                expected_error='Pointer readback' if name=='gop-provider-vtable' else 'vtable' if 'vtable' in name else 'alias'
                require(expected_error in str(error),'Extra display negative failed for wrong reason: '+str(error))
                controls.append({'case':name,'result':'REJECTED','check':str(error)})
            else:raise ValueError('Corrupt concrete display prelink was accepted: '+name)
        result=subprocess.run([sys.executable,parser,candidate],capture_output=True,text=True,env=env);(out/'loader-parser.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Actual DarwinBoot parser refused full display prelink')
        require(all(sha(ROOT/p)==h for p,h in before.items()),'Display prelink changed an existing native/default/GPU artifact')
        sealed.replace(out/'mach.display.sealed');candidate.replace(out/'kernel.macho');candidate.with_suffix('.json').replace(out/'emission.json')
        (out/'mach.display.sealed.crypto-hmac.json').write_text(json.dumps(seal,indent=2)+'\n')
        (out/'kernel.macho.crypto-hmac.json').write_text(json.dumps({**seal,'kernel_sha256':digest(data),'sealed_native_input_sha256':digest(native)},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/build_display_kernel.py',ROOT/'scripts/build_gpu_graphics_prelink.py',ROOT/'scripts/prepare_graphics_lifecycle.py',
        PROFILE,CONFIG,SECURITY,FIXTURE,GOP_FIXTURE,ROOT/'scripts/prepare_gop_provider.py',emitter,emitter.parent/'native_prelink.py',sealer,sealer.parent/'kernel_target.py',parser]
    report={'result':'IOS16_CONCRETE_DISPLAY_AND_ORIGINAL_GRAPHICS_STRICT_PRELINK_PASS','builder_sha256':sha(Path(__file__)),
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'display_kernel_report_sha256':sha(kernel_path),
        'graphics_lifecycle_report_sha256':sha(ROOT/'reports/ios16-graphics-lifecycle.json'),'original_kernelcache_sha256':digest(original),
        'isolated_native_input_sha256':digest(source_bytes),'linked_source_objects':64,
        **{field:str((out/name).relative_to(ROOT)) for field,name in [('candidate','kernel.macho'),('sealed_native','mach.display.sealed'),('emission_record','emission.json'),
            ('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.display.sealed.crypto-hmac.json')]},
        **{field+'_sha256':sha(out/name) for field,name in [('candidate','kernel.macho'),('sealed_native','mach.display.sealed'),('emission_record','emission.json'),
            ('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.display.sealed.crypto-hmac.json')]},
        'components':record['components'],'kernel_interfaces':record['kernel_interfaces'],'pointer_counts':record['pointer_counts'],**base,**extra,
        'original_binding_count':196,'negative_readback_controls':controls,'source_crypto_post_field_verified':True,'darwinboot_production_parser':'PASS',
        'protected_default_artifact_sha256':before,'default_artifacts_unchanged':True,'original_executable_bytes_unchanged':True,'native_executable_bytes_unchanged':True,
        'strict_emission':True,'allow_missing':False,'substitute_addresses':False,'concrete_class_and_module_entry_linked':True,
        'runtime_entry_invoked':False,'runtime_provider_registered':False,'initializer_lifecycle_qualified':False,'abi_qualified':False,
        'loadable':False,'runtime_qualified':False,'default_kernel_selected':False,'boot_payload_packaged':False,'hardware_tested':False,'ready_for_ios_boot':False,
        'scope':'Separate full concrete-display/native-module/GPU source kernel plus the exact 27 original graphics components and seven interfaces. '
            'Read back all 58962 original pointer fixups, 196 absolute aliases, 338 owned and 340 original-base vtable words, 178 provider and 14 provider-metaclass slots, 53 constructors and 53 finalizers. '
            'POST and actual DarwinBoot parsing pass, ten corrupt controls are rejected. Explicit preparation/provider/attachment is linked but has not run on a kernel. '
            'Full original parent lifecycle, power, automatic matching, physical rendering and boot readiness remain unqualified.'}
    (ROOT/'reports/ios16-display-prelink.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: concrete display/GOP + 27 original graphics components, 58962 fixups, 196 aliases, four vtables, 53 constructors/finalizers, POST and loader parsing; defaults unchanged')


if __name__=='__main__':main()
