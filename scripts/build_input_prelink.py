#!/usr/bin/env python3
"""Strict original iPhone IOHIDFamily closure with concrete source input."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib
from build_gpu_graphics_prelink import PROFILE,SECURITY,ORIGINAL,digest,original_context,validate_image,negative_controls,verify_post
from build_ufs_prelink import check_storage
from build_input_native import fresh,read_table,edge_personality,SLIDE
from native_driver_build import ROOT,TREE,NATIVE,require,sha,symbols,macho
from native_prelink import backed_offset,exports
from prepare_hid_source_interface import concrete_methods,BASE
from prepare_hid_event_abi import CONTRACT as EVENT_CONTRACT,methods as event_methods

CONFIG=PROFILE.parent/'input-prelink.json'

def check_input(data,native,original,context,source,obj):
    image=macho(data);names={s['name']:s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
    methods=concrete_methods(obj,'DodgeInput');read_table(data,methods);require(read_table(data,methods)==read_table(native,methods),'Source input table address changed')
    for n,value in source['original_bindings'].items():
        a=int(value,16);require(names[n]['kind']==3 and names[n]['value']==a,'Original HID alias differs: '+n)
        owner=context['owner'](a-SLIDE);require(owner and owner[2]=='com.apple.iokit.IOHIDFamily','Original HID alias owner differs')
        if not (n.endswith('gMetaClassE') or n.startswith('_dodge_original_') or n.startswith('__ZTV')):
            require(owner[3]['initprot']&4,'HID method alias is not executable')
            before=backed_offset(context['image']['segments'],a-SLIDE,16,len(original));after=backed_offset(image['segments'],a,16,len(data))
            require(data[after:after+16]==original[before:before+16],'Original HID method bytes differ')
    parent=json.loads(BASE.read_text());vptr=int(parent['vptr'],16);old=backed_offset(context['image']['segments'],vptr-16,209*8,len(original));new=backed_offset(image['segments'],vptr-16+SLIDE,209*8,len(data))
    before=struct.unpack_from('<209Q',original,old);after=struct.unpack_from('<209Q',data,new)
    native_names={n:a for a,ns in exports(native,macho(native)).items() for n in ns}
    for old_value,new_value in zip(before,after):
        if not old_value:wanted=0
        elif context['owner'](old_value):wanted=old_value+SLIDE
        else:
            choices={native_names[n] for n in context['exports'].get(old_value,[]) if n in native_names}
            require(len(choices)==1,'HID parent lacks a unique native pointer binding');wanted=next(iter(choices))
        require(new_value==wanted,'Original HID parent vtable pointer differs')
    edge_obj=ROOT/'build/ios16-hid-edge-source/DodgeHidEventDriver.late.o';edge_methods=event_methods(edge_obj,'DodgeHidEventDriver',219)
    def edge_table(blob):
        mi=macho(blob);ns={s['name']:s for s in symbols(blob) if not s['kind']&0xe0 and s['kind']&14}
        a=ns['__ZTV19DodgeHidEventDriver']['value']+16;at=backed_offset(mi['segments'],a,219*8,len(blob))
        values=list(struct.unpack_from('<219Q',blob,at))
        require(values==[ns[n]['value'] for n in edge_methods],'Concrete event edge vtable pointer differs');return a
    require(edge_table(data)==edge_table(native),'Concrete edge table moved during prelink')
    require(edge_personality(data)==source['edge_personality_readback'],'Source edge personality changed during prelink')
    contract=json.loads(EVENT_CONTRACT.read_text());driver=contract['classes']['IOHIDEventDriver']
    for n,value in source['edge_original_bindings'].items():
        a=int(value,16);require(names[n]['kind']==3 and names[n]['value']==a,'Original event edge alias changed')
        owner=context['owner'](a-SLIDE);require(owner and owner[2]=='com.apple.iokit.IOHIDFamily','Original event edge alias owner changed')
        if not (n.endswith('gMetaClassE') or n.startswith('_dodge_original_') or n.startswith('__ZTV')):
            require(owner[3]['initprot']&4,'Original event method alias is not executable')
            a0=backed_offset(context['image']['segments'],a-SLIDE,16,len(original));a1=backed_offset(image['segments'],a,16,len(data))
            require(original[a0:a0+16]==data[a1:a1+16],'Original event edge code bytes changed')
    edge_parent=int(driver['vptr'],16)-16
    a0=backed_offset(context['image']['segments'],edge_parent,221*8,len(original));a1=backed_offset(image['segments'],edge_parent+SLIDE,221*8,len(data))
    for old_value,new_value in zip(struct.unpack_from('<221Q',original,a0),struct.unpack_from('<221Q',data,a1)):
        if not old_value:wanted=0
        elif context['owner'](old_value):wanted=old_value+SLIDE
        else:
            candidates={native_names[n] for n in context['exports'].get(old_value,[]) if n in native_names}
            require(len(candidates)==1,'Original event driver parent lacks unique native binding');wanted=next(iter(candidates))
        require(wanted==new_value,'Original event edge parent vtable differs')
    start=names['_dodge_touch_spi_firmware']['value'];end=names['_dodge_touch_spi_firmware_end']['value']
    require(end-start==source['embedded_spi_firmware_bytes'],'Embedded SPI firmware extent differs')
    at=backed_offset(image['segments'],start,end-start,len(data))
    require(digest(data[at:at+end-start])==source['embedded_spi_firmware_sha256'],'Embedded SPI firmware bytes differ')
    return {'concrete_input_vtable_entries_read_back':207,'original_hid_parent_words_read_back':209,'original_hid_aliases_read_back':len(source['original_bindings']),
            'concrete_edge_vtable_entries_read_back':219,'original_event_driver_parent_words_read_back':221,'original_event_aliases_read_back':71,
            'embedded_spi_firmware_bytes_read_back':end-start,'embedded_spi_firmware_sha256':source['embedded_spi_firmware_sha256']}

def main():
    path=ROOT/'reports/ios16-input-native.json';source=fresh(path)
    lock=json.loads((ROOT/'upstream.lock.json').read_text());require(sha(CONFIG)==lock['iphone_input_prelink']['sha256'],'Reviewed input closure changed')
    for name,h in source['dependency_report_sha256'].items():require(sha(ROOT/'reports'/name)==h,'Input dependency changed: '+name)
    for p,h in json.loads((ROOT/source['link_manifest']).read_text()).items():require(sha(ROOT/p)==h,'Input native link input changed: '+p)
    source_path=ROOT/source['isolated_kernel'];source_bytes=source_path.read_bytes();require(digest(source_bytes)==source['isolated_kernel_sha256'],'Source input kernel changed')
    profile=tomllib.loads(PROFILE.read_text());config=json.loads(CONFIG.read_text());original=ORIGINAL.read_bytes();security=json.loads(SECURITY.read_text())
    roots=profile['kernel']['prelink']['roots']+config['additional_roots'];context=original_context(original,roots,config)
    gpu=json.loads((ROOT/'reports/gpu-link-probe.json').read_text());link={'original_absolute_bindings_preserved':gpu['original_absolute_bindings_preserved'],'real_linked_entry_points':source['combined_native_entries']}
    storage=json.loads((ROOT/'reports/ios16-ufs-root.json').read_text());storage={**storage,'actual_iobsd_hook':source['actual_iobsd_hook']}
    display=json.loads((ROOT/'reports/ios16-display-kernel.json').read_text());service=json.loads((ROOT/'reports/ios16-display-service.json').read_text())
    display_obj=next(ROOT/o['path'] for o in service['objects'] if o['path'].endswith('DodgeIPhoneFramebuffer.late.o'))
    ufs_obj=next(ROOT/o['path'] for o in storage['objects'] if o['path'].endswith('NativeUfs.late.o'))
    input_obj=next(ROOT/o['path'] for o in source['objects'] if o['path'].endswith('DodgeInput.late.o'))
    protected={**source['protected_default_artifact_sha256'],str(source_path.relative_to(ROOT)):sha(source_path)}
    out=ROOT/'build/cph2653-input-prelink';out.mkdir(parents=True,exist_ok=True)
    emitter=TREE/'kits/XnuPrelink/emit_prelink.py';sealer=TREE/'scripts/seal-source-crypto-kernel.py';parser=ROOT/'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env={**os.environ,'UNIXNU_XNU_ARCH':'arm64','UNIXNU_IOS_VERSION':'16.0','PATH':'/usr/lib/llvm-14/bin'+os.pathsep+os.environ['PATH']}
    with tempfile.TemporaryDirectory(prefix='checked-',dir=out) as temp:
        work=Path(temp);sealed=work/'mach.input.sealed';sealed.write_bytes(source_bytes);candidate=work/'kernel.macho'
        r=subprocess.run([sys.executable,sealer,sealed,'--kernel-args',' '.join(config['boot_arguments'])],capture_output=True,text=True,env=env)
        (out/'seal.log').write_text(r.stdout+r.stderr);require(not r.returncode,'Input POST seal failed')
        native=sealed.read_bytes();seal=json.loads(sealed.with_suffix(sealed.suffix+'.crypto-hmac.json').read_text());at=int(seal['hmac_file_offset'],16)
        require(len(native)==len(source_bytes) and native[:at]==source_bytes[:at] and native[at+32:]==source_bytes[at+32:],'Input sealing changed other bytes');verify_post(native,seal)
        command=[sys.executable,emitter,'--kernel',sealed,'--prelinked',ORIGINAL,'--slide='+config['slide'],'--output',candidate]
        for n in roots:command+=['--root',n]
        for n in profile['kernel']['prelink']['early_security_init']:command+=['--early-security-init',n]
        command+=['--early-security-fixture',SECURITY]
        r=subprocess.run(command,capture_output=True,text=True,env=env);(out/'prelink.log').write_text(r.stdout+r.stderr);require(not r.returncode,'Strict input/original IOHID prelink failed')
        data=candidate.read_bytes();record=json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256']==digest(data) and record['native_sha256']==digest(native) and record['original_sha256']==digest(original),'Input emission hashes differ')
        def validate(value):
            base=validate_image(value,record,native,original,context,config,link,seal,security)
            storage_checks=check_storage(value,native,original,context,storage,display,display_obj,ufs_obj)
            input_checks=check_input(value,native,original,context,source,input_obj)
            return base,storage_checks,input_checks
        base,storage_checks,input_checks=validate(data);controls=negative_controls(data,record,native,original,context,config,link,seal,security)
        image=macho(data);table={s['name']:s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
        edge_xml=data.index(b'<array><dict><key>IOClass</key><string>DodgeHidEventDriver</string>')
        edge_namespace=data.index(b'<key>CFBundleIdentifier</key><string>__kernel__',edge_xml)+len(b'<key>CFBundleIdentifier</key><string>')
        offsets=[('concrete-input-table',backed_offset(image['segments'],table['__ZTV10DodgeInput']['value']+16+180*8,8,len(data)),'Concrete input vtable'),
                 ('original-hid-parent-table',backed_offset(image['segments'],int(json.loads(BASE.read_text())['vptr'],16)+SLIDE+205*8,8,len(data)),'Original HID parent vtable'),
                 ('embedded-stock-spi-firmware',backed_offset(image['segments'],table['_dodge_touch_spi_firmware']['value']+28,4,len(data)),'Embedded SPI firmware'),
                 ('concrete-event-edge-table',backed_offset(image['segments'],table['__ZTV19DodgeHidEventDriver']['value']+16+198*8,8,len(data)),'Concrete event edge vtable'),
                 ('original-event-driver-table',backed_offset(image['segments'],int(json.loads(EVENT_CONTRACT.read_text())['classes']['IOHIDEventDriver']['vptr'],16)+SLIDE+218*8,8,len(data)),'Original event edge parent vtable'),
                 ('source-edge-personality-namespace',edge_namespace,'Source edge personality')]
        for n,offset,reason in offsets:
            bad=bytearray(data);bad[offset]^=1
            try:check_input(bad,native,original,context,source,input_obj)
            except ValueError as error:require(reason in str(error),'Input corruption rejected for another reason: '+str(error));controls.append({'case':n,'result':'REJECTED','check':str(error)})
            else:raise ValueError('Corrupt input prelink accepted')
        r=subprocess.run([sys.executable,parser,candidate],capture_output=True,text=True,env=env);(out/'parser.log').write_text(r.stdout+r.stderr);require(not r.returncode,'Actual DarwinBoot parser refused input candidate')
        require(all(sha(ROOT/p)==h for p,h in protected.items()),'Input prelink modified protected artifacts')
        sealed.replace(out/'mach.input.sealed');candidate.replace(out/'kernel.macho');candidate.with_suffix('.json').replace(out/'emission.json')
        (out/'mach.input.sealed.crypto-hmac.json').write_text(json.dumps(seal,indent=2)+'\n')
        (out/'kernel.macho.crypto-hmac.json').write_text(json.dumps({**seal,'kernel_sha256':digest(data),'sealed_native_input_sha256':digest(native)},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/build_input_native.py',ROOT/'scripts/build_ufs_prelink.py',ROOT/'scripts/build_gpu_graphics_prelink.py',ROOT/'scripts/prepare_hid_source_interface.py',
           CONFIG,BASE,EVENT_CONTRACT,ROOT/'scripts/prepare_hid_event_abi.py',PROFILE,SECURITY,emitter,emitter.parent/'native_prelink.py',sealer,sealer.parent/'kernel_target.py',parser]
    report={'result':'IOS16_CPH2653_INPUT_STORAGE_DISPLAY_AND_ORIGINAL_COMPONENTS_STRICT_PRELINK_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'input_source_report_sha256':sha(path),
            'native_source_input_sha256':digest(source_bytes),'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':digest(original),
            'components':record['components'],'kernel_interfaces':record['kernel_interfaces'],'pointer_counts':record['pointer_counts'],**base,**storage_checks,**input_checks,
            'combined_source_objects':source['combined_source_objects'],'combined_original_aliases':len(source['combined_original_bindings']),
            **{k:str((out/n).relative_to(ROOT)) for k,n in [('candidate','kernel.macho'),('sealed_native','mach.input.sealed'),('emission_record','emission.json'),('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.input.sealed.crypto-hmac.json')]},
            **{k+'_sha256':sha(out/n) for k,n in [('candidate','kernel.macho'),('sealed_native','mach.input.sealed'),('emission_record','emission.json'),('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.input.sealed.crypto-hmac.json')]},
            'negative_controls':controls,'darwinboot_production_parser':'PASS','source_crypto_post_verified':True,'strict_no_undefined':True,
            'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'original_hid_family_embedded':True,
            'source_private_event_vtable_or_fields_modified':False,'enabled_by_default':False,'runtime_qualified':False,
            'hardware_tested':False,'default_kernel_selected':False,'ready_for_ios_boot':False,
            'scope':'Separate source input/storage/display kernel plus exact original iPhone IOHIDFamily and declared closure. Full original pointer and executable readback, '
                    'three concrete and three original-parent tables, actual BSD queue hook, POST and production loader parser. No controller IO, HID parser/start runtime, UI or iOS boot qualification.'}
    (ROOT/'reports/ios16-input-prelink.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: input prelink {len(record["components"])} original components, {base["pointer_sites_read_back"]} pointers, {len(source["combined_original_bindings"])} aliases; defaults unchanged')

if __name__=='__main__':main()
