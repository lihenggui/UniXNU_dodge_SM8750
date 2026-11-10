#!/usr/bin/env python3
"""Embed exact iPhone components into the combined UFS/display source kernel."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from build_gpu_graphics_prelink import PROFILE,CONFIG,SECURITY,ORIGINAL,digest,original_context,validate_image,negative_controls,verify_post
from build_display_kernel import concrete_table
from build_ufs_root import concrete_methods
from native_driver_build import ROOT,TREE,NATIVE,macho,require,sha,symbols
from native_prelink import backed_offset,exports
from prepare_storage_abi import FIXTURE


def check_storage(data,native,original,context,root,display,display_object,ufs_object):
    image=macho(data);slide=int(json.loads(FIXTURE.read_text())['slide'],0)
    names={s['name']:s for s in symbols(data) if not s['kind']&0xe0 and s['kind']&14}
    aliases=root['combined_original_bindings'];require(len(aliases)==208,'Combined source/original alias inventory changed')
    for name,value in aliases.items():
        address=int(value,16);require(names[name]['kind']==3 and names[name]['value']==address,'Combined original alias differs: '+name)
        owner=context['owner'](address-slide);require(owner is not None,'Combined original alias escaped selected components')
        metadata=name.endswith('gMetaClassE') or name.startswith('_dodge_original_')
        table=name.startswith('__ZTV')
        if name in root['original_bindings']:require(owner[2]=='com.apple.iokit.IOStorageFamily','Storage alias has a different original owner')
        if not metadata and not table:
            require(owner[3]['initprot']&4,'Original method alias is not executable')
            old=backed_offset(context['image']['segments'],address-slide,16,len(original));new=backed_offset(image['segments'],address,16,len(data))
            require(data[new:new+16]==original[old:old+16],'Original method bytes changed')
    require(concrete_table(display_object,data)==concrete_table(display_object,native),'Combined concrete display vtable changed')
    methods=concrete_methods(ufs_object);vptr=names['__ZTV14NativeUfsBlock']['value']+16
    at=backed_offset(image['segments'],vptr,190*8,len(data))
    require(list(struct.unpack_from('<190Q',data,at))==[names[n]['value'] for n in methods],'Combined concrete UFS vtable changed')
    native_names={n:a for a,ns in exports(native,macho(native)).items() for n in ns}
    def parent_table(linked,count):
        old_at=backed_offset(context['image']['segments'],linked-slide,count*8,len(original))
        new_at=backed_offset(image['segments'],linked,count*8,len(data))
        before=struct.unpack_from('<'+str(count)+'Q',original,old_at);after=struct.unpack_from('<'+str(count)+'Q',data,new_at)
        for value,actual in zip(before,after):
            if not value:wanted=0
            elif context['owner'](value):wanted=value+slide
            else:
                choices={native_names[n] for n in context['exports'].get(value,[]) if n in native_names}
                require(len(choices)==1,'Original parent vtable lacks a unique native binding');wanted=next(iter(choices))
            require(actual==wanted,'Original parent vtable pointer changed')
    parent_table(int(aliases['__ZTV25IOMobileFramebufferLegacy'],16),340)
    parent_table(int(aliases['__ZTV20IOBlockStorageDevice'],16),192)
    hook=root['actual_iobsd_hook'];at=backed_offset(image['segments'],int(hook['address'],16),hook['bytes'],len(data))
    require(digest(data[at:at+hook['bytes']])==hook['sha256'],'Combined native IOBSD hook changed')
    return {'original_aliases_read_back':208,'original_storage_aliases_read_back':len(root['original_bindings']),
            'concrete_display_vtable_entries_read_back':338,'concrete_storage_vtable_entries_read_back':190,
            'original_display_parent_words_read_back':340,'original_storage_parent_words_read_back':192,
            'actual_iobsd_hook_read_back':hook}


def main():
    root_path=ROOT/'reports/ios16-ufs-root.json';root=json.loads(root_path.read_text())
    require('PASS' in root['result'] and root['builder_sha256']==sha(ROOT/'scripts/build_ufs_root.py') and root['combined_source_objects']==68 and root['strict_no_undefined'],
            'Need the current complete combined UFS/display native kernel')
    for path,h in root['source_sha256'].items():require(sha(ROOT/path)==h,'Combined source changed: '+path)
    require(root['storage_abi_report_sha256']==sha(ROOT/'reports/ios16-storage-abi.json') and root['display_kernel_report_sha256']==sha(ROOT/'reports/ios16-display-kernel.json'),
            'Combined source dependency report changed')
    source=ROOT/root['isolated_kernel'];source_bytes=source.read_bytes();require(digest(source_bytes)==root['isolated_kernel_sha256'],'Combined source kernel changed')
    config=json.loads(CONFIG.read_text());profile=tomllib.loads(PROFILE.read_text());original=ORIGINAL.read_bytes();security=json.loads(SECURITY.read_text())
    context=original_context(original,profile['kernel']['prelink']['roots']+config['additional_roots'],config)
    gpu_link=json.loads((ROOT/'reports/gpu-link-probe.json').read_text())
    link={'original_absolute_bindings_preserved':gpu_link['original_absolute_bindings_preserved'],'real_linked_entry_points':root['combined_native_entries']}
    display=json.loads((ROOT/'reports/ios16-display-kernel.json').read_text());service=json.loads((ROOT/'reports/ios16-display-service.json').read_text())
    display_obj=next(ROOT/o['path'] for o in service['objects'] if o['path'].endswith('DodgeIPhoneFramebuffer.late.o'))
    ufs_obj=next(ROOT/o['path'] for o in root['objects'] if o['path'].endswith('NativeUfs.late.o'))
    protected={**root['protected_default_artifact_sha256'],str(source.relative_to(ROOT)):sha(source)}
    require(all(sha(ROOT/p)==h for p,h in protected.items()),'Existing default/display artifact changed')
    out=ROOT/'build/cph2653-storage-prelink';out.mkdir(parents=True,exist_ok=True)
    emitter=TREE/'kits/XnuPrelink/emit_prelink.py';sealer=TREE/'scripts/seal-source-crypto-kernel.py';parser=ROOT/'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env={**os.environ,'UNIXNU_XNU_ARCH':'arm64','UNIXNU_IOS_VERSION':'16.0','PATH':'/usr/lib/llvm-14/bin'+os.pathsep+os.environ['PATH']}
    with tempfile.TemporaryDirectory(prefix='checked-',dir=out) as temporary:
        work=Path(temporary);sealed=work/'mach.storage.sealed';sealed.write_bytes(source_bytes);candidate=work/'kernel.macho'
        result=subprocess.run([sys.executable,sealer,sealed,'--kernel-args',' '.join(config['boot_arguments'])],capture_output=True,text=True,env=env)
        (out/'seal.log').write_text(result.stdout+result.stderr);require(not result.returncode,'Combined kernel POST sealing failed')
        native=sealed.read_bytes();seal=json.loads(sealed.with_suffix(sealed.suffix+'.crypto-hmac.json').read_text());at=int(seal['hmac_file_offset'],16)
        require(len(native)==len(source_bytes) and native[:at]==source_bytes[:at] and native[at+32:]==source_bytes[at+32:],'Combined sealing changed bytes outside POST field');verify_post(native,seal)
        command=[sys.executable,emitter,'--kernel',sealed,'--prelinked',ORIGINAL,'--slide='+config['slide'],'--output',candidate]
        for name in profile['kernel']['prelink']['roots']+config['additional_roots']:command+=['--root',name]
        for name in profile['kernel']['prelink']['early_security_init']:command+=['--early-security-init',name]
        command+=['--early-security-fixture',SECURITY]
        result=subprocess.run(command,capture_output=True,text=True,env=env);(out/'prelink.log').write_text(result.stdout+result.stderr)
        require(not result.returncode,'Strict combined UFS/display prelink failed')
        data=candidate.read_bytes();record=json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256']==digest(data) and record['native_sha256']==digest(native) and record['original_sha256']==digest(original),'Combined prelink record hashes differ')
        def validate(value):
            base=validate_image(value,record,native,original,context,config,link,seal,security)
            extra=check_storage(value,native,original,context,root,display,display_obj,ufs_obj);return base,extra
        base,extra=validate(data);controls=negative_controls(data,record,native,original,context,config,link,seal,security)
        image=macho(data);names=symbols(data);symbol_command=next(a for kind,a,n in image['commands'] if kind==2);symbol_offset,=struct.unpack_from('<I',data,symbol_command+8)
        symbol_index=next(i for i,s in enumerate(names) if s['name']=='__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass' and s['kind']==3)
        vptr=next(s['value']+16 for s in names if s['name']=='__ZTV14NativeUfsBlock' and not s['kind']&0xe0 and s['kind']&14)
        controls_at=[('storage-original-constructor-alias',symbol_offset+symbol_index*16+8,'alias'),
                     ('storage-concrete-vtable',backed_offset(image['segments'],vptr+184*8,8,len(data)),'vtable')]
        for name,offset,expected in controls_at:
            bad=bytearray(data);bad[offset]^=1
            try:validate(bad)
            except ValueError as error:
                require(expected in str(error),'Combined negative failed for wrong reason: '+str(error));controls.append({'case':name,'result':'REJECTED','check':str(error)})
            else:raise ValueError('Corrupt storage prelink accepted: '+name)
        result=subprocess.run([sys.executable,parser,candidate],capture_output=True,text=True,env=env);(out/'loader-parser.log').write_text(result.stdout+result.stderr)
        require(not result.returncode,'Actual DarwinBoot parser refused combined source/original kernel')
        require(all(sha(ROOT/p)==h for p,h in protected.items()),'Combined prelink modified protected defaults/display/input')
        sealed.replace(out/'mach.storage.sealed');candidate.replace(out/'kernel.macho');candidate.with_suffix('.json').replace(out/'emission.json')
        (out/'mach.storage.sealed.crypto-hmac.json').write_text(json.dumps(seal,indent=2)+'\n')
        (out/'kernel.macho.crypto-hmac.json').write_text(json.dumps({**seal,'kernel_sha256':digest(data),'sealed_native_input_sha256':digest(native)},indent=2)+'\n')
    files=[Path(__file__),ROOT/'scripts/build_ufs_root.py',ROOT/'scripts/build_gpu_graphics_prelink.py',ROOT/'scripts/build_display_kernel.py',
           PROFILE,CONFIG,SECURITY,FIXTURE,emitter,emitter.parent/'native_prelink.py',sealer,sealer.parent/'kernel_target.py',parser]
    report={'result':'IOS16_COMBINED_UFS_DISPLAY_AND_ORIGINAL_COMPONENTS_STRICT_PRELINK_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'root_source_report_sha256':sha(root_path),
            'native_kernel_sha256':sha(NATIVE),'original_kernelcache_sha256':digest(original),'native_source_input_sha256':digest(source_bytes),
            'combined_source_objects':68,'components':record['components'],'kernel_interfaces':record['kernel_interfaces'],
            'pointer_counts':record['pointer_counts'],**base,**extra,
            **{field:str((out/name).relative_to(ROOT)) for field,name in [('candidate','kernel.macho'),('sealed_native','mach.storage.sealed'),('emission_record','emission.json'),
                ('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.storage.sealed.crypto-hmac.json')]},
            **{field+'_sha256':sha(out/name) for field,name in [('candidate','kernel.macho'),('sealed_native','mach.storage.sealed'),('emission_record','emission.json'),
                ('post_record','kernel.macho.crypto-hmac.json'),('sealed_post_record','mach.storage.sealed.crypto-hmac.json')]},
            'negative_controls':controls,'darwinboot_production_parser':'PASS','source_crypto_post_verified':True,
            'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'native_and_original_executable_bytes_unchanged':True,
            'storage_before_graphics_iobsd_hook_linked':True,'root_argument_enabled_by_default':False,'graphics_argument_enabled_by_default':False,
            'runtime_entries_invoked':False,'runtime_qualified':False,'hardware_tested':False,'default_kernel_selected':False,
            'root_authenticated':False,'boot_payload_packaged':False,'ready_for_ios_boot':False,
            'scope':'Separate combined 68-object source candidate plus 27 exact original iPhone components/seven interfaces, including complete read-only UFS root-window publication. '
                    'Checks every original pointer, all 208 original aliases, two concrete and two original-parent vtables, POST and actual DarwinBoot parsing. '
                    'The actual IOBSD hook selects root startup before graphics only with explicit boot arguments, both disabled by default. '
                    'No physical partition, authenticated root, original userspace, transport/runtime/hardware qualification or default artifact replacement.'}
    (ROOT/'reports/ios16-storage-prelink.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: combined UFS/display + original iPhone prelink, 68 objects / 208 aliases / 52 source entries; pointers, vtables, POST and actual loader read back; no activation')


if __name__=='__main__':main()
