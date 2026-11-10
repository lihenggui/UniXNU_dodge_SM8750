#!/usr/bin/env python3
"""Strictly prelink the isolated GPU kernel with original iPhone graphics, offline."""
from bisect import bisect_right
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from native_driver_build import ROOT,TREE,NATIVE,macho,require,sha,symbols
from native_prelink import backed_offset,exports,unserialize_xml

PROFILE=ROOT/'profiles/os/ios-16.7.16-20H392/profile.toml'
CONFIG=PROFILE.parent/'gpu-prelink.json'
SECURITY=PROFILE.parent/'security-init.json'
ORIGINAL=ROOT/'build/unixnu/ipsw/20H392/kernelcache.decompressed'
LINK_REPORT=ROOT/'reports/gpu-link-probe.json'


def digest(data):return hashlib.sha256(data).hexdigest()


def native_entry_bytes(data,image,address,size):
    # Linked globals can be in genuine Mach-O zero-fill storage. Require the
    # same mapped segment geometry and read its file prefix plus zero suffix.
    matches=[s for s in image['segments'] if s['va']<=address and address+size<=s['va']+s['size']]
    require(len(matches)==1,'Native source entry has ambiguous or absent VM storage')
    segment,=matches;offset=address-segment['va'];available=max(0,min(size,segment['filesize']-offset))
    at=segment['fileoff']+offset
    require(not available or at+available<=len(data),'Native source entry file storage exceeds input')
    return data[at:at+available]+bytes(size-available),{key:segment[key] for key in ('name','va','size','filesize','fileoff')}


def original_context(raw,roots,config):
    image=macho(raw);info,=[s for s in image['segments'] if s['name']=='__PRELINK_INFO']
    at=backed_offset(image['segments'],info['va'],info['filesize'],len(raw))
    metadata=unserialize_xml(raw[at:at+info['filesize']])
    entries={e['CFBundleIdentifier']:e for e in metadata['_PrelinkInfoDictionary']}
    require(len(entries)==len(metadata['_PrelinkInfoDictionary']),'Duplicate original component identities')
    selected=set();interfaces=set();pending=list(roots)
    while pending:
        name=pending.pop()
        if name in selected or name in interfaces:continue
        require(name in entries,'Missing original declared dependency: '+name)
        if entries[name].get('OSKernelResource') is True:interfaces.add(name);continue
        selected.add(name);pending.extend(entries[name].get('OSBundleLibraries') or {})
    require(sorted(selected)==config['expected_executables'] and sorted(interfaces)==config['expected_kernel_interfaces'],
        'Original graphics dependency closure differs from reviewed profile')
    require(not selected.intersection(config['excluded_hardware_components']),'Stock Apple display hardware driver was selected')
    modules={};extents=[]
    for name in sorted(selected):
        header=entries[name]['_PrelinkExecutableLoadAddr'];module=macho(raw,backed_offset(image['segments'],header,32,len(raw)))
        require(module['kind']==11,'Original component is not an ordinary ARM64 kext: '+name)
        modules[name]=module
        for segment in module['segments']:
            if segment['size'] and segment['name']!='__LINKEDIT':extents.append((segment['va'],segment['va']+segment['size'],name,segment))
    extents.sort(key=lambda row:row[:3])
    require(all(left[1]<=right[0] for left,right in zip(extents,extents[1:])),'Original selected component extents overlap')
    starts=[e[0] for e in extents]
    def owner(address):
        index=bisect_right(starts,address)-1
        return extents[index] if index>=0 and address<extents[index][1] else None
    packed=metadata['_PrelinkLinkKASLROffsets'];count,=struct.unpack_from('<I',packed)
    require(len(packed)==4+count*4,'Original relocation table extent changed')
    offsets=struct.unpack_from('<'+str(count)+'I',packed,4)
    require(len(set(offsets))==count,'Duplicate original relocation sites')
    base,=[s['va'] for s in image['segments'] if s['name']=='__PRELINK_TEXT'];sites={}
    for offset in offsets:
        address=base+offset;extent=owner(address)
        if extent:
            require(owner(address+7)==extent,'Original pointer crosses selected component extent')
            sites[address]=extent[2]
    return {'image':image,'entries':entries,'modules':modules,'sites':sites,'owner':owner,'exports':exports(raw,image)}


def verify_post(data,seal):
    start=int(seal['code_file_offset'],16);size=seal['code_bytes'];at=int(seal['hmac_file_offset'],16)
    require(0<=start<=len(data)-size and size>0 and 0<=at<=len(data)-32 and not start<=at<start+size,'POST field bounds differ')
    mac=hmac.digest(b'\0',data[start:start+size],'sha256')
    require(mac.hex()==seal['hmac_sha256'] and data[at:at+32]==mac,'POST field does not match actual native instructions')


def validate_image(data,record,native,original,context,config,link,seal,fixture):
    image=macho(data);native_image=macho(native);parent=context['image']['segments'];slide=int(config['slide'],0)
    require(image['kind']==2 and record['slide']==slide,'Prelink architecture or reviewed slide changed')
    require(record['components']==config['expected_executables'] and record['kernel_interfaces']==config['expected_kernel_interfaces'] and
        not record['codeless_components'],'Prelink component inventory differs from original declared closure')
    verify_post(data,seal)
    for segment in native_image['segments']:
        if segment['filesize'] and segment['initprot']&4:
            old=backed_offset(native_image['segments'],segment['va'],segment['filesize'],len(native))
            new=backed_offset(image['segments'],segment['va'],segment['filesize'],len(data))
            require(data[new:new+segment['filesize']]==native[old:old+segment['filesize']],'Native executable bytes changed during prelink')
    rows=record['bindings'];require(len(rows)==len(context['sites']) and len({r['site'] for r in rows})==len(rows),
        'Prelink pointer inventory omits or duplicates original selected sites')
    require(sum(record['pointer_counts'].values())==len(rows),'Prelink pointer counts differ')
    native_names={}
    for address,names in exports(native,native_image).items():
        for name in names:native_names.setdefault(name,set()).add(address)
    for row in rows:
        require(context['sites'].get(row['site'])==row['module'] and row['new_site']==row['site']+slide,'Prelink pointer provenance differs')
        at=backed_offset(parent,row['site'],8,len(original));target,=struct.unpack_from('<Q',original,at)
        require(target==row['target'],'Prelink pointer no longer matches original input')
        if row['kind']=='component':
            require(context['owner'](target) is not None and row['new_target']==target+slide,'Prelink component pointer target differs')
        else:
            require(row['kind']=='kernel' and context['owner'](target) is None,'Prelink pointer kind differs')
            choices={a for name in context['exports'].get(target,[]) for a in native_names.get(name,())}
            require(choices=={row['new_target']} and any(s['va']<=row['new_target']<s['va']+s['size'] for s in native_image['segments']),
                'Prelink kernel pointer has no unique mapped native name binding')
        at=backed_offset(image['segments'],row['new_site'],8,len(data))
        require(struct.unpack_from('<Q',data,at)[0]==row['new_target'],'Pointer readback differs at '+hex(row['new_site']))
    executable=[]
    for name,module in context['modules'].items():
        for segment in module['segments']:
            if segment['name']!='__TEXT_EXEC' or not segment['filesize']:continue
            old=backed_offset(parent,segment['va'],segment['filesize'],len(original))
            new=backed_offset(image['segments'],segment['va']+slide,segment['filesize'],len(data))
            value=digest(original[old:old+segment['filesize']])
            require(value==record['original_executable_sha256'][name] and digest(data[new:new+segment['filesize']])==value,
                'Original executable readback differs: '+name)
            executable.append({'component':name,'address':hex(segment['va']+slide),'bytes':segment['filesize'],'sha256':value})
    # Real kernel runtime bodies may be private externals (N_PEXT), including
    # UBSAN. Keep those definitions while excluding debugger STAB records.
    table={s['name']:s for s in symbols(data) if not s['kind']&0xe0}
    require(not any(s['kind']==1 for s in table.values()),'Prelinked native symbol table contains unresolved imports')
    aliases=[]
    for name,value in link['original_absolute_bindings_preserved'].items():
        address=int(value,16)
        require(name in table and table[name]['kind']==3 and table[name]['value']==address,'Original alias symbol differs: '+name)
        extent=context['owner'](address-slide);require(extent is not None,'Original alias has no selected component: '+name)
        expected=('com.apple.iokit.IOGPUFamily' if 'IOAcceleratorES' in name else
            'com.apple.iokit.IOSurface' if name.startswith('_native_iphone_surface_') else 'com.apple.iokit.IOMobileGraphicsFamily')
        require(extent[2]==expected,'Original alias resolves to the wrong selected component: '+name)
        at=backed_offset(image['segments'],address,32,len(data))
        if not name.endswith('gMetaClassE'):
            require(extent[3]['name']=='__TEXT_EXEC','Original function alias is outside executable component storage')
            old=backed_offset(parent,address-slide,32,len(original))
            require(data[at:at+32]==original[old:old+32],'Original function alias bytes differ: '+name)
        aliases.append({'symbol':name,'address':hex(address),'component':expected,'kind':'metadata' if name.endswith('gMetaClassE') else 'function'})
    require(len(aliases)==20,'Exact original binding count differs')
    for name,value in link['real_linked_entry_points'].items():
        address=int(value,16);require(name in table and table[name]['kind']&14==14 and table[name]['value']==address,'Native source entry address changed: '+name)
        old,old_geometry=native_entry_bytes(native,native_image,address,8);new,new_geometry=native_entry_bytes(data,image,address,8)
        require(new==old and new_geometry==old_geometry,'Native source entry bytes/zero-fill geometry changed: '+name)
    info,=[s for s in image['segments'] if s['name']=='__PRELINK_INFO'];at=backed_offset(image['segments'],info['va'],info['filesize'],len(data))
    metadata=unserialize_xml(data[at:at+info['filesize']]);entries={e['CFBundleIdentifier']:e for e in metadata['_PrelinkInfoDictionary']}
    expected=set(config['expected_executables']+config['expected_kernel_interfaces'])
    require(len(entries)==len(metadata['_PrelinkInfoDictionary']) and set(entries)==expected,'Emitted original component metadata differs')
    initializers={name:int(entry['address'],0)+slide for name,entry in fixture['initializers'].items()}
    require(record['early_security_initializers']==initializers=={name:entry['_NativePrelinkEarlySecurityInit'] for name,entry in entries.items()
        if '_NativePrelinkEarlySecurityInit' in entry},'Original early security metadata changed')
    for entry in fixture['initializers'].values():
        for block in entry['code']:
            at=backed_offset(image['segments'],int(block['va'],0)+slide,block['size'],len(data))
            require(digest(data[at:at+block['size']])==block['sha256'],'Original early security code changed')
    for name,entry in record['module_entrypoints'].items():
        original_entry=context['entries'][name];old=backed_offset(parent,original_entry['_PrelinkKmodInfo'],196,len(original))
        address=original_entry['_PrelinkKmodInfo']+slide;new=backed_offset(image['segments'],address,196,len(data))
        start,stop=struct.unpack_from('<QQ',original,old+180);wanted=(start+slide if start else 0,stop+slide if stop else 0)
        require(entry['kmod_info_va']==address and (entry['start_va'],entry['stop_va'])==wanted and
            struct.unpack_from('<QQ',data,new+180)==wanted,'Original module entrypoint readback differs: '+name)
    require(not any(record[k] for k in ('abi_qualified','loadable','runtime_qualified','instruction_relocation_complete','register_dataflow_qualified')),
        'Static prelink overstates runtime/ABI qualification')
    return {'pointer_sites_read_back':len(rows),'original_executable_segments':executable,'original_aliases':aliases,
        'native_source_entries_preserved':len(link['real_linked_entry_points']),'early_security_entries_read_back':len(initializers)}


def negative_controls(data,record,native,original,context,config,link,seal,fixture):
    image=macho(data);cases=[]
    pointer=backed_offset(image['segments'],record['bindings'][0]['new_site'],8,len(data))
    code=backed_offset(image['segments'],int(link['original_absolute_bindings_preserved']['_native_iphone_submit_default_packet'],16),4,len(data))
    symcommand,=[at for cmd,at,_ in image['commands'] if cmd==2];symoff,=struct.unpack_from('<I',data,symcommand+8)
    index,=[i for i,s in enumerate(symbols(data)) if s['name']=='_native_iphone_surface_id' and s['kind']==3]
    for name,at,expected in [('pointer',pointer,'Pointer readback'),('original-code',code,'Original executable readback'),
            ('post-field',int(seal['hmac_file_offset'],16),'POST field'),('native-code',int(seal['code_file_offset'],16),'POST field'),
            ('absolute-alias',symoff+index*16+8,'Original alias symbol')]:
        bad=bytearray(data);bad[at]^=1
        try:validate_image(bad,record,native,original,context,config,link,seal,fixture)
        except ValueError as error:
            require(expected in str(error),'Negative prelink control failed for the wrong reason: '+name+' / '+str(error))
            cases.append({'case':name,'result':'REJECTED','check':str(error)})
        else:raise ValueError('Corrupt static prelink was accepted: '+name)
    return cases


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());pin=lock['iphone_gpu_prelink_profile']
    require(pin['path']==str(CONFIG.relative_to(ROOT)) and sha(CONFIG)==pin['sha256'],'Reviewed GPU prelink profile changed')
    config=json.loads(CONFIG.read_text());profile=tomllib.loads(PROFILE.read_text());board=tomllib.loads((ROOT/'board.toml').read_text())
    require(config['schema_version']==1 and config['product']==profile['ipsw']['product']=='iPhone10,3' and config['build']==profile['ipsw']['build']=='20H392' and
        config['original_kernelcache_sha256']==profile['kernel']['prelink']['kernelcache_sha256'] and config['slide']==profile['kernel']['prelink']['slide'] and
        config['boot_arguments']==board['payload']['kernel_args'] and not config['selected_by_default'] and not config['initialization_lifecycle_qualified'],
        'GPU prelink profile is not the reviewed original iPhone/boot-argument target')
    link=json.loads(LINK_REPORT.read_text());source=ROOT/link['isolated_kernel'];source_bytes=source.read_bytes();original=ORIGINAL.read_bytes()
    require(link['result']=='GPU_ISOLATED_NATIVE_AND_RELOCATABLE_LINK_PASS' and link['linked_source_objects']==54 and link['strict_no_undefined'] and
        link['builder_sha256']==sha(ROOT/'scripts/check_gpu_link.py') and link['candidate_report_sha256']==sha(ROOT/'reports/gpu-kernel-candidate.json') and
        digest(source_bytes)==link['isolated_kernel_sha256'] and digest(original)==config['original_kernelcache_sha256'] and link['native_kernel_sha256']==sha(NATIVE),
        'Need the current actual 54-object native link and original iPhone input')
    protected=[NATIVE,TREE.parent/'kernel/kernel.macho',ROOT/'build/cph2653-native-bringup/boot.img']
    before={str(p.relative_to(ROOT)):sha(p) for p in protected}
    roots=profile['kernel']['prelink']['roots']+config['additional_roots'];context=original_context(original,roots,config)
    fixture=json.loads(SECURITY.read_text());out=ROOT/'build/cph2653-gpu-graphics-prelink';out.mkdir(parents=True,exist_ok=True)
    emitter=TREE/'kits/XnuPrelink/emit_prelink.py';sealer=TREE/'scripts/seal-source-crypto-kernel.py'
    parser=ROOT/'sources/UniXNU/drivers/DarwinBoot/Test/test-kernel-parser.py'
    env={**os.environ,'UNIXNU_XNU_ARCH':'arm64','UNIXNU_IOS_VERSION':'16.0','PATH':'/usr/lib/llvm-14/bin'+os.pathsep+os.environ['PATH']}
    with tempfile.TemporaryDirectory(prefix='checked-',dir=out) as temporary:
        work=Path(temporary);sealed=work/'mach.gpu.sealed';sealed.write_bytes(source_bytes);candidate=work/'kernel.macho'
        seal_command=[sys.executable,sealer,sealed,'--kernel-args',' '.join(config['boot_arguments'])]
        result=subprocess.run(seal_command,env=env,text=True,capture_output=True);(out/'seal.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Source GPU kernel POST sealing failed; see '+str(out/'seal.log'))
        native=sealed.read_bytes();seal=json.loads(sealed.with_suffix(sealed.suffix+'.crypto-hmac.json').read_text());at=int(seal['hmac_file_offset'],16)
        require(len(native)==len(source_bytes) and native[:at]==source_bytes[:at] and native[at+32:]==source_bytes[at+32:] and
            seal['kernel_sha256']==digest(native),'POST sealing changed bytes outside its source integrity field')
        verify_post(native,seal)
        command=[sys.executable,emitter,'--kernel',sealed,'--prelinked',ORIGINAL,'--slide='+config['slide'],'--output',candidate]
        for root in roots:command+=['--root',root]
        for request in profile['kernel']['prelink']['early_security_init']:command+=['--early-security-init',request]
        command+=['--early-security-fixture',SECURITY]
        result=subprocess.run(command,env=env,text=True,capture_output=True);(out/'emission.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Strict original graphics prelink failed; see '+str(out/'emission.log'))
        data=candidate.read_bytes();record=json.loads(candidate.with_suffix('.json').read_text())
        require(record['candidate_sha256']==digest(data) and record['candidate_bytes']==len(data) and record['native_sha256']==digest(native) and
            record['original_sha256']==digest(original) and record['early_security_fixture_sha256']==sha(SECURITY),'Emitter record/input hashes differ')
        checked=validate_image(data,record,native,original,context,config,link,seal,fixture)
        controls=negative_controls(data,record,native,original,context,config,link,seal,fixture)
        result=subprocess.run([sys.executable,parser,candidate],env=env,text=True,capture_output=True);(out/'loader-parser.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Actual DarwinBoot parser refused graphics candidate; see '+str(out/'loader-parser.log'))
        require(all(sha(ROOT/path)==value for path,value in before.items()) and sha(source)==link['isolated_kernel_sha256'],
            'An existing default/native link artifact changed during isolated graphics preparation')
        # Promote only after all checks. No default path or boot container is written.
        sealed.replace(out/'mach.gpu.sealed');candidate.replace(out/'kernel.macho');candidate.with_suffix('.json').replace(out/'emission.json')
        (out/'mach.gpu.sealed.crypto-hmac.json').write_text(json.dumps(seal,indent=2)+'\n')
        final_seal={**seal,'kernel_sha256':digest(data),'sealed_native_input_sha256':digest(native)}
        (out/'kernel.macho.crypto-hmac.json').write_text(json.dumps(final_seal,indent=2)+'\n')
    sources=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'board.toml',PROFILE,CONFIG,SECURITY,emitter,
        emitter.parent/'native_prelink.py',sealer,sealer.parent/'kernel_target.py',parser]
    report={'result':'GPU_ORIGINAL_IPHONE_GRAPHICS_STRICT_PRELINK_PASS','builder_sha256':sha(Path(__file__)),
        'profile':str(CONFIG.relative_to(ROOT)),'profile_sha256':sha(CONFIG),'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sources},
        'link_report_sha256':sha(LINK_REPORT),'original_kernelcache_sha256':digest(original),'isolated_native_input_sha256':digest(source_bytes),
        'sealed_native':str((out/'mach.gpu.sealed').relative_to(ROOT)),'sealed_native_sha256':digest(native),
        'candidate':str((out/'kernel.macho').relative_to(ROOT)),'candidate_sha256':digest(data),'candidate_bytes':len(data),
        'emission_record':str((out/'emission.json').relative_to(ROOT)),'emission_record_sha256':sha(out/'emission.json'),
        'post_record':str((out/'kernel.macho.crypto-hmac.json').relative_to(ROOT)),'post_record_sha256':sha(out/'kernel.macho.crypto-hmac.json'),
        'sealed_post_record':str((out/'mach.gpu.sealed.crypto-hmac.json').relative_to(ROOT)),
        'sealed_post_record_sha256':sha(out/'mach.gpu.sealed.crypto-hmac.json'),
        'components':record['components'],'kernel_interfaces':record['kernel_interfaces'],'pointer_counts':record['pointer_counts'],**checked,
        'negative_readback_controls':controls,'original_executable_bytes_unchanged':True,'native_executable_bytes_unchanged':True,
        'source_crypto_post_field_verified':True,'source_crypto_runtime_selftests_executed':False,'darwinboot_production_parser':'PASS',
        'protected_default_artifact_sha256':before,'default_artifacts_unchanged':True,'strict_emission':True,'allow_missing':False,
        'substitute_addresses':False,'concrete_legacy_display_provider_installed':False,'initializer_lifecycle_qualified':False,
        'abi_qualified':False,'loadable':False,'runtime_qualified':False,'default_kernel_selected':False,'boot_payload_packaged':False,'hardware_tested':False,'ready_for_ios_boot':False,
        'scope':'Separate strict static candidate combining the actual 54-object source GPU kernel with the original iPhone graphics dependency closure. '
                'All selected original relocation sites, executable bytes, twenty original aliases, native source entries and two security entries are read back. '
                'The source POST field is populated and checked without modifying executable bytes or running selftests. Five corrupt readback controls are rejected. '
                'Actual loader parsing passes. Concrete display service, original initialization order, ABI, runtime, physical rendering and boot packaging remain unqualified/unselected.'}
    (ROOT/'reports/gpu-graphics-prelink.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: strict GPU + {len(record["components"])} original components / {len(record["kernel_interfaces"])} interfaces; '
        f'{checked["pointer_sites_read_back"]:,} pointers, 20 original aliases, POST field and actual loader readback; default unchanged')


if __name__=='__main__':main()
