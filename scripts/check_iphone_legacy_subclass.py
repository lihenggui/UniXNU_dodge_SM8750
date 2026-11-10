#!/usr/bin/env python3
"""Check a native derived Legacy vtable and emit exact inherited-method bindings.

The derived class is an ABI test fixture, never a registered display provider.
Opaque inherited symbols are vtable placeholders, not source-call prototypes.
"""
import hashlib
import json
import struct
import subprocess
import tomllib

from check_ios16_swap import original_input
from native_driver_build import ROOT,NATIVE,build_objects,inspect_object,macho,require,sha,symbols
from native_prelink import backed_offset,exports,unserialize_xml

SOURCE=ROOT/'tests/IPhoneLegacySubclassProbe.cpp'
HEADER=ROOT/'profiles/os/ios-16.7.16-20H392/graphics/OriginalLegacyFramebufferABI.h'
OWN={0:'D1Ev',1:'D0Ev',178:'12submitPacketEPKvPv',211:'10backend211EjPvj',212:'10backend212EjPjPv',
     242:'10backend242EPvS0_',243:'9opaque243Ev',274:'13startHardwareEv',276:'13kickSwapQueueEv',
     282:'19validateSwapRequestEP18IOMFBSwapIORequest',292:'10backend292EPvb',293:'10backend293EPvS0_',
     321:'10backend321EjPvPjj',322:'10backend322Ej',329:'10backend329Ev'}


def run(command,log):
    result=subprocess.run(command,capture_output=True,text=True,timeout=120)
    log.write_text(result.stdout+result.stderr)
    require(result.returncode==0,'Native subclass command failed; see '+str(log))


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text())['iphone_display_interface']
    contract_path=ROOT/lock['path'];contract=json.loads(contract_path.read_text())
    require(sha(contract_path)==lock['sha256'] and sha(HEADER)==lock['header_sha256'],'Exact Legacy interface inputs changed')
    classes,original,original_image,read=original_input()
    require(classes['original_kernelcache_sha256']==contract['original_kernelcache_sha256'],'Subclass and interface use different iPhone kernels')
    original_table=struct.unpack('<338Q',read(int(contract['legacy_vptr'],16),338*8))
    raw_native=NATIVE.read_bytes();native_image=macho(raw_native)
    native_exports={name:address for address,group in exports(raw_native,native_image).items() for name in group}
    native_vptr=native_exports['__ZTV9IOService']+16
    native_table=struct.unpack_from('<168Q',raw_native,backed_offset(native_image['segments'],native_vptr,168*8,len(raw_native)))
    info=next(s for s in original_image['segments'] if s['name']=='__PRELINK_INFO')
    entry=next(e for e in unserialize_xml(read(info['va'],info['filesize']))['_PrelinkInfoDictionary']
               if e['CFBundleIdentifier']=='com.apple.iokit.IOMobileGraphicsFamily')
    module=macho(original,backed_offset(original_image['segments'],entry['_PrelinkExecutableLoadAddr'],32,len(original)))
    original_text=next(s for s in module['segments'] if s['name']=='__TEXT_EXEC')
    out=ROOT/'build/ios16-display-subclass';out.mkdir(parents=True,exist_ok=True)
    obj,=build_objects([SOURCE],out,[HEADER.parent],['-Wno-overloaded-virtual'])
    data=obj.read_bytes();image=inspect_object(data);names=symbols(data)
    const=next(s for segment in image['segments'] for s in segment['sections'] if s['name']=='__const')
    vtable_name='__ZTV25IPhoneLegacySubclassProbe'
    vtable=next(s for s in names if s['name']==vtable_name)
    require(read(int(contract['legacy_vptr'],16)+338*8,8)==bytes(8) and
            vtable['value']==const['va'] and const['size']==(338+3)*8 and
            data[const['fileoff']:const['fileoff']+16]==bytes(16) and
            data[const['fileoff']+340*8:const['fileoff']+341*8]==bytes(8),
            'Native derived vtable header/338 entries/terminating zero differ')
    offset,count=struct.unpack_from('<2I',data,const['command_offset']+56)
    require(count==338,'Native derived vtable must have exactly 338 pointer relocations')
    slots={};bindings={};original_bindings={};own_slots=[];native_slots=[]
    for index in range(count):
        address,bits=struct.unpack_from('<2I',data,offset+index*8)
        require(bits>>24==0x0e and address>=16 and address%8==0,'Unexpected native derived vtable relocation type')
        slot=(address-16)//8;symbol=names[bits&0xffffff];name=symbol['name']
        require(0<=slot<338 and slot not in slots and struct.unpack_from('<Q',data,const['fileoff']+address)[0]==0,
                'Native derived vtable slot/addend differs')
        slots[slot]=name
        if slot in OWN:
            require(name=='__ZN25IPhoneLegacySubclassProbe'+OWN[slot] and symbol['kind']&14==14,
                    'Own native override moved or has the wrong declaration: '+str(slot))
            own_slots.append(slot)
        elif 'IOMobileFramebufferLegacy' in name:
            require(symbol['kind']==1,'Inherited Legacy entry unexpectedly has a source implementation')
            if slot>=168 and slot not in (246,281):require(name.endswith('opaque'+str(slot)+'Ev'),'Opaque inherited slot shifted')
            bindings[name]=original_bindings[name]=original_table[slot]
        else:
            require(slot<168 and symbol['kind']==1 and native_exports.get(name)==native_table[slot],
                    'Compiled inherited public IOService symbol differs from the actual native vtable: '+str(slot)+' '+name)
            bindings[name]=native_exports[name];native_slots.append(slot)
    require(set(slots)==set(range(338)) and len(own_slots)==15 and len(original_bindings)==168 and len(native_slots)==155,
            'Derived vtable own/original/native classification changed')
    for key,suffix in (('protected_constructor','C2EPK11OSMetaClass'),('protected_destructor','D2Ev')):
        name='__ZN25IOMobileFramebufferLegacy'+suffix;bindings[name]=original_bindings[name]=int(contract[key],16)
    code_bindings=dict(original_bindings)
    metadata_name='__ZN25IOMobileFramebufferLegacy10gMetaClassE'
    bindings[metadata_name]=original_bindings[metadata_name]=int(contract['legacy_metadata'],16)
    remaining=[]
    for symbol in names:
        if symbol['kind']==1 and symbol['name'] not in bindings:
            name=symbol['name'];require(name in native_exports,'Subclass has an unclassified external dependency: '+name)
            bindings[name]=native_exports[name];remaining.append(name)
    require(remaining==['__ZN8OSObjectdlEPvm'] and len(bindings)==327 and len(original_bindings)==171,
            'Subclass constructor/destructor/allocator dependencies differ')
    require(all(original_text['va']<=address<original_text['va']+original_text['filesize'] for address in code_bindings.values()),
            'Original subclass alias escaped the exact IOMobileGraphicsFamily code segment')
    require(any(s['name']=='__DATA' and s['va']<=original_bindings[metadata_name]<s['va']+s['size'] for s in module['segments']),
            'Original Legacy parent metaclass is not within its actual component data segment')
    slide=int(tomllib.loads((contract_path.parent/'profile.toml').read_text())['kernel']['prelink']['slide'],0)
    def assemble(name,values):
        source=out/(name+'.S');source.write_text(''.join(f'.globl {key}\n.set {key},{value:#x}\n' for key,value in sorted(values.items())))
        output=source.with_suffix('.o')
        run([str(ROOT/'.toolchains/xnu-linux/llvm/bin/clang'),'-target','arm64-apple-ios16.0','-c',str(source),'-o',str(output)],source.with_suffix('.log'))
        raw=output.read_bytes();obj_image=inspect_object(raw)
        require({s['name']:s['value'] for s in symbols(raw) if s['kind']==3}==values and
                all(not s['size'] for segment in obj_image['segments'] for s in segment['sections']),
                'Subclass binding object contains code/data or wrong absolute targets')
        return output
    absolute=assemble('original-subclass-bindings',{name:address+slide for name,address in original_bindings.items()})
    archive=out/'libIPhone16LegacySubclassBindings.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,absolute],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,absolute.name])==absolute.read_bytes(),'Subclass bindings archive readback changed')
    fixture=assemble('fixture-bindings',bindings);linked=out/'subclass-probe.macho'
    command=[str(ROOT/'.toolchains/xnu-linux/CommandLineTools/usr/bin/ld'),'-arch','arm64','-static','-platform_version','ios','16.0','16.0',
             '-e','_iphone_legacy_probe_construct','-no_uuid','-pagezero_size','0','-image_base','0xfffffff005000000',str(obj),str(fixture),'-o',str(linked)]
    run(command,out/'link.log');linked_raw=linked.read_bytes();linked_image=macho(linked_raw)
    linked_names={s['name']:s for s in symbols(linked_raw) if not s['kind']&0xe0}
    require(not any(s['kind']==1 for s in linked_names.values()),'Strict native subclass fixture retains undefined symbols')
    require(all(linked_names[name]['kind']==3 and linked_names[name]['value']==address for name,address in bindings.items()),
            'Strict native subclass fixture lost an exact native/original absolute binding')
    table_address=linked_names[vtable_name]['value']+16
    at=backed_offset(linked_image['segments'],table_address,338*8,len(linked_raw));pointers=struct.unpack_from('<338Q',linked_raw,at)
    expected=[linked_names[slots[slot]]['value'] for slot in range(338)]
    require(list(pointers)==expected,'Linked native derived vtable does not read back all 338 exact targets')
    corrupted=bytearray(linked_raw);corrupted[at+168*8]^=1
    require(list(struct.unpack_from('<338Q',corrupted,at))!=expected,'Corrupted inherited vtable pointer was not detected')
    manifest=out/'link-command.json';manifest.write_text(json.dumps(command,indent=2)+'\n')
    from ios16_subclass_emulation import emulate
    cases,original_lifetime=emulate(linked,contract,classes,read)
    report={'result':'IOS16_NATIVE_LEGACY_SUBCLASS_LAYOUT_BINDINGS_AND_BOUNDED_LIFETIME_PASS',
        'builder_sha256':sha(ROOT/'scripts/check_iphone_legacy_subclass.py'),'emulator_sha256':sha(ROOT/'scripts/ios16_subclass_emulation.py'),
        'source_sha256':{str(path.relative_to(ROOT)):sha(path) for path in (SOURCE,HEADER,ROOT/'scripts/native_driver_build.py')},
        'interface_report_sha256':sha(ROOT/'reports/ios16-display-interface.json'),'interface_contract_sha256':sha(contract_path),
        'original_kernelcache_sha256':classes['original_kernelcache_sha256'],'native_kernel_sha256':sha(NATIVE),
        'legacy_base_bytes':5728,'fixture_instance_bytes':5736,'marker_offset':5728,'native_vtable_entries':338,
        'native_vtable_zero_sentinel_bytes':8,'own_override_slots':sorted(own_slots),'native_inherited_slots':len(native_slots),
        'original_inherited_slots':168,'original_binding_count':171,'original_code_binding_count':170,'original_metaclass_binding_count':1,
        'strict_link_pointer_readbacks':338,
        'original_component':entry['CFBundleIdentifier'],'slide':slide,
        'original_bindings':{name:hex(address+slide) for name,address in sorted(original_bindings.items())},
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),'binding_object':str(absolute.relative_to(ROOT)),'binding_object_sha256':sha(absolute),
        'native_probe':str(obj.relative_to(ROOT)),'native_probe_sha256':sha(obj),'linked_fixture':str(linked.relative_to(ROOT)),'linked_fixture_sha256':sha(linked),
        'link_manifest':str(manifest.relative_to(ROOT)),'link_manifest_sha256':sha(manifest),
        'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
        'original_lifetime':original_lifetime,'arm64_cases':cases,'case_count':len(cases),
        'inherited_pointer_corruption_control':'REJECTED','binding_object_has_code_or_data':False,
        'slot243_fixture_traps_without_claiming_prototype':True,'strict_no_undefined':True,
        'original_parent_ctor_dtor_code_executed':True,'source_parent_ctor_dtor_code_executed':True,'parent_lifetime_uses_peers':False,
        'original_metaclass_registered':False,'original_iokit_instance_constructed':False,
        'real_display_provider_installed':False,'kernel_candidate_includes_fixture':False,'default_kernel_selected':False,'hardware_tested':False,
        'scope':'Native layout-only derived class with all nine abstract entries overridden by test functions; no source display implementation. '
                '338 vtable slots are classified and read back after strict linking; 170 original-code and one parent-metaclass absolute aliases have no implementation bytes. '
                'Bounded CPU lifetime tests execute original and actual source-kernel IOService parent constructors/destructors without parent peers and compare all object bytes. '
                'Allocator, registration, init/start/stop and full IOKit lifetime are unexecuted. Slot 243 remains a trap in this fixture, not a recovered prototype.'}
    (ROOT/'reports/ios16-display-subclass.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: native derived Legacy vtable / 338 pointer readbacks, 171 original code/metaclass bindings and '+str(len(cases))+' bounded constructor/destructor CPU cases; fixture is not a provider')


if __name__=='__main__':main()
