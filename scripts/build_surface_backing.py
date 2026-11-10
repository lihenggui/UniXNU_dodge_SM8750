#!/usr/bin/env python3
"""Build the exact iPhone backing-subrange source candidate, without selecting or executing it."""
import hashlib
import json
import struct
import subprocess

from check_ios16_swap import original_input
from check_surface_backing_host import check as check_host
from native_driver_build import ROOT, NATIVE, archive_imports, build_objects, macho, require, sha, symbols
from native_prelink import backed_offset, exports


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    surface=json.loads((ROOT/'reports/ios16-surface-interface.json').read_text())
    spec=lock['iphone_surface_interface']
    require(sha(ROOT/spec['path'])==spec['sha256']==surface['contract_sha256'] and
            sha(ROOT/spec['header'])==spec['header_sha256']==surface['header_sha256'], 'Current IOSurface contract required')
    require(sha(ROOT/surface['archive'])==surface['archive_sha256'], 'Original surface aliases changed')
    _,original,image,read=original_input()
    def words(a,n):return struct.unpack('<%dI'%(n//4),read(a,n))
    names={n:a for a,g in exports(original,image).items() for n in g}
    native=NATIVE.read_bytes();native_image=macho(native)
    native_names={n:a for a,g in exports(native,native_image).items() for n in g}
    for table,index,method in (('__ZTV11IOMemoryMap',17,'__ZN11IOMemoryMap9getLengthEv'),
                               ('__ZTV11IOMemoryMap',19,'__ZN11IOMemoryMap19getMemoryDescriptorEv'),
                               ('__ZTV18IOMemoryDescriptor',21,'__ZNK18IOMemoryDescriptor12getDirectionEv'),
                               ('__ZTV18IOMemoryDescriptor',22,'__ZNK18IOMemoryDescriptor9getLengthEv')):
        at=backed_offset(native_image['segments'],native_names[table]+16+index*8,8,len(native))
        require(struct.unpack('<Q',read(names[table]+16+index*8,8))[0]==names[method] and
                struct.unpack_from('<Q',native,at)[0]==native_names[method],
                'Native/original backing descriptor virtual slot differs: '+method)
    # The device-region method loads +64 as an IOMemoryMap, then calls
    # the actual original public physical-address implementation.
    a,b=words(0xfffffff005a57d2c,8)
    require(a==0xf9402000 and b & 0xfc000000==0x14000000,'Device-region map getter path differs')
    imm=b & 0x3ffffff;stub=0xfffffff005a57d30+4*(imm-(1<<26) if imm & (1<<25) else imm)
    x,y,z=words(stub,12)
    require(x & 0x9f00001f==0x90000010 and y & 0xffc003ff==0xf9400210 and z==0xd61f0200,
            'Device-region physical address does not use the original import stub')
    v=((x>>5)&0x7ffff)*4+((x>>29)&3)
    if v & (1<<20):v-=1<<21
    got=(stub & ~4095)+(v<<12)+((y>>10)&4095)*8
    require(struct.unpack('<Q',read(got,8))[0]==names['__ZN11IOMemoryMap18getPhysicalAddressEv'],
            'The region +64 object is not used as the original IOMemoryMap')
    # Original getPhysicalSegment forwards fOffset + requested offset to
    # the real parent descriptor. Check register flow, not a guessed name.
    offset_flow=0xfffffff007789390
    require(words(offset_flow,20)==(0xf9400ae0,0xf94012e8,0x8b160101,0xf9400008,0xf9404d08),
            'Original map parent/offset forwarding differs')
    methods={}
    for name,offset in (('getMemoryDescriptor',16),('getLength',48),('getVirtualAddress',40)):
        symbol=f'__ZN11IOMemoryMap{len(name)}{name}Ev'
        expected=struct.pack('<2I',0xf9400000|((offset//8)<<10),0xd65f03c0)
        at=backed_offset(native_image['segments'],native_names[symbol],8,len(native))
        require(read(names[symbol],8)==expected==native[at:at+8], 'Native/original IOMemoryMap field differs: '+name)
        methods[name]={'original':hex(names[symbol]),'field':offset,'sha256':hashlib.sha256(expected).hexdigest()}
    out=ROOT/'build/ios16-surface-backing';out.mkdir(parents=True,exist_ok=True)
    driver=ROOT/'drivers/DodgeDisplay'
    probe=out/'map-offset.cpp'
    probe.write_text('#include <IOKit/IOMemoryDescriptor.h>\nextern "C" uint64_t iphone_map_offset(IOMemoryMap *p){return p->fOffset;}\n')
    obj,probe_obj=build_objects([driver/'DodgeSurfaceBacking.cpp',probe],out,[ROOT/spec['header'].rsplit('/',1)[0]])
    data=probe_obj.read_bytes();im=macho(data)
    text,=[s for seg in im['segments'] for s in seg['sections'] if s['name']=='__text']
    function,=[s for s in symbols(data) if s['name']=='_iphone_map_offset']
    at=text['fileoff']+function['value']-text['va']
    require(data[at:at+8]==struct.pack('<2I',0xf9401000,0xd65f03c0),
            'Actual native private IOMemoryMap header uses another fOffset field')
    binding=ROOT/'build/ios16-surface-interface/original-surface-bindings.o'
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',ROOT/surface['archive'],binding.name])==binding.read_bytes(),
            'Surface alias object does not match its checked archive')
    imports=archive_imports([obj,binding])
    require(not imports['required_board_or_original_imports'] and not imports['native_static_link_only_imports'],
            'Surface backing source has unresolved required imports: '+repr(imports))
    archive=out/'libDodgeSurfaceBacking.a'
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,obj,binding],check=True)
    require(subprocess.check_output(['/usr/bin/llvm-ar-14','t',archive],text=True).splitlines()==[obj.name,binding.name],
            'Unexpected backing archive members')
    test=ROOT/'tests/DodgeSurfaceLayoutTest.cpp'
    ownership_test=ROOT/'tests/DodgeSurfaceBackingTest.cpp'
    shim=ROOT/'tests/surface_backing_include'
    host=check_host(out)
    report={'result':'IOS16_SURFACE_BACKING_SOURCE_CANDIDATE_PASS','native_kernel_sha256':sha(NATIVE),
        'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
        'surface_contract_sha256':surface['contract_sha256'],'surface_bindings_archive_sha256':surface['archive_sha256'],
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in (driver/'DodgeSurfaceBacking.cpp',driver/'DodgeSurfaceBacking.h',
            driver/'DodgeSurfaceLayout.h',test,ownership_test,shim/'IOKit/IOMemoryDescriptor.h',
            shim/'IOKit/IOSubMemoryDescriptor.h',ROOT/'scripts/check_surface_backing_host.py')},'native_header_offset_probe_sha256':sha(probe_obj),
        'device_region_map_field':64,'map_offset_field':32,'original_offset_flow_sha256':hashlib.sha256(read(offset_flow,20)).hexdigest(),
        'original_and_native_map_methods':methods,'imports':imports,
        'host_layout_tests':host['layout'],'host_provider_peer_tests':host['ownership'],
        'plain_nonplanar_bgra_only':True,'linear_unit_4byte_elements_only':True,'subrange_includes_map_and_surface_offsets':True,
        'uses_retaining_iosubmemorydescriptor_api':True,'caller_surface_mutation_serialization_required':True,
        'original_iokit_objects_executed':False,'ownership_runtime_qualified':False,'default_selected':False,'hardware_tested':False,
        'scope':'Actual iOS16 source candidate obtains a checked device-region map, creates an owned IOSubMemoryDescriptor for the '
            'bounded visible rows, and preserves descriptor direction. Native ABI field checks and sanitized arithmetic tests pass; '
            'real original-object lifetime, cache/SMMU ownership and producer fences remain unqualified.'}
    (ROOT/'reports/ios16-surface-backing.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: actual iOS16 backing-subrange source archive, original/native IOMemoryMap fields and native public imports; not selected')


if __name__=='__main__':main()
