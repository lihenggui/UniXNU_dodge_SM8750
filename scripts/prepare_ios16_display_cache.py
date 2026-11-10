#!/usr/bin/env python3
"""Extract original iPhone display-cache evidence from regular APFS image files."""
import hashlib
import json
import mmap
from pathlib import Path
import struct
import subprocess
import urllib.request

from native_driver_build import ROOT,pinned_sources,require,sha

DESTINATION=ROOT/'build/ios16-display-cache'
PREFIX='dyld_shared_cache_arm64'


def file_sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(8<<20):digest.update(block)
    return digest.hexdigest()


def obtain(specification):
    path=ROOT/specification['path']
    if not path.exists():
        path.parent.mkdir(parents=True,exist_ok=True);temporary=path.with_suffix(path.suffix+'.partial')
        with urllib.request.urlopen(specification['url'],timeout=60) as source,temporary.open('xb') as out:
            while chunk:=source.read(1<<20):out.write(chunk)
        require(file_sha(temporary)==specification['sha256'],'Downloaded host input digest differs');temporary.rename(path)
    require(file_sha(path)==specification['sha256'],'Host input digest differs: '+str(path))
    return path


def build_extractor(lock):
    source=pinned_sources(('apfs_readonly_reference',))['apfs_readonly_reference']
    revision=subprocess.check_output(['git','-C',source/'3rdparty/lzfse','rev-parse','HEAD'],text=True).strip()
    require(revision==lock['apfs_readonly_reference']['lzfse_submodule'],'APFS LZFSE submodule differs')
    package=obtain(lock['apfs_host_bzip2_headers']);dependencies=ROOT/'.toolchains/apfs-deps'
    subprocess.run(['dpkg-deb','-x',package,dependencies],check=True)
    build=ROOT/'.toolchains/apfs-readonly';log=ROOT/'build/apfs-reader-build.log'
    with log.open('w') as output:
        subprocess.run(['cmake','-S',source,'-B',build,'-DCMAKE_CXX_FLAGS=-I'+str(dependencies/'usr/include'),
            '-DCMAKE_EXE_LINKER_FLAGS=-L'+str(dependencies/'usr/lib/x86_64-linux-gnu')],check=True,stdout=output,stderr=subprocess.STDOUT)
        subprocess.run(['cmake','--build',build,'--target','apfsutil','--parallel','4'],check=True,stdout=output,stderr=subprocess.STDOUT)
    binary=build/'apfs-extract'
    subprocess.run(['/usr/bin/g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(source),
        ROOT/'tools/ApfsExtract.cpp',build/'libapfs.a',build/'liblzfse.a',build/'libcrypto.a','-lz',
        dependencies/'usr/lib/x86_64-linux-gnu/libbz2.a','-o',binary],check=True)
    return binary


def format_offsets(lock):
    header=obtain(lock['apple_dyld_cache_format']);source=DESTINATION/'cache-offsets.cpp';binary=DESTINATION/'cache-offsets'
    names=('mappingOffset','mappingCount','codeSignatureOffset','codeSignatureSize','localSymbolsOffset','localSymbolsSize',
        'uuid','sharedRegionStart','mappingWithSlideOffset','subCacheArrayOffset','subCacheArrayCount','symbolFileUUID','imagesOffset','imagesCount')
    source.write_text('#include <cstddef>\n#include <cstdio>\n#include "'+str(header)+'"\nint main(){\n(void)cryptexPrefixes;\n'+
        '\n'.join('std::printf("'+name+' %zu\\n",offsetof(dyld_cache_header,'+name+'));' for name in names)+
        '\nstd::printf("image_info_bytes %zu\\n",sizeof(dyld_cache_image_info));\n'
        'std::printf("subcache_entry_bytes %zu\\n",sizeof(dyld_subcache_entry));\n'
        'std::printf("local_entry_bytes %zu\\n",sizeof(dyld_cache_local_symbols_entry_64));\n}\n')
    subprocess.run(['/usr/bin/g++','-std=c++17','-Wall','-Wextra','-Werror',source,'-o',binary],check=True)
    return {name:int(value) for name,value in (line.split() for line in subprocess.check_output([binary],text=True).splitlines())}


def cstring(data,offset,limit):
    require(0<=offset<limit<=len(data),'String offset lies outside cache metadata')
    end=data.find(b'\0',offset,limit);require(end>=offset,'Unterminated cache metadata string')
    return data[offset:end].decode('utf-8')


def cache_header(data,offsets):
    require(len(data)>=512 and bytes(data[:16]).rstrip(b'\0')==b'dyld_v1   arm64','Expected exact ordinary ARM64 shared cache')
    result={name:struct.unpack_from('<'+kind,data,offsets[name])[0] for name,kind in (
        ('mappingOffset','I'),('mappingCount','I'),('codeSignatureOffset','Q'),('codeSignatureSize','Q'),
        ('localSymbolsOffset','Q'),('localSymbolsSize','Q'),('sharedRegionStart','Q'),('subCacheArrayOffset','I'),
        ('subCacheArrayCount','I'),('imagesOffset','I'),('imagesCount','I'))}
    result['uuid']=bytes(data[offsets['uuid']:offsets['uuid']+16]).hex()
    result['symbolFileUUID']=bytes(data[offsets['symbolFileUUID']:offsets['symbolFileUUID']+16]).hex()
    result['mappings']=[]
    for index in range(result['mappingCount']):
        at=result['mappingOffset']+index*32
        require(at+32<=len(data),'Cache mapping table exceeds file')
        va,size,fileoff,maximum,initial=struct.unpack_from('<3Q2I',data,at)
        require(size and fileoff+size<=len(data) and (va|size|fileoff)&4095==0,'Cache mapping extent/alignment differs')
        result['mappings'].append({'address':va,'bytes':size,'fileoff':fileoff,'maxprot':maximum,'initprot':initial})
    return result


def verify_directory(data,offsets,corrupt_offset=None):
    header=cache_header(data,offsets);at,size=header['codeSignatureOffset'],header['codeSignatureSize']
    require(at>=512 and 12<=size and at+size<=len(data),'Cache signature bounds differ')
    signature=bytes(data[at:at+size]);magic,length,count=struct.unpack_from('>3I',signature)
    require(magic==0xfade0cc0 and 12+count*8<=length<=size,'Invalid cache signature container')
    directories=[]
    for index in range(count):
        slot,start=struct.unpack_from('>2I',signature,12+index*8)
        require(12+count*8<=start and start+8<=length,'Cache signature slot exceeds container')
        magic,extent=struct.unpack_from('>2I',signature,start)
        require(extent>=8 and start+extent<=length,'Cache signature component exceeds container')
        if magic!=0xfade0c02:continue
        directory=signature[start:start+extent];require(len(directory)>=48,'Truncated cache CodeDirectory')
        version,flags,hashoff,ident,special,pages,limit=struct.unpack_from('>7I',directory,8)
        hashsize,algorithm,platform,shift=struct.unpack_from('4B',directory,36)
        if version>=0x20300:
            require(len(directory)>=64,'Truncated 64-bit cache limit');limit=struct.unpack_from('>Q',directory,56)[0] or limit
        require((hashsize,algorithm)==(32,2) and shift in (12,14) and limit==at and
            pages==(limit+(1<<shift)-1)>>shift and hashoff>=48+special*hashsize and hashoff+pages*hashsize<=extent,
            'Unsupported cache CodeDirectory/hash coverage')
        require(struct.unpack_from('>I',directory,44)[0]==0,'Scatter cache hash layout is not qualified')
        for page in range(pages):
            low=page<<shift;high=min(limit,(page+1)<<shift);block=bytes(data[low:high])
            if corrupt_offset is not None and low<=corrupt_offset<high:
                changed=bytearray(block);changed[corrupt_offset-low]^=1;block=changed
            require(hashlib.sha256(block).digest()==directory[hashoff+page*32:hashoff+(page+1)*32],
                'Original cache code hash mismatch at slot '+str(page))
        directories.append({'slot':slot,'hash_block_bytes':1<<shift,'code_slots':pages,'cdhash':hashlib.sha256(directory).hexdigest()[:40]})
    require(directories,'No original cache CodeDirectory found')
    return directories


def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());DESTINATION.mkdir(parents=True,exist_ok=True)
    volume_report=json.loads((ROOT/'reports/ios16-volumes.json').read_text())
    system,=[v for v in volume_report['images'] if v['name']=='SystemOS'];image=ROOT/system['path']
    require(volume_report['product']=='iPhone10,3' and volume_report['build']=='20H392' and file_sha(image)==system['raw_sha256'],
        'Original iPhone SystemOS input changed')
    extractor=build_extractor(lock);offsets=format_offsets(lock);records={}
    def extract(name,expected_uuid=None):
        require(name==PREFIX or name==PREFIX+'.symbols' or name.startswith(PREFIX+'.') and '/' not in name,'Unexpected cache extraction name')
        path=DESTINATION/name
        if not path.exists():subprocess.run([extractor,image,'0','/System/Library/Caches/com.apple.dyld/'+name,path],check=True)
        with path.open('rb') as stream:
            data=mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ)
            header=cache_header(data,offsets)
            if expected_uuid:require(header['uuid']==expected_uuid,'Extracted cache UUID differs from main cache table')
            integrity=verify_directory(data,offsets)
            # Corrupt each native 4K part of the first full 16K hash unit, or
            # the first 4K unit when the file uses 4K integrity blocks.
            controls=[]
            for byte in range(0,integrity[0]['hash_block_bytes'],4096):
                try:verify_directory(data,offsets,byte)
                except ValueError as error:
                    require('code hash mismatch' in str(error),'Cache mutation refused for an unrelated reason')
                else:raise ValueError('Changed cache code passed embedded integrity hashes')
                controls.append(byte)
            records[name]={'path':str(path.relative_to(ROOT)),'bytes':len(data),'sha256':file_sha(path),'uuid':header['uuid'],
                'mappings':header['mappings'],'code_directories':integrity,'changed_4k_piece_controls':controls}
            data.close()
        return path,header
    main_path,header=extract(PREFIX);main_data=main_path.read_bytes()
    images=[]
    for index in range(header['imagesCount']):
        at=header['imagesOffset']+index*offsets['image_info_bytes'];require(at+32<=len(main_data),'Image table exceeds main cache')
        address,mtime,inode,name,pad=struct.unpack_from('<3Q2I',main_data,at)
        if cstring(main_data,name,len(main_data)).endswith('/IOMobileFramebuffer.framework/IOMobileFramebuffer'):
            images.append({'index':index,'address':address,'path':cstring(main_data,name,len(main_data))})
    selected,=images;subcaches=[]
    for index in range(header['subCacheArrayCount']):
        at=header['subCacheArrayOffset']+index*offsets['subcache_entry_bytes'];require(at+56<=len(main_data),'Subcache table exceeds main cache')
        identity,vmoffset,suffix=struct.unpack_from('<16sQ32s',main_data,at)
        suffix=suffix.split(b'\0',1)[0].decode('ascii');require(suffix.startswith('.') and '/' not in suffix,'Unsafe cache suffix')
        subcaches.append({'uuid':identity.hex(),'offset':vmoffset,'suffix':suffix})
    candidates=[s for s in subcaches if s['offset']<=selected['address']-header['sharedRegionStart']]
    target=max(candidates,key=lambda item:item['offset']);extract(PREFIX+target['suffix'],target['uuid']);extract(PREFIX+'.symbols',header['symbolFileUUID'])
    # Existing supplemental data is audited too; no opaque downloaded cache
    # is silently treated as a validated framework input.
    for item in subcaches:
        if (DESTINATION/(PREFIX+item['suffix'])).exists() and PREFIX+item['suffix'] not in records:
            extract(PREFIX+item['suffix'],item['uuid'])
    report={'result':'IOS16_DISPLAY_CACHE_READONLY_EXTRACTION_AND_INTEGRITY_PASS','product':'iPhone10,3','build':'20H392',
        'builder_sha256':sha(Path(__file__)),'extractor_source_sha256':sha(ROOT/'tools/ApfsExtract.cpp'),
        'extractor':str(extractor.relative_to(ROOT)),'extractor_sha256':file_sha(extractor),'reader_source':lock['apfs_readonly_reference'],
        'compression_headers':lock['apfs_host_bzip2_headers'],'cache_format':lock['apple_dyld_cache_format'],'derived_format_offsets':offsets,
        'source_image':str(image.relative_to(ROOT)),'source_image_sha256':system['raw_sha256'],'framework':selected,
        'cache_files':list(records.values()),'source_open_mode':'O_RDONLY','filesystem_mounted':False,'block_devices_opened':False,
        'cache_bytes_modified':False,'apple_cms_authentication_verified':False,'kernel_apfs_or_dyld_executed':False,'hardware_tested':False,
        'scope':'Original display cache and local symbols extracted through read-only APFS library calls from the pinned regular iPhone image. '
                'UUID tables and every embedded SHA-256 code slot, plus corruption controls, are checked. '
                'This is file provenance/integrity evidence, not Apple CMS trust, kernel APFS operation or userspace execution.'}
    (ROOT/'reports/ios16-display-cache.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(len(records))+' original display cache files extracted/read back; embedded code hashes and corruption controls pass; no mount')


if __name__=='__main__':main()
