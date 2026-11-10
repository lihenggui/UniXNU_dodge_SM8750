#!/usr/bin/env python3
"""Bounded read access to audited original display cache files; no code loading."""
import json
import mmap
import struct

from native_driver_build import ROOT,macho,require,sha
from prepare_ios16_display_cache import PREFIX,cache_header,cstring,file_sha


class DisplayCache:
    def __init__(self):
        self.handles=[];self.data={};self.mappings=[]
        self.report=json.loads((ROOT/'reports/ios16-display-cache.json').read_text())
        lock=json.loads((ROOT/'upstream.lock.json').read_text())
        require(self.report['result']=='IOS16_DISPLAY_CACHE_READONLY_EXTRACTION_AND_INTEGRITY_PASS' and
            self.report['builder_sha256']==sha(ROOT/'scripts/prepare_ios16_display_cache.py') and
            self.report['extractor_source_sha256']==sha(ROOT/'tools/ApfsExtract.cpp') and
            self.report['cache_format']==lock['apple_dyld_cache_format'] and
            sha(ROOT/lock['apple_dyld_cache_format']['path'])==lock['apple_dyld_cache_format']['sha256'],
            'Refresh exact iPhone display cache extraction/integrity evidence')
        self.offsets=self.report['derived_format_offsets']
        for record in self.report['cache_files']:
            path=ROOT/record['path'];require(file_sha(path)==record['sha256'],'Original display cache bytes changed')
            stream=path.open('rb');data=mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ);self.handles.append((stream,data))
            self.data[path.name]=data
            header=cache_header(data,self.offsets)
            require(header['uuid']==record['uuid'] and header['mappings']==record['mappings'],'Cache mapping/UUID evidence changed')
            self.mappings.extend((item,data) for item in header['mappings'])
        self.address=self.report['framework']['address']
        mapping,data=self.locate(self.address,32)
        self.image=macho(data,mapping['fileoff']+self.address-mapping['address'])

    def locate(self,address,size):
        require(0<=address<1<<64 and 0<size<=1<<32 and address+size<=1<<64,'Invalid cache address span')
        matches=[(item,data) for item,data in self.mappings if item['address']<=address and address+size<=item['address']+item['bytes']]
        require(len(matches)==1,'Address is outside a unique extracted cache mapping: '+hex(address))
        return matches[0]

    def read(self,address,size):
        item,data=self.locate(address,size);at=item['fileoff']+address-item['address'];return bytes(data[at:at+size])

    def local_symbols(self):
        main=cache_header(self.data[PREFIX],self.offsets);data=self.data[PREFIX+'.symbols'];header=cache_header(data,self.offsets)
        start,size=header['localSymbolsOffset'],header['localSymbolsSize']
        require(start>=512 and start+size<=len(data),'Local symbol area exceeds cache file')
        lists,count,strings,length,entries,entry_count=struct.unpack_from('<6I',data,start)
        require(lists+count*16<=size and strings+length<=size and entries+entry_count*self.offsets['local_entry_bytes']<=size,
            'Local symbol tables exceed their cache area')
        matches=[]
        for index in range(entry_count):
            image,first,total=struct.unpack_from('<Q2I',data,start+entries+index*self.offsets['local_entry_bytes'])
            require(first+total<=count,'Local symbol image exceeds nlist table')
            if image==self.address-main['sharedRegionStart']:matches.append((first,total))
        (first,total),=matches;result={}
        for index in range(first,first+total):
            text,kind,section,description,address=struct.unpack_from('<IBBHQ',data,start+lists+index*16)
            require(text<length,'Local symbol string index exceeds pool')
            name=cstring(data,start+strings+text,start+strings+length)
            require(name not in result,'Duplicate display local symbol');result[name]=address
        return result

    def close(self):
        for stream,data in self.handles:data.close();stream.close()
        self.handles=[]

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
