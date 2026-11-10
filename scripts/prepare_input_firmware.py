#!/usr/bin/env python3
"""Extract exact stock QUP4 SPI SEFW bytes, without distributing firmware."""
import hashlib
import json
from pathlib import Path
import struct
import urllib.request
from native_driver_build import ROOT,require,sha
OUT=ROOT/'build/ios16-touch-firmware'
PIN=ROOT/'hardware/dodge-spi-firmware.json'

def extract(module,spec):
    require(len(module)==spec['source_module']['bytes'] and hashlib.sha256(module).hexdigest()==spec['source_module']['sha256'],'Stock SPI module bytes differ')
    at=int(spec['payload']['module_file_offset'],0);n=spec['payload']['bytes']
    require(0<=at<=len(module)-n,'SPI firmware extent exceeds original module')
    # Require a single data-section owner, independent of the pinned offset.
    pe,=struct.unpack_from('<I',module,60);require(module[:2]==b'MZ' and module[pe:pe+4]==b'PE\0\0','Not the original PE module')
    machine,count=struct.unpack_from('<HH',module,pe+4);optsz,=struct.unpack_from('<H',module,pe+20)
    require(machine==0xaa64 and 0<count<32,'Unexpected OEM module architecture')
    owners=[]
    for i in range(count):
        offset=pe+24+optsz+40*i;raw,fileoff=struct.unpack_from('<II',module,offset+16)
        if fileoff<=at and at+n<=fileoff+raw:owners.append(module[offset:offset+8].rstrip(b'\0').decode())
    require(len(owners)==1 and owners[0] in ('.data','.rdata'),'Original SPI firmware is not owned by a PE data section')
    blob=module[at:at+n];f=struct.unpack_from('<III8H',blob)
    require(f==(0x57464553,1,0x40000000,1,2818,9,442,28,69,2072,1796),'Original SPI SEFW header differs')
    require(hashlib.sha256(blob).hexdigest()==spec['payload']['sha256'],'Original SPI SEFW payload differs')
    return blob,owners[0]

def main():
    lock=json.loads((ROOT/'upstream.lock.json').read_text());require(sha(PIN)==lock['dodge_spi_firmware']['sha256'],'SPI firmware manifest changed')
    spec=json.loads(PIN.read_text());OUT.mkdir(parents=True,exist_ok=True)
    for item in lock['dodge_input_cold_references']['files']:
        p=ROOT/item['path']
        if not p.exists():
            p.parent.mkdir(parents=True,exist_ok=True)
            with urllib.request.urlopen(item['url'],timeout=60) as stream:p.write_bytes(stream.read())
        require(sha(p)==item['sha256'],'Cold input reference changed')
    module=ROOT/spec['source_module']['path'];require(module.is_file(),'Extract stock OEM modules with audit_stock_uefi.py first')
    raw=module.read_bytes();blob,section=extract(raw,spec)
    comparison=spec['independent_stock_module_comparison'];other=ROOT/comparison['path'];require(sha(other)==comparison['sha256'],'Independent OEM module changed')
    offset=int(comparison['offset'],0);require(other.read_bytes()[offset:offset+len(blob)]==blob,'Independent original SPI payload differs')
    stock=json.loads((ROOT/'reports/stock-uefi.json').read_text())
    require(any(m['path']==str(module.relative_to(ROOT)) and m['sha256']==sha(module) and m['name']=='SPI' for m in stock['executables']),'Stock executable inventory does not own SPI input')
    for item in stock['inputs']:require(sha(ROOT/item['path'])==item['sha256'],'OEM source image changed')
    controls=[]
    for name,position in [('module-identity',0),('header-protocol',int(spec['payload']['module_file_offset'],0)+12),('code-payload',int(spec['payload']['module_file_offset'],0)+28)]:
        bad=bytearray(raw);bad[position]^=1
        try:extract(bad,spec)
        except ValueError as e:controls.append({'case':name,'result':'REJECTED','check':str(e)})
        else:raise ValueError('Corrupt original SPI module accepted')
    path=OUT/'stock-spi-sefw.bin';path.write_bytes(blob)
    asm=OUT/'DodgeTouchSpiFirmware.S'
    asm.write_text('.section __TEXT,__const\n.balign 4\n.globl _dodge_touch_spi_firmware\n_dodge_touch_spi_firmware:\n.incbin "'+str(path)+'"\n.globl _dodge_touch_spi_firmware_end\n_dodge_touch_spi_firmware_end:\n')
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',PIN,module,other,*[ROOT/i['path'] for i in lock['dodge_input_cold_references']['files']]]
    report={'result':'CPH2653_ORIGINAL_QUP4_SPI_FIRMWARE_EXTRACTION_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'pin_sha256':sha(PIN),
            'firmware':str(path.relative_to(ROOT)),'firmware_sha256':sha(path),'firmware_bytes':len(blob),
            'assembly':str(asm.relative_to(ROOT)),'assembly_sha256':sha(asm),'pe_data_section':section,
            'stock_report_sha256':sha(ROOT/'reports/stock-uefi.json'),'independent_original_module_payload_identical':True,
            'firmware_words':442,'configuration_entries':69,'qup_hardware_version':'0x40000000','negative_controls':controls,
            'oem_signature_authenticated':False,'runtime_loaded':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Exact SEFW v1 SPI image from hash-pinned public CPH2653 OEM SPI PE data, byte-identical in original I2C PE. '
                    'ROM/driver compatibility, register writes and firmware execution require separate qualification; generated bytes and assembly remain ignored.'}
    (ROOT/'reports/ios16-touch-firmware.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: exact stock QUP4 SPI SEFW, 2141 bytes / 442 words / 69 configurations; independent OEM copy identical')
if __name__=='__main__':main()
