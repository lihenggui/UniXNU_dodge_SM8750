#!/usr/bin/env python3
"""Package the isolated display candidate locally; never operate a device."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace

from native_driver_build import ROOT,NATIVE,require,sha
from prepare_device_tree import parse_adt

sys.path.insert(0,str(ROOT/'sources/UniXNU/scripts'))
from unixnu import bootimg
from unixnu.payload import EPOCH,write_volume,check_args

DEPENDENCIES=('ios16-display-prelink','ios16-display-kernel-lifecycle','ios16-gop-provider-kernel','native-payload','uefi-build')


def copy_from_fat(image,name,destination):
    subprocess.run(['mcopy','-i',str(image),'::/EFI/UniXNU/'+name,str(destination)],check=True,capture_output=True)


def main():
    reports={name:json.loads((ROOT/'reports'/f'{name}.json').read_text()) for name in DEPENDENCIES}
    prelink=reports['ios16-display-prelink'];cpu=reports['ios16-display-kernel-lifecycle'];baseline=reports['native-payload'];firmware=reports['uefi-build']
    require('PASS' in prelink['result'] and prelink['strict_emission'] and prelink['darwinboot_production_parser']=='PASS' and
        'PASS' in cpu['result'] and cpu['case_count']==32 and cpu['candidate_sha256']==prelink['candidate_sha256'] and
        prelink['linked_source_objects']==64 and prelink['native_source_entries_preserved']==42,
        'Need current strict display prelink and complete CPU checks')
    gop=reports['ios16-gop-provider-kernel']
    require('PASS' in gop['result'] and gop['candidate_sha256']==prelink['candidate_sha256'] and gop['case_count']==18 and
        gop['actual_original_allocator_and_native_parent_constructors_executed'],'Need current original GOP provider CPU checks')
    for name,digest in cpu['dependency_report_sha256'].items():require(sha(ROOT/'reports'/f'{name}.json')==digest,'Stale CPU dependency: '+name)
    for report in (prelink,cpu,gop):
        for name,digest in report['source_sha256'].items():require(sha(ROOT/name)==digest,'Stale display candidate source: '+name)
    candidate=ROOT/prelink['candidate'];original_fat=ROOT/baseline['payload'];fd=ROOT/'build/cph2653-uefi-menu/SILICIUM_UEFI.fd'
    require(sha(candidate)==prelink['candidate_sha256'] and sha(original_fat)==baseline['payload_sha256'],'Candidate or source FAT changed')
    require(baseline['result']=='PASS' and not firmware['returncode'] and firmware['darwinboot_integrated'] and
        sha(fd)==baseline['firmware_sha256']==next(item['sha256'] for item in firmware['artifacts'] if item['path'].endswith('.fd')),
        'Need validated original menu firmware')
    protected={str(p.relative_to(ROOT)):sha(p) for p in (NATIVE,ROOT/baseline['boot_image'],original_fat,fd,
        ROOT/'build/unixnu/dodge/ios-16.7.16-20H392/dodge/kernel/kernel.macho',candidate)}
    board=tomllib.loads((ROOT/'board.toml').read_text());gpu_config=json.loads((ROOT/'profiles/os/ios-16.7.16-20H392/gpu-prelink.json').read_text())
    line=check_args(gpu_config['boot_arguments'],board['payload']['command_line_length'])
    out=ROOT/'build/cph2653-display-bringup';out.mkdir(parents=True,exist_ok=True)
    tools={'clang':Path('/usr/bin/clang-14'),'llvm-objcopy':Path('/usr/bin/llvm-objcopy-14'),'llvm-nm':Path('/usr/bin/llvm-nm-14')}
    tool_dir=out/'tools';tool_dir.mkdir(exist_ok=True)
    for name,path in tools.items():
        require(path.is_file(),'Missing actual host LLVM tool: '+str(path));link=tool_dir/name
        if link.exists():require(link.is_symlink() and link.resolve()==path.resolve(),'Unexpected container host tool: '+name)
        else:link.symlink_to(path)
    uefi=ROOT/'uefi/Mu-Silicium';dtb=uefi/'Resources/DTBs/dodge.dtb'
    with tempfile.TemporaryDirectory(prefix='checked-',dir=out) as temporary:
        work=Path(temporary);stage=work/'stage';stage.mkdir()
        subprocess.run(['mcopy','-s','-i',str(original_fat),'::/EFI',str(stage)],check=True,capture_output=True)
        directory=stage/'EFI/UniXNU';config_path=directory/'unixnu.toml'
        require(config_path.is_file(),'Source FAT lacks actual menu configuration')
        config=tomllib.loads(config_path.read_text());entry,=[e for e in config['entry'] if e['id']=='xnu']
        require(entry['type']=='xnu' and entry['path']=='Payloads/kernel.macho' and entry['args']==line,
            'Existing FAT boot arguments/path differ from the candidate POST/profile contract')
        old_title='title = "'+board['payload']['title']+'"';text=config_path.read_text()
        require(text.count(old_title)==1,'Unexpected menu title configuration')
        config_path.write_text(text.replace(old_title,'title = "OnePlus 13: experimental iPhone graphics development"'))
        shutil.copyfile(candidate,directory/'Payloads/kernel.macho')
        adt=directory/'Payloads/kernel.macho.adt'
        require(sha(adt)==baseline['adt_sha256'],'Copied ADT changed from the validated iPhone input')
        nodes=parse_adt(adt.read_bytes())
        for path,key,value in [('/','model',b'iPhone10,3\0'),('/product','artwork-device-idiom',b'phone\0'),
            ('/chosen','chip-id',struct.pack('<I',0x8015)),('/chosen','darwinboot-memory-size',struct.pack('<Q',4<<30)),
            ('/buttons','home-button-type',struct.pack('<I',2))]:
            require(nodes[path].get(key)==value,'Experimental ADT lost the iPhone/board contract: '+key)
        for path in [*stage.rglob('*'),stage]:os.utime(path,(EPOCH,EPOCH))
        fat=work/'payload.img';write_volume(stage,fat,board['payload']['volume'],board['payload']['size_mib'])
        readback=work/'readback';readback.mkdir()
        for name in ('unixnu.toml','Payloads/kernel.macho','Payloads/kernel.macho.adt'):
            target=readback/Path(name).name;copy_from_fat(fat,name,target)
            require(sha(target)==sha(directory/name),'Experimental FAT readback differs: '+name)
        boot=work/'boot.img';old_path=os.environ['PATH'];os.environ['PATH']=str(tool_dir)+os.pathsep+old_path
        try:bootimg.build(SimpleNamespace(board=board,work=work),uefi,fd,dtb,ramdisk=fat,output=boot)
        finally:os.environ['PATH']=old_path
        record=json.loads((work/'boot.json').read_text())
        require(record['header_version']==4 and record['ramdisk_bytes']==fat.stat().st_size and record['image_sha256']==sha(boot),
            'Actual Android container readback differs')
        require(all(sha(ROOT/name)==digest for name,digest in protected.items()),'Experimental packaging changed a default/input artifact')
        adt_sha=sha(adt);config_sha=sha(config_path)
        for name in ('payload.img','boot.img','boot.json'):(work/name).replace(out/name)
    files=[Path(__file__),ROOT/'scripts/native_driver_build.py',ROOT/'scripts/prepare_device_tree.py',
        ROOT/'sources/UniXNU/scripts/unixnu/bootimg.py',ROOT/'sources/UniXNU/scripts/unixnu/payload.py',
        ROOT/'sources/UniXNU/scripts/unixnu/util.py',ROOT/'sources/UniXNU/scripts/unixnu/config.py',
        ROOT/'board.toml',ROOT/'profiles/os/ios-16.7.16-20H392/gpu-prelink.json',
        uefi/'BootShim/BootShim.S',uefi/'Resources/Configs/dodge.toml',uefi/'Resources/Scripts/mkbootimg.py',dtb]
    report={'result':'IOS16_ISOLATED_DISPLAY_DEVELOPMENT_CONTAINER_READBACK_PASS','builder_sha256':sha(Path(__file__)),
        'dependency_report_sha256':{name:sha(ROOT/'reports'/f'{name}.json') for name in DEPENDENCIES},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'candidate':prelink['candidate'],'candidate_sha256':prelink['candidate_sha256'],
        'host_tools_sha256':{str(path):sha(path) for path in tools.values()},
        'artifacts':{str((out/name).relative_to(ROOT)):sha(out/name) for name in ('payload.img','boot.img','boot.json')},
        'boot_image':str((out/'boot.img').relative_to(ROOT)),'boot_image_sha256':sha(out/'boot.img'),'boot_image_bytes':(out/'boot.img').stat().st_size,
        'payload':str((out/'payload.img').relative_to(ROOT)),'payload_sha256':sha(out/'payload.img'),
        'adt_sha256':adt_sha,'menu_sha256':config_sha,'kernel_args':line,'firmware_sha256':sha(fd),
        'linked_source_objects':64,'native_source_entries':42,'original_graphics_components':27,'original_interfaces':7,
        'boot_header_version':4,'fat_readback':'kernel, iPhone ADT and experimental menu match',
        'android_container_readback':'actual production builder verified header, gzip, shim, FD, firmware DTB and complete FAT bytes',
        'protected_default_artifact_sha256':protected,'default_artifacts_unchanged':True,'boot_payload_packaged':True,
        'unified_graphics_boot_entry_linked':True,'unified_graphics_boot_entry_automatically_invoked':False,
        'real_class_gop_provider_factory_and_late_entry_linked':True,'gop_provider_automatically_published':False,
        'opt_in_iobsd_graphics_hook_linked':True,'late_graphics_boot_requires_explicit_argument':True,
        'original_graphics_embedded':True,'original_userspace_included':False,'private_seed_disclosed':False,
        'phone_operations':'none','default_kernel_selected':False,'runtime_qualified':False,'hardware_tested':False,'ready_for_ios_boot':False,
        'scope':'Separate offline development container: the full concrete-display/native-boot/GPU source candidate and exact original graphics '
            'inside a verified 160 MiB FAT ramdisk, existing iPhone ADT and menu firmware, in an Android v4 image. '
            'Explicit boot coordination is linked but not automatically invoked. No working iOS system, original userspace/root, '
            'kernel runtime, physical provider, power or hardware qualification. No existing payload/image is replaced.'}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    (ROOT/'reports/ios16-display-payload.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: isolated display/native-boot/original-graphics FAT + Android v4 container; all inputs read back, defaults unchanged; no phone operations')


if __name__=='__main__':main()
