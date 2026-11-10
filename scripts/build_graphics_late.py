#!/usr/bin/env python3
"""Build an opt-in IOBSD worker and isolated native-object overlay."""
import json
from pathlib import Path
import subprocess

from check_graphics_late_host import check as check_host
from graphics_late_overlay import stage
from native_driver_build import ROOT,TREE,OBJDIR,NATIVE,archive_imports,build_objects,inspect_object,require,sha


def main():
    out=ROOT/'build/ios16-graphics-late';patched,overlay=stage(out)
    host=check_host(out,patched)
    objects=build_objects([ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.cpp'],out)
    recipe=OBJDIR/'iokit/DEVELOPMENT/IOKitBSDInit.cpo.json'
    record=json.loads(recipe.read_text().strip().rstrip(','));args=record['arguments'];command=[];i=0;changed=0
    while i<len(args):
        value=args[i]
        if value==record['file']:command.append(str(patched));changed+=1
        elif value in ('-o','-MF','-MJ'):i+=1
        elif value not in ('-MD','-MP'):command.append(value)
        i+=1
    require(changed==1,'Original IOBSD compile recipe does not identify one actual source input')
    override=out/'IOKitBSDInit.late.cpo';command+=['-o',str(override)]
    with (out/'IOKitBSDInit.late.log').open('w') as stream:
        result=subprocess.run(command,cwd=record['directory'],stdout=stream,stderr=subprocess.STDOUT,timeout=120)
    require(result.returncode==0,'Actual isolated IOBSD overlay compilation failed')
    overlay_manifest=out/'bsd-compile-command.json';overlay_manifest.write_text(json.dumps({'arguments':command,'directory':record['directory'],
        'source':str(patched),'recipe':str(recipe.relative_to(ROOT)),'recipe_sha256':sha(recipe)},indent=2)+'\n')
    for p in [*objects,override]:
        require(all(not s['size'] for seg in inspect_object(p.read_bytes())['segments'] for s in seg['sections'] if s['name']=='__mod_init_func'),
                'Late graphics startup entered early constructors')
    archive=out/'libDodgeGraphicsLate.a';archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14','rcsD',archive,*objects],check=True)
    for p in objects:require(subprocess.check_output(['/usr/bin/llvm-ar-14','p',archive,p.name])==p.read_bytes(),'Late archive member differs')
    imports=archive_imports(objects)
    require(set(imports['required_board_or_original_imports'])=={'_dodge_graphics_boot_gop','_dodge_graphics_boot_status'},'Unexpected late scheduling dependency')
    native_object=OBJDIR/'iokit/DEVELOPMENT/IOKitBSDInit.cpo'
    overlay.update({'original_object':str(native_object.relative_to(ROOT)),'original_object_sha256':sha(native_object),
                    'replacement_object':str(override.relative_to(ROOT)),'replacement_object_sha256':sha(override),
                    'compile_manifest':str(overlay_manifest.relative_to(ROOT)),'compile_manifest_sha256':sha(overlay_manifest)})
    files=[Path(__file__),ROOT/'scripts/graphics_late_overlay.py',ROOT/'scripts/check_graphics_late_host.py',
           ROOT/'scripts/native_driver_build.py',ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.cpp',ROOT/'drivers/DodgeDisplay/DodgeGraphicsLate.h',
           ROOT/'drivers/DodgeDisplay/DodgeGopProvider.h',ROOT/'drivers/DodgeDisplay/DodgeGraphicsBoot.h',ROOT/'tests/DodgeGraphicsLateTest.cpp',
           *sorted((ROOT/'tests/graphics_late_include').rglob('*.h')),patched,ROOT/overlay['patch']['path'],
           ROOT/overlay['base_source'],recipe,TREE/'.cache/xnu-work/osfmk/kern/thread.c',TREE/'.cache/xnu-work/osfmk/kern/thread.h']
    report={'result':'IOS16_OPT_IN_IOBSD_GRAPHICS_WORKER_AND_ISOLATED_NATIVE_OVERLAY_PASS','builder_sha256':sha(Path(__file__)),
            'native_kernel_sha256':sha(NATIVE),'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},
            'archive':str(archive.relative_to(ROOT)),'archive_sha256':sha(archive),
            'objects':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in objects],'imports':imports,
            'compile_manifest':str((out/'compile-commands.json').relative_to(ROOT)),'compile_manifest_sha256':sha(out/'compile-commands.json'),
            'native_object_overlay':overlay,'host_tests':host,'host_binary':str((out/'graphics-late-host').relative_to(ROOT)),
            'host_binary_sha256':sha(out/'graphics-late-host'),'hook_extracted':str((out/'IOKitBSDInit.extracted.cpp').relative_to(ROOT)),
            'hook_extracted_sha256':sha(out/'IOKitBSDInit.extracted.cpp'),
            'boot_argument':'dodge-graphics=1','schedule_after_real_iobsd_publication':True,'independent_kernel_thread_required':True,
            'one_worker_after_successful_queue':True,'thread_start_failure_retryable':True,'retry_attempts':200,'retry_milliseconds':10,
            'pre_hardware_not_ready_or_busy_retry_only':True,'hardware_attempt_never_retried':True,'owned_successful_display_retained':True,
            'default_boot_argument_enabled':False,'early_initializer_present':False,'original_native_source_or_object_modified':False,
            'native_hook_executed_on_kernel':False,'runtime_qualified':False,'default_kernel_selected':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'The actual isolated IOKitBSDInit source calls a scheduling entry after publishing IOBSD. Only explicit dodge-graphics=1 '
                    'queues a separate kernel thread for the real GOP/GPU/display entry. Bounded retries stop before repeating any hardware attempt. '
                    'The native source/object and default filelist/kernel stay untouched; only the separate display link substitutes the rebuilt object. '
                    'Sanitized checks execute the extracted actual hook and source worker with scheduler, IOKit and boot peers. No kernel runtime or hardware execution.'}
    (ROOT/'reports/ios16-graphics-late.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: opt-in late graphics worker, actual isolated IOBSD object and '+str(host['case_count'])+' sanitized scheduling cases')


if __name__=='__main__':main()
