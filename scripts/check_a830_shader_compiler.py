#!/usr/bin/env python3
"""Exercise real A830 machine-code generation and reassembly over NIR and an AIR-derived fragment."""
import argparse
import json
import os
import shlex
import subprocess

from native_driver_build import ROOT, require, sha


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--configure-only',action='store_true')
    args=parser.parse_args()
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    production=json.loads((ROOT/'reports/turnip-ios16.json').read_text())
    work=ROOT/'.cache/gpu-work/mesa'
    require(production['mesa_revision']==lock['mesa_reference']['revision']==
            subprocess.check_output(['git','-C',work,'rev-parse','HEAD'],text=True).strip(),'Production Mesa revision differs')
    import sys
    sys.path.insert(0,str(ROOT/'sources/UniXNU/scripts'))
    from mesa_patch_identity import validate_recorded_patches
    pins=json.loads((ROOT/'sources/UniXNU/scripts/data/adreno-compiler-inputs.json').read_text())
    validate_recorded_patches(ROOT/'sources/UniXNU',work,pins)
    out=ROOT/'build/a830-shader-compiler-host';out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'tools/A830CompilerProbe.c'
    env={k:v for k,v in os.environ.items() if not k.startswith(('IR3_','FD_MESA_','NIR_','MESA_SHADER_','TU_'))}
    env.update(PATH=str(ROOT/'.venv-gpu/bin')+':'+str(ROOT/'.toolchains/gpu-host/bin')+':'+
               str(ROOT/'.toolchains/gpu-host/usr/bin')+':'+env.get('PATH',''),
               CC='/usr/bin/gcc',CXX='/usr/bin/g++',CFLAGS='',CXXFLAGS='',CPPFLAGS='',LDFLAGS='')
    options=['-Dgallium-drivers=','-Dvulkan-drivers=','-Dplatforms=','-Dtools=freedreno,nir',
        '-Dglx=disabled','-Degl=disabled','-Dgbm=disabled','-Dopengl=false','-Dgles1=disabled','-Dgles2=disabled',
        '-Dllvm=disabled','-Dshared-glapi=disabled','-Dxmlconfig=disabled','-Dshader-cache=disabled',
        '-Dbuild-tests=false','-Dvideo-codecs=','-Dvulkan-layers=','-Dlibunwind=disabled','-Dlmsensors=disabled',
        '-Dvalgrind=disabled','-Dexpat=disabled','-Dzstd=disabled','-Dbuildtype=debugoptimized','-Db_ndebug=false',
        '-Doffline-adreno-probe='+str(source)]
    meson=ROOT/'.venv-gpu/bin/meson'
    command=[meson,'configure',out] if (out/'build.ninja').exists() else [meson,'setup',out,work,'--wrap-mode=nodownload']
    with (out/'configure.log').open('w') as log:
        result=subprocess.run([*command,*options],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
    require(result.returncode==0,'A830 host compiler configuration failed; see '+str(out/'configure.log'))
    if args.configure_only:print('PASS: offline host IR3 compiler configured');return
    target='src/freedreno/ir3/adreno_compiler_probe'
    # The upstream external-consumer target links NIR/IR3. Link its real VTN
    # frontend as well using the actual Meson-generated compiler/link flags.
    # Only our host executable's link command is extended; Mesa is unchanged.
    commands=subprocess.check_output(['ninja','-C',out,'-t','commands',target],env=env,text=True).splitlines()
    link=shlex.split(commands[-1])
    require(link[:3]==['/usr/bin/g++','-o',target] and link.count('-Wl,--start-group')==1,
            'Unexpected actual Mesa host linker recipe')
    vtn='src/compiler/spirv/libvtn.a'
    link.insert(link.index('-Wl,--start-group')+1,vtn)
    targets=[item for item in link if item.endswith(('.o','.a')) and not item.startswith('/')]
    (out/'host-link-command.json').write_text(json.dumps(link,indent=2)+'\n')
    with (out/'build.log').open('w') as log:
        result=subprocess.run(['ninja','-C',out,'-j4',*targets],env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1200)
        if result.returncode==0:result=subprocess.run(link,cwd=out,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120)
    require(result.returncode==0,'A830 host compiler build failed; see '+str(out/'build.log'))
    binary=out/target
    require(binary.read_bytes()[:5]==b'\x7fELF\x02','Expected a real host compiler ELF')
    needed=subprocess.check_output(['readelf','-d',binary],text=True).lower()
    require('libvulkan' not in needed and 'libdrm' not in needed,'Offline code generator unexpectedly links a GPU transport')
    # The actual compiler's own assemble/disassemble/reassemble comparison
    # must succeed before it returns a variant. Its check ignores padding nops.
    env['IR3_SHADER_DEBUG']='asmroundtrip'
    cases=[]
    for stage in ('cs','vs','fs'):
        output=out/(stage+'.bin');assembly=out/(stage+'.asm')
        result=subprocess.run([binary,stage,output,assembly],env=env,capture_output=True,text=True,timeout=30)
        (out/(stage+'.log')).write_text(result.stdout+result.stderr)
        require(result.returncode==0,'Real A830 code generation failed: '+stage+'; see per-case log')
        value=json.loads(result.stdout)
        require(value['generation']==8 and value['chip_id']=='0x44050001' and value['gpu_execution'] is False and
                value['asm_roundtrip'] is True and 'raw 0x' not in assembly.read_text() and
                value['bytes']==output.stat().st_size and output.stat().st_size%8==0 and assembly.stat().st_size>100,
                'Unexpected real A830 compiler output')
        cases.append({'stage':stage,'binary':str(output.relative_to(ROOT)),'binary_sha256':sha(output),
                      'disassembly':str(assembly.relative_to(ROOT)),'disassembly_sha256':sha(assembly),'bytes':value['bytes']})
    translation=json.loads((ROOT/'reports/metal-translation-tests.json').read_text())
    fragment,=[item for item in translation['spirv_modules'] if item['case']=='render-colored' and item['stage']=='VK_SHADER_STAGE_FRAGMENT_BIT']
    spirv=ROOT/fragment['path']
    require(sha(spirv)==fragment['sha256'],'AIR-derived fragment SPIR-V changed')
    output=out/'air-fragment.bin';assembly=out/'air-fragment.asm'
    result=subprocess.run([binary,'fs',output,assembly,'--spirv',spirv],env=env,capture_output=True,text=True,timeout=30)
    (out/'air-fragment.log').write_text(result.stdout+result.stderr)
    require(result.returncode==0,'Actual AIR-derived SPIR-V to A830 code generation failed; see air-fragment.log')
    value=json.loads(result.stdout)
    require(value['generation']==8 and value['synthetic_nir'] is False and value['asm_roundtrip'] is True and
            value['bytes']==output.stat().st_size and 'raw 0x' not in assembly.read_text(),'Invalid AIR-derived A830 code')
    translated=[{'input_spirv':fragment['path'],'input_sha256':fragment['sha256'],'stage':'fs',
                 'binary':str(output.relative_to(ROOT)),'binary_sha256':sha(output),
                 'disassembly':str(assembly.relative_to(ROOT)),'disassembly_sha256':sha(assembly),'bytes':value['bytes']}]
    refused_binary=out/'invalid-stage.bin';refused_assembly=out/'invalid-stage.asm'
    require(not refused_binary.exists() and not refused_assembly.exists(),'Preserve unexpected negative-control output')
    invalid=subprocess.run([binary,'invalid-stage',refused_binary,refused_assembly],env=env,capture_output=True,timeout=10)
    require(invalid.returncode==2 and not invalid.stdout and not refused_binary.exists() and not refused_assembly.exists(),
            'Invalid shader stage was not refused before output')
    resource_source=out/'resource-control.frag';resource_spirv=out/'resource-control.spv'
    resource_source.write_text('#version 450\nlayout(set=0,binding=0) uniform sampler2D image;\n'
        'layout(location=0) out vec4 color;\nvoid main(){color=texture(image,vec2(0.5));}\n')
    glslang=ROOT/'.toolchains/gpu-host/bin/glslangValidator'
    result=subprocess.run([glslang,'-V','--target-env','vulkan1.2','-S','frag',resource_source,'-o',resource_spirv],
                          env=env,capture_output=True,text=True,timeout=30)
    require(result.returncode==0,'Real resource-binding refusal fixture did not compile')
    result=subprocess.run([ROOT/'.toolchains/gpu-host/usr/bin/spirv-val','--target-env','vulkan1.2',resource_spirv],capture_output=True,timeout=15)
    require(result.returncode==0,'Resource-binding refusal fixture is not valid SPIR-V')
    result=subprocess.run([binary,'fs',refused_binary,refused_assembly,'--spirv',resource_spirv],env=env,capture_output=True,text=True,timeout=30)
    require(result.returncode==10 and result.stderr.startswith('REFUSED: full Vulkan descriptor lowering') and not result.stdout and
            not refused_binary.exists() and not refused_assembly.exists(), 'Resource shader was not refused before guessing Vulkan layout')
    report={'result':'A830_REAL_IR3_NIR_AND_SPIRV_HOST_CHECK_PASS','host_binary':str(binary.relative_to(ROOT)),
        'host_binary_sha256':sha(binary),'source_sha256':sha(source),'mesa_revision':production['mesa_revision'],
        'production_mesa_patches':production['patches'],'production_source_id':production['source_id'],
        'compiler_assertions_enabled':True,'machine_code_disasm_reassembly_checked':True,'roundtrip_ignores_padding_nops':True,
        'invalid_stage_refused_without_outputs':True,
        'resource_spirv_refused_without_guessing_pipeline_layout':True,'full_vulkan_descriptor_pipeline_tested':False,
        'host_c_compiler':subprocess.check_output(['/usr/bin/gcc','--version'],text=True).splitlines()[0],
        'chip_id':'0x44050001','generation':8,'cases':cases,'translated_spirv_cases':translated,
        'inputs':'Three owned synthetic NIR programs and one actual AIR-derived SPIR-V fragment; no original Apple framework shaders',
        'host_link_command_sha256':sha(out/'host-link-command.json'),'shader_cache_disabled':True,
        'gpu_device_created':False,'gpu_execution':False,'hardware_tested':False,
        'vulkan_loader_or_drm_linked':False,
        'scope':'Actual production Mesa NIR/IR3 source emits and disassembles A830 machine code on a Linux CPU host. '
                'No GPU device, submission, pixels or physical capability observation.'}
    (ROOT/'reports/a830-shader-compiler.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: actual Mesa A830 machine code/reassembly for three synthetic NIR programs and one AIR-derived SPIR-V fragment; no GPU execution')


if __name__=='__main__':main()
