// SPDX-License-Identifier: BSD-2-Clause-Patent
// Offline consumer of the real pinned Mesa NIR/IR3 compiler. No GPU device.
#include "compiler/nir/nir_builder.h"
#include "compiler/spirv/nir_spirv.h"
#include "freedreno/ir3/ir3_compiler.h"
#include "freedreno/ir3/ir3_nir.h"
#include "freedreno/ir3/ir3_shader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv)
{
    if((argc!=4 && argc!=6) || (argc==6 && (strcmp(argv[4],"--spirv") || strcmp(argv[1],"fs"))) ||
       (strcmp(argv[1],"cs") && strcmp(argv[1],"vs") && strcmp(argv[1],"fs")))return 2;
    const struct fd_dev_id id={.chip_id=0x44050001};
    const struct fd_dev_info *info=fd_dev_info_raw(&id);
    if(!info || info->chip!=8)return 3;
    const struct ir3_compiler_options options={.disable_cache=true,.bindless_fb_read_descriptor=-1,.bindless_fb_read_slot=-1};
    struct ir3_compiler *compiler=ir3_compiler_create(NULL,&id,info,&options);
    if(!compiler || compiler->gen!=8 || !(ir3_shader_debug & IR3_DBG_ASM_ROUNDTRIP))return 4;
    const mesa_shader_stage stage=!strcmp(argv[1],"cs")?MESA_SHADER_COMPUTE:
        (!strcmp(argv[1],"vs")?MESA_SHADER_VERTEX:MESA_SHADER_FRAGMENT);
    glsl_type_singleton_init_or_ref();
    nir_shader *nir=NULL;
    if(argc==6) {
        FILE *input=fopen(argv[5],"rb");
        if(!input || fseek(input,0,SEEK_END))return 2;
        long size=ftell(input);
        if(size<20 || size>4*1024*1024 || size%4 || fseek(input,0,SEEK_SET))return 2;
        uint32_t *words=malloc((size_t)size);
        if(!words || fread(words,1,(size_t)size,input)!=(size_t)size)return 2;
        fclose(input);
        if(words[0]!=0x07230203)return 2;
        const struct spirv_to_nir_options spirv_options={.environment=NIR_SPIRV_VULKAN};
        nir=spirv_to_nir(words,(size_t)size/4,NULL,stage,"main",&spirv_options,ir3_get_compiler_options(compiler));
        free(words);
        if(!nir)return 9;
        nir_foreach_variable_with_modes(variable,nir,nir_var_uniform|nir_var_mem_ubo|nir_var_mem_ssbo|nir_var_mem_push_const) {
            // This direct IR3 consumer has no full Vulkan pipeline layout.
            // Resource descriptors must be lowered by Turnip, not guessed.
            fprintf(stderr,"REFUSED: full Vulkan descriptor lowering is required\n");
            return 10;
        }
        NIR_PASS(_,nir,nir_lower_variable_initializers,nir_var_function_temp);
        NIR_PASS(_,nir,nir_lower_returns);
        NIR_PASS(_,nir,nir_inline_functions);
        NIR_PASS(_,nir,nir_opt_deref);
        nir_remove_non_entrypoints(nir);
        NIR_PASS(_,nir,nir_lower_var_copies);
        NIR_PASS(_,nir,nir_lower_vars_to_ssa);
    } else {
        nir_builder b=nir_builder_init_simple_shader(stage,ir3_get_compiler_options(compiler),"CPH2653 offline synthetic NIR");
        nir=b.shader;
        if(stage==MESA_SHADER_COMPUTE) {
            nir->info.workgroup_size[0]=nir->info.workgroup_size[1]=nir->info.workgroup_size[2]=1;
            nir->info.num_ssbos=1;
            nir_def *index=nir_channel(&b,nir_load_global_invocation_id(&b,32),0);
            nir_def *offset=nir_imul_imm(&b,index,4);
            nir_store_ssbo(&b,nir_iadd_imm(&b,index,7),nir_imm_int(&b,0),offset,.write_mask=1,.align_mul=4);
        } else {
            nir_variable *out=nir_variable_create(nir,nir_var_shader_out,glsl_vec4_type(),"result");
            out->data.location=stage==MESA_SHADER_VERTEX?VARYING_SLOT_POS:FRAG_RESULT_DATA0;
            out->data.driver_location=0;
            nir_store_var(&b,out,nir_imm_vec4(&b,0.125f,0.25f,0.5f,1.0f),15);
        }
    }
    nir_validate_shader(nir,"owned A830 input");
    if(stage==MESA_SHADER_COMPUTE) {
        const nir_lower_compute_system_values_options sysval_options={.has_base_workgroup_id=true};
        NIR_PASS(_,nir,nir_lower_compute_system_values,&sysval_options);
    }
    nir_assign_io_var_locations(nir,nir_var_shader_in);
    nir_assign_io_var_locations(nir,nir_var_shader_out);
    ir3_nir_lower_io(nir);
    const struct ir3_shader_options shader_options={.api_wavesize=IR3_SINGLE_OR_DOUBLE,.real_wavesize=IR3_SINGLE_OR_DOUBLE};
    ir3_finalize_nir(compiler,&shader_options.nir_options,nir);
    nir_shader_gather_info(nir,nir_shader_get_entrypoint(nir));
    struct ir3_shader *shader=ir3_shader_from_nir(compiler,nir,&shader_options);
    const struct ir3_shader_key key={};
    struct ir3_shader_variant *variant=ir3_shader_get_variant(shader,&key,false,true,NULL,NULL);
    if(!variant || !variant->bin || !variant->disasm_info.disasm || !variant->info.size || variant->info.size>4*1024*1024)return 5;
    FILE *binary=fopen(argv[2],"wb"),*assembly=fopen(argv[3],"w");
    if(!binary || !assembly)return 6;
    if(fwrite(variant->bin,1,variant->info.size,binary)!=variant->info.size)return 7;
    // Mesa frees the IR after assembly; use the real disassembly retained
    // during compilation, rather than calling an IR-dependent printer again.
    if(fputs(variant->disasm_info.disasm,assembly)<0)return 7;
    if(fclose(binary) || fclose(assembly))return 8;
    printf("{\"chip_id\":\"0x44050001\",\"generation\":%u,\"stage\":\"%s\",\"bytes\":%u,\"gpu_execution\":false,\"synthetic_nir\":%s,\"asm_roundtrip\":true}\n",
        compiler->gen,argv[1],variant->info.size,argc==4?"true":"false");
    ir3_shader_destroy(shader);ir3_compiler_destroy(compiler);glsl_type_singleton_decref();
    return 0;
}
