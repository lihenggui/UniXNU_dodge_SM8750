#!/usr/bin/env python3
"""Check target clock topology against the captured DTB and pinned OEM facts."""
import argparse
import json
from pathlib import Path
import re
import urllib.request
from compare_oneplus13t import read_fdt,find,registers,node_path
from check_input_clock_host import check
from native_driver_build import ROOT,require,sha

FACTS=ROOT/'hardware/dodge-touch-clock.json'

def derive():
    lock=json.loads((ROOT/'upstream.lock.json').read_text())
    references=lock['dodge_input_clock_references']['files']
    for item in references:
        p=ROOT/item['path']
        if not p.exists():
            p.parent.mkdir(parents=True,exist_ok=True)
            with urllib.request.urlopen(item['url'],timeout=60) as stream:p.write_bytes(stream.read())
        require(sha(p)==item['sha256'],'Input clock reference changed: '+str(p))
    source={Path(r['path']).name.removeprefix('clock-'):(ROOT/r['path']).read_text() for r in references}
    gcc=source['gcc-sun.c']
    def block(kind,name):
        matches=re.findall(r'static struct '+kind+r'\s+'+re.escape(name)+r'\s*=\s*\{(.*?)\n\};',gcc,re.S)
        require(len(matches)==1,'Ambiguous OEM clock record: '+name);return matches[0]
    branches=[]
    for name in ('gcc_qupv3_wrap1_core_2x_clk','gcc_qupv3_wrap1_core_clk',
                 'gcc_qupv3_wrap_1_m_ahb_clk','gcc_qupv3_wrap_1_s_ahb_clk','gcc_qupv3_wrap1_s4_clk'):
        b=block('clk_branch',name)
        reg=int(re.search(r'\.halt_reg\s*=\s*(0x[0-9a-f]+)',b)[1],0)
        vote=int(re.search(r'\.enable_reg\s*=\s*(0x[0-9a-f]+)',b)[1],0)
        bit=int(re.search(r'\.enable_mask\s*=\s*BIT\((\d+)\)',b)[1])
        require(vote==0x52008 and 'BRANCH_HALT_VOTED' in b,'OEM branch vote policy changed')
        hwcg='hwcg_reg' in b
        if hwcg:require(int(re.search(r'\.hwcg_reg\s*=\s*(0x[0-9a-f]+)',b)[1],0)==reg and '.hwcg_bit = 1' in b,'OEM HWCG fact changed')
        branches.append({'name':name,'status_register':hex(reg),'vote_bit':bit,'hardware_gating_bit':1 if hwcg else None})
    require([b['status_register'] for b in branches]==['0x2315c','0x23148','0x23140','0x23144','0x183cc'] and
            [b['vote_bit'] for b in branches]==[18,19,20,21,26],'Target branches differ')
    rcg=block('clk_rcg2','gcc_qupv3_wrap1_s4_clk_src')
    require(re.search(r'\.cmd_rcgr\s*=\s*0x183dc',rcg) and re.search(r'\.mnd_width\s*=\s*16',rcg) and
            re.search(r'\.hid_width\s*=\s*5',rcg) and 'gcc_parent_map_0' in rcg and
            'HW_CLK_CTRL_MODE' in rcg and 'ftbl_gcc_qupv3_wrap1_s0_clk_src' in rcg,'Target RCG facts changed')
    freq=re.search(r'static const struct freq_tbl ftbl_gcc_qupv3_wrap1_s0_clk_src\[\] = \{(.*?)\n\};',gcc,re.S)[1]
    frequencies=[int(v) for v in re.findall(r'F\((\d+),',freq)]
    require(len(frequencies)==16 and max(frequencies)==120000000 and 19200000 in frequencies,'Target frequency limits changed')
    require(re.search(r'GCC_QUPV3_WRAP1_S4_CLK\s+96\b',source['qcom,gcc-sun.h']) and
            re.search(r'GCC_QUPV3_WRAP_1_M_AHB_CLK\s+125\b',source['qcom,gcc-sun.h']) and
            re.search(r'GCC_QUPV3_WRAP_1_S_AHB_CLK\s+126\b',source['qcom,gcc-sun.h']),'Target DT clock IDs changed')
    rpmh=source['clk-rpmh.c']
    require('"qcom,sun-rpmh-clk", .data = &clk_rpmh_pineapple' in rpmh and
            'DEFINE_CLK_RPMH_ARC(xo_pad, "xo.lvl", 0x03, 2)' in rpmh and
            'DEFINE_CLK_RPMH_FIXED(pineapple, bi_tcxo, bi_tcxo_ao, xo_pad, xo_pad_ao, 2)' in rpmh and
            re.search(r'RPMH_CXO_CLK\s+0\b',source['qcom,rpmh.h']),'XO divider/provider facts changed')
    capture=json.loads((ROOT/'analysis/oneplus13-hardware-info.json').read_text())
    path=Path(capture['source_directory'])/'device-tree.dtb'
    require(sha(path)=='f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11','Captured DTB changed')
    root=read_fdt(path.read_bytes());handles={n.scalar('phandle'):n for n in root.walk() if 'phandle' in n.properties}
    touch=find(root,'synaptics_tcm_hbp@0');se=touch.parent;wrapper=se.parent
    require(se.strings('clock-names')==['se-clk'] and len(se.cells('clocks'))==2,'Unexpected target SE clock binding')
    provider,clock=se.cells('clocks');node=handles[provider]
    require(node.strings('compatible')==['qcom,sun-gcc','syscon'] and registers(node)[0][0]==0x100000 and clock==96 and
            wrapper.strings('clock-names')==['m-ahb','s-ahb'] and wrapper.cells('clocks')==[provider,125,provider,126],'Target clock topology changed')
    parents=node.cells('clocks');parent=handles[parents[0]]
    require(node.strings('clock-names')[0]=='bi_tcxo' and parents[1]==0 and parent.strings('compatible')==['qcom,sun-rpmh-clk'],'Target XO parent changed')
    board=find(root,'xo_board');require(board.scalar('clock-frequency')==76800000,'Board oscillator changed')
    return {'schema_version':1,'device':'OnePlus 13 CPH2653 / dodge / SM8750',
            'captured_dtb_sha256':sha(path),'gcc_node':node_path(node),'gcc_base':'0x100000','se_clock_id':clock,
            'xo_board_hz':76800000,'xo_pad_divisor':2,'bi_tcxo_divisor':2,'bi_tcxo_hz':19200000,
            'root_command_register':'0x183dc','root_configuration_register':'0x183e0','vote_register':'0x52008',
            'branches':branches,'vendor_se_frequency_table_hz':frequencies,
            'policy':'Raise only target bus and serial votes. Initialize stopped/unvoted/non-DFS SE4 root to XO only after idle/foreign-protocol/DMA/GPI/FIFO checks; retain unrelated CFG fields. Adopt live roots/DFS read-only using actual locked GPLL0 L/alpha/postdivider and M/N rates, capped at 120 MHz. Read back writes and recheck selected source/ownership. No PLL/reset/voltage/table/global-clock write; pin resources after attempts.',
            'source_reference_files':references,'hardware_tested':False,'cold_clock_runtime_qualified':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');args=p.parse_args()
    facts=derive()
    if args.write:
        require(not FACTS.exists(),'Refuse to replace reviewed clock facts');FACTS.write_text(json.dumps(facts,indent=2)+'\n')
    require(json.loads(FACTS.read_text())==facts,'Reviewed input clock facts changed')
    lock=json.loads((ROOT/'upstream.lock.json').read_text());require(sha(FACTS)==lock['dodge_input_clock']['sha256'],'Input clock fact pin changed')
    host=check();files=[Path(__file__),ROOT/'scripts/check_input_clock_host.py',ROOT/'scripts/compare_oneplus13t.py',FACTS,
                      *[ROOT/i['path'] for i in facts['source_reference_files']],*[ROOT/p for p in host['source_sha256']]]
    report={'result':'CPH2653_CAPTURED_CLOCK_TOPOLOGY_AND_SOURCE_SANITIZERS_PASS','builder_sha256':sha(Path(__file__)),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in files},'host_tests':host,
            'fact_manifest':str(FACTS.relative_to(ROOT)),'fact_manifest_sha256':sha(FACTS),'source_host_cases':host['case_count'],
            'stopped_unvoted_non_dfs_xo_root_initialization_implemented':True,'live_pll_and_mnd_rates_read_back':True,
            'global_pll_or_voltage_or_reset_programming_implemented':False,'hardware_tested':False,'ready_for_ios_boot':False,
            'scope':'Exact CPH2653 clock topology and source/register facts plus actual cold clock code under sanitizers. '
                    'MMIO branch/root update/PLL behavior are peers. A local stopped SE4 root can use XO without programming shared PLLs; actual power/interconnect/clock transitions remain unqualified.'}
    (ROOT/'reports/ios16-input-clock.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: exact target 76.8 MHz -> /2 -> /2 XO, SE4/M-AHB/S-AHB IDs and five clock votes; cold source checks pass')

if __name__=='__main__':main()
