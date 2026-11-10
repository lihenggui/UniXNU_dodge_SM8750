#!/usr/bin/env python3
"""Build board vote policy from the captured OnePlus 13 DT declarations, offline."""
import json
import os
import re
import shutil
import subprocess

from native_driver_build import ROOT, archive_imports, build_objects, pinned_sources, require, sha


def generate(board):
    # The structure and consuming vote builder come from the pinned MIT 13T
    # integration; every frequency, corner, SKU and bandwidth below is target
    # data already extracted from the hash-pinned CPH2653 runtime DTB.
    rows = ['/* SPDX-License-Identifier: MIT */',
            '/* Generated from the captured CPH2653 runtime DT declarations. */',
            '#pragma once', '#include <stdint.h>',
            'typedef struct {uint32_t hz,level,bandwidth;} PaganiGpuOpp;',
            'typedef struct {uint32_t speed_bin,sku[2],initial,count;PaganiGpuOpp opps[16];} PaganiGpuProfile;',
            'static const PaganiGpuProfile pagani_gpu_profiles[] = {']
    for profile in board['power_bins']:
        levels = profile['levels']
        initial_hz, = [row[1] for row in levels if row[0] == profile['initial_index']]
        opps = [(0, 0, 0)] + sorted(set(tuple(row[1:4]) for row in levels))
        require(len(opps) <= 16 and len({row[0] for row in opps}) == len(opps), 'Ambiguous target GPU frequency policy')
        initial, = [i for i, row in enumerate(opps) if row[0] == initial_hz]
        speed = profile['speed_bin'] if profile['speed_bin'] is not None else 0xffffffff
        sku = profile['sku_codes'] or [0, 0]
        require(len(sku) == 2, 'Invalid target SKU selector')
        rows.append('    {%su,{%s},%du,%du,{' % (speed, ','.join(str(x) + 'u' for x in sku), initial, len(opps)))
        rows += ['        {%du,%du,%du},' % row for row in opps]
        rows.append('    }},')
    rows += ['};', 'static const uint32_t pagani_gpu_bandwidths[] = {' +
             ','.join(str(x) + 'u' for x in board['ddr_bus_table']) + '};']
    gmu = board['gmu_frequency_corner_pairs']
    require(len(gmu) == 4, 'Unexpected target GMU frequency declaration')
    rows += ['static const PaganiGpuOpp pagani_gmu_opps[] = {{0,0,0},' +
             ','.join('{%du,%du,0}' % tuple(gmu[i:i + 2]) for i in (0, 2)) + '};']
    return '\n'.join(rows) + '\n'


def main():
    sources = pinned_sources(('oneplus13t_reference', 'sm8750', 'a830_firmware_reference'))
    board_path = ROOT / 'hardware/dodge-gpu.json'
    board = json.loads(board_path.read_text())
    require(board['captured_dtb_sha256'] == 'f961f2596c31c51b8db5be7b9e680aa35c86b71694820a7b5844f9829a3e7d11',
            'GPU declarations are not from the reviewed captured DTB')
    require(board['level_columns'][:4] == ['index', 'hz', 'corner_level', 'bus_index'],
            'Unexpected GPU declaration columns')
    reference = sources['oneplus13t_reference'] / 'package'
    out = ROOT / 'build/cph2653-gpu-policy'
    stage = out / 'source'
    stage.mkdir(parents=True, exist_ok=True)
    for name in ('PaganiGpuVotes.c', 'PaganiGpuVotes.h'):
        shutil.copyfile(reference / name, stage / name)
    header = stage / 'PaganiGpuOpps.h'
    header.write_text(generate(board))

    def normalized(text):
        return re.sub(r'\s+', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))

    same = normalized(header.read_text()) == normalized((reference / header.name).read_text())
    soc = sources['sm8750'] / 'kits/Sm8750Platform'
    firmware = sources['a830_firmware_reference']
    includes = (stage, soc, firmware)
    # This is an existing controller/command-db/vote regression, now consuming
    # the header actually generated from this device's six profiles.
    binary = out / 'policy-test'
    command = ['gcc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
               '-DADRENO_HFI_HOST_TEST']
    for path in includes:
        command += ['-I', str(path)]
    command += [str(file) for file in (soc / 'Test/gpu-votes.c', stage / 'PaganiGpuVotes.c',
                soc / 'Sm8750GmuCommandDb.c', soc / 'Sm8750GpuPower.c', firmware / 'AdrenoHfiVotes.c',
                firmware / 'AdrenoHfiStartup.c', firmware / 'AdrenoHfi.c')]
    command += ['-o', str(binary)]
    with (out / 'test.log').open('w') as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        subprocess.run([binary], check=True, stdout=log, stderr=subprocess.STDOUT, timeout=30,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1'))
    objects = build_objects([stage / 'PaganiGpuVotes.c'], out, includes)
    archive = out / 'libDodgeGpuPolicy.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/llvm-ar-14', 'rcs', archive, *objects], check=True)
    report = {'result': 'CPH2653_GPU_POLICY_SOURCE_BUILD_PASS', 'captured_dtb_sha256': board['captured_dtb_sha256'],
              'generated_header_sha256': sha(header), 'target_profiles': len(board['power_bins']),
              'target_policy_values_match_pinned_13t': same, 'native_target': 'arm64-apple-ios16.0',
              'archive': str(archive.relative_to(ROOT)), 'archive_sha256': sha(archive), 'imports': archive_imports(objects),
              'vote_builder_sha256': sha(stage / 'PaganiGpuVotes.c'), 'host_regression': 'ASan/UBSan PASS',
              'candidate_fixed_initial_hz': 525000000, 'native_kernel_selected': False,
              'active_fuse_bin_known': False, 'active_socinfo_sku_known': False, 'real_command_db_tested': False,
              'hardware_tested': False, 'scope': 'Target DT policy build and fixture rail/HFI checks; candidate fixed OPP is not a measured or enabled power policy.'}
    (ROOT / 'reports/gpu-policy.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: six target GPU policies, existing Gen8 vote failures, and native iOS 16 policy archive')


if __name__ == '__main__':
    main()
