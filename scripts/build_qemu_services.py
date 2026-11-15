#!/usr/bin/env python3
"""Build and verify the iPhone VM service path without operating a phone."""
import argparse
import importlib
import json
from pathlib import Path
import subprocess
import sys

from native_driver_build import ROOT, require, sha

REPORT = ROOT / 'reports/ios16-qemu-services-stack.json'
STAGES = (
    ('percpu_host', 'check_percpu_iteration', (), 'ios16-percpu-iteration-host'),
    ('exec', 'check_qemu_exec', (), 'ios16-qemu-exec-entry'),
    ('kernel', 'build_qemu_store', (), 'ios16-qemu-store-kernel'),
    ('old_percpu_kernel', 'build_qemu_store', ('--old-percpu',), 'ios16-qemu-store-kernel-old-percpu'),
    ('persistence', 'check_qemu_store', (), 'ios16-qemu-store-entry'),
    ('services', 'check_qemu_services', (), 'ios16-qemu-services-entry'),
)


def collect():
    stages, reports = {}, {}
    for name, module, arguments, filename in STAGES:
        path = ROOT / 'reports' / (filename + '.json')
        row = json.loads(path.read_text())
        importlib.import_module(module).check_report(row)
        require('PASS' in row['result'] and row['hardware_tested'] is False, 'Incomplete VM service stage: ' + name)
        script = ROOT / 'scripts' / (module + '.py')
        stages[name] = {'report': str(path.relative_to(ROOT)), 'sha256': sha(path),
            'builder': str(script.relative_to(ROOT)), 'builder_sha256': sha(script), 'arguments': list(arguments)}
        reports[name] = row
    positive, negative = reports['kernel'], reports['old_percpu_kernel']
    require(not positive['old_percpu_control'] and negative['old_percpu_control'] and
        positive['candidate_sha256'] != negative['candidate_sha256'] and
        positive['class_tables'] == negative['class_tables'] and positive['layout'] == negative['layout'] and
        positive['root_archive_preserved_members'] == negative['root_archive_preserved_members'],
        'Per-CPU regression kernels differ in their storage or class inputs')
    services = reports['services']
    require(services['kernel_reports'] == {case: stages[name]['report']
        for case, name in (('positive', 'kernel'), ('negative', 'old_percpu_kernel'))}, 'Service report used another kernel')
    return {'result': 'IOS16_QEMU_SERVICES_SOURCE_AND_RUNTIME_STACK_PASS', 'product': 'iPhone10,3', 'build': '20H392',
        'source_sha256': {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__))}, 'stages': stages,
        'candidate': positive['candidate'], 'candidate_sha256': positive['candidate_sha256'],
        'percpu_host_cases': reports['percpu_host']['total_cases'], 'percpu_fault_reproduced_with_old_consumer': True,
        'launchd_early_boot_complete': True, 'original_SpringBoard_process_executed': True, 'Data_cold_resume_verified': True,
        'hardware_tested': False, 'graphical_interface_tested': False, 'full_system_booted': False,
        'physical_storage_enabled': False, 'hardware_data_protection': False, 'phone_operations': 'none',
        'scope': 'Four-job source compilation with inherited host limits, sanitizer tests of the real per-CPU macros, '
                 'original iPhone exec, persistent VM Data crash/cold resume, and original system-service execution. '
                 'The old mbuf consumer reproduces the kernel fault; the fixed consumer returns and launchd completes early boot. '
                 'SpringBoard process execution is identified by its original UUID; graphics and phone functionality are unqualified.'}


def check_report(report):
    require(report == collect(), 'VM service aggregate is stale')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true')
    mode.add_argument('--record-existing', action='store_true', help='Validate and record completed stages without rerunning VMs')
    args = parser.parse_args()
    if not args.check_only and not args.record_existing:
        for name, module, arguments, _ in STAGES:
            print('BUILD:', name, flush=True)
            subprocess.run([sys.executable, ROOT / 'scripts' / (module + '.py'), *arguments], cwd=ROOT, check=True)
    report = collect()
    if args.check_only:
        require(json.loads(REPORT.read_text()) == report, 'VM service aggregate is stale')
    else:
        REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: iPhone VM service source, original early boot, per-CPU regression and persistent Data')


if __name__ == '__main__':
    main()
