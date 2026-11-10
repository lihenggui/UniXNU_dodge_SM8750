#!/usr/bin/env python3
"""Compile DarwinBoot's layout against the selected Apple ARM64 boot header."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    apple = ROOT / 'sources/xnu-ios16/pexpert/pexpert/arm64/boot.h'
    loader = ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg/Driver/BootArgs.h'
    text = apple.read_text()
    public = text[text.index('#define BOOT_LINE_LENGTH'):text.index('#define SOC_DEVICE_TYPE_BUFFER_SIZE')]
    fields = [('Revision', 'Revision'), ('Version', 'Version'), ('VirtualBase', 'virtBase'),
              ('PhysicalBase', 'physBase'), ('MemorySize', 'memSize'), ('TopOfKernelData', 'topOfKernelData'),
              ('Video', 'Video'), ('MachineType', 'machineType'), ('DeviceTree', 'deviceTreeP'),
              ('DeviceTreeLength', 'deviceTreeLength'), ('CommandLine', 'CommandLine'),
              ('BootFlags', 'bootFlags'), ('MemorySizeActual', 'memSizeActual')]
    fake = '''#include <stdint.h>
#include <stddef.h>
typedef uint16_t UINT16; typedef uint32_t UINT32; typedef uint64_t UINT64; typedef char CHAR8;
#define STATIC_ASSERT _Static_assert
#define OFFSET_OF offsetof
'''
    checks = '\n'.join(f'_Static_assert(offsetof(DARWIN_BOOT_ARGS, {a}) == offsetof(boot_args, {b}), "{a}");' for a, b in fields)
    program = f'''#include "{loader}"
#include <stdio.h>
{public}
{checks}
_Static_assert(sizeof(DARWIN_BOOT_ARGS) == sizeof(boot_args), "whole boot_args");
_Static_assert(sizeof(((DARWIN_BOOT_ARGS *)0)->CommandLine) == BOOT_LINE_LENGTH, "command line bound");
int main(void) {{
 printf("%zu %zu %zu\\n", sizeof(DARWIN_BOOT_ARGS), offsetof(DARWIN_BOOT_ARGS, BootFlags), offsetof(DARWIN_BOOT_ARGS, MemorySizeActual));
 return 0;
}}
'''
    compiler = shutil.which('clang-14') or shutil.which('clang')
    if not compiler:
        raise SystemExit('A host C compiler is required')
    with tempfile.TemporaryDirectory(prefix='boot-args-', dir=ROOT / 'build') as temporary:
        work = Path(temporary)
        (work / 'Base.h').write_text(fake)
        source = work / 'check.c'
        source.write_text(program)
        command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(work), str(source), '-o', str(work / 'check')]
        subprocess.run(command + ['-DDARWIN_BOOT_COMMAND_LINE_LENGTH=608'], check=True)
        size, flags, actual = map(int, subprocess.check_output([str(work / 'check')], text=True).split())
        negative = subprocess.run(command + ['-DDARWIN_BOOT_COMMAND_LINE_LENGTH=1024'], capture_output=True, text=True)
        if negative.returncode == 0 or 'whole boot_args' not in negative.stderr:
            raise SystemExit('Mismatched Darwin 23 layout was not rejected against Darwin 22')
        invalid = subprocess.run(command + ['-DDARWIN_BOOT_COMMAND_LINE_LENGTH=700'], capture_output=True, text=True)
        if invalid.returncode == 0 or 'Unsupported Darwin boot_args' not in invalid.stderr:
            raise SystemExit('Unknown ABI selection was not rejected')
    report = {'result': 'PASS', 'xnu_revision': '1b191cb58250d0705d8a51287127505aa4bc0789',
              'apple_header_sha256': hashlib.sha256(apple.read_bytes()).hexdigest(),
              'loader_header_sha256': hashlib.sha256(loader.read_bytes()).hexdigest(),
              'command_line_bytes': 608, 'boot_args_bytes': size,
              'boot_flags_offset': flags, 'memory_size_actual_offset': actual,
              'compared_field_count': len(fields), 'newer_layout_negative_control': 'rejected',
              'unknown_layout_negative_control': 'rejected',
              'scope': 'Host compilation of production loader and actual Apple structure; no hardware handoff.'}
    (ROOT / 'reports/boot-args-abi.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(fields)} fields match Darwin 22; size {size:#x}, actual-memory offset {actual:#x}; mismatches rejected')


if __name__ == '__main__':
    main()
