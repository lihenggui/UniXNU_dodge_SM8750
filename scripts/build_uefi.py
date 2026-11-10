#!/usr/bin/env python3
"""Build the pinned dodge UEFI with four jobs and inherited host limits."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def memory_budget():
    """Record the inherited cgroup limit without setting a build memory cap."""
    try:
        entries = Path('/proc/self/cgroup').read_text().splitlines()
    except OSError:
        return {'effective_memory_max_bytes': None, 'limit_source': 'unavailable'}
    entry = next((line for line in entries if line.startswith('0::')), None)
    if entry is None:
        return {'effective_memory_max_bytes': None, 'limit_source': 'unavailable'}
    base = Path('/sys/fs/cgroup')
    group = base / entry.split(':', 2)[2].lstrip('/')
    limits = []
    while group == base or base in group.parents:
        path = group / 'memory.max'
        if path.is_file() and (value := path.read_text().strip()) != 'max':
            limits.append(int(value))
        group = group.parent
    effective = min(limits) if limits else None
    return {'effective_memory_max_bytes': effective,
            'limit_source': 'inherited-cgroup-v2'}


def llvm_directory(explicit):
    if explicit:
        candidates = [Path(explicit).expanduser()]
    elif os.environ.get('CLANG_BIN'):
        candidates = [Path(os.environ['CLANG_BIN'])]
    else:
        candidates = sorted(Path('/usr/lib').glob('llvm-*/bin'),
                            key=lambda p: int(p.parent.name.split('-')[-1]), reverse=True)
        if found := shutil.which('clang'):
            candidates.append(Path(found).resolve().parent)
    required = ('clang', 'llvm-objcopy', 'llvm-ar', 'lld-link')
    for directory in candidates:
        if all((directory / name).is_file() and os.access(directory / name, os.X_OK)
               for name in required):
            return directory.resolve()
    raise SystemExit('LLVM is incomplete: need clang, llvm-objcopy, llvm-ar and lld-link in one real bin directory.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--update-dependencies', action='store_true',
                        help='Run the pinned platform dependency updater before compiling')
    parser.add_argument('--with-unixnu-menu', action='store_true',
                        help='Include UniXNU and DarwinBoot; the XNU kernel is a separate payload input')
    parser.add_argument('--llvm-bin', help='Real LLVM bin directory; no relocated compiler symlinks')
    parser.add_argument('--python', type=Path, default=ROOT / '.venv-uefi/bin/python')
    parser.add_argument('--target', choices=('DEBUG', 'RELEASE'), default='DEBUG')
    args = parser.parse_args()
    budget = memory_budget()
    print('MEMORY_BUDGET', json.dumps(budget), flush=True)
    llvm = llvm_directory(args.llvm_bin)
    python = args.python.absolute()
    version = subprocess.check_output([str(python), '-c',
        'import sys; print(".".join(map(str,sys.version_info[:3]))); '
        'assert sys.version_info >= (3,11); import tomllib, coloredlogs, edk2toolext'], text=True).strip()
    required = ('make', 'gcc', 'g++', 'git', 'mono', 'nasm')
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise SystemExit('Missing host tools: ' + ', '.join(missing))
    source = ROOT / 'uefi/Mu-Silicium'
    subprocess.run([str(python), str(ROOT / 'scripts/apply_uefi_patch.py'),
                    '--source', str(source)], check=True)
    from prepare_sources import patch_state
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    print('BOOT_SHIM_PATCH', patch_state(source, lock['boot_shim_patch'], not args.check_only), flush=True)
    print('SIMPLEFB_PATCH', patch_state(source, lock['simplefb_patch'], not args.check_only), flush=True)
    if args.with_unixnu_menu:
        prepare = [str(python), str(ROOT / 'scripts/apply_unixnu_menu.py'), '--source', str(source)]
        if not args.check_only:
            prepare.append('--apply')
        subprocess.run(prepare, check=True)
    versions = {'python': version,
                'clang': subprocess.check_output([str(llvm / 'clang'), '--version'], text=True).splitlines()[0],
                'llvm_bin': str(llvm)}
    print('HOST_TOOLS', json.dumps(versions), flush=True)
    if args.check_only:
        return
    subprocess.run([str(python), str(ROOT / 'scripts/check_simplefb.py')], check=True)
    env = os.environ.copy()
    env['PATH'] = os.pathsep.join([str(python.parent), str(llvm), env.get('PATH', '')])
    env['CLANG_BIN'] = str(llvm) + '/'
    # The copied sysroot belongs to Ubuntu 24.04; use this host's libraries.
    env.pop('LD_LIBRARY_PATH', None)
    env.update(PYTHONUNBUFFERED='1', MAX_CONCURRENT_THREAD_NUMBER='4',
               CMAKE_BUILD_PARALLEL_LEVEL='4', MAKEFLAGS='-j4')
    # Stuart does not import this value from the process environment. Its
    # target.txt parser supplies the actual EDK II -n option.
    target_file = source / 'Conf/target.txt'
    if not target_file.is_file():
        target_file.parent.mkdir(exist_ok=True)
        target_file.write_bytes((source / 'Mu_Basecore/BaseTools/Conf/target.template').read_bytes())
    text = target_file.read_text()
    text = re.sub(r'(?m)^\s*MAX_CONCURRENT_THREAD_NUMBER\s*=.*$', '', text)
    target_file.write_text(text.rstrip() + '\nMAX_CONCURRENT_THREAD_NUMBER = 4\n')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    log_path = ROOT / f'analysis/uefi-build-{stamp}.log'
    log_path.parent.mkdir(exist_ok=True)
    command = [str(python), 'build_uefi.py', '-d', 'dodge', '-r', args.target]
    commands = []
    if args.update_dependencies:
        commands.append([str(python), 'Platforms/OnePlus/dodgePkg/DeviceBuild.py',
                         '--update', '-t', args.target])
    commands.append(command)
    print('BUILD_LOG', log_path, flush=True)
    with log_path.open('w') as log:
        for command in commands:
            print('BUILD_COMMAND', ' '.join(command), flush=True)
            log.write('COMMAND ' + ' '.join(command) + '\n')
            log.flush()
            result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                break
    record = {'command': command, 'returncode': result.returncode,
              'planned_commands': commands,
              'upstream_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
              'host_tools': versions, 'memory_budget': budget, 'max_concurrent_threads': 4,
              'phone_operations': 'none', 'log': str(log_path)}
    build_log = log_path.read_text(errors='replace')
    record['parallel_jobs_confirmed'] = bool(re.search(r'Cmd to run is: build [^\n]* -n 4\b', build_log))
    record['menu_integrated'] = 'INF UniXNUPkg/Application/UniXNU/UniXNU.inf' in (
        source / 'Platforms/OnePlus/dodgePkg/dodge.fdf').read_text()
    record['darwinboot_integrated'] = 'INF DarwinBootPkg/Driver/DarwinBoot.inf' in (
        source / 'Platforms/OnePlus/dodgePkg/dodge.fdf').read_text()
    if result.returncode == 0 and not record['parallel_jobs_confirmed']:
        raise SystemExit('The build did not confirm the requested EDK II -n 4 limit; inspect ' + str(log_path))
    (ROOT / 'analysis/uefi-build-result.json').write_text(json.dumps(record, indent=2) + '\n')
    print('BUILD_RETURN_CODE', result.returncode, flush=True)
    print('\n'.join(log_path.read_text(errors='replace').splitlines()[-55:]), flush=True)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
