#!/usr/bin/env python3
"""Check the actual APFS lookup backport and its observed ARM64 boundary."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree'


def main():
    spec = json.loads((ROOT / 'upstream.lock.json').read_text())['vfs_backport']
    source = TREE / '.cache/xnu-work/bsd/vfs/vfs_subr.c'
    function = re.search(r'^struct mount \*\nvfs_getvfs_with_vfsops\(.*?^}', source.read_text(), re.M | re.S)[0]
    if hashlib.sha256(function.encode()).hexdigest() != spec['function_sha256']:
        raise SystemExit('Backport differs from the pinned public Apple function')
    program = '''
#include <assert.h>
#include <stddef.h>
typedef struct { int val[2]; } fsid_t;
struct vfsops { int tag; };
struct mount { const struct vfsops *mnt_op; };
typedef struct mount *mount_t;
static fsid_t identifier;
static mount_t result;
static mount_t mount_list_lookupby_fsid(fsid_t *fsid, int locked, int withref) {
    assert(fsid == &identifier && locked == 0 && withref == 0);
    return result;
}
''' + function + '''
int main(void) {
    struct vfsops expected = {1}, other = {2};
    struct mount mount = { &expected };
    assert(vfs_getvfs_with_vfsops(&identifier, &expected) == NULL);
    result = &mount;
    assert(vfs_getvfs_with_vfsops(&identifier, &expected) == &mount);
    assert(vfs_getvfs_with_vfsops(&identifier, &other) == NULL);
    assert(vfs_getvfs_with_vfsops(&identifier, NULL) == NULL);
    mount.mnt_op = NULL;
    assert(vfs_getvfs_with_vfsops(&identifier, NULL) == &mount);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='vfs-backport-') as temporary:
        work = Path(temporary)
        path = work / 'behavior.c'
        path.write_text(program)
        subprocess.run(['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-Werror', str(path), '-o', str(work / 'behavior')], check=True)
        subprocess.run([str(work / 'behavior')], check=True)
        recipe = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/vfs_conf.o.json'
        record = json.loads(recipe.read_text().strip().rstrip(','))
        boundary = work / 'boundary.c'
        boundary.write_text('''
#include <sys/mount_internal.h>
_Static_assert(sizeof(fsid_t) == 8, "observed fsid width");
_Static_assert(__builtin_offsetof(struct mount, mnt_op) == 0x28, "observed operations pointer");
_Static_assert(__builtin_offsetof(struct mount, mnt_vfsstat.f_fsid) == 0xc0, "observed fsid member");
''')
        command, args, index = [], record['arguments'], 0
        while index < len(args):
            value = args[index]
            if value == record['file']:
                command.append(str(boundary))
            elif value in ('-o', '-MF', '-MJ'):
                index += 1
            elif value not in ('-c', '-MD', '-MP'):
                command.append(value)
            index += 1
        command += ['-fsyntax-only', '-w']
        check = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
        if check.returncode:
            raise SystemExit(check.stderr[-3500:])
    report = {'result': 'PASS', 'source_revision': spec['revision'], 'function_sha256': spec['function_sha256'],
              'behavior': ['not found returns NULL', 'matching operations return the actual mount',
                           'mismatched operations return NULL', 'original lookup flags preserved'],
              'arm64': {'fsid_bytes': 8, 'mount_ops_offset': '0x28', 'mount_fsid_offset': '0xc0'},
              'scope': 'Extracted production function exercised on the host; actual XNU mount headers compiled for ARM64. Complete APFS ABI and runtime remain unqualified.'}
    (ROOT / 'reports/vfs-backport.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: original Apple lookup function, mismatch rejection and observed ARM64 mount prefix')


if __name__ == '__main__':
    main()
