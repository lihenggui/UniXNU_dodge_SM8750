#!/usr/bin/env python3
"""Check preserved typed-pointer checks and byte-buffer alignment on ARM64."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree/.cache/xnu-work'


def main():
    compiler = ROOT / '.toolchains/xnu-linux/llvm/bin/clang'
    text = (WORK / 'osfmk/kern/kalloc.h').read_text()
    start = text.index('#if defined(__cplusplus) && __has_builtin(__remove_pointer)')
    end = text.index('\n\n\n/*!', start)
    macros = text[start:end]
    cpp = macros + '''
struct Typed { void *pointer; long value; };
Typed *typed;
void *erased;
int *wrong;
int scalar;
static_assert(KALLOC_TYPE_IS_COMPATIBLE_PTR(typed, Typed));
static_assert(KALLOC_TYPE_IS_COMPATIBLE_PTR(erased, Typed));
static_assert(!KALLOC_TYPE_IS_COMPATIBLE_PTR(wrong, Typed));
static_assert(!KALLOC_TYPE_IS_COMPATIBLE_PTR(scalar, Typed));
KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(typed, Typed);
KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(erased, Typed);
'''
    uio = (WORK / 'bsd/sys/uio_internal.h').read_text()
    structs = uio[uio.index('struct kern_iovec {'):uio.index('/* values for uio_flags */')]
    sizes = uio[uio.index('#define UIO_SIZEOF_IOVS'):uio.index('#define UIO_IS_USER_SPACE32')]
    attr = (WORK / 'bsd/vfs/vfs_attrlist.c').read_text()
    declaration = re.search(r'_Alignas\(union iovecs\) uio_stackbuf_t\s+uio_buf\[UIO_SIZEOF\(1\)\];', attr)[0]
    c = '''
typedef unsigned long long uint64_t, u_int64_t, user_addr_t, user_size_t;
typedef unsigned int uint32_t, u_int32_t;
typedef long off_t;
enum uio_seg { segment = 0 };
enum uio_rw { direction = 0 };
#define XNU_PTRAUTH_SIGNED_PTR(x)
#define MAX(a,b) ((a) > (b) ? (a) : (b))
''' + structs + sizes + declaration + '''
_Static_assert(sizeof(uio_stackbuf_t) == 1, "byte element");
_Static_assert(sizeof(uio_buf) == UIO_SIZEOF(1), "unchanged capacity");
_Static_assert(__alignof__(uio_buf) >= _Alignof(union iovecs), "required pointer alignment");
_Static_assert(sizeof(uio_buf) == 72, "ARM64 one-iovec capacity");
'''
    with tempfile.TemporaryDirectory(prefix='allocator-compat-', dir=ROOT / 'build') as temporary:
        work = Path(temporary)
        for name, program, language in [('pointers.cpp', cpp, 'c++'), ('uio.c', c, 'c')]:
            path = work / name
            path.write_text(program)
            result = subprocess.run([str(compiler), '-target', 'arm64-apple-ios16.0', '-ffreestanding',
                                     '-std=gnu++17' if language == 'c++' else '-std=gnu11',
                                     '-fsyntax-only', str(path)], capture_output=True, text=True)
            if result.returncode:
                raise SystemExit(result.stderr)
        bad = work / 'wrong.cpp'
        bad.write_text(cpp + 'KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(wrong, Typed);\n')
        refused = subprocess.run([str(compiler), '-target', 'arm64-apple-ios16.0', '-std=gnu++17',
                                  '-fsyntax-only', str(bad)], capture_output=True, text=True)
        if refused.returncode == 0 or 'Pointer type is not compatible' not in refused.stderr:
            raise SystemExit('Wrong allocation type was not rejected by the production assertion')
    report = {'result': 'PASS', 'target': 'arm64-apple-ios16.0',
              'typed_pointer': 'accepted', 'void_wildcard': 'accepted', 'wrong_pointer': 'rejected',
              'non_pointer': 'rejected', 'uio_byte_capacity': 72, 'uio_alignment': 8,
              'source_sha256': {name: hashlib.sha256((WORK / name).read_bytes()).hexdigest()
                                for name in ('osfmk/kern/kalloc.h', 'bsd/sys/uio_internal.h')},
              'scope': 'Production source macros/structures compiled for ARM64, including a negative type check; no hardware runtime.'}
    (ROOT / 'reports/allocator-compat.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: typed/void pointers, rejected wrong types, 72-byte aligned UIO storage')


if __name__ == '__main__':
    main()
