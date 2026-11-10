#!/usr/bin/env python3
"""Build a pinned EROFS reader in the workspace for offline stock-file extraction."""
import io
import json
import os
import subprocess
import tarfile

from native_driver_build import ROOT, pinned_sources, require, sha


def main():
    source = pinned_sources(('erofs_tools',))['erofs_tools']
    spec = json.loads((ROOT / 'upstream.lock.json').read_text())['erofs_tools']
    out = ROOT / 'build/firmware-tools'
    work = out / 'erofs-utils'
    prefix = ROOT / '.toolchains/gpu-host'
    record = out / 'manifest.json'
    binary = prefix / 'bin/fsck.erofs'
    if record.exists() and binary.exists():
        previous = json.loads(record.read_text())
        if previous['source_revision'] == spec['revision'] and previous['fsck_sha256'] == sha(binary):
            print('PASS: pinned workspace EROFS reader already built')
            return
    out.mkdir(parents=True, exist_ok=True)
    if not work.exists():
        data = subprocess.check_output(['git', '-C', source, 'archive', 'HEAD'])
        work.mkdir()
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(work, filter='data')
    (prefix / 'bin').mkdir(parents=True, exist_ok=True)
    for name in ('aclocal', 'automake'):
        alias = prefix / 'bin' / name
        if not alias.exists():
            alias.symlink_to('../usr/bin/' + name + '-1.16')
    # Debian's data file has an absolute compiled-in include directory. Keep
    # the package intact and relocate that single directory in our own config.
    config = out / 'autom4te.cfg'
    config.write_text((prefix / 'usr/share/autoconf/autom4te.cfg').read_text().replace(
        '/usr/share/autoconf', str(prefix / 'usr/share/autoconf')))
    libtool_data = out / 'libtool-data'
    libtool_data.mkdir(exist_ok=True)
    for name, target in (('build-aux', prefix / 'usr/share/libtool/build-aux'),
                         ('libltdl', prefix / 'usr/share/libtool'), ('m4', prefix / 'usr/share/aclocal')):
        link = libtool_data / name
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    env = dict(os.environ, PATH=str(prefix / 'bin') + ':' + str(prefix / 'usr/bin') + ':' + os.environ.get('PATH', ''),
               PERL5LIB=str(prefix / 'usr/share/autoconf') + ':' + str(prefix / 'usr/share/automake-1.16'),
               AC_MACRODIR=str(prefix / 'usr/share/autoconf'),
               AUTOM4TE_CFG=str(config),
               AUTOM4TE=str(prefix / 'usr/bin/autom4te'),
               AUTOCONF=str(prefix / 'usr/bin/autoconf'), AUTOHEADER=str(prefix / 'usr/bin/autoheader'),
               trailer_m4=str(prefix / 'usr/share/autoconf/autoconf/trailer.m4'),
               AUTOMAKE_LIBDIR=str(prefix / 'usr/share/automake-1.16'),
               ACLOCAL_AUTOMAKE_DIR=str(prefix / 'usr/share/aclocal-1.16'),
               ACLOCAL_PATH=str(prefix / 'usr/share/aclocal') + ':/usr/share/aclocal',
               LIBTOOLIZE_PKGDATADIR=str(prefix / 'usr/share/libtool'),
               LIBTOOLIZE_PKGAUXDIR=str(prefix / 'usr/share/libtool/build-aux'),
               _lt_pkgdatadir=str(libtool_data),
               liblz4_CFLAGS='-I' + str(prefix / 'usr/include'), liblz4_LIBS='-l:liblz4.so.1',
               LDFLAGS='-L' + str(prefix / 'usr/lib/x86_64-linux-gnu'))
    commands = [['./autogen.sh'], ['./configure', '--prefix=' + str(prefix), '--disable-fuse', '--enable-lz4'],
                ['make', '-j4'], ['make', 'install']]
    with (out / 'build.log').open('w') as log:
        for command in commands:
            result = subprocess.run(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            require(result.returncode == 0, 'EROFS reader build failed; see build/firmware-tools/build.log')
    version = subprocess.check_output([binary, '--version'], text=True, stderr=subprocess.STDOUT).strip()
    help_result = subprocess.run([binary, '--help'], capture_output=True, text=True)
    help_text = help_result.stdout + help_result.stderr
    require('--extract' in help_text, 'The reader cannot extract files')
    record.write_text(json.dumps({'source_revision': spec['revision'], 'version': version,
        'fsck_sha256': sha(binary), 'scope': 'Offline file extraction only; no mounts or devices.'}, indent=2) + '\n')
    print('PASS: pinned EROFS reader built locally:', version)


if __name__ == '__main__':
    main()
