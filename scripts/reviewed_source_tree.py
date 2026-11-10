#!/usr/bin/env python3
"""Verify complete patched file contents against HEAD plus a reviewed overlay sequence."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

from native_driver_build import ROOT, require, sha


def reviewed_tree(source, specifications):
    source = Path(source)
    with tempfile.TemporaryDirectory(prefix='reviewed-tree-') as directory:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(directory) / 'index'))

        def git(*args):
            return subprocess.check_output(['git', '-C', str(source), *map(str, args)], env=env, stderr=subprocess.PIPE)

        git('read-tree', 'HEAD')
        for spec in specifications:
            patch = ROOT / spec['path']
            require(sha(patch) == spec['sha256'], 'Reviewed source overlay digest differs')
            git('apply', '--cached', '--check', patch)
            git('apply', '--cached', patch)
        tree = git('write-tree').decode().strip()
        records = git('ls-tree', '-rz', '--full-tree', tree).split(b'\0')
        expected = set()
        total = 0
        for record in records:
            if not record:
                continue
            attributes, name = record.split(b'\t', 1)
            mode, kind, identifier = attributes.split()
            require(kind == b'blob' and mode in (b'100644', b'100755', b'120000'),
                    'Unsupported patched source entry: ' + name.decode())
            relative = name.decode()
            expected.add(relative)
            path = source / relative
            if mode == b'120000':
                require(path.is_symlink(), 'Source symlink differs: ' + relative)
                data = os.readlink(path).encode()
            else:
                require(path.is_file() and not path.is_symlink(), 'Patched source file is absent or redirected: ' + relative)
                require(bool(path.stat().st_mode & 0o111) == (mode == b'100755'), 'Unrecorded source executable mode: ' + relative)
                data = path.read_bytes()
            actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            require(actual == identifier.decode(), 'Unrecorded patched source content: ' + relative)
            total += len(data)
        extras = {name.decode() for name in git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0') if name}
        require(not extras - expected, 'Unrecorded patched source additions: ' + ', '.join(sorted(extras - expected)))
    return {'git_tree': tree, 'files_verified': len(expected), 'bytes_verified': total,
            'method': 'Every blob matches HEAD plus hash-locked overlays via a private index; user index preserved'}
