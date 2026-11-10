#!/usr/bin/env python3
"""Overlapping source overlays must be idempotent without altering user staging."""
import difflib
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_sources


class OverlayTests(unittest.TestCase):
    def check_series(self, applied_count, apply_missing):
        with tempfile.TemporaryDirectory(prefix='overlay-test-') as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()

            def git(*args, check=True):
                return subprocess.run(['git', '-C', str(source), *map(str, args)], capture_output=True,
                                      text=True, check=check)

            git('init', '-q')
            versions = ['header\none\ntwo\nthree\nend\n', 'header\nONE\ntwo\nthree\nend\n',
                        'header\nONE\nTWO\nthree\nend\n']
            (source / 'code').write_text(versions[0])
            (source / 'user').write_text('original\n')
            git('add', 'code', 'user')
            git('-c', 'user.name=Overlay Test', '-c', 'user.email=overlay@example.invalid',
                'commit', '-qm', 'Temporary test baseline')
            specifications = []
            for index in range(2):
                path = root / f'{index}.patch'
                path.write_text(''.join(difflib.unified_diff(versions[index].splitlines(keepends=True),
                    versions[index + 1].splitlines(keepends=True), fromfile='a/code', tofile='b/code')))
                specifications.append({'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
            (source / 'code').write_text(versions[applied_count])
            (source / 'user').write_text('user staged change\n')
            git('add', 'user')
            before = (source / '.git/index').read_bytes()
            if applied_count == 2:
                self.assertNotEqual(git('apply', '--reverse', '--check', root / '0.patch', check=False).returncode, 0)
            with patch.object(prepare_sources, 'ROOT', root):
                result = prepare_sources.patch_series_state(source, specifications, apply_missing)
            self.assertEqual(result, ['already-applied'] * applied_count +
                             [('applied' if apply_missing else 'applicable')] * (2 - applied_count))
            self.assertEqual((source / 'code').read_text(), versions[2 if apply_missing else applied_count])
            self.assertEqual((source / 'user').read_text(), 'user staged change\n')
            self.assertEqual((source / '.git/index').read_bytes(), before)

    def test_fully_applied_overlapping_patches_preserve_user_index(self):
        self.check_series(2, False)

    def test_missing_suffix_can_be_applied_without_restaging_user_changes(self):
        self.check_series(1, True)

    def test_clean_source_is_checked_without_changes(self):
        self.check_series(0, False)


if __name__ == '__main__':
    unittest.main()
