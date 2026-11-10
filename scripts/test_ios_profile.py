#!/usr/bin/env python3
"""Regressions for selecting an iPhone OS without inheriting an iPad target."""
import os
import subprocess
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu import kernel, payload, profiles
from unixnu.util import Error


class ProfileTests(unittest.TestCase):
    def test_partial_kernel_pass_cannot_start_archive_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
            names = ('osfmk/DEVELOPMENT/startup.o.json', 'osfmk/DEVELOPMENT/prng_random.o.json',
                     'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json', 'bsd/DEVELOPMENT/vfs_conf.o.json')
            for name in names:
                path = obj / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{}')
            self.assertFalse(kernel.bootstrap_ready(tree))
            (obj / 'link.filelist').write_text('missing.o\n')
            self.assertFalse(kernel.bootstrap_ready(tree))
            (obj / 'missing.o').write_bytes(b'object')
            self.assertTrue(kernel.bootstrap_ready(tree))

    def test_payload_command_line_fits_the_selected_loader_abi(self):
        self.assertEqual(payload.check_args(['a' * 607], 608), 'a' * 607)
        with self.assertRaisesRegex(Error, 'limit is 607'):
            payload.check_args(['a' * 608], 608)
        self.assertEqual(payload.check_args(['a' * 1000]), 'a' * 1000)
        with self.assertRaisesRegex(Error, 'supported DarwinBoot ABI'):
            payload.check_args(['-v'], 700)

    def test_device_iphone_profile_is_visible_and_major_is_unambiguous(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            core, device = base / 'core', base / 'device'
            for parent, name in ((core, 'ipados-17.7.11-21H461'), (device, 'ios-16.7.16-20H392')):
                (parent / 'profiles/os' / name).mkdir(parents=True)
            ctx = SimpleNamespace(root=core, device=device)
            self.assertEqual(profiles.resolve_os(ctx, '16'), 'ios-16.7.16-20H392')
            self.assertEqual(profiles.resolve_os(ctx, '17'), 'ipados-17.7.11-21H461')
            (device / 'profiles/os/ipados-16.7.16-test').mkdir()
            with self.assertRaisesRegex(Error, 'unambiguous'):
                profiles.resolve_os(ctx, '16')
            self.assertEqual(profiles.resolve_os(ctx, 'ios-16.7.16-20H392'), 'ios-16.7.16-20H392')

    def test_linux_target_uses_selected_arch_and_deployment_version(self):
        ctx = SimpleNamespace(tree=Path('/unused-tree'), board={'os': {'arch': 'arm64', 'ios_version': '16.0'}})
        with patch.object(Path, 'exists', return_value=True), patch.dict(os.environ, {'UNIXNU_TOOLCHAIN': '/unused-prefix'}):
            env = kernel.linux_env(ctx)
            self.assertEqual(env['DARWIN_TRIPLE'], 'arm64-apple-ios16.0')
            self.assertEqual(env['UNIXNU_SDK_VERSION'], '16.0')
            ctx.board['os'].update(arch='arm64e', ios_version='27.0')
            env = kernel.linux_env(ctx)
            self.assertEqual(env['DARWIN_TRIPLE'], 'arm64e-apple-ios27.0')
            self.assertEqual(env['UNIXNU_SDK_VERSION'], '27.0')

    def test_aes_binding_builder_rejects_another_original_cache_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(os.environ, UNIXNU_ORIGINAL_KERNELCACHE_SHA256='0' * 64)
            result = subprocess.run([sys.executable, str(ROOT / 'sources/UniXNU/scripts/build-software-aes-bindings.py'),
                                     '--objects-dir', temporary], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('kernelcache', result.stderr)
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
