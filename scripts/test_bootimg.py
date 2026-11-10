#!/usr/bin/env python3
"""Check Android v0/v3/v4 readback using the pinned Mu-Silicium image writer."""
import gzip
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sources/UniXNU/scripts'))
from unixnu import bootimg
from unixnu.util import Error


class BootImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='bootimg-test-')
        cls.work = Path(cls.temporary.name)
        cls.combined = b'compiled-shim-and-firmware-fixture' * 32
        cls.tree = bytes.fromhex('d00dfeed00000008')
        (cls.work / 'kernel').write_bytes(gzip.compress(cls.combined, mtime=0) + cls.tree)
        cls.ramdisk = cls.work / 'ramdisk'
        cls.ramdisk.write_bytes(b'FAT payload readback fixture')
        cls.settings = {}
        for version in (0, 3, 4):
            values = dict(bootimg.DEFAULTS, header_version=version, base=0x10000000)
            command = [sys.executable, str(ROOT / 'uefi/Mu-Silicium/Resources/Scripts/mkbootimg.py'),
                       '--kernel', str(cls.work / 'kernel'), '--ramdisk', str(cls.ramdisk),
                       '-o', str(cls.work / f'v{version}.img')]
            for key, value in values.items():
                command += ['--' + key, str(value)]
            subprocess.run(command, check=True, capture_output=True)
            cls.settings[version] = values

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def verify(self, path, version):
        return bootimg.verify(path, self.combined, self.tree, self.ramdisk, self.settings[version])

    def test_real_writer_roundtrips_legacy_and_modern_headers(self):
        for version in self.settings:
            with self.subTest(version=version):
                result = self.verify(self.work / f'v{version}.img', version)
                self.assertEqual(result['header_version'], version)
                self.assertEqual(result['ramdisk_bytes'], self.ramdisk.stat().st_size)
                self.assertEqual(result['signature_bytes'], 4096 if version == 4 else 0)

    def test_modern_headers_refuse_corrupt_fields_and_truncation(self):
        original = (self.work / 'v4.img').read_bytes()
        cases = [original[:40], original[:-1]]
        for offset, value in ((20, 1580), (24, 1), (40, 3), (8, 0xffffffff), (1580, 8192)):
            data = bytearray(original)
            struct.pack_into('<I', data, offset, value)
            cases.append(data)
        for index, data in enumerate(cases):
            with self.subTest(case=index):
                path = self.work / 'bad.img'
                path.write_bytes(data)
                with self.assertRaises(Error):
                    self.verify(path, 4)

    def test_ramdisk_bytes_and_legacy_addresses_are_checked(self):
        for version in self.settings:
            data = bytearray((self.work / f'v{version}.img').read_bytes())
            if version == 0:
                struct.pack_into('<I', data, 12, 0)
            else:
                kernel_size = struct.unpack_from('<I', data, 8)[0]
                start = 4096 + ((kernel_size + 4095) & ~4095)
                data[start] ^= 1
            path = self.work / 'bad.img'
            path.write_bytes(data)
            with self.subTest(version=version), self.assertRaises(Error):
                self.verify(path, version)


if __name__ == '__main__':
    unittest.main()
