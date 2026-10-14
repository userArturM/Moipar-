import tempfile
import unittest
from pathlib import Path
from tools.verify_windows_build import is_pe

class BinaryVerifierTests(unittest.TestCase):
    def test_rejects_fake_mz_header(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "fake.exe"
            path.write_bytes(b"MZ" + b"\0" * 4096)
            self.assertFalse(is_pe(path))

    def test_accepts_valid_pe_signature(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "sample.exe"
            data = bytearray(4096)
            data[:2] = b"MZ"
            data[0x3c:0x40] = (0x80).to_bytes(4, "little")
            data[0x80:0x84] = b"PE\0\0"
            path.write_bytes(data)
            self.assertTrue(is_pe(path))

    def test_rejects_invalid_offset(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bad.exe"
            data = bytearray(4096)
            data[:2] = b"MZ"
            data[0x3c:0x40] = (0xffffffff).to_bytes(4, "little")
            path.write_bytes(data)
            self.assertFalse(is_pe(path))
