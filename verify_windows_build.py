import json
import os
import tempfile
import unittest
from unittest.mock import patch

from windows_hello import HelloUnlock, HelloUnavailable


class HelloTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.vault = os.path.join(self.dir.name, 'vault.dat')
        self.hello_file = os.path.join(self.dir.name, 'hello.json')
        with open(self.vault, 'w') as f:
            json.dump({'magic': 'passvault-v2', 'version': 2,
                       'kdf': {'salt': 'abc', 'n': 65536, 'r': 8, 'p': 1}}, f)
        self.hello = HelloUnlock(self.vault, self.hello_file)

    def test_default_disabled(self):
        self.assertFalse(self.hello.enabled())

    def test_enroll_requires_windows(self):
        with patch('windows_hello.sys.platform', 'linux'):
            with self.assertRaises(HelloUnavailable):
                self.hello.enroll('password')

    def test_disable_removes_token(self):
        with open(self.hello_file, 'w') as f:
            f.write('{}')
        self.assertTrue(self.hello.enabled())
        self.hello.disable()
        self.assertFalse(self.hello.enabled())

    def test_binding_invalidates_key_change(self):
        from windows_hello import _vault_binding
        before = _vault_binding(self.vault)
        with open(self.vault, 'r+') as f:
            data = json.load(f)
            data['kdf']['salt'] = 'new'
            f.seek(0)
            json.dump(data, f)
            f.truncate()
        self.assertNotEqual(before, _vault_binding(self.vault))

    def test_binding_survives_payload_updates(self):
        from windows_hello import _vault_binding
        before = _vault_binding(self.vault)
        with open(self.vault, 'r+') as f:
            data = json.load(f)
            data['data'] = 'new ciphertext'
            f.seek(0)
            json.dump(data, f)
            f.truncate()
        self.assertEqual(before, _vault_binding(self.vault))


if __name__ == '__main__':
    unittest.main()
