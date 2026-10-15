from pathlib import Path
import hashlib
import json
import tempfile
import unittest
import zipfile
from tools.package_store import build,FILES

class StorePackageTests(unittest.TestCase):
    def test_store_zip_is_minimal_and_deterministic(self):
        with tempfile.TemporaryDirectory() as folder:
            a=build(Path(folder)/'one');b=build(Path(folder)/'two')
            self.assertEqual(hashlib.sha256(a.read_bytes()).digest(),hashlib.sha256(b.read_bytes()).digest())
            with zipfile.ZipFile(a) as archive:
                self.assertEqual(set(archive.namelist()),set(FILES))
                manifest=json.loads(archive.read('manifest.json'))
                self.assertNotIn('key',manifest)
                self.assertNotIn('update_url',manifest)
                self.assertEqual(manifest['manifest_version'],3)
                self.assertIn('fill.js',archive.namelist())
