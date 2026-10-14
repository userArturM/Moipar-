import base64,hashlib,json
import unittest
from pathlib import Path
from browser_identity import EXTENSION_ID

class IdentityTests(unittest.TestCase):
    def test_extension_id_matches_committed_public_key(self):
        root=Path(__file__).resolve().parents[1]
        manifest=json.loads((root/"browser_extension/manifest.json").read_text(encoding="utf-8"))
        public=base64.b64decode(manifest["key"])
        actual="".join(chr(97+int(n,16)) for n in hashlib.sha256(public).hexdigest()[:32])
        self.assertEqual(actual,EXTENSION_ID)
        self.assertEqual((root/"browser_extension/extension_id.txt").read_text().strip(),EXTENSION_ID)
