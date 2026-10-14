import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from register_browser_host import register, make_manifest

class RegistrationTests(unittest.TestCase):
    def test_chrome_and_yandex_per_user_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/"browser_host.exe"
            exe.write_bytes(b"test")
            registry=MagicMock()
            registry.HKEY_CURRENT_USER=123
            with patch.dict("sys.modules",{"winreg":registry}), patch.dict(os.environ,{"APPDATA":tmp}):
                manifest=register("a"*32,str(exe))
            data=json.loads(Path(manifest).read_text(encoding="utf-8"))
            self.assertTrue(os.path.samefile(data["path"],exe))
            self.assertEqual(data["allowed_origins"],["chrome-extension://"+"a"*32+"/"])
            self.assertIn(str(Path(tmp)/"MoiParoli"/"native"),manifest)
            keys=[call.args[1] for call in registry.CreateKey.call_args_list]
            self.assertEqual(len(keys),2)
            self.assertTrue(any("Google" in key for key in keys))
            self.assertTrue(any("Yandex" in key for key in keys))

    def test_invalid_extension_id_and_missing_exe(self):
        with self.assertRaises(ValueError):
            make_manifest("bad","missing.exe")
        with self.assertRaises(ValueError):
            make_manifest("a"*32,"missing.exe")
