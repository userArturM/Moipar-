import os
import tempfile
import unittest
from moi_paroli import Vault
from browser_host import handle,save_to_vault,candidate_from_message

class BrowserSaveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=os.path.join(self.tmp.name,"vault.dat")
        self.vault=Vault(self.path)
        self.vault.create("SaveTestOnly!789")
        self.message={"action":"save_credentials","url":"https://example.test/login",
                      "credentials":{"login":"test@example.test","password":"FakePassword!789","title":"Example"}}

    def save(self,message=None):
        return handle(message or self.message,saver=lambda host,candidate:save_to_vault(self.vault,host,candidate))

    def test_browser_password_persists_after_reopen(self):
        self.assertTrue(self.save()["ok"])
        self.vault.lock()
        self.vault.unlock("SaveTestOnly!789")
        self.assertEqual(self.vault.active()[0]["password"],"FakePassword!789")

    def test_password_update_keeps_history_and_avoids_duplicate(self):
        self.save()
        self.message["credentials"]["password"]="NewFakePassword!456"
        self.save()
        self.assertEqual(len(self.vault.active()),1)
        self.assertEqual(self.vault.active()[0]["history"][0]["password"],"FakePassword!789")

    def test_same_password_does_not_duplicate(self):
        self.save()
        self.save()
        self.assertEqual(len(self.vault.active()),1)

    def test_http_and_invalid_payload_rejected_before_prompt(self):
        seen=[]
        message=dict(self.message,url="http://example.test")
        self.assertFalse(handle(message,saver=lambda *args:seen.append(args))["ok"])
        self.assertFalse(handle(dict(self.message,credentials={"password":""}),saver=lambda *args:seen.append(args))["ok"])
        self.assertEqual(seen,[])

    def test_cancel_does_not_save(self):
        self.assertFalse(handle(self.message,saver=lambda *args:{"ok":False,"error":"Canceled"})["ok"])
        self.assertEqual(self.vault.active(),[])

    def test_ping_needs_no_unlock(self):
        self.vault.lock()
        self.assertIn("save_credentials",handle({"action":"ping"})["supports"])
