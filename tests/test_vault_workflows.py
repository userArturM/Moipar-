import os
import json
import tempfile
import unittest
from moi_paroli import Vault, WrongPassword, SyncConflict, parse_csv, export_csv_text

class VaultWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "vault.dat")
        self.vault = Vault(self.path)
        self.vault.create("MasterTest!789")

    def test_create_edit_reopen_and_history(self):
        row = self.vault.add({"title": "Example", "login": "test", "password": "One!123"})
        self.vault.update(row["id"], {"password": "Two!456"})
        self.vault.lock()
        self.vault.unlock("MasterTest!789")
        self.assertEqual(self.vault.get(row["id"])["password"], "Two!456")
        self.assertEqual(self.vault.get(row["id"])["history"][0]["password"], "One!123")

    def test_wrong_password_does_not_unlock(self):
        self.vault.lock()
        with self.assertRaises(WrongPassword):
            self.vault.unlock("Wrong")
        self.assertFalse(self.vault.unlocked)

    def test_trash_restore(self):
        row = self.vault.add({"title": "Example", "password": "Example!789"})
        self.vault.soft_delete(row["id"])
        self.assertFalse(self.vault.active())
        self.vault.restore(row["id"])
        self.assertEqual(len(self.vault.active()), 1)

    def test_backup_validation(self):
        self.vault.add({"title": "Example", "password": "Example!789"})
        with open(self.path, "rb") as f:
            before = f.read()
        self.assertEqual(Vault.validate_backup(self.path, "MasterTest!789"), 1)
        with self.assertRaises(WrongPassword):
            Vault.validate_backup(self.path, "Wrong")
        with open(self.path, "rb") as f:
            self.assertEqual(before, f.read())

    def test_conflicting_updates_are_rejected(self):
        row = self.vault.add({"title": "Example", "password": "Example!789"})
        other = Vault(self.path)
        other.unlock("MasterTest!789")
        other.update(row["id"], {"login": "remote"})
        with self.assertRaises(SyncConflict):
            self.vault.update(row["id"], {"login": "local"})

    def test_csv_export_import(self):
        self.vault.add({"title": "Example", "login": "test", "password": "Example!789"})
        source, rows, skipped = parse_csv(export_csv_text(self.vault.active()).encode("utf-8"))
        self.assertEqual(rows[0]["password"], "Example!789")
        self.assertEqual(skipped, 0)
