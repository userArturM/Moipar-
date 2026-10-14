import os
import tempfile
import unittest
from moi_paroli import Vault, SyncConflict

class ConflictTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=os.path.join(self.tmp.name,"vault.dat")
        self.local=Vault(self.path)
        self.local.create("ConflictTest!789")
        self.entry=self.local.add({"title":"Example","login":"base","password":"One!789"})
        self.remote=Vault(self.path)
        self.remote.unlock("ConflictTest!789")

    def conflict(self):
        self.remote.update(self.entry["id"],{"login":"remote"})
        with self.assertRaises(SyncConflict):
            self.local.update(self.entry["id"],{"login":"local"})
        return self.local.conflict_snapshot()

    def test_keep_both_and_reopen(self):
        snapshot=self.conflict()
        self.local.resolve_conflicts(snapshot,{self.entry["id"]:"both"})
        probe=Vault(self.path)
        probe.unlock("ConflictTest!789")
        self.assertEqual({e["login"] for e in probe.active()},{"local","remote"})
        self.assertEqual(len({e["id"] for e in probe.active()}),2)

    def test_choose_remote(self):
        snapshot=self.conflict()
        self.local.resolve_conflicts(snapshot,{self.entry["id"]:"remote"})
        self.assertEqual(self.local.get(self.entry["id"])["login"],"remote")

    def test_choose_local(self):
        snapshot=self.conflict()
        self.local.resolve_conflicts(snapshot,{self.entry["id"]:"local"})
        self.assertEqual(self.local.get(self.entry["id"])["login"],"local")

    def test_reject_stale_snapshot(self):
        snapshot=self.conflict()
        self.remote.update(self.entry["id"],{"login":"newer"})
        with self.assertRaises(SyncConflict):
            self.local.resolve_conflicts(snapshot,{self.entry["id"]:"both"})

    def test_remote_update_with_same_timestamp_wins_over_unchanged_local(self):
        self.remote.update(self.entry["id"],{"login":"remote"})
        self.assertTrue(self.local.sync_from_disk())
        self.assertEqual(self.local.get(self.entry["id"])["login"],"remote")

    def test_cancel_snapshot_does_not_write(self):
        self.conflict()
        with open(self.path,"rb") as f: before=f.read()
        self.local.conflict_snapshot()
        with open(self.path,"rb") as f: self.assertEqual(f.read(),before)
