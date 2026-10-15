import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from moi_paroli import Vault
from product_features import (preview_backup,restore_selected,remove_category,
    restore_category,duplicate_groups,merge_duplicates,category_change)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.v=Vault(str(Path(self.tmp.name)/'vault.dat'));self.v.create('RecoveryOnly!789')
        self.a=self.v.add({'title':'First','url':'https://example.test/login','login':'user',
            'password':'FirstFake!789','category':'Work','note':'first note'})
        self.v.update(self.a['id'],{'password':'SecondFake!789'})
        self.a['attachments']=[{'name':'test.txt','data':'dGVzdA=='}];self.v.save()

    def test_preview_does_not_touch_backup_and_restore_copies_all_fields(self):
        backup=Path(self.tmp.name)/'copy.dat';backup.write_bytes(Path(self.v.path).read_bytes())
        before=backup.read_bytes();records=preview_backup(str(backup),'RecoveryOnly!789')
        self.assertEqual(backup.read_bytes(),before)
        created=restore_selected(self.v,records,[self.a['id']])
        restored=self.v.get(created[0]);self.assertNotEqual(restored['id'],self.a['id'])
        for field in ('password','history','attachments','note','created'):
            self.assertEqual(restored[field],self.a[field])
        self.assertEqual(len(self.v.active()),2)
        with self.assertRaises(Exception):preview_backup(str(backup),'Wrong')
        self.assertEqual(backup.read_bytes(),before)

    def test_category_trash_restore_survives_reopen_and_sync(self):
        other=Vault(self.v.path);other.unlock('RecoveryOnly!789')
        token=remove_category(self.v,'Work',True)
        self.assertEqual(len(self.v.trash()),1)
        other.sync_from_disk();self.assertIn(token,other.meta['category_trash'])
        self.assertEqual(restore_category(other,token),1)
        self.v.sync_from_disk();self.assertEqual(self.v.get(self.a['id'])['category'],'Work')
        self.assertFalse(self.v.get(self.a['id'])['deleted'])
        self.assertTrue(self.v.meta['category_trash'][token]['restored'])
        self.v.lock();self.v.unlock('RecoveryOnly!789')
        self.assertTrue(self.v.meta['category_trash'][token]['restored'])

    def test_category_restore_does_not_overwrite_later_edit(self):
        token=remove_category(self.v,'Work')
        self.v.update(self.a['id'],{'category':'Personal','note':'later'})
        self.assertEqual(restore_category(self.v,token),0)
        self.assertEqual(self.v.get(self.a['id'])['category'],'Personal')
        self.assertEqual(self.v.get(self.a['id'])['note'],'later')

    def test_recovery_transactions_rollback_on_disk_error(self):
        before=copy.deepcopy((self.v.entries,self.v.meta))
        with patch.object(self.v,'save',side_effect=OSError('Disk full')):
            with self.assertRaises(OSError):remove_category(self.v,'Work',True)
        self.assertEqual((self.v.entries,self.v.meta),before)
        with self.assertRaises(ValueError):restore_selected(self.v,[],['missing'])

    def test_merge_choices_preserve_history_attachments_and_original_in_trash(self):
        b=self.v.add({'title':'Second','url':'https://EXAMPLE.test/account','login':'user',
            'password':'ThirdFake!789','category':'Home','note':'second note'})
        b['attachments']=[{'name':'another.txt','data':'YQ=='}];self.v.save()
        self.assertEqual(len(duplicate_groups(self.v.active())),1)
        expected={e['id']:self.v._record_hash(e) for e in (self.a,b)}
        merge_duplicates(self.v,[self.a['id'],b['id']],self.a['id'],
            {'password':b['id'],'note':b['id']},expected)
        self.assertEqual(self.a['password'],'ThirdFake!789')
        self.assertEqual(self.a['note'],'second note')
        self.assertEqual({h['password'] for h in self.a['history']},{'FirstFake!789','SecondFake!789'})
        self.assertEqual(len(self.a['attachments']),2)
        self.assertTrue(b['deleted']);self.assertEqual(b['note'],'second note')

    def test_merge_rejects_stale_selection_and_distinct_login(self):
        b=self.v.add({'title':'Other','url':'https://example.test','login':'user','password':'OtherFake!789'})
        expected={e['id']:self.v._record_hash(e) for e in (self.a,b)}
        self.v.update(b['id'],{'note':'changed'})
        with self.assertRaises(ValueError):merge_duplicates(self.v,[self.a['id'],b['id']],self.a['id'],{},expected)
        self.assertEqual(len(self.v.active()),2)
        self.v.update(b['id'],{'login':'USER'})
        self.assertEqual(duplicate_groups(self.v.active()),[])

    def test_scoped_search_never_searches_passwords(self):
        from product_features import matches_query
        self.assertTrue(matches_query(self.a,'site:example.test login:user note:"first note"'))
        self.assertFalse(matches_query(self.a,'note:SecondFake'))
        self.assertFalse(matches_query(self.a,'login:missing'))

    def test_native_probe_accepts_only_framed_success(self):
        from browser_registration import probe_host
        import json,struct,subprocess
        raw=json.dumps({'ok':True,'version':'4.6.0','supports':['save_credentials','get_credentials']}).encode()
        with patch('browser_registration.subprocess.run',return_value=subprocess.CompletedProcess([],0,struct.pack('<I',len(raw))+raw,b'')) as run:
            self.assertEqual(probe_host('host.exe'),{'version':'4.6.0','save':True,'fill':True})
            self.assertIn(b'ping',run.call_args.kwargs['input'])
        with patch('browser_registration.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'broken',b'')):
            with self.assertRaises(ValueError):probe_host('host.exe')
