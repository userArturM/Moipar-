import base64
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
from moi_paroli import Vault
from product_features import category_change,matches_query,copy_backup,backup_info
from github_updates import download_installer,DownloadRedirect

class ProductFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.v=Vault(str(Path(self.tmp.name)/'vault.dat'));self.v.create('FeatureTest!789')
        self.a=self.v.add({'title':'GitHub work','login':'artur@example.test','category':'Work','tags':'important, dev','password':'Unique!789'})
        self.b=self.v.add({'title':'Mail','category':'Work','password':'Other!789'})

    def test_category_rename_style_and_batch_move_survive_reopen(self):
        category_change(self.v,'Work',new_name='Office',color='#0067d9',icon='★')
        category_change(self.v,'Personal',ids=[self.a['id'],self.b['id']])
        self.v.lock();self.v.unlock('FeatureTest!789')
        self.assertNotIn('Work',self.v.categories())
        self.assertEqual(self.v.meta['category_properties']['Office']['icon'],'★')
        self.assertEqual({e['category'] for e in self.v.active()},{'Personal'})
        self.assertEqual(self.v.get(self.a['id'])['history'],[])

    def test_duplicate_rename_and_failed_batch_do_not_partially_change_data(self):
        category_change(self.v,'Personal')
        with self.assertRaises(ValueError):category_change(self.v,'Work',new_name='Personal')
        with self.assertRaises(ValueError):category_change(self.v,'New',ids=[self.a['id'],'unknown'])
        self.assertNotIn('New',self.v.categories())
        self.assertEqual(self.v.get(self.a['id'])['category'],'Work')
        with patch.object(self.v,'save',side_effect=OSError('Disk full')):
            with self.assertRaises(OSError):category_change(self.v,'Work',new_name='Renamed')
        self.assertIn('Work',self.v.categories())

    def test_search_words_fields_and_security_filters(self):
        self.assertTrue(matches_query(self.a,'github artur category:work tag:dev'))
        self.assertTrue(matches_query(self.a,'"GitHub work"'))
        self.assertFalse(matches_query(self.a,'github absent'))
        self.assertFalse(matches_query(self.a,'tag:de'))
        self.assertTrue(matches_query(self.a,'is:weak',{'weak':{self.a['id']}}))
        self.assertFalse(matches_query(self.a,'is:weak',{}))
        self.assertFalse(matches_query(self.a,'Unique!789'),'Passwords must not be searchable')

    def test_independent_backup_is_encrypted_and_restorable(self):
        folder=Path(self.tmp.name)/'external'
        backup=copy_backup(self.v,folder)
        self.assertNotIn(b'Unique!789',backup.read_bytes())
        self.assertEqual(Vault.validate_backup(str(backup),'FeatureTest!789'),2)
        self.assertEqual(backup_info(self.v,str(folder))['days'],0)
        with self.assertRaises(ValueError):copy_backup(self.v,Path(self.v.path).parent)

    def test_download_checks_hash_and_does_not_replace_existing_file_on_failure(self):
        body=b'MZ'+b'FakeInstallerTestOnly'*100
        target=Path(self.tmp.name)/'setup.exe';target.write_bytes(b'previous')
        opener=MagicMock();opener.open.return_value.__enter__.return_value=io.BytesIO(body)
        with patch('urllib.request.build_opener',return_value=opener):
            with self.assertRaises(ValueError):download_installer('https://github.com/owner/repo/releases/download/v4.5/setup.exe',target,'0'*64)
        self.assertEqual(target.read_bytes(),b'previous')
        self.assertFalse(target.with_suffix('.exe.part').exists())
        opener.open.return_value.__enter__.return_value=io.BytesIO(body)
        with patch('urllib.request.build_opener',return_value=opener):
            download_installer('https://github.com/owner/repo/releases/download/v4.5/setup.exe',target,hashlib.sha256(body).hexdigest())
        self.assertEqual(target.read_bytes(),body)

    def test_untrusted_download_or_redirect_is_rejected(self):
        with self.assertRaises(ValueError):download_installer('https://evil.test/setup.exe','unused','0'*64)
        import urllib.request
        with self.assertRaises(ValueError):DownloadRedirect().redirect_request(urllib.request.Request('https://github.com/file'),None,302,'',{},'http://evil.test/file')

    def test_category_metadata_sync_and_renamed_category_does_not_return(self):
        other=Vault(self.v.path);other.unlock('FeatureTest!789')
        category_change(self.v,'Empty',color='#7048bd',icon='★')
        self.assertTrue(other.sync_from_disk())
        self.assertEqual(other.meta['category_properties']['Empty']['icon'],'★')
        category_change(self.v,'Empty',new_name='Renamed')
        other.meta['categories'].append('Stale');other.save()
        self.assertNotIn('Empty',other.categories())
        self.assertIn('Renamed',other.categories())
