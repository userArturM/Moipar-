import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error
import base64
import localization
from moi_paroli import Vault,MIN_MASTER_LEN
from github_updates import check,version,save_token,load_token

class Release44Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=os.path.join(self.tmp.name,'vault.dat')
        self.addCleanup(localization.set_language,'ru')

    def test_four_character_master_creation_and_change(self):
        self.assertEqual(MIN_MASTER_LEN,4)
        v=Vault(self.path);v.create('1234')
        v.add({'title':'Test','password':'SavedPassword!789'})
        v.change_password('abcd');v.lock();v.unlock('abcd')
        self.assertEqual(v.active()[0]['password'],'SavedPassword!789')

    def test_shorter_password_rejected_before_write(self):
        with self.assertRaises(ValueError):Vault(self.path).create('123')
        self.assertFalse(os.path.exists(self.path))
        v=Vault(self.path);v.create('1234')
        with self.assertRaises(ValueError):v.change_password('123')
        self.assertTrue(v.verify_password('1234'))

    def test_category_removal_preserves_records_and_trash(self):
        v=Vault(self.path);v.create('1234')
        active=v.add({'title':'Active','category':'Работа','password':'First!789'})
        trashed=v.add({'title':'Trash','category':'Работа','password':'Second!789'})
        v.soft_delete(trashed['id']);v.delete_category('Работа');v.lock();v.unlock('1234')
        self.assertNotIn('Работа',v.categories())
        self.assertEqual(v.get(active['id'])['password'],'First!789')
        self.assertEqual(v.get(trashed['id'])['category'],'')
        self.assertTrue(v.get(trashed['id'])['deleted'])

    def test_empty_category_and_failed_save_rollback(self):
        v=Vault(self.path);v.create('1234');v.meta['categories']=['Empty'];v.save()
        with patch.object(v,'save',side_effect=OSError('Locked')):
            with self.assertRaises(OSError):v.delete_category('Empty')
        self.assertIn('Empty',v.categories())
        v.delete_category('Empty');v.lock();v.unlock('1234')
        self.assertNotIn('Empty',v.categories())

    def response(self,data):
        from unittest.mock import MagicMock
        response=MagicMock();response.__enter__.return_value=response
        response.read.return_value=json.dumps(data).encode()
        return response

    def test_release_update_and_version_equivalence(self):
        self.assertEqual(version('v4.4'),version('4.4.0'))
        with patch('urllib.request.urlopen',return_value=self.response({'tag_name':'v4.5','html_url':'https://github.com/owner/repo/releases/tag/v4.5'})):
            self.assertTrue(check('owner/repo','4.4')['newer'])

    def test_actions_fallback_checks_successful_build_version(self):
        error=urllib.error.HTTPError('url',404,'Not found',None,None)
        responses=[error,self.response({'workflow_runs':[{'head_sha':'abc','html_url':'https://github.com/owner/repo/actions/runs/123'}]}),
                   self.response({'content':base64.b64encode(b'APP_VERSION = "4.5"').decode()})]
        with patch('urllib.request.urlopen',side_effect=responses) as request:
            result=check('owner/repo','4.4',token='TestOnly')
        self.assertTrue(result['newer'])
        self.assertIn('status=success',request.call_args_list[1].args[0].full_url)
        self.assertEqual(request.call_args_list[0].args[0].get_header('Authorization'),'Bearer TestOnly')

    def test_private_access_error_does_not_claim_latest(self):
        error=urllib.error.HTTPError('url',404,'Not found',None,None)
        with patch('urllib.request.urlopen',side_effect=error):result=check('owner/repo','4.4')
        self.assertIn('error',result);self.assertNotIn('newer',result)
        self.assertIn('приватного',result['error'])

    def test_token_is_protected_and_removable(self):
        save_token(self.tmp.name,'FakeTokenOnly123')
        raw=(Path(self.tmp.name)/'github_update_token.bin').read_bytes()
        self.assertNotIn(b'FakeTokenOnly123',raw)
        self.assertEqual(load_token(self.tmp.name),'FakeTokenOnly123')
        save_token(self.tmp.name,'');self.assertEqual(load_token(self.tmp.name),'')

    def test_language_changes_ui_text_only(self):
        localization.set_language('en')
        self.assertEqual(localization.tr('Ваши пароли'),'Your passwords')
        self.assertEqual(localization.tr('Пароли не совпадают'),'Passwords do not match')
        v=Vault(self.path);v.create('1234');v.add({'title':'Мой аккаунт','category':'Личные','password':'Secret!789'})
        self.assertEqual(v.active()[0]['title'],'Мой аккаунт')
        localization.set_language('ru')
        self.assertEqual(localization.tr('Ваши пароли'),'Ваши пароли')

    def test_extension_icon_files_exist_and_match_sizes(self):
        from PIL import Image
        root=Path(__file__).resolve().parents[1]/'browser_extension'
        manifest=json.loads((root/'manifest.json').read_text(encoding='utf8'))
        for size,path in manifest['icons'].items():
            with Image.open(root/path) as img:self.assertEqual(img.size,(int(size),int(size)))
        self.assertEqual(manifest['version'],'4.4.0')
