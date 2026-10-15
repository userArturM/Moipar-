import base64
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from PIL import Image
import moi_paroli as app
from browser_identity import EXTENSION_ID,HOST
from github_updates import check

ROOT=Path(__file__).resolve().parents[1]


class BitoraBrandTests(unittest.TestCase):
    def test_shell_identity_is_separate_and_failure_does_not_block_startup(self):
        from windows_branding import SHELL_APP_ID,set_shell_identity
        self.assertEqual(SHELL_APP_ID,'Bitora.Password')
        with patch('windows_branding.sys.platform','win32'),patch('ctypes.windll') as dll:
            setter=dll.shell32.SetCurrentProcessExplicitAppUserModelID
            setter.return_value=0
            self.assertTrue(set_shell_identity())
            setter.assert_called_once_with(SHELL_APP_ID)
            setter.side_effect=OSError('Unavailable')
            self.assertFalse(set_shell_identity())

    def test_windows_icon_has_all_sizes_and_matches_supplied_logo(self):
        with Image.open(ROOT/'icon.ico') as icon,Image.open(ROOT/'brand.png') as brand:
            self.assertTrue({(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)}.issubset(icon.ico.sizes()))
            self.assertEqual(icon.ico.getimage((256,256)).convert('RGBA').tobytes(),brand.convert('RGBA').tobytes())

    def test_name_and_stable_storage_browser_identity(self):
        self.assertEqual(app.APP_NAME,'Bitora Paswword Manager')
        self.assertEqual(HOST,'ru.moiparoli.host')
        self.assertEqual(EXTENSION_ID,'odddlefcmbmjphfnglidnmdpdlofmfgn')
        manifest=json.loads((ROOT/'browser_extension/manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['name'],'Bitora Paswword Manager')
        installer=(ROOT/'installer.iss').read_text(encoding='utf-8')
        self.assertIn('AppId={{B7E1C0A2-6D54-4C57-9A3E-5F2D1A9C7E31}',installer)
        self.assertIn('DefaultDirName={autopf}\\MoiParoli',installer)
        self.assertEqual(app.APP_ID,'MoiParoli')

    def test_logo_matches_embedded_asset_and_keeps_transparency(self):
        with Image.open(io.BytesIO(base64.b64decode(app.ICON_B64))) as embedded,Image.open(ROOT/'app_icon.png') as asset:
            self.assertEqual(embedded.convert('RGBA').tobytes(),asset.convert('RGBA').tobytes())
            self.assertEqual(embedded.getpixel((0,0))[3],0)
        for size in (16,32,48,128):
            with Image.open(ROOT/f'browser_extension/icon{size}.png') as icon:
                self.assertEqual(icon.size,(size,size))
                self.assertEqual(icon.mode,'RGBA')
                self.assertEqual(icon.getpixel((0,0))[3],0)

    def test_design_migration_is_once_and_preserves_paths_and_other_preferences(self):
        with tempfile.TemporaryDirectory() as folder:
            settings=app.Settings(str(Path(folder)/'settings.json'))
            settings.data.update(theme='light',vault_path='D:/existing/vault.dat',keyfile_path='',
                language='en',font_size=13,external_backup_dir='E:/backups',idle_minutes=9)
            self.assertTrue(settings.apply_midnight_design())
            loaded=app.Settings(settings.path)
            self.assertEqual(loaded.get('theme'),'dark')
            self.assertTrue(loaded.get('sidebar_collapsed'))
            for field in ('vault_path','keyfile_path','language','font_size','external_backup_dir','idle_minutes'):
                self.assertEqual(loaded.get(field),settings.get(field))
            loaded.set('theme','light')
            self.assertFalse(loaded.apply_midnight_design())
            self.assertEqual(loaded.get('theme'),'light')

    def test_atelier_migration_runs_once_and_preserves_existing_data_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            settings=app.Settings(str(Path(folder)/'settings.json'))
            settings.data.update(theme='light',design_version='midnight',sidebar_collapsed=True,
                                 vault_path='D:/existing/vault.dat',language='en')
            self.assertTrue(settings.apply_atelier_design())
            self.assertEqual(settings.get('design_version'),'midnight-atelier')
            self.assertFalse(settings.get('sidebar_collapsed'))
            self.assertEqual(settings.get('vault_path'),'D:/existing/vault.dat')
            self.assertEqual(settings.get('language'),'en')
            settings.set('theme','light')
            self.assertFalse(settings.apply_midnight_design())
            self.assertFalse(settings.apply_atelier_design())
            self.assertEqual(settings.get('theme'),'light')

    def test_update_prefers_new_name_and_accepts_legacy_name(self):
        for names,chosen in ((['MoiParoli-Setup.exe','Bitora-password-Setup.exe'],'Bitora-password-Setup.exe'),
                             (['MoiParoli-Setup.exe'],'MoiParoli-Setup.exe')):
            response={'tag_name':'v4.6.0','html_url':'https://github.com/owner/repo/releases/tag/v4.6.0',
                'assets':[{'name':name,'browser_download_url':'https://github.com/owner/repo/releases/download/v4.6.0/'+name,'digest':'sha256:'+'a'*64} for name in names]}
            with patch('urllib.request.urlopen') as open_url:
                open_url.return_value.__enter__.return_value.read.return_value=json.dumps(response).encode()
                self.assertTrue(check('owner/repo','4.5.5')['download_url'].endswith(chosen))
