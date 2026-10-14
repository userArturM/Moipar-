import os
import tempfile
import unittest
from unittest.mock import patch
import tkinter as tk
from tkinter import ttk
from moi_paroli import Vault
from browser_host import save_record

class NativeSaveConsentTests(unittest.TestCase):
    def run_save(self,mode):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,MOIPAROLI_DIR=folder):
            path=os.path.join(folder,'vault.dat')
            vault=Vault(path)
            vault.create('ConsentTest!789')
            real_tk=tk.Tk
            def factory():
                root=real_tk()
                def act():
                    if mode=='cancel':
                        root.destroy()
                        return
                    widgets=[]
                    def walk(parent):
                        for child in parent.winfo_children():
                            widgets.append(child)
                            walk(child)
                    walk(root)
                    entries=[w for w in widgets if isinstance(w,ttk.Entry)]
                    entries[1].insert(0,'Wrong' if mode=='wrong' else 'ConsentTest!789')
                    if mode=='wrong':root.after(300,root.destroy)
                    next(w for w in widgets if isinstance(w,ttk.Button) and
                         w.cget('text')=='Подтвердить и сохранить').invoke()
                root.after(150,act)
                return root
            with patch('tkinter.Tk',side_effect=factory):
                result=save_record('example.test',{'url':'https://example.test','login':'new',
                                   'password':'FakeSecret!789','title':'Example'})
            reopened=Vault(path)
            reopened.unlock('ConsentTest!789')
            return result,reopened.active()

    def test_confirm_saves_without_returning_password(self):
        result,records=self.run_save('confirm')
        self.assertTrue(result['ok'])
        self.assertNotIn('password',result)
        self.assertEqual(records[0]['password'],'FakeSecret!789')

    def test_cancel_leaves_vault_unchanged(self):
        result,records=self.run_save('cancel')
        self.assertFalse(result['ok'])
        self.assertEqual(records,[])

    def test_wrong_master_password_cannot_save(self):
        result,records=self.run_save('wrong')
        self.assertFalse(result['ok'])
        self.assertEqual(records,[])
