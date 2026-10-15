import os
import tempfile
import unittest
from unittest.mock import patch
import tkinter as tk
from tkinter import ttk
from moi_paroli import Vault
from browser_host import select_record

class NativeConsentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env=patch.dict(os.environ,{"MOIPAROLI_DIR":self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        vault=Vault(os.path.join(self.tmp.name,"vault.dat"))
        vault.create("NativeConsentTest!789")
        for login in ("first","second"):
            vault.add({"title":login,"login":login,"url":"https://example.test",
                       "password":login+"Password!789"})
        self.real_tk=tk.Tk

    def run_dialog(self, mode):
        def factory():
            root=self.real_tk()
            def first():
                if mode=="cancel":
                    root.destroy()
                    return
                entries=[]
                def walk(widget):
                    for child in widget.winfo_children():
                        if isinstance(child,ttk.Entry): entries.append(child)
                        walk(child)
                walk(root)
                entries[0].insert(0,"Wrong" if mode=="wrong" else "NativeConsentTest!789")
                if mode=="wrong":root.after(300,root.destroy)
                root.after(150,choose)
                next(w for w in root.winfo_children() if isinstance(w,ttk.Button)).invoke()
            def choose():
                for child in root.winfo_children():
                    if isinstance(child,tk.Toplevel):
                        if mode=="cancel-selection":
                            child.destroy()
                            return
                        listing=next(w for w in child.winfo_children() if isinstance(w,tk.Listbox))
                        listing.selection_clear(0,"end")
                        listing.selection_set(1)
                        next(w for w in child.winfo_children() if isinstance(w,ttk.Button)).invoke()
            root.after(150,first)
            return root
        with patch("tkinter.Tk",side_effect=factory):
            return select_record("example.test")

    def test_cancel_returns_no_password(self):
        result=self.run_dialog("cancel")
        self.assertFalse(result["ok"])
        self.assertNotIn("password",result)

    def test_wrong_password_returns_no_secret(self):
        result=self.run_dialog("wrong")
        self.assertFalse(result["ok"])
        self.assertNotIn("password",result)

    def test_choose_second_account(self):
        result=self.run_dialog("choose")
        self.assertEqual(result["login"],"second")

    def test_cancel_selection_returns_no_secret(self):
        result=self.run_dialog("cancel-selection")
        self.assertFalse(result["ok"])
        self.assertNotIn("password",result)
