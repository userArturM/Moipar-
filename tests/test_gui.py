import os
import tempfile
import unittest
from unittest.mock import patch
import moi_paroli as m

@unittest.skipIf(m.tk is None, "Tk unavailable")
class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {"MOIPAROLI_DIR": self.tmp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        with patch.object(m.App, "_start_services"), patch.object(m.App, "apply_capture"):
            self.app = m.App()
        self.addCleanup(self.cleanup_root)
        self.app.settings.set("lock_on_minimize",False)
        self.app.settings.set("lock_on_session_lock",False)
        self.app.vault.create("UITestPassword!789")
        self.app.show_main()
        self.app.root.update()

    def cleanup_root(self):
        for job in self.app.root.tk.call("after", "info"):
            self.app.root.after_cancel(job)
        self.app.root.destroy()

    def close_dialog(self):
        for w in self.app.root.winfo_children():
            if isinstance(w, m.tk.Toplevel):
                w.destroy()

    def test_dialogs_open(self):
        for cls in (m.GeneratorDialog, m.EntryDialog, m.SettingsDialog, m.AuditDialog):
            with self.subTest(dialog=cls.__name__):
                self.app.root.after(100, self.close_dialog)
                cls(self.app, self.app.root)

    def test_search_theme_and_lock(self):
        row = self.app.vault.add({"title": "Example", "login": "demo", "password": "Example!789"})
        self.app.refresh_all()
        self.app.search.set("Example")
        self.assertEqual(len(self.app.tree.get_children()), 1)
        self.app.tree.selection_set(row["id"])
        self.app.show_details()
        self.app.toggle_theme()
        self.assertEqual(len(self.app.tree.get_children()), 1)
        self.app.lock()
        self.assertFalse(self.app.vault.unlocked)

    def test_scaling_long_records_and_keyboard(self):
        row=self.app.vault.add({"title":"Очень длинное название сервиса "*8,
                                "login":"long-address@example.test","password":"FakePassword!789",
                                "note":"Длинная заметка "*80})
        for percent in (125,150,175,200):
            with self.subTest(scale=percent):
                self.app.root.tk.call("tk","scaling",percent/100*96/72)
                self.app.apply_theme()
                self.app.show_main()
                self.app.tree.selection_set(row["id"])
                self.app.show_details()
                self.app.root.update()
                self.assertGreater(self.app.tree.winfo_height(),0)
                self.app.root.event_generate("<Control-f>")
                self.app.root.update()
                self.app.search_entry.focus_force()
                self.app.search_entry.event_generate("<Tab>")
                self.app.root.update()
                self.assertTrue(self.app.root.focus_get() is not None)
