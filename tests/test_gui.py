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

    def test_language_switch_and_animation_finish(self):
        self.app.set_language('en')
        self.app.root.update()
        self.assertEqual(self.app.root.title(),'My Passwords')
        self.assertEqual(self.app.tree.heading('category')['text'],'Category')
        self.app.animate_entry()
        self.app.root.after(350,self.app.root.quit)
        self.app.root.mainloop()
        self.assertAlmostEqual(float(self.app.root.attributes('-alpha')),1.0)
        self.assertIsNone(self.app._animation_id)
        self.app.settings.set('animations',False)
        self.app.animate_entry()
        self.assertIsNone(self.app._animation_id)
        self.app.set_language('ru')
        self.assertEqual(self.app.tree.heading('category')['text'],'Категория')

    def test_new_feature_dialogs_and_collapsible_sidebar(self):
        import feature_dialogs
        self.app.toggle_sidebar()
        self.assertTrue(self.app._sidebar_hidden)
        self.app.toggle_sidebar()
        self.assertFalse(self.app._sidebar_hidden)
        for open_dialog in (feature_dialogs.categories,feature_dialogs.backups):
            open_dialog(self.app)
            self.app.root.update()
            self.close_dialog()
        feature_dialogs.updates(self.app,{'version':'4.6','url':'https://github.com/userArturM/Moipar-/releases/tag/v4.6','notes':'Test only'})
        self.app.root.update();self.close_dialog()
        self.app.notify('Test notification')
        self.assertTrue(self.app._notification.winfo_exists())

    def test_font_size_multi_selection_search_and_session_lock(self):
        first=self.app.vault.add({'title':'GitHub Work','login':'alice','password':'Strong!789'})
        second=self.app.vault.add({'title':'Other','login':'bob','password':'OtherStrong!789'})
        self.app.settings.set('font_size',14);self.app.apply_theme();self.app.show_main()
        self.assertEqual(str(self.app.tree.cget('selectmode')),'extended')
        self.app.tree.selection_set([first['id'],second['id']])
        self.assertEqual(len(self.app.tree.selection()),2)
        self.app.search.set('github alice')
        self.assertEqual(self.app.tree.get_children(),(first['id'],))
        self.app.settings.set('lock_on_session_lock',True)
        with patch('moi_paroli.win_session_locked',return_value=True):self.app._watch_tick()
        self.assertFalse(self.app.vault.unlocked)

    def test_late_hello_success_cannot_unlock_a_new_locked_session(self):
        self.app.lock()
        error=m.ttk.Label(self.app.root)
        jobs=[]
        class DelayedThread:
            def __init__(self,target,**kwargs):jobs.append(target)
            def start(self):pass
        with patch('moi_paroli.threading.Thread',DelayedThread),patch.object(self.app.hello,'verify',return_value=True),patch.object(self.app.hello,'retrieve_after_verification',return_value='UITestPassword!789'):
            self.app.hello_login(error)
            self.app.lock()
            jobs[0]()
            while not self.app._q.empty():self.app._q.get_nowait()()
        self.assertFalse(self.app.vault.unlocked)

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
