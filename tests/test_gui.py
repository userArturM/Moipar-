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

    def test_midnight_messages_cancel_and_input_and_lock_close(self):
        from midnight_dialogs import messagebox,simpledialog
        def choose(label):
            def visit(widget):
                for child in widget.winfo_children():
                    if isinstance(child,m.DesignButton) and child.cget('text')==label:child.invoke();return True
                    if visit(child):return True
                return False
            self.assertTrue(visit(self.app.root))
        self.app.root.after(80,lambda:choose('Нет'))
        self.assertFalse(messagebox.askyesno('Test','Synthetic confirmation',parent=self.app.root))
        self.app.root.after(80,lambda:choose('Продолжить'))
        self.assertEqual(simpledialog.askstring('Test','Synthetic input',initialvalue='Fake',parent=self.app.root),'Fake')
        self.app.settings.set('lock_on_session_lock',True)
        self.app.root.after(80,lambda:self.app._session_event('session'))
        self.assertIsNone(simpledialog.askstring('Test','Synthetic input',parent=self.app.root))
        self.assertFalse(self.app.vault.unlocked)

    def test_drag_preserves_selection_and_drop_can_be_undone(self):
        from types import SimpleNamespace
        from product_features import category_change
        for name in ('Personal','Work'):category_change(self.app.vault,name)
        ids=[self.app.vault.add({'title':title,'category':'Work','password':'FakeOnly!789'})['id'] for title in ('First','Second')]
        self.app.refresh_all();self.app.root.update()
        self.app.tree.selection_set(ids);view=self.app.record_view
        event=SimpleNamespace(y=10,x_root=view.winfo_rootx()+20,y_root=view.winfo_rooty()+10,state=0)
        view.press(event)
        self.assertEqual(set(self.app.tree.selection()),set(ids))
        with patch.object(self.app,'_drop_target',return_value='Personal'):
            self.app._drop_records(ids,event.x_root,event.y_root)
        self.assertTrue(all(self.app.vault.get(item)['category']=='Personal' for item in ids))
        self.app.undo_action()
        self.assertTrue(all(self.app.vault.get(item)['category']=='Work' for item in ids))
        self.app.reorder_category('Work',-1)
        self.assertEqual(self.app.vault.categories(),['Work','Personal'])
        self.app.undo_action();self.assertEqual(self.app.vault.categories(),['Personal','Work'])
        self.app.move_to_category(ids,'Personal')
        self.app.vault.update(ids[0],{'note':'A newer edit'})
        with patch.object(m.messagebox,'showwarning') as warning:
            self.app.undo_action()
        warning.assert_called_once()
        self.assertEqual(self.app.vault.get(ids[0])['note'],'A newer edit')

    def test_idle_uses_monotonic_clock_and_resume_gap_locks(self):
        self.app.last_activity=10
        self.app.settings.set('idle_minutes',1)
        with patch('moi_paroli.time.monotonic',return_value=71):self.app._idle_tick()
        self.assertFalse(self.app.vault.unlocked)
        self.app.vault.unlock('UITestPassword!789');self.app.show_main()
        self.app._watch_clock=(100,100)
        with patch('moi_paroli.time.monotonic',return_value=102),patch('moi_paroli.time.time',return_value=200):self.app._watch_tick()
        self.assertFalse(self.app.vault.unlocked)

    def test_midnight_navigation_and_category_picker(self):
        self.assertEqual(self.app.root.title(),'Bitora Paswword Manager')
        self.assertEqual(self.app.theme_name,'dark')
        self.assertTrue(self.app._sidebar_hidden)
        self.assertEqual(tuple(self.app.tree.cget('displaycolumns')),('fav','title','login'))
        row=self.app.vault.add({'title':'Work item','category':'Work','password':'FakeOnly!789'})
        self.app.vault.add({'title':'Other item','category':'Personal','password':'OtherFake!789'})
        self.app.refresh_all();self.app.set_library_filter('cat:Work')
        self.assertEqual(self.app.tree.get_children(),(row['id'],))
        self.assertIn('Work',self.app.library_filter.get())
        self.app.set_library_filter('all')
        self.assertEqual(len(self.app.tree.get_children()),2)
        self.app.root.update()
        self.assertLess(self.app.rail.winfo_width(),self.app.root.winfo_width()/4)

    def test_designed_record_list_selection_keyboard_and_virtualization(self):
        from types import SimpleNamespace
        for index in range(1000):
            self.app.vault.entries.append(m.normalize({'title':f'Entry {index:04d}',
                'login':'fake@example.test','password':'NeverDrawThis!789'}))
        self.app.refresh_all();self.app.root.update()
        view=self.app.record_view
        self.assertFalse(self.app.tree.winfo_ismapped())
        self.assertTrue(view.winfo_ismapped())
        self.assertLess(len(view.drawn),40)
        view.select_at(SimpleNamespace(y=10,state=0))
        first=self.app.tree.selection()[0]
        view.select_at(SimpleNamespace(y=view.row_height+10,state=4))
        self.assertEqual(len(self.app.tree.selection()),2)
        view.move('last');self.app.root.update()
        self.assertEqual(self.app.tree.selection(),(view.ids[-1],))
        self.assertIn(view.ids[-1],view.drawn)
        text=' '.join(view.itemcget(item,'text') for item in view.find_all() if view.type(item)=='text')
        self.assertNotIn('NeverDrawThis',text)
        self.assertEqual(self.app.tree.identify_row(10),view.ids[view.index_at(10)])
        self.app.goto_entry(first);self.app.root.update()
        self.assertIn(first,view.drawn)
        self.app.toggle_filters();self.app.root.update()
        self.assertTrue(self.app.filter_bar.winfo_ismapped())
        self.app.toggle_filters();self.assertFalse(self.app.filter_bar.winfo_manager())

    def test_multi_selection_survives_sort_and_context_menu_and_keyboard_range(self):
        from types import SimpleNamespace
        for title in ('Alpha','Beta','Gamma','Delta'):
            self.app.vault.add({'title':title,'password':'FakeOnly!789'})
        self.app.refresh_all();self.app.root.update()
        view=self.app.record_view
        view.move('first');view.move(1,extend=True)
        chosen=set(self.app.tree.selection())
        self.assertEqual(len(chosen),2)
        view.move(-1,extend=True)
        self.assertEqual(len(self.app.tree.selection()),1)
        view.move(1,extend=True)
        with patch.object(self.app.ctx,'tk_popup'):
            self.app.context_menu(SimpleNamespace(y=10,x_root=0,y_root=0))
        self.assertEqual(set(self.app.tree.selection()),chosen)
        self.app.sort_by('title')
        self.assertEqual(set(self.app.tree.selection()),chosen)
        view.select_all();self.assertEqual(len(self.app.tree.selection()),4)

    def test_recovery_dialogs_and_duplicate_choices_open_in_both_languages(self):
        import feature_dialogs
        for title in ('First','Second'):
            self.app.vault.add({'title':title,'url':'https://example.test','login':'fake-user','password':'FakeOnly!789','category':'Work'})
        for language in ('ru','en'):
            self.app.set_language(language)
            for show in (feature_dialogs.duplicates,feature_dialogs.category_trash,
                         lambda app:feature_dialogs.delete_category(app,'Work')):
                show(self.app);self.app.root.update()
                windows=[w for w in self.app.root.winfo_children() if isinstance(w,m.tk.Toplevel)]
                self.assertTrue(windows)
                self.assertGreater(windows[-1].winfo_height(),100)
                if show is feature_dialogs.duplicates:
                    def descendants(widget):
                        for child in widget.winfo_children():
                            yield child
                            yield from descendants(child)
                    listing=next(w for w in descendants(windows[-1]) if isinstance(w,m.ttk.Treeview))
                    listing.selection_set('0');listing.event_generate('<<TreeviewSelect>>');self.app.root.update()
                    choices=[w for w in descendants(windows[-1]) if isinstance(w,m.ttk.Combobox)]
                    self.assertEqual(len(choices),9)
                    self.assertTrue(all('FakeOnly' not in w.get() for w in choices))
                self.close_dialog()
        self.app.set_language('ru')

    def test_backup_preview_and_browser_diagnostics_open(self):
        import feature_dialogs
        with patch.object(feature_dialogs.filedialog,'askopenfilename',return_value=self.app.vault.path),\
             patch.object(feature_dialogs.simpledialog,'askstring',return_value='UITestPassword!789'):
            feature_dialogs.backup_preview(self.app)
            self.app.root.update();self.close_dialog()
        with patch('browser_registration.diagnose',return_value=[]),\
             patch('browser_registration.probe_host',return_value={'version':m.APP_VERSION,'save':True,'fill':True}):
            self.app.root.after(150,self.close_dialog)
            m.BrowserDialog(self.app,self.app.root)

    def test_language_switch_and_animation_finish(self):
        self.app.set_language('en')
        self.app.root.update()
        self.assertEqual(self.app.root.title(),'Bitora Paswword Manager')
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

    def test_login_card_scrolls_at_large_scales_in_both_languages(self):
        self.app.lock()
        original=self.app.vault.path
        for new in (False,True):
            self.app.vault.path=os.path.join(self.tmp.name,'missing.dat') if new else original
            for language in ('ru','en'):
                self.app.set_language(language)
                for scale in (125,150,175,200):
                    with self.subTest(new=new,language=language,scale=scale):
                        self.app.root.tk.call('tk','scaling',scale/100*96/72)
                        self.app.apply_theme();self.app.show_login();self.app.root.update()
                        card=self.app.login_card;canvas=card.scroll_canvas
                        self.assertGreater(canvas.winfo_height(),100)
                        self.assertGreaterEqual(card.winfo_y(),0)
                        extent=list(map(float,canvas.cget('scrollregion').split()))
                        self.assertGreaterEqual(extent[3],card.winfo_reqheight())
                        buttons=[w for w in card.winfo_children() if isinstance(w,(m.ttk.Button,m.DesignButton))]
                        last=buttons[-1]
                        last.event_generate('<FocusIn>');self.app.root.update()
                        top=last.winfo_rooty()-canvas.winfo_rooty()
                        self.assertGreaterEqual(top,0)
                        self.assertLessEqual(top+last.winfo_height(),canvas.winfo_height()+2)
        self.app.vault.path=original
        self.app.set_language('ru')

    def test_new_feature_dialogs_and_collapsible_sidebar(self):
        import feature_dialogs
        before=self.app._sidebar_hidden
        self.app.toggle_sidebar()
        self.assertNotEqual(self.app._sidebar_hidden,before)
        self.app.toggle_sidebar()
        self.assertEqual(self.app._sidebar_hidden,before)
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
