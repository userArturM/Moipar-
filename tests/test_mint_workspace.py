import copy
import unittest
from unittest.mock import patch
import moi_paroli as m
from reference_ui import entry_kind, overview, KINDS
from tests import test_gui


class RecordTypes(unittest.TestCase):
    def test_legacy_classification_does_not_rewrite_records(self):
        entries=[{'url':'https://example.test','password':'fake'}, {'login':'demo'}, {'note':'text'}]
        before=copy.deepcopy(entries)
        self.assertEqual([entry_kind(e) for e in entries],['website','application','note'])
        self.assertEqual(entries,before)

    def test_overview_excludes_trash_and_counts_passwords_only(self):
        rows=[m.normalize(dict(title='Login',url='https://example.test',password='a',favorite=True)),
              m.normalize(dict(title='Card',kind='card')),m.normalize(dict(title='Trash',password='a',deleted='2026-10-15'))]
        result=overview(rows,m.strength)
        self.assertEqual(result['total'],1)
        self.assertEqual(result['counts']['card'],1)
        self.assertEqual(result['weak'],1)
        self.assertEqual(result['reused'],0)
        self.assertEqual([e['title'] for e in result['favorites']],['Login'])

    def test_typed_csv_roundtrip_keeps_secret_fields_and_notes(self):
        row=m.normalize(dict(title='Synthetic card',kind='card',note='Fake note',
            fields=[dict(name='CVV',value='000',secret=True)]))
        _,rows,skipped=m.parse_csv(m.export_csv_text([row]).encode('utf8'))
        self.assertEqual(skipped,0)
        self.assertEqual(rows[0]['kind'],'card')
        self.assertEqual(rows[0]['fields'],row['fields'])
        self.assertEqual(rows[0]['note'],'Fake note')


class MintDesktop(unittest.TestCase):
    setUp=test_gui.DesktopTests.setUp
    cleanup_root=test_gui.DesktopTests.cleanup_root

    def test_button_motion_finishes_and_destroy_cancels_callbacks(self):
        button=self.app.rail_buttons['home']
        button._hover(True)
        self.assertIsNotNone(button._fade_id)
        done=m.tk.BooleanVar(value=False)
        self.app.root.after(180,lambda:done.set(True))
        self.app.root.wait_variable(done)
        self.assertIsNone(button._fade_id)
        self.assertEqual(button._paint_fill,button._surface_fill())
        button._hover(False)
        button.destroy()
        self.assertIsNone(button._fade_id)

    def test_disabled_motion_keeps_actions_instant_and_disabled_button_inert(self):
        self.app.settings.set('animations',False)
        called=[]
        button=m.DesignButton(self.app.root,'Example',lambda:called.append(True),self.app.t)
        button._hover(True);button.invoke()
        self.assertEqual(called,[True])
        self.assertIsNone(button._fade_id)
        self.assertIsNone(button._release_id)
        button.configure(state='disabled');button.invoke()
        self.assertEqual(called,[True])
        button.destroy()

    def test_home_navigation_search_and_type_filters(self):
        for key in KINDS:self.app.vault.add(dict(title='Synthetic '+key,kind=key))
        self.app.refresh_all();self.app.navigate_workspace('home');self.app.root.update()
        self.assertTrue(self.app.home_active)
        self.assertTrue(self.app.home_view.winfo_ismapped())
        self.assertFalse(self.app.record_view.winfo_ismapped())
        for key in KINDS:
            self.app.navigate_workspace('type:'+key)
            self.assertEqual(len(self.app.tree.get_children()),1)
            self.assertEqual(self.app.selected(),None)
            entry=self.app.vault.get(self.app.tree.get_children()[0])
            self.assertEqual(entry['kind'],key)
        self.app.navigate_workspace('home');self.app.search.set('Synthetic card')
        self.assertFalse(self.app.home_active)
        self.assertEqual(len(self.app.tree.get_children()),1)

    def test_type_survives_edit_reopen_and_nonpasswords_do_not_fail_audit(self):
        row=self.app.vault.add(dict(title='Synthetic',kind='document'))
        self.app.vault.update(row['id'],dict(kind='note',note='Fake'))
        self.assertEqual(self.app.vault.audit(),[])
        self.app.vault.lock();self.app.vault.unlock('UITestPassword!789')
        self.assertEqual(self.app.vault.get(row['id'])['kind'],'note')

    def test_home_scrolling_scales_and_navigation_remain_available(self):
        for scale in (125,150,175,200):
            self.app.root.tk.call('tk','scaling',scale/100*96/72)
            self.app.apply_theme();self.app.show_main();self.app.root.update()
            self.assertTrue(self.app.home_view.winfo_ismapped())
            self.assertGreater(self.app.home_scroll.canvas.winfo_height(),100)
            self.assertGreater(self.app.rail_scroll.canvas.winfo_height(),100)
            self.app.navigate_workspace('type:card');self.app.root.update()
            self.assertTrue(self.app.record_view.winfo_ismapped())

    def test_card_dialog_applies_secret_template_and_saves_type(self):
        def save():
            for top in self.app.root.winfo_children():
                if isinstance(top,m.tk.Toplevel):
                    def visit(w):
                        for child in w.winfo_children():
                            if isinstance(child,m.tk.Entry) or isinstance(child,m.ttk.Entry):
                                if not child.cget('show') and child.winfo_class()=='TEntry':
                                    child.insert(0,'Synthetic');return True
                            if visit(child):return True
                    visit(top)
                    def click(w):
                        for child in w.winfo_children():
                            if isinstance(child,m.DesignButton) and child.cget('text')=='Сохранить':child.invoke();return True
                            if click(child):return True
                    click(top)
        self.app._new_entry_kind='card'
        self.app.root.after(100,save)
        dialog=m.EntryDialog(self.app,self.app.root)
        self.assertEqual(dialog.result['kind'],'card')

