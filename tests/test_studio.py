import hashlib
import re
import unittest
from unittest.mock import patch
import moi_paroli as m
from tests import test_gui
import studio_ui
from site_policy import normalize_sites


class StudioTests(unittest.TestCase):
    setUp=test_gui.DesktopTests.setUp
    cleanup_root=test_gui.DesktopTests.cleanup_root

    def test_fast_navigation_cancels_old_transition_and_respects_motion_setting(self):
        studio=self.app.studio
        self.app.navigate_workspace('audit');old=studio.transition_job
        self.assertIsNotNone(old)
        self.app.navigate_workspace('home')
        self.assertNotIn(old,self.app.root.tk.call('after','info'))
        self.app.settings.set('animations',False)
        self.app.navigate_workspace('settings');self.assertIsNone(studio.transition_job)

    def test_pearl_migration_preserves_data_paths_and_later_theme_choice(self):
        original={key:self.app.settings.get(key) for key in ('vault_path','keyfile_path','language','idle_minutes','clipboard_seconds')}
        self.app.settings.data['design_version']='studio'
        self.assertTrue(self.app.settings.apply_pearl_design())
        self.assertEqual(self.app.settings.get('theme'),'light')
        for key,value in original.items():self.assertEqual(self.app.settings.get(key),value)
        self.app.settings.set('theme','dark')
        for migrate in (self.app.settings.apply_midnight_design,self.app.settings.apply_atelier_design,self.app.settings.apply_mint_design,self.app.settings.apply_studio_design,self.app.settings.apply_pearl_design):
            self.assertFalse(migrate())
        self.assertEqual(self.app.settings.get('theme'),'dark')

    def test_card_hover_timer_is_cancelled_when_collection_is_rebuilt(self):
        self.app.vault.add(dict(title='Synthetic hover',login='fake@example.test'))
        self.app.refresh_all();self.app.studio.set_layout('cards');self.app.root.update()
        tile=self.app.studio.cards.tiles[0]
        tile.hover(True);self.assertIsNotNone(tile.motion_job)
        self.app.studio.cards.refresh();self.app.root.update()
        self.assertIsNone(tile.motion_job)

    def test_compact_navigation_fits_and_short_sidebar_does_not_overscroll(self):
        for percent in (100,200):
            self.app.root.tk.call('tk','scaling',percent/100*96/72)
            self.app.root.geometry('1440x900');self.app.apply_theme();self.app.show_main();self.app.root.update()
            rail=self.app.rail_scroll
            for item in self.app.rail_buttons.values():
                self.assertLessEqual(item.winfo_y()+item.winfo_height(),rail.canvas.winfo_height()+2)
            if rail.content.winfo_reqheight()<=rail.canvas.winfo_height():
                rail.canvas.event_generate('<MouseWheel>',delta=-120);self.app.root.update()
                self.assertEqual(rail.canvas.yview()[0],0)

    def test_background_motion_respects_setting_and_destroy(self):
        effect=self.app.ambient_band._ambient
        self.app.root.update();effect.resume()
        self.assertIsNotNone(effect.job)
        effect.pause();self.assertIsNone(effect.job)
        self.app.settings.set('animations',False);effect.resume()
        self.assertIsNone(effect.job)
        self.app.ambient_band.destroy();self.assertIsNone(effect.job)

    def test_separate_command_window_reuses_commands_and_closes_after_lock(self):
        from command_window import open_commands
        self.app.navigate_workspace('settings')
        top=open_commands(self.app);self.app.root.update()
        self.assertIs(open_commands(self.app),top)
        found=[]
        def visit(widget):
            for child in widget.winfo_children():
                if isinstance(child,m.DesignButton) and child.cget('text')==m.tr('Заблокировать'):found.append(child)
                visit(child)
        visit(top)
        self.assertEqual(len(found),1)
        found[0].invoke();self.app.root.update()
        self.assertFalse(self.app.vault.unlocked)
        self.assertFalse(top.winfo_exists())

    def test_accounts_navigation_contains_websites_and_apps_only(self):
        expected=[]
        for kind in ('website','application','note','card'):
            row=self.app.vault.add(dict(title=kind,kind=kind,login='synthetic@example.test'))
            if kind in ('website','application'):expected.append(row['id'])
        self.app.navigate_workspace('accounts');self.app.root.update()
        self.assertEqual(set(self.app.tree.get_children()),set(expected))
        self.assertEqual(self.app.atelier_title.cget('text'),m.tr('Аккаунты'))

    def test_cards_list_audit_and_preferences_share_real_navigation(self):
        row=self.app.vault.add(dict(title='Fixture',login='fake@example.test',url='https://example.test',password='SyntheticOnly!2026'))
        self.app.refresh_all();self.app.studio.set_layout('cards');self.app.root.update()
        self.assertTrue(self.app.studio.cards.winfo_ismapped())
        self.assertEqual(self.app.studio.cards.ids,[row['id']])
        self.app.studio.cards.open(row['id']);self.app.root.update()
        self.assertTrue((self.app.detail_panel if self.app.compact else self.app.record_view).winfo_ismapped())
        self.assertEqual(self.app.selected()['id'],row['id'])
        self.app.navigate_workspace('audit');self.app.root.update()
        self.assertTrue(self.app.studio.audit.winfo_ismapped())
        self.app.navigate_workspace('settings');self.app.root.update()
        self.assertTrue(self.app.studio.preferences.winfo_ismapped())

    def test_breach_results_are_current_session_and_password_bound(self):
        row=self.app.vault.add(dict(title='Fixture',password='SyntheticOnly!2026'))
        _,groups=studio_ui.password_groups(self.app)
        self.assertEqual(len(groups['unchecked']),1)
        self.assertEqual(len(groups['strong']),0)
        studio_ui.remember_breaches(self.app,{'SyntheticOnly!2026':0})
        self.assertEqual(len(studio_ui.password_groups(self.app)[1]['strong']),1)
        self.app.vault.update(row['id'],dict(password='DifferentOnly!2026'))
        self.assertEqual(len(studio_ui.password_groups(self.app)[1]['unchecked']),1)
        self.app.lock();self.assertEqual(self.app._breach_results,{})

    def test_english_preferences_and_audit_have_no_untranslated_labels(self):
        self.app.set_language('en');self.app.navigate_workspace('settings');self.app.root.update()
        labels=[]
        def collect(widget):
            try:labels.append(str(widget.cget('text')))
            except (m.tk.TclError,TypeError):pass
            if isinstance(widget,m.tk.Canvas):
                for item in widget.find_all():
                    if widget.type(item)=='text':labels.append(widget.itemcget(item,'text'))
            for child in widget.winfo_children():collect(child)
        preferences=self.app.studio.preferences
        for page in preferences.PAGES:
            preferences.show(page);self.app.root.update();collect(preferences)
        self.app.navigate_workspace('audit');self.app.root.update();collect(self.app.studio.audit)
        # A configured filesystem path is user data and is intentionally not translated.
        self.assertEqual([value for value in labels if re.search('[А-Яа-яЁё]',value)],[])

    def test_excluded_host_is_enforced_by_native_save_and_fill(self):
        import browser_host
        self.app.settings.set('ignored_sites',['example.test'])
        with patch('browser_host.select_record') as select:
            result=browser_host.handle(dict(action='get_credentials',url='https://example.test'),selector=select)
            self.assertFalse(result['ok']);select.assert_not_called()
        self.assertEqual(normalize_sites(['https://EXAMPLE.test/login','example.test']),['example.test'])
        with self.assertRaises(ValueError):normalize_sites(['https://user:secret@example.test'])

    def test_authenticator_cards_copy_full_current_code(self):
        self.app.vault.add(dict(title='TOTP fixture',totp='JBSWY3DPEHPK3PXP'))
        self.app.studio.set_layout('cards');self.app.navigate_workspace('auth');self.app.root.update()
        called=[]
        self.app.copy_text=lambda value,label:called.append(value)
        def visit(widget):
            for child in widget.winfo_children():
                if isinstance(child,m.DesignButton) and child.cget('text')==m.tr('Копировать код'):child.invoke();return True
                if visit(child):return True
            return False
        self.assertTrue(visit(self.app.studio.cards))
        self.assertRegex(called[0],r'^\d{6}$')

    def test_custom_symbol_alphabet(self):
        value=m.generate_password(32,lower=False,upper=False,digits=False,symbols=True,ambiguous=True,symbol_chars='+-')
        self.assertEqual(len(value),32);self.assertLessEqual(set(value),set('+-'))
        with self.assertRaises(ValueError):m.generate_password(symbol_chars='\n')
