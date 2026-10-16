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
