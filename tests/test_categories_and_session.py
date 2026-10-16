import os
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from moi_paroli import Vault,App
from product_features import category_change,move_records,reorder_categories,undo_change,trash_records
from session_guard import SessionGuard,event_reason,idle_seconds


class CategoryActionsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.vault=Vault(str(Path(self.temp.name)/'vault.dat'));self.vault.create('SyntheticOnly!789')
        category_change(self.vault,'Work');category_change(self.vault,'Personal')
        self.entry=self.vault.add({'title':'Example','category':'Work','password':'Fake!789'})

    def test_order_persists_syncs_and_can_be_undone(self):
        other=Vault(self.vault.path);other.unlock('SyntheticOnly!789')
        change=reorder_categories(self.vault,['Work','Personal'])
        other.sync_from_disk(write=False)
        self.assertEqual(other.categories(),['Work','Personal'])
        other.add({'title':'Other','category':'Work','password':'FakeOther!789'})
        self.vault.sync_from_disk(write=False)
        self.assertEqual(self.vault.categories(),['Work','Personal'])
        undo_change(self.vault,change)
        self.assertEqual(self.vault.categories(),['Personal','Work'])

    def test_move_and_undo_preserve_fields_and_refuse_stale_undo(self):
        change=move_records(self.vault,[self.entry['id']],'Personal')
        self.assertEqual(self.vault.get(self.entry['id'])['category'],'Personal')
        self.assertNotIn('password',str(change))
        undo_change(self.vault,change)
        self.assertEqual(self.vault.get(self.entry['id'])['category'],'Work')
        change=move_records(self.vault,[self.entry['id']],'Personal')
        self.vault.update(self.entry['id'],{'note':'Later edit'})
        with self.assertRaises(ValueError):undo_change(self.vault,change)
        self.assertEqual(self.vault.get(self.entry['id'])['note'],'Later edit')
        self.assertEqual(self.vault.get(self.entry['id'])['category'],'Personal')

    def test_multi_delete_undo_and_cancelled_invalid_move(self):
        second=self.vault.add({'title':'Second','password':'FakeOnly!789'})
        change=trash_records(self.vault,[self.entry['id'],second['id']])
        self.assertEqual(len(self.vault.trash()),2)
        undo_change(self.vault,change);self.assertEqual(len(self.vault.active()),2)
        with self.assertRaises(ValueError):move_records(self.vault,[self.entry['id'],'missing'],'Personal')
        self.assertEqual(self.vault.get(self.entry['id'])['category'],'Work')


class SessionTests(unittest.TestCase):
    def test_invalid_idle_preferences_keep_a_safe_timer(self):
        self.assertEqual(idle_seconds('invalid'),300)
        self.assertEqual(idle_seconds(None),300)
        self.assertEqual(idle_seconds(0),float('inf'))
        self.assertEqual(idle_seconds(99999),86400)

    def test_event_reasons_and_unrelated_notifications(self):
        for value in (2,4,6,7,11):self.assertEqual(event_reason(0x2B1,value),'session')
        for value in (4,6,7,18):self.assertEqual(event_reason(0x218,value),'suspend')
        self.assertIsNone(event_reason(0x218,10))
        self.assertIsNone(event_reason(0x2B1,8))

    def test_event_settings_and_repeated_event_do_not_unlock(self):
        app=types.SimpleNamespace(vault=Mock(unlocked=True),settings={'lock_on_suspend':True,'lock_on_session_lock':True},lock=Mock())
        App._session_event(app,'session');app.lock.assert_called_once()
        app.lock.reset_mock();app.settings['lock_on_suspend']=False
        App._session_event(app,'suspend');app.lock.assert_not_called()
        app.vault.unlocked=False;App._session_event(app,'session');app.lock.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows only')
    def test_native_listener_starts_and_stops_without_changing_session(self):
        import ctypes,threading
        from ctypes import wintypes
        received=threading.Event();reasons=[]
        def callback(reason):reasons.append(reason);received.set()
        guard=SessionGuard(callback);guard.start()
        self.addCleanup(guard.stop)
        self.assertTrue(guard.ready.wait(5))
        self.assertIsNotNone(guard.hwnd)
        post=ctypes.windll.user32.PostMessageW
        post.argtypes=[wintypes.HWND,wintypes.UINT,wintypes.WPARAM,wintypes.LPARAM]
        post(guard.hwnd,0x2B1,7,0)
        self.assertTrue(received.wait(3));self.assertIn('session',reasons)
        guard.stop();guard.thread.join(5)
        self.assertFalse(guard.thread.is_alive())
