import types
import unittest
from unittest.mock import Mock, patch

from native_auth import request_hello, unlock_error
from moi_paroli import App, WrongPassword, CorruptVault, KeyfileRequired


class FakeRoot:
    def __init__(self):
        self.jobs=[]
        self.destroyed=None

    def bind(self, name, callback, **kwargs):
        self.destroyed=callback

    def after(self, ms, callback):
        self.jobs.append(callback)

    def poll(self):
        self.jobs.pop(0)()


class NativeAuthTests(unittest.TestCase):
    def test_late_hello_cannot_change_master_in_a_new_session(self):
        app=types.SimpleNamespace(vault=Mock(unlocked=True,uses_keyfile=False),hello=Mock(),
                                  root=object(),_auth_epoch=1,_choose_new_master=Mock())
        app.hello.enabled.return_value=True
        callbacks=[]
        with patch('native_auth.request_hello',side_effect=lambda root,hello,approved,failed:callbacks.append(approved)):
            App.change_master_hello(app)
        app._auth_epoch=2
        callbacks[0]('SyntheticOnly')
        app._choose_new_master.assert_not_called()

    def test_lock_during_new_password_prompts_prevents_save(self):
        app=types.SimpleNamespace(vault=Mock(unlocked=True),root=object(),_auth_epoch=1,_do=Mock())
        def ask(*args,**kwargs):
            app._auth_epoch+=1
            return 'SyntheticOnly!789'
        with patch('moi_paroli.simpledialog.askstring',side_effect=ask):App._choose_new_master(app)
        app._do.assert_not_called()

    def run_approval(self, verified=True, close_during_verify=False, close_after_verify=False):
        root=FakeRoot()
        approved,failed=Mock(),Mock()
        def verify(hwnd):
            if close_during_verify:root.destroyed(types.SimpleNamespace(widget=root))
            return verified
        hello=Mock()
        hello.verify.side_effect=verify
        hello.retrieve_after_verification.return_value='SyntheticTestOnly'
        class ImmediateThread:
            def __init__(self,target,**kwargs):self.target=target
            def start(self):self.target()
        with patch('native_auth.threading.Thread',ImmediateThread),patch('moi_paroli.win_hwnd',return_value=123):
            cancel=request_hello(root,hello,approved,failed)
            if close_after_verify:cancel()
            root.poll()
        return hello,approved,failed

    def test_cancel_never_retrieves_cached_password(self):
        hello,approved,failed=self.run_approval(False)
        hello.retrieve_after_verification.assert_not_called()
        approved.assert_not_called()
        failed.assert_called_once()

    def test_success_requires_verified_os_approval(self):
        hello,approved,failed=self.run_approval()
        hello.verify.assert_called_once_with(123)
        approved.assert_called_once_with('SyntheticTestOnly')
        failed.assert_not_called()

    def test_closing_dialog_during_os_approval_discards_result(self):
        hello,approved,failed=self.run_approval(close_during_verify=True)
        hello.retrieve_after_verification.assert_not_called()
        approved.assert_not_called()

    def test_late_queued_password_is_discarded_after_close(self):
        hello,approved,failed=self.run_approval(close_after_verify=True)
        approved.assert_not_called()

    def test_error_messages_distinguish_auth_file_and_key_failures(self):
        self.assertIn('мастер-пароль',unlock_error(WrongPassword()))
        self.assertIn('ключевой файл',unlock_error(KeyfileRequired()))
        self.assertIn('прочитать',unlock_error(CorruptVault('invalid')))
        self.assertIn('доступа',unlock_error(OSError()))
