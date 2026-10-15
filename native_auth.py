"""Windows Hello approval for native browser dialogs; no secrets go to browser UI."""
import os
import queue
import threading

from localization import tr
from windows_hello import HelloUnlock, HelloUnavailable


def unlock_error(error):
    from moi_paroli import WrongPassword, KeyfileRequired, CorruptVault
    if isinstance(error, WrongPassword):
        return tr('Неверный мастер-пароль или ключевой файл. Проверьте раскладку и Caps Lock.')
    if isinstance(error, KeyfileRequired):
        return tr('Для этого хранилища нужен ключевой файл.')
    if isinstance(error, CorruptVault):
        return tr('Не удалось прочитать хранилище. Проверьте выбранный файл и резервные копии.')
    if isinstance(error, OSError):
        return tr('Нет доступа к файлу хранилища или ключевому файлу.')
    return tr(str(error)) if isinstance(error, HelloUnavailable) else tr('Не удалось выполнить действие. Повторите попытку.')


def hello_for_vault(path, folder):
    return HelloUnlock(path, os.path.join(folder, 'hello_credential.json'))


def request_hello(root, hello, approved, failed):
    """Run the OS ceremony off Tk's thread, then deliver only to a live dialog.

    retrieve_after_verification must never run before a successful verify.
    Closing the dialog invalidates the result, including a late OS approval.
    """
    from moi_paroli import win_hwnd
    hwnd = win_hwnd(root)
    results = queue.Queue()
    state = {'active': True}

    def cancel(event=None):
        if event is None or event.widget is root:
            state['active'] = False
            while not results.empty():
                try:
                    results.get_nowait()
                except queue.Empty:
                    break

    root.bind('<Destroy>', cancel, add='+')

    def work():
        try:
            if not hello.verify(hwnd):
                raise HelloUnavailable(tr('Подтверждение Windows Hello отменено'))
            if not state['active']:
                return
            password = hello.retrieve_after_verification()
            if state['active']:
                results.put((True, password))
            password = None
        except (HelloUnavailable, OSError, ValueError, KeyError) as error:
            if state['active']:
                results.put((False, unlock_error(error)))

    def poll():
        if not state['active']:
            return
        try:
            ok, value = results.get_nowait()
        except queue.Empty:
            root.after(50, poll)
            return
        state['active'] = False
        if ok:
            approved(value)
        else:
            failed(value)
        value = None

    root.after(50, poll)
    threading.Thread(target=work, daemon=True).start()
    return cancel
