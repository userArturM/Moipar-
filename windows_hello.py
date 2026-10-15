"""Optional convenience unlock, requiring Windows Hello verification + per-user DPAPI.

IMPORTANT: DPAPI is scoped to the Windows login, not cryptographically bound to the
Windows Hello gesture. Malware running as that same user can potentially access the
DPAPI-protected credential. Do not treat this as hardware-bound key protection.
"""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import sys
import tempfile
import subprocess
from pathlib import Path


class HelloUnavailable(RuntimeError):
    pass


def _require_windows():
    if sys.platform != 'win32':
        raise HelloUnavailable('Windows Hello доступен только в Windows 10/11')


class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def _data_blob(raw):
    buffer = ctypes.create_string_buffer(raw, max(len(raw), 1))
    return DATA_BLOB(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer, DATA_BLOB


def _dpapi(raw, encrypt, entropy):
    _require_windows()
    import ctypes.wintypes
    inp, inp_buf, Blob = _data_blob(raw)
    ent, ent_buf, _ = _data_blob(entropy)
    output = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    fun = crypt.CryptProtectData if encrypt else crypt.CryptUnprotectData
    if encrypt:
        fun.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
                        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fun(ctypes.byref(inp), 'MoiParoli local quick unlock', ctypes.byref(ent),
                 None, None, 0x01, ctypes.byref(output))
    else:
        fun.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fun(ctypes.byref(inp), None, ctypes.byref(ent), None, None, 0x01, ctypes.byref(output))
    if not ok:
        raise OSError(ctypes.get_last_error(), 'Ошибка защиты Windows DPAPI')
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        free = ctypes.windll.kernel32.LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(output.pbData)


def _vault_binding(vault_path):
    # Ties a cached password to *this vault*, but allows normal entry updates.
    with open(vault_path, encoding='utf-8') as handle:
        data = json.load(handle)
    if data.get('magic') != 'passvault' or data.get('version') != 2:
        raise HelloUnavailable('Быстрый вход поддерживает только vault.dat v2')
    kdf = data['kdf']
    fingerprint = json.dumps([os.path.abspath(vault_path), kdf['salt'], kdf['n'],
                              kdf['r'], kdf['p'], bool(data.get('keyfile'))], ensure_ascii=False)
    return hashlib.sha256(fingerprint.encode()).hexdigest()


class HelloUnlock:
    def __init__(self, vault_path, credential_path):
        self.vault_path = vault_path
        self.credential_path = credential_path

    def enabled(self):
        return os.path.isfile(self.credential_path)

    def disable(self):
        if os.path.isfile(self.credential_path):
            os.remove(self.credential_path)

    def enroll(self, master_password):
        _require_windows()
        if not master_password:
            raise ValueError('Мастер-пароль обязателен')
        if not os.path.isfile(self.vault_path):
            raise HelloUnavailable('Файл хранилища не найден')
        fingerprint = _vault_binding(self.vault_path)
        with open(self.vault_path, encoding='utf-8') as vault_file:
            requires_keyfile = json.load(vault_file).get('keyfile')
        if requires_keyfile:
            raise HelloUnavailable('Для хранилищ с ключевым файлом быстрый вход отключён')
        cipher = _dpapi(master_password.encode('utf-8'), True, fingerprint.encode())
        from base64 import b64encode
        payload = {'version': 1, 'vault': fingerprint, 'encrypted': b64encode(cipher).decode('ascii')}
        folder = os.path.dirname(os.path.abspath(self.credential_path))
        os.makedirs(folder, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=folder, prefix='.hello-', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle)
            os.replace(temp_path, self.credential_path)
            try:
                os.chmod(self.credential_path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def verify(self, hwnd=None):
        _require_windows()
        if not hwnd:
            raise HelloUnavailable('Для Windows Hello требуется окно приложения')
        root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
        helper = root / 'hello_verify.exe'
        if not helper.is_file():
            raise HelloUnavailable('Компонент Windows Hello не собран. Используйте мастер-пароль.')
        try:
            result = subprocess.run([str(helper), str(int(hwnd))],
                                             creationflags=subprocess.CREATE_NO_WINDOW,
                                             check=False, timeout=120, capture_output=True)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HelloUnavailable('Проверка Hello недоступна или истекло время ожидания') from exc
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        if result.returncode == 2:
            raise HelloUnavailable('Windows Hello не настроен или недоступен')
        raise HelloUnavailable('Не удалось выполнить проверку Windows Hello. Используйте мастер-пароль.')

    def retrieve_after_verification(self):
        from base64 import b64decode
        fingerprint = _vault_binding(self.vault_path)
        with open(self.credential_path, encoding='utf-8') as handle:
            payload = json.load(handle)
        if payload.get('vault') != fingerprint or payload.get('version') != 1:
            raise HelloUnavailable('Хранилище или мастер-ключ изменены. Повторно включите Windows Hello.')
        return _dpapi(b64decode(payload['encrypted'], validate=True), False, fingerprint.encode()).decode('utf-8')

