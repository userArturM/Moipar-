#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Мои пароли Pro 4.0 — менеджер личных паролей для Windows.

Безопасность
  * AES-256-GCM, ключ из мастер-пароля через scrypt; любая порча файла обнаруживается.
  * Автосохранение при каждом изменении: атомарная запись, .bak и ежедневные копии.
  * Автоблокировка (по времени и при сворачивании), очистка буфера обмена, корзина 30 дней.

Возможности
  * Тёмная панель с показателями безопасности, категории, теги, избранное, поиск.
  * Импорт из CSV: Chrome / Edge / Яндекс / Firefox, Bitwarden, LastPass, KeePass, 1Password.
  * Коды 2FA (TOTP), история паролей, генератор, аудит, восстановление из копий.

Запуск из исходников:  pip install cryptography   →   python moi_paroli.py
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import math
import os
import queue
import re
import secrets
import shutil
import string
import struct
import sys
import time
import uuid
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from windows_hello import HelloUnlock, HelloUnavailable
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
except ImportError:  # tkinter нужен только для окна
    tk = ttk = messagebox = simpledialog = filedialog = None

APP_NAME = "Мои пароли"
APP_ID = "MoiParoli"
APP_VERSION = "4.2"
KDF_N, KDF_R, KDF_P = 2 ** 16, 8, 1
KDF_MAX_N = 2 ** 20
MIN_MASTER_LEN = 10
TRASH_DAYS = 30
OLD_PASSWORD_DAYS = 365
HISTORY_LIMIT = 10
BACKUPS_KEEP = 14
ISSUE_WEAK = "Слабый пароль"
ISSUE_REUSED = "Повторяющийся пароль"
ISSUE_OLD = "Пароль не менялся больше года"
ISSUE_EMPTY = "Нет пароля"


# ==========================================================================
#  Утилиты
# ==========================================================================
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except (TypeError, ValueError):
            continue
    return None


def hostname(url):
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "//" + u
    host = (urlparse(u).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def b64d(text):
    return base64.b64decode(text.encode("ascii"))


def data_dir():
    custom = os.environ.get("MOIPAROLI_DIR")
    if custom:
        base = custom
    else:
        root = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
        base = os.path.join(root, APP_ID)
        legacy = os.path.join(root, "PassVault")  # данные предыдущих версий переносим один раз
        if (not os.path.exists(os.path.join(base, "vault.dat"))
                and os.path.exists(os.path.join(legacy, "vault.dat"))):
            os.makedirs(base, exist_ok=True)
            try:
                shutil.copyfile(os.path.join(legacy, "vault.dat"), os.path.join(base, "vault.dat"))
            except OSError:
                pass
    os.makedirs(base, exist_ok=True)
    return base


def shred_file(path):
    """Перезаписать файл нулями и удалить (на SSD гарантий нет, но это лучше, чем ничего)."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(b"\0" * size)
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)


# ==========================================================================
#  Пароли: генератор, оценка стойкости, TOTP
# ==========================================================================
SYMBOLS = "!@#$%^&*-_=+?"
AMBIGUOUS = set("O0oIl1|")
COMMON_PARTS = ("password", "qwerty", "123456", "111111", "admin", "letmein", "welcome",
                "iloveyou", "йцукен", "пароль", "123123", "abc123")


def generate_password(length=16, lower=True, upper=True, digits=True, symbols=True,
                      ambiguous=False):
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("не выбран ни один тип символов")
    if not ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    length = max(len(pools), min(int(length), 128))
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def strength(pw):
    """Возвращает (оценка_в_битах, текст, уровень 0..3)."""
    if not pw:
        return 0, "—", 0
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^\w\s]|_", pw):
        pool += 33
    if re.search(r"[^\x00-\x7f]", pw):
        pool += 64
    if re.search(r"\s", pw):
        pool += 1
    bits = len(pw) * math.log2(max(pool, 2))
    if len(set(pw)) <= len(pw) / 2:
        bits *= 0.6
    if re.search(r"(.)\1{2,}", pw):
        bits *= 0.8
    low = pw.lower()
    if any(part in low for part in COMMON_PARTS):
        bits = min(bits, 20)
    bits = int(bits)
    if bits < 28:
        return bits, "Очень слабый", 0
    if bits < 45:
        return bits, "Слабый", 0
    if bits < 60:
        return bits, "Средний", 1
    if bits < 80:
        return bits, "Хороший", 2
    return bits, "Отличный", 3


def totp_secret(value):
    """Принимает секрет в base32 или ссылку otpauth://; возвращает bytes-ключ."""
    s = (value or "").strip()
    if s.lower().startswith("otpauth://"):
        q = parse_qs(urlparse(s).query)
        s = (q.get("secret") or [""])[0]
    s = re.sub(r"[\s-]", "", s).upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def totp_now(secret, period=30, digits=6, at=None):
    key = totp_secret(secret)
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# ==========================================================================
#  Хранилище
# ==========================================================================
class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class CorruptVault(VaultError):
    pass


class KeyfileRequired(VaultError):
    pass


class SyncConflict(VaultError):
    """Один и тот же объект изменён локально и на диске; данные не перезаписаны."""


class KeyChanged(VaultError):
    pass


ENTRY_DEFAULTS = {
    "title": "", "url": "", "login": "", "password": "", "totp": "",
    "category": "", "tags": "", "note": "", "favorite": False,
    "source": "", "history": None, "deleted": None, "created": "", "updated": "",
    "fields": None, "attachments": None, "mtime": "",
}


def normalize(entry):
    e = dict(entry)
    for k, v in ENTRY_DEFAULTS.items():
        if k not in e or e[k] is None and k not in ("deleted",):
            e[k] = [] if k in ("history", "fields", "attachments") else v
    e["favorite"] = bool(e["favorite"])
    if not e.get("id"):
        e["id"] = uuid.uuid4().hex
    if not e["created"]:
        e["created"] = e["updated"] or now_str()
    if not e["updated"]:
        e["updated"] = e["created"]
    return e


def dup_key(e):
    return (e["title"].strip().lower(), e["login"].strip().lower(),
            hostname(e["url"]), e["password"])


def split_tags(text):
    return [x.strip() for x in (text or "").split(",") if x.strip()]


def stamp(e):
    """Метка последнего изменения записи — по ней решаются конфликты при синхронизации."""
    return max(e.get("mtime") or "", e.get("updated") or "", e.get("deleted") or "")


class Vault:
    MAGIC = "passvault"
    VERSION = 2
    AAD = b"passvault-v2"
    ATTACH_LIMIT = 3 * 1024 * 1024
    TOMBSTONE_DAYS = 90

    def __init__(self, path):
        self.path = path
        self.key = None
        self.kdf = None
        self.keyfile = b""
        self.entries = []
        self.meta = {"categories": [], "tombstones": {}}
        self.backup_dir = None
        self.merged = False
        self._sig = None
        self._base_entries = {}

    # --- состояние
    @property
    def unlocked(self):
        return self.key is not None

    @property
    def uses_keyfile(self):
        return bool(self.keyfile)

    def exists(self):
        return os.path.exists(self.path)

    @staticmethod
    def derive(password, salt, n, r, p, keyfile=b""):
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8") + keyfile)

    @staticmethod
    def keyfile_digest(content):
        return hashlib.sha256(content).digest() if content else b""

    @staticmethod
    def header_needs_keyfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return bool(json.load(f).get("keyfile"))
        except (OSError, ValueError, AttributeError):
            return False

    def _new_kdf(self):
        return {"salt": os.urandom(16), "n": KDF_N, "r": KDF_R, "p": KDF_P}

    # --- создание / вход
    def create(self, password, keyfile=None):
        self.keyfile = self.keyfile_digest(keyfile)
        self.kdf = self._new_kdf()
        self.key = self.derive(password, **self.kdf, keyfile=self.keyfile)
        self.entries = []
        self.meta = {"categories": [], "tombstones": {}}
        self._sig = None
        self.save(check_external=False)

    def unlock(self, password, keyfile=None):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                blob = json.load(f)
        except (OSError, ValueError) as ex:
            raise CorruptVault(str(ex))
        magic = blob.get("magic") if isinstance(blob, dict) else None
        if magic == "passvault-v1":
            return self._unlock_v1(blob, password)
        if magic != self.MAGIC or blob.get("version") != 2:
            raise CorruptVault("неизвестный формат файла")
        needs = bool(blob.get("keyfile"))
        if needs and not keyfile:
            raise KeyfileRequired()
        digest = self.keyfile_digest(keyfile) if needs else b""
        try:
            k = blob["kdf"]
            n, r, p = int(k["n"]), int(k["r"]), int(k["p"])
            salt, nonce, ct = b64d(k["salt"]), b64d(blob["nonce"]), b64d(blob["data"])
        except (KeyError, TypeError, ValueError) as ex:
            raise CorruptVault(f"повреждён заголовок: {ex}")
        if not (2 ** 14 <= n <= KDF_MAX_N and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
            raise CorruptVault("недопустимые параметры шифрования")
        key = self.derive(password, salt, n, r, p, digest)
        try:
            raw = AESGCM(key).decrypt(nonce, ct, self.AAD)
        except InvalidTag:
            raise WrongPassword()
        except ValueError as ex:
            raise CorruptVault(str(ex))
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError as ex:
            raise CorruptVault(str(ex))
        self.kdf = {"salt": salt, "n": n, "r": r, "p": p}
        self.key = key
        self.keyfile = digest
        self.entries = [normalize(e) for e in doc.get("entries", [])]
        self.meta = doc.get("meta") or {}
        self.meta.setdefault("categories", [])
        self.meta.setdefault("tombstones", {})
        self._sig = self._disk_sig()
        self._remember_base()
        self.purge_old_trash()

    def _unlock_v1(self, blob, password):
        """Открывает файл первой версии (Fernet) и переводит его в новый формат."""
        try:
            salt = b64d(blob["salt"])
            old_key = base64.urlsafe_b64encode(self.derive(password, salt, 2 ** 15, 8, 1))
            raw = Fernet(old_key).decrypt(blob["data"].encode("ascii"))
            entries = json.loads(raw.decode("utf-8"))
        except InvalidToken:
            raise WrongPassword()
        except (KeyError, TypeError, ValueError) as ex:
            raise CorruptVault(str(ex))
        shutil.copyfile(self.path, self.path + ".v1.bak")
        self.keyfile = b""
        self.kdf = self._new_kdf()
        self.key = self.derive(password, **self.kdf)
        self.entries = [normalize(e) for e in entries]
        self.meta = {"categories": [], "tombstones": {}}
        self.save(check_external=False)

    def lock(self):
        self.key = None
        self.kdf = None
        self.keyfile = b""
        self.entries = []
        self.meta = {"categories": [], "tombstones": {}}
        self._sig = None
        self.merged = False
        self._base_entries = {}

    def verify_password(self, password):
        if not self.unlocked:
            return False
        return hmac.compare_digest(self.derive(password, **self.kdf, keyfile=self.keyfile), self.key)

    def change_password(self, new_password):
        self.sync_from_disk(write=False)          # сначала подтянуть чужие правки (старым ключом)
        self.kdf = self._new_kdf()
        self.key = self.derive(new_password, **self.kdf, keyfile=self.keyfile)
        self.save(check_external=False)

    def set_keyfile(self, password, content):
        """Включает (content=bytes) или выключает (None) ключевой файл. Нужен мастер-пароль."""
        if not self.verify_password(password):
            raise WrongPassword()
        self.sync_from_disk(write=False)
        old = (self.kdf, self.key, self.keyfile)
        self.keyfile = self.keyfile_digest(content)
        self.kdf = self._new_kdf()
        self.key = self.derive(password, **self.kdf, keyfile=self.keyfile)
        try:
            self.save(check_external=False)
        except Exception:
            self.kdf, self.key, self.keyfile = old
            raise

    # --- синхронизация с диском (облачная папка, второй компьютер)
    def _disk_sig(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _read_remote(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            k = blob["kdf"]
            salt, nonce, ct = b64d(k["salt"]), b64d(blob["nonce"]), b64d(blob["data"])
            same = (blob.get("magic") == self.MAGIC and blob.get("version") == 2
                    and salt == self.kdf["salt"] and int(k["n"]) == self.kdf["n"]
                    and int(k["r"]) == self.kdf["r"] and int(k["p"]) == self.kdf["p"]
                    and bool(blob.get("keyfile")) == bool(self.keyfile))
        except (OSError, ValueError, KeyError, TypeError) as ex:
            raise CorruptVault(str(ex))
        if not same:
            raise KeyChanged()
        try:
            raw = AESGCM(self.key).decrypt(nonce, ct, self.AAD)
        except InvalidTag:
            raise KeyChanged()
        except ValueError as ex:
            raise CorruptVault(str(ex))
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError as ex:
            raise CorruptVault(str(ex))
        return [normalize(e) for e in doc.get("entries", [])], doc.get("meta") or {}

    @staticmethod
    def _fp(entries, tombstones):
        data = [sorted(entries, key=lambda e: e["id"]), sorted(tombstones.items())]
        return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

    @staticmethod
    def _record_hash(record):
        return hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest() if record is not None else None

    def _remember_base(self):
        self._base_entries = {e["id"]: self._record_hash(e) for e in self.entries}

    def _assert_no_conflicts(self, remote):
        """Трёхсторонняя проверка относительно последнего состояния диска."""
        local = {e["id"]: e for e in self.entries}
        other = {e["id"]: e for e in remote}
        conflicts = []
        for item_id in set(local) | set(other) | set(self._base_entries):
            base = self._base_entries.get(item_id)
            lhs = self._record_hash(local.get(item_id))
            rhs = self._record_hash(other.get(item_id))
            if lhs != base and rhs != base and lhs != rhs:
                conflicts.append(item_id)
        if conflicts:
            raise SyncConflict("Конфликт изменений: " + ", ".join(conflicts[:5]) +
                               ". Сохранение отменено; проверьте другие устройства.")

    def _merge(self, r_entries, r_meta):
        """Объединение по записям: побеждает более поздняя правка; удаления помнятся 90 дней."""
        tomb = dict(r_meta.get("tombstones") or {})
        for k, v in (self.meta.get("tombstones") or {}).items():
            if v > tomb.get(k, ""):
                tomb[k] = v
        by_id = {e["id"]: e for e in r_entries}
        for e in self.entries:
            r = by_id.get(e["id"])
            base = self._base_entries.get(e["id"])
            if self._record_hash(e) == base:
                continue
            if r is None or self._record_hash(r) == base or stamp(e) >= stamp(r):
                by_id[e["id"]] = e
        self.entries = [e for e in by_id.values()
                        if not (e["id"] in tomb and stamp(e) <= tomb[e["id"]])]
        cats = list(r_meta.get("categories") or []) + list(self.meta.get("categories") or [])
        self.meta["categories"] = list(dict.fromkeys(cats))
        self.meta["tombstones"] = tomb

    def conflict_snapshot(self):
        sig = self._disk_sig()
        remote, meta = self._read_remote()
        if self._disk_sig() != sig:
            raise SyncConflict("Хранилище снова изменилось. Повторите сравнение.")
        local = {e["id"]: e for e in self.entries}
        other = {e["id"]: e for e in remote}
        conflicts = []
        for item_id in set(local) | set(other) | set(self._base_entries):
            base = self._base_entries.get(item_id)
            lhs, rhs = self._record_hash(local.get(item_id)), self._record_hash(other.get(item_id))
            if lhs != base and rhs != base and lhs != rhs:
                conflicts.append({"id": item_id, "local": local.get(item_id), "remote": other.get(item_id)})
        return json.loads(json.dumps({"sig": sig, "local_fp": self._fp(self.entries, self.meta.get("tombstones", {})),
                                      "conflicts": conflicts}, ensure_ascii=False))

    def resolve_conflicts(self, snapshot, choices):
        if self._disk_sig() != tuple(snapshot["sig"]):
            raise SyncConflict("Хранилище снова изменилось. Повторите сравнение.")
        if self._fp(self.entries, self.meta.get("tombstones", {})) != snapshot["local_fp"]:
            raise SyncConflict("Локальные записи изменились. Повторите сравнение.")
        conflicts = snapshot["conflicts"]
        if set(choices) != {c["id"] for c in conflicts} or any(
                value not in ("local", "remote", "both") for value in choices.values()):
            raise ValueError("Выберите вариант для каждого конфликта")
        remote, meta = self._read_remote()
        if self._disk_sig() != tuple(snapshot["sig"]):
            raise SyncConflict("Хранилище снова изменилось. Повторите сравнение.")
        self._merge(remote, meta)
        for conflict in conflicts:
            item_id = conflict["id"]
            mode = choices[item_id]
            self.entries = [e for e in self.entries if e["id"] != item_id]
            selected = [conflict["local"]] if mode == "local" else [conflict["remote"]]
            if mode == "both":
                selected = [conflict["remote"], conflict["local"]]
            selected = [json.loads(json.dumps(e)) for e in selected if e is not None]
            for index, entry in enumerate(selected):
                if index:
                    entry["id"] = uuid.uuid4().hex
                    entry["title"] += " (локальная копия)"
                self._touch(entry)
                self.entries.append(entry)
                self.meta["tombstones"].pop(entry["id"], None)
        if self._disk_sig() != tuple(snapshot["sig"]):
            raise SyncConflict("Хранилище снова изменилось. Повторите сравнение.")
        self._sig = tuple(snapshot["sig"])
        self.save(check_external=False)

    def sync_from_disk(self, write=True):
        """Подтянуть изменения, сделанные другим компьютером. True — локальные данные изменились."""
        sig = self._disk_sig()
        if not self.unlocked or sig is None or sig == self._sig:
            return False
        r_entries, r_meta = self._read_remote()
        remote_fp = self._fp(r_entries, r_meta.get("tombstones") or {})
        before = self._fp(self.entries, self.meta.get("tombstones") or {})
        self._assert_no_conflicts(r_entries)
        self._merge(r_entries, r_meta)
        after = self._fp(self.entries, self.meta.get("tombstones") or {})
        self._sig = sig
        self._remember_base()
        if after != before:
            self.merged = True
        if write and after != remote_fp:
            self.save(check_external=False)
        return after != before

    # --- запись на диск (автосохранение)
    def save(self, check_external=True):
        if not self.unlocked:
            raise VaultError("хранилище заблокировано")
        if check_external and self._sig is not None:
            self.sync_from_disk(write=False)
        payload = json.dumps({"entries": self.entries, "meta": self.meta},
                             ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)
        blob = {
            "magic": self.MAGIC, "version": self.VERSION, "keyfile": bool(self.keyfile),
            "kdf": {"name": "scrypt", "salt": b64e(self.kdf["salt"]), "n": self.kdf["n"],
                    "r": self.kdf["r"], "p": self.kdf["p"]},
            "nonce": b64e(nonce),
            "data": b64e(AESGCM(self.key).encrypt(nonce, payload, self.AAD)),
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(blob, f)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(self.path):
            self._daily_backup()
            shutil.copyfile(self.path, self.path + ".bak")
        os.replace(tmp, self.path)
        self._sig = self._disk_sig()
        self._remember_base()

    def backups_dir(self):
        return self.backup_dir or os.path.join(os.path.dirname(self.path), "backups")

    @classmethod
    def validate_backup(cls, path, password, keyfile=None):
        """Полная проверка AEAD без изменения рабочего файла или данных пользователя."""
        import tempfile
        # Unlock may migrate legacy files or purge old trash; only touch a copy.
        with tempfile.TemporaryDirectory() as folder:
            copy = os.path.join(folder, "probe.dat")
            shutil.copyfile(path, copy)
            probe = cls(copy)
            try:
                probe.unlock(password, keyfile)
                return len(probe.entries)
            finally:
                probe.lock()

    def _daily_backup(self):
        try:
            d = self.backups_dir()
            os.makedirs(d, exist_ok=True)
            target = os.path.join(d, "vault-" + datetime.now().strftime("%Y-%m-%d") + ".dat")
            if not os.path.exists(target):
                shutil.copyfile(self.path, target)
            files = sorted(f for f in os.listdir(d) if f.startswith("vault-") and f.endswith(".dat"))
            for old in files[:-BACKUPS_KEEP]:
                os.remove(os.path.join(d, old))
        except OSError:
            pass  # сбой резервной копии не должен мешать сохранению

    # --- выборки
    def active(self):
        return [e for e in self.entries if not e["deleted"]]

    def trash(self):
        return [e for e in self.entries if e["deleted"]]

    def get(self, entry_id):
        return next((e for e in self.entries if e["id"] == entry_id), None)

    def categories(self):
        names = set(self.meta.get("categories", [])) | {e["category"] for e in self.active() if e["category"]}
        return sorted(names, key=str.lower)

    def _register_category(self, cat):
        if cat and cat not in self.meta["categories"]:
            self.meta["categories"].append(cat)

    @staticmethod
    def _touch(e):
        e["mtime"] = now_str()

    def _tombstone(self, ids):
        tomb = self.meta.setdefault("tombstones", {})
        now = now_str()
        for i in ids:
            tomb[i] = now
        limit = (datetime.now() - timedelta(days=self.TOMBSTONE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        for k in [k for k, v in tomb.items() if v < limit]:
            del tomb[k]

    # --- операции (каждая сразу сохраняется)
    def add(self, data):
        e = normalize(dict(data, id=None, created="", updated="", deleted=None, history=[],
                           attachments=[], mtime=""))
        e["created"] = e["updated"] = e["mtime"] = now_str()
        self.entries.append(e)
        self._register_category(e["category"])
        self.save()
        return e

    def update(self, entry_id, data):
        e = self.get(entry_id)
        if not e:
            return None
        new_pw = data.get("password", e["password"])
        if e["password"] and new_pw != e["password"]:
            e["history"].insert(0, {"password": e["password"], "changed": now_str()})
            del e["history"][HISTORY_LIMIT:]
        for k in ("title", "url", "login", "password", "totp", "category", "tags", "note",
                  "favorite", "fields"):
            if k in data:
                e[k] = data[k]
        e["updated"] = now_str()
        self._touch(e)
        self._register_category(e["category"])
        self.save()
        return e

    def set_favorite(self, entry_id, flag):
        e = self.get(entry_id)
        if e:
            e["favorite"] = bool(flag)
            self._touch(e)
            self.save()

    def soft_delete(self, entry_id):
        e = self.get(entry_id)
        if e:
            e["deleted"] = now_str()
            self._touch(e)
            self.save()

    def restore(self, entry_id):
        e = self.get(entry_id)
        if e:
            e["deleted"] = None
            self._touch(e)
            self.save()

    def purge(self, entry_id):
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self._tombstone([entry_id])
        self.save()

    def empty_trash(self):
        gone = [e["id"] for e in self.entries if e["deleted"]]
        self.entries = [e for e in self.entries if not e["deleted"]]
        self._tombstone(gone)
        self.save()

    def purge_old_trash(self):
        limit = datetime.now() - timedelta(days=TRASH_DAYS)
        old = [e["id"] for e in self.entries
               if e["deleted"] and (parse_dt(e["deleted"]) or datetime.now()) < limit]
        if old:
            self.entries = [e for e in self.entries if e["id"] not in old]
            self._tombstone(old)
            self.save()

    def bulk_add(self, items, source=""):
        keys = {dup_key(e) for e in self.entries}
        added = dup = 0
        for item in items:
            e = normalize(dict(item, id=None, created="", updated="", deleted=None, history=[],
                               attachments=[], mtime=""))
            if source and not e["source"]:
                e["source"] = source
            k = dup_key(e)
            if k in keys:
                dup += 1
                continue
            keys.add(k)
            e["created"] = e["updated"] = e["mtime"] = now_str()
            self.entries.append(e)
            self._register_category(e["category"])
            added += 1
        if added:
            self.save()
        return added, dup

    # --- вложения (хранятся внутри зашифрованного файла)
    def add_attachment(self, entry_id, name, data):
        e = self.get(entry_id)
        if not e:
            return None
        if len(data) > self.ATTACH_LIMIT:
            raise VaultError("Файл больше 3 МБ")
        att = {"id": uuid.uuid4().hex, "name": name, "size": len(data), "data": b64e(data)}
        e["attachments"].append(att)
        self._touch(e)
        try:
            self.save()
        except Exception:
            e["attachments"].remove(att)
            raise
        return att["id"]

    def remove_attachment(self, entry_id, att_id):
        e = self.get(entry_id)
        if e:
            e["attachments"] = [a for a in e["attachments"] if a["id"] != att_id]
            self._touch(e)
            self.save()

    def get_attachment(self, entry_id, att_id):
        e = self.get(entry_id)
        for a in (e["attachments"] if e else []):
            if a["id"] == att_id:
                return b64d(a["data"])
        return None

    # --- аудит безопасности
    def audit(self):
        """Список (проблема, запись)."""
        issues = []
        act = self.active()
        by_pw = {}
        for e in act:
            if e["password"]:
                by_pw.setdefault(e["password"], []).append(e)
        limit = datetime.now() - timedelta(days=OLD_PASSWORD_DAYS)
        for e in act:
            if not e["password"]:
                issues.append((ISSUE_EMPTY, e))
                continue
            if strength(e["password"])[2] == 0:
                issues.append((ISSUE_WEAK, e))
            if len(by_pw[e["password"]]) > 1:
                issues.append((ISSUE_REUSED, e))
            d = parse_dt(e["updated"])
            if d and d < limit:
                issues.append((ISSUE_OLD, e))
        return issues

    def summary(self):
        """Показатели для панели: числа записей с проблемами и общая оценка."""
        kinds = {ISSUE_WEAK: "weak", ISSUE_REUSED: "reused", ISSUE_OLD: "old", ISSUE_EMPTY: "empty"}
        groups = {k: set() for k in kinds.values()}
        for text, e in self.audit():
            groups[kinds[text]].add(e["id"])
        bad = set().union(*groups.values())
        act = self.active()
        total = len(act)
        return {"total": total, "weak": len(groups["weak"]), "reused": len(groups["reused"]),
                "old": len(groups["old"]), "empty": len(groups["empty"]),
                "totp": sum(1 for e in act if e["totp"]),
                "score": 100 if not total else round(100 * (1 - len(bad) / total))}


class Settings:
    DEFAULTS = {"theme": "dark", "idle_minutes": 5, "clipboard_seconds": 30,
                "lock_on_minimize": True, "geometry": "", "lock_on_session_lock": True,
                "close_to_tray": True, "hotkey_enabled": True, "hotkey": "Ctrl+Alt+P",
                "protect_capture": False, "autotype_enter": False, "check_updates": False,
                "update_repo": "", "vault_path": "", "keyfile_path": ""}

    def __init__(self, path):
        self.path = path
        self.data = dict(self.DEFAULTS)
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def get(self, key):
        return self.data.get(key, self.DEFAULTS.get(key))

    def set(self, key, value):
        self.data[key] = value
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
        except OSError:
            pass


# ==========================================================================
#  Импорт / экспорт CSV
# ==========================================================================
SYNONYMS = {
    "title": {"name", "title", "account", "site", "service", "название", "сервис"},
    "url": {"url", "website", "web site", "login_uri", "uri", "адрес", "сайт"},
    "login": {"username", "login", "login name", "login_username", "user", "email",
              "логин", "имя пользователя"},
    "password": {"password", "pass", "login_password", "пароль"},
    "note": {"note", "notes", "comment", "comments", "extra", "заметка", "заметки", "комментарий"},
    "totp": {"totp", "otp", "login_totp", "otpauth"},
    "category": {"group", "folder", "grouping", "category", "папка", "группа", "категория"},
    "fav": {"favorite", "fav", "избранное"},
}
SKIP_TYPES = {"card", "identity", "credit card", "secure note", "note"}


def detect_source(h):
    if "login_username" in h:
        return "Bitwarden"
    if "grouping" in h and "extra" in h:
        return "LastPass"
    if "httprealm" in h:
        return "Firefox"
    if "group" in h and "title" in h and "username" in h:
        return "KeePassXC"
    if "login name" in h and "account" in h:
        return "KeePass"
    if "title" in h and ("website" in h or "otpauth" in h):
        return "1Password"
    if "name" in h and "url" in h and "username" in h and "password" in h:
        return "Chrome / Edge / Яндекс"
    return "CSV"


def parse_csv(raw):
    """raw — bytes. Возвращает (источник, список записей, число пропущенных строк)."""
    text = None
    for enc in ("utf-8-sig", "cp1251"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None or not text.strip():
        raise ValueError("файл пустой или в неизвестной кодировке")
    first = text.splitlines()[0]
    delim = ";" if first.count(";") > first.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)
    if not reader.fieldnames:
        raise ValueError("не найден заголовок таблицы")
    headers = [(h or "").strip().lower() for h in reader.fieldnames]
    source = detect_source(headers)
    colmap = {}
    for low in headers:
        for field, syn in SYNONYMS.items():
            if low in syn and field not in colmap:
                colmap[field] = low
    if "password" not in colmap:
        raise ValueError("в файле нет столбца с паролями")
    items, skipped = [], 0
    for raw_row in reader:
        row = {}
        for k, v in raw_row.items():
            if isinstance(v, list):
                v = " ".join(v)
            row[(k or "").strip().lower()] = (v or "").strip()

        def g(field):
            return row.get(colmap[field], "") if field in colmap else ""

        if row.get("type", "").lower() in SKIP_TYPES:
            skipped += 1
            continue
        url, login, password = g("url"), g("login"), g("password")
        if url.lower() == "http://sn":  # защищённая заметка LastPass
            url = ""
        if not (url or login or password):
            skipped += 1
            continue
        items.append({
            "title": g("title") or hostname(url) or login or "Без названия",
            "url": url, "login": login, "password": password, "totp": g("totp"),
            "note": g("note"), "category": g("category") or f"Импорт: {source}",
            "favorite": g("fav").lower() in ("1", "true", "yes", "да"),
            "source": source,
        })
    return source, items, skipped


def export_csv_text(entries):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["name", "url", "username", "password", "totp", "category", "tags", "note", "favorite", "extra"])
    for e in entries:
        w.writerow([e["title"], e["url"], e["login"], e["password"], e["totp"], e["category"],
                    e["tags"], e["note"], "1" if e["favorite"] else "", format_fields(e["fields"])])
    return out.getvalue()


# ==========================================================================
#  Шаблоны записей, свои поля, импорт Excel
# ==========================================================================
TEMPLATES = {
    "Пустая запись": {},
    "Сайт / сервис": {"category": "Сайты"},
    "Банк / карта": {"category": "Финансы", "fields": [
        ("Номер карты", False), ("Срок действия", False), ("CVV", True),
        ("ПИН-код", True), ("Секретное слово", True)]},
    "Wi-Fi": {"category": "Сети", "fields": [("Название сети (SSID)", False), ("Тип защиты", False)]},
    "Лицензионный ключ": {"category": "Программы", "fields": [
        ("Ключ", True), ("Версия", False), ("Привязан к e-mail", False)]},
    "Сервер / SSH": {"category": "Серверы", "fields": [
        ("Хост", False), ("Порт", False), ("Ключ SSH", True)]},
    "Электронная почта": {"category": "Почта", "fields": [
        ("Пароль приложения", True), ("Резервный e-mail", False)]},
}


def format_fields(fields):
    """Список полей -> текст по строкам «Название = значение» (секретные: «Название* = …»)."""
    return "\n".join(f'{f["name"]}{"*" if f.get("secret") else ""} = {f.get("value", "")}'
                     for f in fields)


def parse_fields(text, keep_empty=False):
    out = []
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        secret = name.endswith("*")
        name = name.rstrip("*").strip()
        if name and (value or keep_empty):
            out.append({"name": name, "value": value, "secret": secret})
    return out


def xlsx_to_csv_bytes(path):
    """Превращает таблицу Excel (.xlsx) в CSV, чтобы использовать тот же разбор, что и для CSV."""
    try:
        import openpyxl
    except ImportError:
        raise ValueError("для импорта Excel нужен модуль openpyxl")
    try:
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    except Exception as ex:
        raise ValueError(f"не удалось открыть книгу Excel: {ex}")
    best = None
    for ws in wb.worksheets:
        rows = [["" if c is None else str(c) for c in row] for row in ws.iter_rows(values_only=True)]
        rows = [r for r in rows if any(x.strip() for x in r)]
        if not rows:
            continue
        header = [h.strip().lower() for h in rows[0]]
        if any(h in SYNONYMS["password"] for h in header):
            best = rows
            break
        if best is None:
            best = rows
    wb.close()
    if not best:
        raise ValueError("в книге нет данных")
    out = io.StringIO()
    csv.writer(out).writerows(best)
    return out.getvalue().encode("utf-8")


# ==========================================================================
#  Сеть: проверка утечек и обновлений (только по запросу пользователя)
# ==========================================================================
def pwned_count(password, timeout=8):
    """Сколько раз пароль встречается в известных утечках (Have I Been Pwned).
    Наружу уходят только первые 5 символов SHA-1 — сам пароль с компьютера не уходит."""
    sha = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + prefix,
                                 headers={"User-Agent": "MoiParoli", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8")
    for line in text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def parse_version(text):
    nums = re.findall(r"\d+", text or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


REPO_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$")


def check_update(repo, timeout=8):
    if not REPO_RE.match(repo or ""):
        raise ValueError("репозиторий нужно указать в виде «владелец/имя»")
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                 headers={"User-Agent": "MoiParoli",
                                          "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    tag = data.get("tag_name", "")
    return {"version": tag, "newer": parse_version(tag) > parse_version(APP_VERSION),
            "url": data.get("html_url", ""), "notes": data.get("body", "") or ""}


# ==========================================================================
#  Windows: автоввод, горячая клавиша, трей, защита окна. Любая ошибка здесь
#  молча игнорируется — программа должна работать и без этих функций.
# ==========================================================================
IS_WIN = sys.platform == "win32"
_MUTEX = None


def win_single_instance():
    global _MUTEX
    if not IS_WIN:
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        _MUTEX = k.CreateMutexW(None, False, "MoiParoli_SingleInstance_Mutex")
        return k.GetLastError() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True


def win_message(text):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, APP_NAME, 0x40)
    except Exception:
        print(text)


def win_hwnd(window):
    try:
        import ctypes
        return ctypes.windll.user32.GetParent(window.winfo_id())
    except Exception:
        return 0


def win_foreground():
    if not IS_WIN:
        return 0
    try:
        import ctypes
        return ctypes.windll.user32.GetForegroundWindow()
    except Exception:
        return 0


def win_activate(hwnd):
    if not (IS_WIN and hwnd):
        return
    try:
        import ctypes
        u = ctypes.windll.user32
        if u.IsIconic(hwnd):
            u.ShowWindow(hwnd, 9)
        u.SetForegroundWindow(hwnd)
    except Exception:
        pass


def win_session_locked():
    """True, если Windows заблокирована (Win+L) или показан экран входа."""
    if not IS_WIN:
        return False
    try:
        import ctypes
        u = ctypes.windll.user32
        u.OpenInputDesktop.restype = ctypes.c_void_p
        h = u.OpenInputDesktop(0, False, 0x0100)
        if not h:
            return True
        u.CloseDesktop(ctypes.c_void_p(h))
        return False
    except Exception:
        return False


def win_capture_protect(window, enabled):
    """Скрывает окно от скриншотов и записи экрана."""
    if not IS_WIN:
        return
    try:
        import ctypes
        u = ctypes.windll.user32
        hwnd = win_hwnd(window)
        if not u.SetWindowDisplayAffinity(hwnd, 0x11 if enabled else 0) and enabled:
            u.SetWindowDisplayAffinity(hwnd, 0x01)  # старые версии Windows: окно будет чёрным
    except Exception:
        pass


def _win_input_types():
    import ctypes
    from ctypes import wintypes
    ptr = ctypes.c_size_t

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ptr)]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ptr)]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]

    class _U(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = [("type", wintypes.DWORD), ("u", _U)]

    return INPUT, KEYBDINPUT


def _win_send(events):
    """events — список (виртуальный код, scan-код, флаги)."""
    import ctypes
    INPUT, KEYBDINPUT = _win_input_types()
    arr = (INPUT * len(events))()
    for i, (vk, scan, flags) in enumerate(events):
        arr[i].type = 1
        arr[i].ki = KEYBDINPUT(vk, scan, flags, 0, 0)
    sent = ctypes.windll.user32.SendInput(len(events), ctypes.byref(arr), ctypes.sizeof(INPUT))
    return sent == len(events)


def win_type_text(text):
    if not IS_WIN:
        return False
    try:
        for ch in text:
            if ch in "\r\n":
                continue
            data = ch.encode("utf-16-le")
            for i in range(0, len(data), 2):
                unit = int.from_bytes(data[i:i + 2], "little")
                if not _win_send([(0, unit, 0x0004), (0, unit, 0x0004 | 0x0002)]):
                    return False
            time.sleep(0.004)
        return True
    except Exception:
        return False


def win_press(vk):
    if not IS_WIN:
        return False
    try:
        return _win_send([(vk, 0, 0), (vk, 0, 0x0002)])
    except Exception:
        return False


def win_autotype(login, password, press_enter=False):
    ok = True
    if login:
        ok = win_type_text(login)
    if ok and login and password:
        time.sleep(0.05)
        ok = win_press(0x09)          # Tab
    if ok and password:
        ok = win_type_text(password)
    if ok and press_enter:
        time.sleep(0.05)
        ok = win_press(0x0D)          # Enter
    return ok


HOTKEY_MODS = {"ctrl": 0x0002, "control": 0x0002, "alt": 0x0001, "shift": 0x0004, "win": 0x0008}


def parse_hotkey(text):
    """«Ctrl+Alt+P» -> (модификаторы, виртуальный код клавиши)."""
    parts = [p.strip().lower() for p in (text or "").split("+") if p.strip()]
    if len(parts) < 2:
        raise ValueError("нужны модификатор и клавиша, например Ctrl+Alt+P")
    mods = 0
    for m in parts[:-1]:
        if m not in HOTKEY_MODS:
            raise ValueError(f"неизвестный модификатор: {m}")
        mods |= HOTKEY_MODS[m]
    key = parts[-1]
    if len(key) == 1 and key.isascii() and key.isalnum():
        vk = ord(key.upper())
    elif key == "space":
        vk = 0x20
    elif re.fullmatch(r"f([1-9]|1[0-2])", key):
        vk = 0x70 + int(key[1:]) - 1
    else:
        raise ValueError(f"неизвестная клавиша: {key}")
    return mods | 0x4000, vk  # 0x4000 — не повторять при удержании


class HotkeyListener(threading.Thread):
    """Глобальная горячая клавиша Windows (работает, даже если окно скрыто в трее)."""

    def __init__(self, callback, mods, vk):
        super().__init__(daemon=True)
        self.callback, self.mods, self.vk = callback, mods, vk
        self.ok = False
        self.thread_id = None
        self.ready = threading.Event()

    def run(self):
        try:
            import ctypes
            from ctypes import wintypes
            user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
            self.thread_id = kernel32.GetCurrentThreadId()
            self.ok = bool(user32.RegisterHotKey(None, 1, self.mods, self.vk))
            self.ready.set()
            if not self.ok:
                return
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == 0x0312:  # WM_HOTKEY
                    self.callback(win_foreground())
            user32.UnregisterHotKey(None, 1)
        except Exception:
            self.ready.set()

    def stop(self):
        try:
            import ctypes
            if self.thread_id:
                ctypes.windll.user32.PostThreadMessageW(self.thread_id, 0x0012, 0, 0)  # WM_QUIT
        except Exception:
            pass


def start_tray(app):
    """Значок в области уведомлений. Если pystray/Pillow не установлены — работаем без него."""
    try:
        import pystray
        from PIL import Image
        img = Image.open(io.BytesIO(base64.b64decode(ICON_B64)))
        menu = pystray.Menu(
            pystray.MenuItem("Открыть", lambda *a: app.post(app.show_window), default=True),
            pystray.MenuItem("Быстрый поиск", lambda *a: app.post(app.quick_search)),
            pystray.MenuItem("Заблокировать", lambda *a: app.post(app.lock)),
            pystray.MenuItem("Выход", lambda *a: app.post(app.quit_app)))
        icon = pystray.Icon("MoiParoli", img, APP_NAME, menu)
        icon.run_detached()
        return icon
    except Exception:
        return None


# ==========================================================================
#  Оформление
# ==========================================================================
FF = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

DARK = {"bg": "#101217", "side": "#171a21", "panel": "#1c2028", "card": "#242932",
        "fg": "#edf1f7", "muted": "#a3adbc", "accent": "#8aa7ff", "accent_hi": "#acc0ff",
        "accent_fg": "#10172b", "sel": "#303d60", "border": "#343b47", "hover": "#303743",
        "good": "#79d6b0", "warn": "#ebc17c", "bad": "#f59ba6"}
LIGHT = {"bg": "#f3f5f9", "side": "#e9edf5", "panel": "#ffffff", "card": "#f5f7fb",
         "fg": "#202b40", "muted": "#5e6d85", "accent": "#465dd8", "accent_hi": "#576fe8",
         "accent_fg": "#ffffff", "sel": "#e3e9ff", "border": "#d8dfeb", "hover": "#e9eef8",
         "good": "#217557", "warn": "#966219", "bad": "#b64055"}
THEMES = {"dark": DARK, "light": LIGHT}
LEVEL_STYLE = {0: "Bad", 1: "Warn", 2: "Good", 3: "Good"}


def dark_titlebar(window, enable=True):
    """Тёмный заголовок окна в Windows 10/11 (на других системах ничего не делает)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1 if enable else 0)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (новый / старый номер)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


ICON_B64 = ("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")


# ==========================================================================
#  Диалоги
# ==========================================================================
def _new_top(app, parent, title):
    top = tk.Toplevel(parent)
    top.title(title)
    top.configure(bg=app.t["bg"])
    top.transient(parent)
    top.resizable(False, False)
    subtitles = {
        "Генератор паролей": "Создайте уникальный пароль для новой учётной записи.",
        "Новая запись": "Сохраните доступ и упорядочьте его в хранилище.",
        "Запись": "Данные аккаунта и параметры доступа.",
        "Настройки": "Безопасность, быстрый вход и поведение приложения.",
        "Аудит безопасности": "Проверьте записи, которым требуется внимание.",
    }
    if title in subtitles:
        header = ttk.Frame(top, padding=(24, 20, 24, 0))
        header.pack(fill="x")
        ttk.Label(header, text=title, font=(FF, 18, "bold")).pack(anchor="w")
        ttk.Label(header, text=subtitles[title], style="BgMuted.TLabel").pack(anchor="w", pady=(5, 0))
    if app.icon:
        try:
            top.iconphoto(False, app.icon)
        except tk.TclError:
            pass
    dark_titlebar(top, app.theme_name == "dark")
    if app.settings.get("protect_capture"):
        win_capture_protect(top, True)
    return top


class ConflictDialog:
    def __init__(self, app, snapshot):
        self.result = None
        self.choices = {}
        conflicts = snapshot["conflicts"]
        top = _new_top(app, app.root, "Разрешить конфликты")
        frame = ttk.Frame(top, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Выберите версию записи", font=(FF, 18, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Пароли скрыты. Сохранение обеих версий создаёт отдельную запись.",
                  wraplength=560, foreground=app.t["muted"]).pack(anchor="w", pady=(5, 18))
        heading = ttk.Label(frame, font=(FF, 12, "bold"))
        heading.pack(anchor="w")
        summary = ttk.Frame(frame)
        summary.pack(fill="x", pady=14)
        labels = []
        for column, title in enumerate(("На этом компьютере", "В файле на диске")):
            summary.columnconfigure(column, weight=1, uniform="version")
            panel = ttk.Frame(summary, style="Card.TFrame", padding=16)
            panel.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
            ttk.Label(panel, text=title, style="Card.TLabel", font=(FF, 10, "bold")).pack(anchor="w")
            label = ttk.Label(panel, style="CardMuted.TLabel", wraplength=240, justify="left")
            label.pack(anchor="w", pady=(10, 0))
            labels.append(label)
        choice = tk.StringVar(value="both")
        for value, text in (("both", "Сохранить обе версии"), ("local", "Оставить локальную"),
                            ("remote", "Взять версию с диска")):
            ttk.Radiobutton(frame, text=text, value=value, variable=choice).pack(anchor="w", pady=4)
        current = [0]
        def render():
            conflict = conflicts[current[0]]
            entry = conflict["local"] or conflict["remote"] or {}
            heading.config(text=f'{current[0] + 1} / {len(conflicts)} · {entry.get("title", "Удалённая запись")}')
            for label, key in zip(labels, ("local", "remote")):
                entry = conflict[key]
                text = "Запись удалена" if entry is None else (
                    f'Логин: {entry.get("login", "")}\nКатегория: {entry.get("category", "")}\n'
                    f'Изменено: {entry.get("updated", "")}\nВложений: {len(entry.get("attachments", []))}\n'
                    f'Пароль: {"есть" if entry.get("password") else "отсутствует"}')
                label.config(text=text)
            choice.set("both")
            save.config(text="Сохранить решения" if current[0] == len(conflicts)-1 else "Следующая запись")
        def advance():
            self.choices[conflicts[current[0]]["id"]] = choice.get()
            if current[0] + 1 == len(conflicts):
                self.result = self.choices
                top.destroy()
            else:
                current[0] += 1
                render()
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(20, 0))
        ttk.Button(buttons, text="Отмена", command=top.destroy).pack(side="right")
        save = ttk.Button(buttons, style="Accent.TButton", command=advance)
        save.pack(side="right", padx=8)
        top.bind("<Escape>", lambda event: top.destroy())
        render()
        top.grab_set()
        app.root.wait_window(top)


class GeneratorDialog:
    def __init__(self, app, parent, select=False):
        self.app, self.result = app, None
        top = self.top = _new_top(app, parent, "Генератор паролей")
        frm = ttk.Frame(top, padding=24)
        frm.pack()
        self.out = tk.StringVar()
        ttk.Entry(frm, textvariable=self.out, width=44, font=("Consolas", 11)).grid(
            row=0, column=0, columnspan=3, sticky="we", pady=(0, 6))
        self.bar = ttk.Progressbar(frm, maximum=100, length=300)
        self.bar.grid(row=1, column=0, columnspan=2, sticky="we")
        self.lbl = ttk.Label(frm, text="")
        self.lbl.grid(row=1, column=2, sticky="e", padx=(8, 0))

        ttk.Label(frm, text="Длина").grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.length = tk.IntVar(value=16)
        ttk.Spinbox(frm, from_=8, to=64, textvariable=self.length, width=6,
                    command=self.regen).grid(row=2, column=1, sticky="w", pady=(12, 0))
        self.opts = {}
        for i, (key, text, default) in enumerate((
                ("lower", "Строчные a–z", True), ("upper", "Заглавные A–Z", True),
                ("digits", "Цифры 0–9", True), ("symbols", "Символы !@#$…", True),
                ("ambiguous", "Разрешить похожие (O/0, l/1)", False))):
            var = tk.BooleanVar(value=default)
            self.opts[key] = var
            ttk.Checkbutton(frm, text=text, variable=var, command=self.regen).grid(
                row=3 + i, column=0, columnspan=3, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=3, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Обновить", command=self.regen).pack(side="left", padx=4)
        ttk.Button(btns, text="Копировать", command=self.copy).pack(side="left", padx=4)
        if select:
            ttk.Button(btns, text="Использовать", style="Accent.TButton",
                       command=self.use).pack(side="left", padx=4)
        else:
            ttk.Button(btns, text="Закрыть", command=top.destroy).pack(side="left", padx=4)
        top.bind("<Escape>", lambda e: top.destroy())
        self.regen()
        top.grab_set()
        parent.wait_window(top)

    def regen(self):
        try:
            length = int(self.length.get())
        except Exception:
            length = 16
        try:
            pw = generate_password(length, **{k: v.get() for k, v in self.opts.items()})
        except ValueError:
            messagebox.showwarning(APP_NAME, "Выберите хотя бы один тип символов.", parent=self.top)
            self.opts["lower"].set(True)
            return
        self.out.set(pw)
        bits, text, level = strength(pw)
        self.bar["value"] = min(100, bits)
        self.bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
        self.lbl.config(text=text)

    def copy(self):
        self.app.copy_text(self.out.get(), "Пароль")

    def use(self):
        self.result = self.out.get()
        self.top.destroy()


class EntryDialog:
    def __init__(self, app, parent, entry=None, category=""):
        self.app, self.result = app, None
        t = app.t
        is_new = not entry
        entry = entry or {}
        top = self.top = _new_top(app, parent, "Новая запись" if is_new else "Запись")
        frm = ttk.Frame(top, padding=16)
        frm.pack()
        self.vars = {}
        r = 0

        def label(row, text):
            ttk.Label(frm, text=text).grid(row=row, column=0, sticky="nw", pady=5, padx=(0, 12))

        if is_new:
            label(r, "Шаблон")
            self.tpl = tk.StringVar(value="Пустая запись")
            cb = ttk.Combobox(frm, textvariable=self.tpl, values=list(TEMPLATES),
                              state="readonly", width=36)
            cb.grid(row=r, column=1, sticky="we")
            cb.bind("<<ComboboxSelected>>", self._apply_template)
            r += 1
        pw_row = None
        for key, text, show in (("title", "Сервис / название *", ""), ("url", "Адрес сайта", ""),
                                ("login", "Логин / e-mail", ""), ("password", "Пароль", "•")):
            label(r, text)
            self.vars[key] = tk.StringVar(value=entry.get(key, ""))
            e = ttk.Entry(frm, textvariable=self.vars[key], width=38, show=show)
            e.grid(row=r, column=1, sticky="we")
            if key == "title":
                e.focus_set()
            if key == "password":
                self.pw_entry, pw_row = e, r
            r += 1
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Показать", variable=self.show_var,
                        command=self._toggle).grid(row=pw_row, column=2, padx=(8, 0), sticky="w")
        ttk.Button(frm, text="Генератор…", command=self._generate).grid(
            row=pw_row, column=3, padx=(4, 0))
        self.bar = ttk.Progressbar(frm, maximum=100)
        self.bar.grid(row=r, column=1, sticky="we", pady=(0, 2))
        self.bar_lbl = ttk.Label(frm, text="", foreground=t["muted"])
        self.bar_lbl.grid(row=r, column=2, columnspan=2, sticky="w", padx=(8, 0))
        self.vars["password"].trace_add("write", lambda *a: self._strength())
        self._strength()
        r += 1

        label(r, "Ключ 2FA (TOTP)")
        self.vars["totp"] = tk.StringVar(value=entry.get("totp", ""))
        ttk.Entry(frm, textvariable=self.vars["totp"], width=38).grid(row=r, column=1, sticky="we")
        ttk.Label(frm, text="секрет или otpauth://", foreground=t["muted"]).grid(
            row=r, column=2, columnspan=2, sticky="w", padx=(8, 0))
        r += 1
        label(r, "Категория")
        self.vars["category"] = tk.StringVar(value=entry.get("category", category))
        ttk.Combobox(frm, textvariable=self.vars["category"], values=app.vault.categories(),
                     width=36).grid(row=r, column=1, sticky="we")
        r += 1
        label(r, "Теги (через запятую)")
        self.vars["tags"] = tk.StringVar(value=entry.get("tags", ""))
        ttk.Entry(frm, textvariable=self.vars["tags"], width=38).grid(row=r, column=1, sticky="we")
        r += 1
        self.fav = tk.BooleanVar(value=entry.get("favorite", False))
        ttk.Checkbutton(frm, text="★ Избранное", variable=self.fav).grid(
            row=r, column=1, sticky="w", pady=4)
        r += 1

        def textbox(row, height, title, hint=None):
            label(row, title)
            box = tk.Text(frm, width=38, height=height, wrap="word", relief="flat",
                          bg=t["card"], fg=t["fg"], insertbackground=t["fg"], highlightthickness=1,
                          highlightbackground=t["border"], highlightcolor=t["accent"], padx=6, pady=4)
            box.grid(row=row, column=1, columnspan=3, sticky="we")
            if hint:
                ttk.Label(frm, text=hint, foreground=t["muted"], font=(FF, 8)).grid(
                    row=row + 1, column=1, columnspan=3, sticky="w")
            return box

        self.fields = textbox(r, 3, "Доп. поля", "по строке: «Название = значение», секретные — «Название* = значение»")
        self.fields.insert("1.0", format_fields(entry.get("fields", [])))
        r += 2
        self.note = textbox(r, 3, "Заметка")
        self.note.insert("1.0", entry.get("note", ""))
        r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=4, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Сохранить", style="Accent.TButton", command=self._ok).pack(
            side="left", padx=4)
        ttk.Button(btns, text="Отмена", command=top.destroy).pack(side="left")
        top.bind("<Escape>", lambda e: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    def _apply_template(self, _=None):
        tpl = TEMPLATES.get(self.tpl.get(), {})
        if tpl.get("category") and not self.vars["category"].get().strip():
            self.vars["category"].set(tpl["category"])
        if tpl.get("fields") and not self.fields.get("1.0", "end").strip():
            self.fields.insert("1.0", format_fields(
                [{"name": n, "value": "", "secret": s} for n, s in tpl["fields"]]))

    def _toggle(self):
        self.pw_entry.config(show="" if self.show_var.get() else "•")

    def _strength(self):
        bits, text, level = strength(self.vars["password"].get())
        self.bar["value"] = min(100, bits)
        self.bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
        self.bar_lbl.config(text=text)

    def _generate(self):
        pw = GeneratorDialog(self.app, self.top, select=True).result
        if pw:
            self.vars["password"].set(pw)
            self.show_var.set(True)
            self._toggle()

    def _ok(self):
        title = self.vars["title"].get().strip()
        if not title:
            messagebox.showwarning(APP_NAME, "Укажите название сервиса.", parent=self.top)
            return
        totp = self.vars["totp"].get().strip()
        if totp:
            try:
                totp_now(totp)
            except Exception:
                messagebox.showwarning(APP_NAME, "Ключ 2FA не распознан. Нужна строка base32 "
                                       "(буквы A–Z и цифры 2–7) или ссылка otpauth://.",
                                       parent=self.top)
                return
        self.result = {
            "title": title,
            "url": self.vars["url"].get().strip(),
            "login": self.vars["login"].get().strip(),
            "password": self.vars["password"].get(),
            "totp": totp,
            "category": self.vars["category"].get().strip(),
            "tags": self.vars["tags"].get().strip(),
            "fields": parse_fields(self.fields.get("1.0", "end")),
            "note": self.note.get("1.0", "end").strip(),
            "favorite": bool(self.fav.get()),
        }
        self.top.destroy()


class AuditDialog:
    def __init__(self, app, parent):
        self.chosen = None
        issues = app.vault.audit()
        top = self.top = _new_top(app, parent, "Аудит безопасности")
        top.resizable(True, True)
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        total = len(app.vault.active())
        head = (f"Проверено записей: {total}. Найдено проблем: {len(issues)}."
                if issues else f"Проверено записей: {total}. Проблем не найдено 👍")
        ttk.Label(frm, text=head, font=(FF, 11, "bold")).pack(anchor="w", pady=(0, 8))
        cols = ("issue", "title", "login")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=14)
        for c, name, w in (("issue", "Проблема", 230), ("title", "Сервис", 200), ("login", "Логин", 200)):
            self.tree.heading(c, text=name)
            self.tree.column(c, width=w, anchor="w")
        self.ids = {}
        for i, (text, e) in enumerate(issues):
            iid = str(i)
            self.ids[iid] = e["id"]
            self.tree.insert("", "end", iid=iid, values=(text, e["title"], e["login"]))
        self.tree.pack(fill="both", expand=True)
        ttk.Label(frm, text="Двойной клик — перейти к записи", foreground=app.t["muted"]).pack(
            anchor="w", pady=(6, 0))
        self.tree.bind("<Double-1>", self._pick)
        top.bind("<Escape>", lambda e: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    def _pick(self, _=None):
        sel = self.tree.selection()
        if sel:
            self.chosen = self.ids.get(sel[0])
            self.top.destroy()


class HistoryDialog:
    def __init__(self, app, parent, entry):
        self.app, self.entry, self.show = app, entry, False
        top = self.top = _new_top(app, parent, "История паролей — " + entry["title"])
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frm, columns=("date", "pw"), show="headings", height=8)
        self.tree.heading("date", text="Заменён")
        self.tree.heading("pw", text="Прежний пароль")
        self.tree.column("date", width=150)
        self.tree.column("pw", width=260)
        self.tree.pack(fill="both", expand=True)
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Показать/скрыть", command=self._toggle).pack(side="left")
        ttk.Button(btns, text="Копировать", command=self._copy).pack(side="left", padx=6)
        ttk.Button(btns, text="Закрыть", command=top.destroy).pack(side="right")
        self._fill()
        top.bind("<Escape>", lambda e: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    def _fill(self):
        self.tree.delete(*self.tree.get_children())
        for i, h in enumerate(self.entry["history"]):
            self.tree.insert("", "end", iid=str(i),
                             values=(h["changed"], h["password"] if self.show else "•" * 10))

    def _toggle(self):
        self.show = not self.show
        self._fill()

    def _copy(self):
        sel = self.tree.selection()
        if sel:
            self.app.copy_text(self.entry["history"][int(sel[0])]["password"], "Пароль")


class SettingsDialog:
    FLAGS = (("lock_on_minimize", "Блокировать при сворачивании окна"),
             ("lock_on_session_lock", "Блокировать при блокировке Windows (Win+L)"),
             ("close_to_tray", "Кнопка ✕ сворачивает в трей, а не закрывает"),
             ("hotkey_enabled", "Быстрый поиск по глобальной горячей клавише"),
             ("protect_capture", "Скрывать окно от скриншотов и записи экрана"),
             ("autotype_enter", "После автоввода нажимать Enter"),
             ("check_updates", "Проверять обновления при запуске"))

    def __init__(self, app, parent):
        s = app.settings
        self.app = app
        top = self.top = _new_top(app, parent, "Настройки")
        frm = ttk.Frame(top, padding=20)
        frm.pack()
        self.idle = tk.IntVar(value=s.get("idle_minutes"))
        self.clip = tk.IntVar(value=s.get("clipboard_seconds"))
        self.hotkey = tk.StringVar(value=s.get("hotkey"))
        self.repo = tk.StringVar(value=s.get("update_repo"))
        self.flags = {k: tk.BooleanVar(value=bool(s.get(k))) for k, _ in self.FLAGS}
        hello_button = ttk.Button(frm, text="Windows Hello: включить / отключить",
                                  command=self._configure_hello)
        ttk.Label(frm, text="Блокировать через (мин) бездействия").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Spinbox(frm, from_=1, to=120, textvariable=self.idle, width=6).grid(row=0, column=1, sticky="w", padx=12)
        ttk.Label(frm, text="Очищать буфер обмена через (сек)").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Spinbox(frm, from_=5, to=300, textvariable=self.clip, width=6).grid(row=1, column=1, sticky="w", padx=12)
        ttk.Label(frm, text="Горячая клавиша быстрого поиска").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Combobox(frm, textvariable=self.hotkey, width=18,
                     values=("Ctrl+Alt+P", "Ctrl+Alt+Space", "Ctrl+Shift+Space", "Ctrl+Alt+L")).grid(
            row=2, column=1, sticky="w", padx=12)
        for i, (key, text) in enumerate(self.FLAGS, start=3):
            ttk.Checkbutton(frm, text=text, variable=self.flags[key]).grid(
                row=i, column=0, columnspan=2, sticky="w", pady=2)
        row = 3 + len(self.FLAGS)
        ttk.Label(frm, text="Репозиторий GitHub для обновлений").grid(row=row, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(frm, textvariable=self.repo, width=24).grid(row=row, column=1, sticky="w", padx=12, pady=(10, 0))
        ttk.Label(frm, text="например: ivan/moi-paroli", foreground=app.t["muted"], font=(FF, 8)).grid(
            row=row + 1, column=1, sticky="w", padx=12)
        hello_button.grid(row=row + 2, column=0, columnspan=2, sticky="ew", pady=(12, 6))
        btns = ttk.Frame(frm)
        btns.grid(row=row + 3, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Сохранить", style="Accent.TButton", command=self.save).pack(side="left", padx=4)
        ttk.Button(btns, text="Отмена", command=top.destroy).pack(side="left")
        top.grab_set()
        parent.wait_window(top)

    def _configure_hello(self):
        self.top.grab_release()
        self.top.withdraw()
        try:
            self.app.configure_hello()
        finally:
            self.top.deiconify()
            self.top.grab_set()

    def save(self):
        s = self.app.settings
        try:
            idle, clip = max(1, int(self.idle.get())), max(5, int(self.clip.get()))
        except Exception:
            messagebox.showwarning(APP_NAME, "Введите числа.", parent=self.top)
            return
        hk = self.hotkey.get().strip()
        try:
            parse_hotkey(hk)
        except ValueError as ex:
            messagebox.showwarning(APP_NAME, f"Горячая клавиша: {ex}", parent=self.top)
            return
        repo = self.repo.get().strip()
        if repo and not REPO_RE.match(repo):
            messagebox.showwarning(APP_NAME, "Репозиторий нужно указать как «владелец/имя».", parent=self.top)
            return
        s.set("idle_minutes", idle)
        s.set("clipboard_seconds", clip)
        s.set("hotkey", hk)
        s.set("update_repo", repo)
        for k, v in self.flags.items():
            s.set(k, bool(v.get()))
        self.app.apply_settings()
        self.top.destroy()


class AttachmentsDialog:
    def __init__(self, app, parent, entry_id):
        self.app, self.eid = app, entry_id
        e = app.vault.get(entry_id)
        top = self.top = _new_top(app, parent, "Вложения — " + e["title"])
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frm, columns=("name", "size"), show="headings", height=8)
        self.tree.heading("name", text="Файл")
        self.tree.heading("size", text="Размер")
        self.tree.column("name", width=300)
        self.tree.column("size", width=100, anchor="e")
        self.tree.pack(fill="both", expand=True)
        ttk.Label(frm, text="Файлы хранятся внутри зашифрованного хранилища. Максимум 3 МБ на файл.",
                  foreground=app.t["muted"]).pack(anchor="w", pady=(6, 0))
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Добавить…", style="Accent.TButton", command=self.add).pack(side="left")
        ttk.Button(btns, text="Сохранить как…", command=self.save_as).pack(side="left", padx=6)
        ttk.Button(btns, text="Удалить", command=self.remove).pack(side="left")
        ttk.Button(btns, text="Закрыть", command=top.destroy).pack(side="right")
        self._fill()
        top.bind("<Escape>", lambda ev: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    @staticmethod
    def _size(n):
        return f"{n / 1024:.0f} КБ" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} МБ"

    def _fill(self):
        self.tree.delete(*self.tree.get_children())
        e = self.app.vault.get(self.eid)
        for a in (e["attachments"] if e else []):
            self.tree.insert("", "end", iid=a["id"], values=(a["name"], self._size(a["size"])))

    def add(self):
        path = filedialog.askopenfilename(parent=self.top, title="Выберите файл")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as ex:
            messagebox.showerror(APP_NAME, f"Не удалось прочитать файл:\n{ex}", parent=self.top)
            return
        ok, _ = self.app._do(self.app.vault.add_attachment, self.eid, os.path.basename(path), data)
        if ok:
            self._fill()
            self.app.saved_note()

    def save_as(self):
        sel = self.tree.selection()
        if not sel:
            return
        e = self.app.vault.get(self.eid)
        att = next((a for a in e["attachments"] if a["id"] == sel[0]), None)
        data = self.app.vault.get_attachment(self.eid, sel[0])
        if att is None or data is None:
            return
        path = filedialog.asksaveasfilename(parent=self.top, initialfile=att["name"])
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                messagebox.showinfo(APP_NAME, "Файл сохранён.", parent=self.top)
            except OSError as ex:
                messagebox.showerror(APP_NAME, f"Ошибка: {ex}", parent=self.top)

    def remove(self):
        sel = self.tree.selection()
        if sel and messagebox.askyesno(APP_NAME, "Удалить вложение?", parent=self.top):
            ok, _ = self.app._do(self.app.vault.remove_attachment, self.eid, sel[0])
            if ok:
                self._fill()
                self.app.saved_note()


class BreachDialog:
    """Проверка всех паролей по базе утечек. Наружу уходят только 5 символов хеша."""

    def __init__(self, app, parent):
        self.app, self.chosen = app, None
        self.entries = [e for e in app.vault.active() if e["password"]]
        self.unique = sorted({e["password"] for e in self.entries})
        top = self.top = _new_top(app, parent, "Проверка на утечки")
        top.resizable(True, True)
        self.frm = ttk.Frame(top, padding=16)
        self.frm.pack(fill="both", expand=True)
        self.lbl = ttk.Label(self.frm, text=f"Проверено 0 из {len(self.unique)}…", font=(FF, 11, "bold"))
        self.lbl.pack(anchor="w")
        self.bar = ttk.Progressbar(self.frm, maximum=max(1, len(self.unique)), length=420)
        self.bar.pack(fill="x", pady=10)
        self.q = queue.Queue()
        self.stop = threading.Event()
        top.protocol("WM_DELETE_WINDOW", self._close)
        threading.Thread(target=self._work, daemon=True).start()
        self._poll()
        top.grab_set()
        parent.wait_window(top)

    def _close(self):
        self.stop.set()
        self.top.destroy()

    def _work(self):
        res = {}
        for i, pw in enumerate(self.unique, 1):
            if self.stop.is_set():
                return
            try:
                res[pw] = pwned_count(pw)
            except Exception as ex:
                self.q.put(("error", str(ex)))
                return
            self.q.put(("progress", i))
            time.sleep(0.12)
        self.q.put(("done", res))

    def _poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "progress":
                    self.bar["value"] = val
                    self.lbl.config(text=f"Проверено {val} из {len(self.unique)}…")
                elif kind == "error":
                    messagebox.showwarning(APP_NAME, f"Не удалось проверить (нужен интернет):\n{val}",
                                           parent=self.top)
                    self._close()
                    return
                else:
                    self._show(val)
                    return
        except queue.Empty:
            pass
        if not self.stop.is_set():
            try:
                self.top.after(100, self._poll)
            except tk.TclError:
                pass

    def _show(self, res):
        self.bar.pack_forget()
        bad = [(e, res.get(e["password"], 0)) for e in self.entries if res.get(e["password"], 0) > 0]
        if not bad:
            self.lbl.config(text="Ваших паролей в известных утечках не найдено 👍")
            ttk.Button(self.frm, text="Закрыть", command=self._close).pack(anchor="e", pady=(12, 0))
            return
        self.lbl.config(text=f"Найдено в утечках: {len(bad)}. Смените эти пароли.")
        tree = ttk.Treeview(self.frm, columns=("title", "login", "n"), show="headings", height=12)
        for c, name, w in (("title", "Сервис", 200), ("login", "Логин", 180), ("n", "Встречается раз", 120)):
            tree.heading(c, text=name)
            tree.column(c, width=w, anchor="w")
        ids = {}
        for e, n in sorted(bad, key=lambda x: -x[1]):
            tree.insert("", "end", iid=e["id"], values=(e["title"], e["login"], f"{n:,}".replace(",", " ")))
            ids[e["id"]] = e["id"]
        tree.pack(fill="both", expand=True)
        ttk.Label(self.frm, text="Двойной клик — перейти к записи", foreground=self.app.t["muted"]).pack(
            anchor="w", pady=(6, 0))

        def pick(_=None):
            sel = tree.selection()
            if sel:
                self.chosen = sel[0]
                self._close()
        tree.bind("<Double-1>", pick)


class KeyfileDialog:
    def __init__(self, app, parent):
        self.app = app
        v = app.vault
        top = self.top = _new_top(app, parent, "Ключевой файл")
        frm = ttk.Frame(top, padding=20)
        frm.pack()
        ttk.Label(frm, text="Ключевой файл сейчас " + ("ВКЛЮЧЁН" if v.uses_keyfile else "выключен"),
                  font=(FF, 12, "bold")).pack(anchor="w")
        ttk.Label(frm, wraplength=440, justify="left", foreground=app.t["muted"], text=(
            "Ключевой файл — второй «ключ» к хранилищу. Для входа понадобятся и мастер-пароль, "
            "и этот файл (его удобно держать на флешке). Украв пароль или файл по отдельности, "
            "хранилище не открыть.\n\nВНИМАНИЕ: если потерять ключевой файл, данные восстановить "
            "невозможно, в том числе из резервных копий. Сразу сделайте копию файла в надёжном месте.")
                  ).pack(anchor="w", pady=12)
        if v.uses_keyfile:
            ttk.Button(frm, text="Выключить ключевой файл", command=self.disable).pack(fill="x", pady=3)
        else:
            ttk.Button(frm, text="Создать новый ключевой файл и включить…", style="Accent.TButton",
                       command=self.create).pack(fill="x", pady=3)
            ttk.Button(frm, text="Включить с уже имеющимся файлом…", command=self.existing).pack(fill="x", pady=3)
        ttk.Button(frm, text="Закрыть", command=top.destroy).pack(fill="x", pady=(10, 0))
        top.grab_set()
        parent.wait_window(top)

    def _password(self):
        pw = simpledialog.askstring(APP_NAME, "Введите мастер-пароль для подтверждения:",
                                    show="•", parent=self.top)
        if not pw:
            return None
        if not self.app.vault.verify_password(pw):
            messagebox.showerror(APP_NAME, "Неверный мастер-пароль.", parent=self.top)
            return None
        return pw

    def create(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.asksaveasfilename(parent=self.top, defaultextension=".key",
                                            title="Куда сохранить ключевой файл (лучше на флешку)",
                                            initialfile="moi-paroli.key")
        if not path:
            return
        content = secrets.token_bytes(64)
        try:
            with open(path, "wb") as f:
                f.write(content)
        except OSError as ex:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить файл:\n{ex}", parent=self.top)
            return
        self._apply(pw, content, path)

    def existing(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.askopenfilename(parent=self.top, title="Выберите ключевой файл")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError as ex:
            messagebox.showerror(APP_NAME, f"Не удалось прочитать файл:\n{ex}", parent=self.top)
            return
        if not content:
            messagebox.showerror(APP_NAME, "Файл пустой.", parent=self.top)
            return
        self._apply(pw, content, path)

    def disable(self):
        pw = self._password()
        if pw and messagebox.askyesno(APP_NAME, "Выключить ключевой файл? Вход будет только по паролю.",
                                      parent=self.top):
            self._apply(pw, None, "")

    def _apply(self, pw, content, path):
        ok, _ = self.app._do(self.app.vault.set_keyfile, pw, content)
        if ok:
            self.app.settings.set("keyfile_path", path)
            messagebox.showinfo(APP_NAME, "Готово. Хранилище пересохранено." + (
                "\nНе потеряйте ключевой файл!" if content else ""), parent=self.top)
            self.top.destroy()


class QuickSearch:
    """Маленькое окно поиска по горячей клавише: Enter — пароль, Ctrl+Enter — ввести в окно."""

    def __init__(self, app, prev_hwnd=0):
        self.app, self.prev, self.items = app, prev_hwnd, []
        t = app.t
        top = self.top = tk.Toplevel(app.root)
        top.overrideredirect(True)
        top.attributes("-topmost", True)
        top.configure(bg=t["accent"])
        w, h = 600, 380
        top.geometry(f"{w}x{h}+{(top.winfo_screenwidth() - w) // 2}+{int(top.winfo_screenheight() * 0.16)}")
        inner = ttk.Frame(top, style="Panel.TFrame", padding=14)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        self.var = tk.StringVar()
        self.entry = ttk.Entry(inner, textvariable=self.var, font=(FF, 14))
        self.entry.pack(fill="x")
        self.lb = tk.Listbox(inner, bg=t["panel"], fg=t["fg"], selectbackground=t["sel"],
                             selectforeground=t["fg"], activestyle="none", relief="flat",
                             highlightthickness=0, borderwidth=0, font=(FF, 11))
        self.lb.pack(fill="both", expand=True, pady=(10, 6))
        ttk.Label(inner, style="Muted.TLabel", text="Enter — пароль   Shift+Enter — логин   "
                  "Ctrl+Enter — ввести в окно   Esc — закрыть").pack(anchor="w")
        self.var.trace_add("write", lambda *a: self._filter())
        for widget in (top, self.entry, self.lb):
            widget.bind("<Return>", lambda e: self._act("pw"))
            widget.bind("<Shift-Return>", lambda e: self._act("login"))
            widget.bind("<Control-Return>", lambda e: self._act("type"))
            widget.bind("<Escape>", lambda e: self.close())
            widget.bind("<Down>", lambda e: self._move(1))
            widget.bind("<Up>", lambda e: self._move(-1))
        self.lb.bind("<Double-1>", lambda e: self._act("pw"))
        top.bind("<FocusOut>", lambda e: top.after(150, self._check_focus))
        self._filter()
        top.after(30, self._focus)

    def _focus(self):
        try:
            self.top.focus_force()
            self.entry.focus_set()
        except tk.TclError:
            pass

    def _check_focus(self):
        try:
            if self.top.focus_displayof() is None:
                self.close()
        except tk.TclError:
            pass

    def _filter(self):
        q = self.var.get().strip().lower()
        pool = [e for e in self.app.vault.active() if not q or q in " ".join(
            (e["title"], e["login"], e["url"], e["tags"], e["category"])).lower()]
        pool.sort(key=lambda e: (not e["favorite"], e["title"].lower()))
        self.items = pool[:60]
        self.lb.delete(0, "end")
        for e in self.items:
            self.lb.insert("end", f'{"★ " if e["favorite"] else ""}{e["title"]}    —    {e["login"]}')
        if self.items:
            self.lb.selection_set(0)

    def _move(self, d):
        if self.items:
            cur = self.lb.curselection()
            i = max(0, min(len(self.items) - 1, (cur[0] if cur else 0) + d))
            self.lb.selection_clear(0, "end")
            self.lb.selection_set(i)
            self.lb.see(i)
        return "break"

    def _cur(self):
        cur = self.lb.curselection()
        return self.items[cur[0]] if cur and cur[0] < len(self.items) else None

    def _act(self, what):
        e = self._cur()
        self.close()
        if not e:
            return "break"
        if what == "pw":
            self.app.copy_text(e["password"], "Пароль")
        elif what == "login":
            self.app.copy_text(e["login"], "Логин")
        else:
            self.app.autotype_entry(e, self.prev)
        return "break"

    def close(self):
        try:
            self.top.destroy()
        except tk.TclError:
            pass
        return "break"


# ==========================================================================
#  Главное приложение
# ==========================================================================
class App:
    COLUMNS = (("fav", "★", 38), ("title", "Сервис", 200), ("login", "Логин", 180),
               ("category", "Категория", 130), ("updated", "Изменено", 100))

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.settings = Settings(os.path.join(data_dir(), "settings.json"))
        vp = self.settings.get("vault_path")
        self.vault = Vault(vp if vp else os.path.join(data_dir(), "vault.dat"))
        self.vault.backup_dir = os.path.join(data_dir(), "backups")
        self.hello = HelloUnlock(self.vault.path, os.path.join(data_dir(), "hello_credential.json"))
        self._q = queue.Queue()
        self.tray = self.hotkey = None
        self._prev_hwnd = 0
        self._sync_at = 0.0
        geo = str(self.settings.get("geometry") or "")
        self.root.geometry(geo if re.fullmatch(r"\d+x\d+(?:[+-]-?\d+){0,2}", geo) else "1360x820")
        self.root.minsize(min(1240, self.root.winfo_screenwidth()-80),
                          min(720, self.root.winfo_screenheight()-100))
        self.icon = self.logo = None
        try:
            self.icon = tk.PhotoImage(data=ICON_B64)
            self.logo = self.icon.subsample(2)
            self.root.iconphoto(True, self.icon)
        except tk.TclError:
            pass
        self.frame = None
        self.last_activity = time.time()
        self.cat_filter = "all"
        self.sort = ("title", False)
        self.pw_visible = False
        self._last_sel = None
        self._clip_job = self._totp_job = self._pw_job = None
        self._fails = 0
        self._next_try = 0.0
        self.apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Unmap>", self._on_unmap)
        for ev in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.root.bind_all(ev, self._touch, add="+")
        self.root.after(5000, self._idle_tick)
        self.root.after(150, self._pump)
        self.root.after(2000, self._watch_tick)
        self.apply_capture()
        self._start_services()
        self.show_login()
        if self.settings.get("check_updates") and self.settings.get("update_repo"):
            self.root.after(3000, lambda: self.check_updates(manual=False))

    # ---------------- тема
    def apply_theme(self):
        name = self.settings.get("theme")
        self.theme_name = name if name in THEMES else "dark"
        t = self.t = THEMES[self.theme_name]
        s = self.style = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        r = self.root
        r.configure(bg=t["bg"])
        r.option_add("*TCombobox*Listbox.background", t["card"])
        r.option_add("*TCombobox*Listbox.foreground", t["fg"])
        r.option_add("*TCombobox*Listbox.selectBackground", t["accent"])
        r.option_add("*TCombobox*Listbox.selectForeground", t["accent_fg"])
        dark_titlebar(r, self.theme_name == "dark")

        s.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["card"],
                    bordercolor=t["border"], lightcolor=t["border"], darkcolor=t["border"],
                    troughcolor=t["border"], focuscolor=t["accent"], font=(FF, 10))
        s.configure("TFrame", background=t["bg"])
        s.configure("Section.TLabel", background=t["panel"], foreground=t["fg"], font=(FF, 13, "bold"))
        s.configure("DetailCaption.TLabel", background=t["panel"], foreground=t["muted"], font=(FF, 10))
        s.configure("Compact.TButton", padding=(10, 5))
        s.configure("Search.TEntry", padding=(12, 10), font=(FF, 11))
        s.configure("TLabel", background=t["bg"], foreground=t["fg"])
        for nm, col in (("Side", t["side"]), ("Panel", t["panel"]), ("Card", t["card"])):
            s.configure(f"{nm}.TFrame", background=col)
            s.configure(f"{nm}.TLabel", background=col, foreground=t["fg"])
        s.configure("BgMuted.TLabel", background=t["bg"], foreground=t["muted"], font=(FF, 9))
        s.configure("Muted.TLabel", background=t["panel"], foreground=t["muted"], font=(FF, 9))
        s.configure("CardMuted.TLabel", background=t["card"], foreground=t["muted"], font=(FF, 9))
        s.configure("SideMuted.TLabel", background=t["side"], foreground=t["muted"], font=(FF, 9))
        s.configure("Title.TLabel", background=t["panel"], foreground=t["fg"], font=(FF, 16, "bold"))
        s.configure("Big.TLabel", background=t["card"], foreground=t["fg"], font=(FF, 24, "bold"))
        s.configure("Brand.TLabel", background=t["side"], foreground=t["fg"], font=(FF, 15, "bold"))
        s.configure("Hero.TLabel", background=t["bg"], foreground=t["fg"], font=(FF, 26, "bold"))
        s.configure("HeroMuted.TLabel", background=t["bg"], foreground=t["muted"], font=(FF, 10))
        s.configure("SideHeading.TLabel", background=t["side"], foreground=t["muted"], font=(FF, 9, "bold"))
        s.configure("Mono.TLabel", background=t["panel"], foreground=t["fg"], font=(MONO, 11))

        s.configure("TButton", padding=(14, 9), background=t["card"], foreground=t["fg"],
                    bordercolor=t["border"], relief="flat", focusthickness=0)
        s.map("TButton", background=[("active", t["hover"]), ("pressed", t["sel"])],
              bordercolor=[("focus", t["accent"])])
        s.configure("Accent.TButton", background=t["accent"], foreground=t["accent_fg"],
                    bordercolor=t["accent"])
        s.map("Accent.TButton", background=[("active", t["accent_hi"]), ("pressed", t["accent"])],
              bordercolor=[("active", t["accent_hi"])])
        s.configure("Ghost.TButton", background=t["side"], foreground=t["fg"], bordercolor=t["side"])
        s.map("Ghost.TButton", background=[("active", t["hover"])], bordercolor=[("active", t["hover"])])
        s.configure("Tool.TMenubutton", background=t["side"], foreground=t["fg"],
                    bordercolor=t["side"], arrowcolor=t["muted"], padding=(10, 6), relief="flat")
        s.map("Tool.TMenubutton", background=[("active", t["hover"])],
              bordercolor=[("active", t["hover"])])

        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=t["panel"], fieldbackground=t["panel"],
                    foreground=t["fg"], rowheight=48, borderwidth=0, relief="flat")
        s.map("Treeview", background=[("selected", t["sel"])], foreground=[("selected", t["fg"])])
        s.configure("Treeview.Heading", background=t["side"], foreground=t["muted"],
                    font=(FF, 9, "bold"), relief="flat", padding=(8, 8), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", t["hover"])])
        s.configure("Side.Treeview", background=t["side"], fieldbackground=t["side"],
                    rowheight=44)
        s.map("Side.Treeview", background=[("selected", t["sel"])])

        for w in ("TEntry", "TCombobox", "TSpinbox"):
            s.configure(w, fieldbackground=t["card"], foreground=t["fg"], insertcolor=t["fg"],
                        padding=6, bordercolor=t["border"], lightcolor=t["border"],
                        darkcolor=t["border"], arrowcolor=t["muted"], background=t["card"])
            s.map(w, bordercolor=[("focus", t["accent"])], lightcolor=[("focus", t["accent"])],
                  darkcolor=[("focus", t["accent"])])
        s.map("TCombobox", fieldbackground=[("readonly", t["card"])])
        s.configure("TCheckbutton", background=t["bg"], foreground=t["fg"],
                    indicatorbackground=t["card"], indicatorforeground=t["accent_fg"])
        s.map("TCheckbutton", indicatorbackground=[("selected", t["accent"]), ("active", t["hover"])],
              background=[("active", t["bg"])])
        s.configure("Vertical.TScrollbar", background=t["border"], troughcolor=t["panel"],
                    bordercolor=t["panel"], arrowcolor=t["muted"], lightcolor=t["border"],
                    darkcolor=t["border"], relief="flat", gripcount=0)
        s.map("Vertical.TScrollbar", background=[("active", t["muted"])])
        s.configure("TPanedwindow", background=t["bg"])
        s.configure("TSeparator", background=t["border"])
        for name, color in (("Bad", t["bad"]), ("Warn", t["warn"]), ("Good", t["good"])):
            s.configure(f"{name}.Horizontal.TProgressbar", background=color, troughcolor=t["border"],
                        lightcolor=color, darkcolor=color, bordercolor=t["border"], thickness=7)

    def toggle_theme(self):
        self.settings.set("theme", "light" if self.theme_name == "dark" else "dark")
        self.apply_theme()
        if self.vault.unlocked:
            self.show_main()
        else:
            self.show_login()

    def _menu(self):
        t = self.t
        return tk.Menu(self.root, tearoff=0, bg=t["panel"], fg=t["fg"], bd=0, relief="flat",
                       activebackground=t["accent"], activeforeground=t["accent_fg"],
                       font=(FF, 10))

    # ---------------- общее
    def _touch(self, _=None):
        self.last_activity = time.time()

    def _idle_tick(self):
        limit = int(self.settings.get("idle_minutes")) * 60
        if self.vault.unlocked and time.time() - self.last_activity > limit:
            self.lock()
        self.root.after(5000, self._idle_tick)

    def _on_unmap(self, event):
        if event.widget is not self.root:
            return

        def check():
            try:
                if (self.vault.unlocked and self.settings.get("lock_on_minimize")
                        and self.root.state() == "iconic"):
                    self.lock()
            except tk.TclError:
                pass
        self.root.after(100, check)

    def on_close(self):
        if self.tray and self.settings.get("close_to_tray"):
            self.hide_window()
        else:
            self.quit_app()

    def _swap(self, frame):
        if self.frame is not None:
            self.frame.destroy()
        self.frame = frame
        self.frame.pack(fill="both", expand=True)

    # ---------------- фоновые службы: очередь событий, трей, горячая клавиша, синхронизация
    def post(self, fn):
        """Выполнить fn в потоке интерфейса (можно вызывать из любого потока)."""
        self._q.put(fn)

    def _pump(self):
        try:
            while True:
                fn = self._q.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.root.after(150, self._pump)

    def _watch_tick(self):
        try:
            if self.vault.unlocked:
                if self.settings.get("lock_on_session_lock") and win_session_locked():
                    self.lock()
                elif time.time() - self._sync_at > 10:
                    self._sync_at = time.time()
                    self._sync_now()
        except Exception:
            pass
        self.root.after(2000, self._watch_tick)

    def _sync_now(self):
        try:
            changed = self.vault.sync_from_disk()
        except SyncConflict:
            self.set_status("Конфликт записей: Инструменты → Разрешить конфликты", self.t["warn"])
            return
        except KeyChanged:
            messagebox.showwarning(APP_NAME, "Хранилище изменено на другом устройстве с другим "
                                   "мастер-паролем или ключевым файлом.\nВойдите заново.", parent=self.root)
            self.lock()
            return
        except (VaultError, OSError):
            return  # файл мог быть записан не до конца — повторим позже
        if changed:
            self.vault.merged = False
            self.refresh_all()
            self.set_status("↻ Подтянуты изменения с другого устройства", self.t["warn"])

    def _after_merge(self):
        if self.vault.merged:
            self.vault.merged = False
            self.refresh_all()
            self.set_status("↻ Подтянуты изменения с другого устройства", self.t["warn"])

    def _start_services(self):
        self.tray = start_tray(self)
        self.restart_hotkey()

    def restart_hotkey(self):
        if self.hotkey:
            self.hotkey.stop()
            self.hotkey = None
        if not (IS_WIN and self.settings.get("hotkey_enabled")):
            return
        try:
            mods, vk = parse_hotkey(self.settings.get("hotkey"))
        except ValueError:
            return
        hk = HotkeyListener(lambda hwnd: self.post(lambda: self.on_hotkey(hwnd)), mods, vk)
        hk.start()
        hk.ready.wait(1.0)
        if hk.ok:
            self.hotkey = hk

    def apply_capture(self):
        win_capture_protect(self.root, bool(self.settings.get("protect_capture")))

    def apply_settings(self):
        self.apply_capture()
        self.restart_hotkey()

    def on_hotkey(self, hwnd=0):
        self._prev_hwnd = hwnd
        if self.vault.unlocked:
            self.quick_search()
        else:
            self.show_window()

    def quick_search(self):
        if not self.vault.unlocked:
            self.show_window()
            return
        QuickSearch(self, self._prev_hwnd)

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        try:
            self.root.attributes("-topmost", True)
            self.root.after(250, lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
        except tk.TclError:
            pass

    def hide_window(self):
        self.root.withdraw()

    def quit_app(self):
        try:
            if self.root.state() == "normal":
                self.settings.set("geometry", self.root.geometry())
        except tk.TclError:
            pass
        if self.hotkey:
            self.hotkey.stop()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.root.destroy()

    # ---------------- автоввод
    def autotype_entry(self, e, hwnd=0, delay=0.35):
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, "Автоввод работает только в Windows.", parent=self.root)
            return
        login, pw = e["login"], e["password"]
        enter = bool(self.settings.get("autotype_enter"))
        own = win_hwnd(self.root)

        def work():
            if hwnd:
                win_activate(hwnd)
            time.sleep(delay)
            if (not win_foreground() or win_foreground() == own or
                    (hwnd and win_foreground() != hwnd)):  # только указанное окно
                self.post(lambda: self.set_status("Автоввод отменён: не выбрано целевое окно",
                                                  self.t["warn"]))
                return
            ok = win_autotype(login, pw, enter)
            self.post(lambda: self.set_status("✓ Данные введены" if ok else "Не удалось ввести данные",
                                              self.t["good"] if ok else self.t["bad"]))
        threading.Thread(target=work, daemon=True).start()

    def autotype_selected(self):
        e = self.selected()
        if not e or e["deleted"]:
            return
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, "Автоввод работает только в Windows.", parent=self.root)
            return
        self.set_status("Ввод через 3 секунды: кликните в нужное поле другого окна…", self.t["warn"])
        self.root.after(3000, lambda: self.autotype_entry(e, 0, 0.0))

    # ---------------- проверки через интернет
    def check_updates(self, manual=True):
        repo = (self.settings.get("update_repo") or "").strip()
        if not REPO_RE.match(repo):
            if manual:
                messagebox.showinfo(APP_NAME, "Укажите репозиторий GitHub в Сервис → Настройки "
                                    "(например, ivan/moi-paroli).", parent=self.root)
            return

        def work():
            try:
                info = check_update(repo)
            except Exception as ex:
                info = {"error": str(ex)}
            self.post(lambda: self._show_update(info, manual))
        threading.Thread(target=work, daemon=True).start()

    def _show_update(self, info, manual):
        if "error" in info:
            if manual:
                messagebox.showwarning(APP_NAME, f"Не удалось проверить обновления:\n{info['error']}",
                                       parent=self.root)
            return
        if info["newer"]:
            if messagebox.askyesno(APP_NAME, f"Доступна версия {info['version']} (у вас {APP_VERSION}).\n"
                                   "Открыть страницу загрузки?", parent=self.root):
                if info["url"].startswith("https://github.com/"):
                    webbrowser.open(info["url"])
        elif manual:
            messagebox.showinfo(APP_NAME, "У вас последняя версия.", parent=self.root)

    def check_breaches(self):
        if not self.vault.active():
            return
        if not messagebox.askyesno(
                APP_NAME, "Пароли будут проверены по базе известных утечек Have I Been Pwned.\n"
                          "Для каждого пароля в интернет уходят только первые 5 символов его хеша SHA-1, "
                          "сам пароль и ваши логины с компьютера не уходят.\n\nНужен интернет. Продолжить?",
                parent=self.root):
            return
        d = BreachDialog(self, self.root)
        if d.chosen:
            self.goto_entry(d.chosen)

    def check_pwned_selected(self):
        e = self.selected()
        if not e or not e["password"]:
            return
        self.set_status("Проверка пароля по базе утечек…", self.t["muted"])

        def work():
            try:
                n = pwned_count(e["password"])
            except Exception as ex:
                self.post(lambda: messagebox.showwarning(
                    APP_NAME, f"Не удалось проверить (нужен интернет):\n{ex}", parent=self.root))
                return
            self.post(lambda: self._pwned_result(e, n))
        threading.Thread(target=work, daemon=True).start()

    def _pwned_result(self, e, n):
        if n:
            self.set_status(f"⚠ Пароль «{e['title']}» найден в утечках ({n} раз)", self.t["bad"])
            messagebox.showwarning(APP_NAME, f"Пароль записи «{e['title']}» найден в известных утечках "
                                   f"({n} раз). Его нужно сменить.", parent=self.root)
        else:
            self.set_status(f"✓ Пароль «{e['title']}» в утечках не найден")

    # ---------------- облачная папка, ключевой файл, вложения
    def move_vault(self):
        folder = filedialog.askdirectory(
            parent=self.root, title="Папка синхронизации (Яндекс.Диск, OneDrive, Dropbox…)")
        if not folder:
            return
        target = os.path.join(folder, "MoiParoli-vault.dat")
        if os.path.exists(target) and not messagebox.askyesno(
                APP_NAME, "В этой папке уже есть файл хранилища. Заменить его текущим?", parent=self.root):
            return
        try:
            shutil.copyfile(self.vault.path, target)
        except OSError as ex:
            messagebox.showerror(APP_NAME, f"Не удалось скопировать:\n{ex}", parent=self.root)
            return
        self.vault.path = target
        self.vault._sig = self.vault._disk_sig()
        self.settings.set("vault_path", target)
        messagebox.showinfo(
            APP_NAME, "Хранилище перенесено в выбранную папку и теперь синхронизируется вашим облаком.\n\n"
                      "На втором компьютере установите «Мои пароли» и выберите Файл → «Подключить "
                      "существующее хранилище…». Правки с обоих компьютеров объединяются автоматически.\n"
                      "Прежний локальный файл остался на месте как резервная копия.", parent=self.root)

    def attach_vault(self):
        path = filedialog.askopenfilename(parent=self.root, title="Выберите файл хранилища",
                                          filetypes=[("Хранилище", "*.dat"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            if not (isinstance(blob, dict) and blob.get("magic") in ("passvault", "passvault-v1")):
                raise ValueError("это не файл хранилища")
        except (OSError, ValueError) as ex:
            messagebox.showerror(APP_NAME, f"Файл не подходит:\n{ex}", parent=self.root)
            return
        if not messagebox.askyesno(APP_NAME, "Программа будет работать с выбранным файлом вместо "
                                   "хранилища на этом компьютере (прежний файл останется на месте). "
                                   "Продолжить?", parent=self.root):
            return
        self._hide_pw(refresh=False)
        self.vault.lock()
        self.vault.path = path
        self.settings.set("vault_path", path)
        self.show_login()

    def manage_keyfile(self):
        KeyfileDialog(self, self.root)

    def attachments(self):
        e = self.selected()
        if e and not e["deleted"]:
            AttachmentsDialog(self, self.root, e["id"])
            self.show_details()

    def _render_custom(self, e):
        for w in self.d_custom.winfo_children():
            w.destroy()
        if not e["fields"]:
            self.dfields["custom"].grid_remove()
            return
        self.dfields["custom"].grid()
        for f in e["fields"]:
            row = ttk.Frame(self.d_custom, style="Panel.TFrame")
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=f["name"], style="Muted.TLabel", font=(FF, 8)).pack(anchor="w")
            line = ttk.Frame(row, style="Panel.TFrame")
            line.pack(fill="x")
            shown = f["value"] if (not f.get("secret") or self.pw_visible) else "•" * 8
            ttk.Label(line, text=shown, style="Mono.TLabel" if f.get("secret") else "Panel.TLabel",
                      wraplength=190, justify="left").pack(side="left", fill="x", expand=True)
            ttk.Button(line, text="Копировать", width=11,
                       command=lambda v=f["value"], n=f["name"]: self.copy_text(v, n)).pack(side="right")

    def _guard(self, fn):
        """Горячая клавиша работает только при открытом хранилище."""
        return lambda e=None: fn() if self.vault.unlocked else None

    def _do(self, fn, *args):
        try:
            res = fn(*args)
        except SyncConflict:
            self.resolve_conflicts()
            return False, None
        except KeyChanged:
            messagebox.showwarning(APP_NAME, "Хранилище изменено на другом устройстве с другим "
                                   "мастер-паролем или ключевым файлом.\nВойдите заново.", parent=self.root)
            self.lock()
            return False, None
        except (OSError, VaultError) as ex:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить данные:\n{ex}", parent=self.root)
            return False, None
        self._after_merge()
        return True, res

    def resolve_conflicts(self):
        try:
            snapshot = self.vault.conflict_snapshot()
            if not snapshot["conflicts"]:
                self.vault.sync_from_disk()
                return
            dialog = ConflictDialog(self, snapshot)
            if dialog.result is None:
                return
            self.vault.resolve_conflicts(snapshot, dialog.result)
            self.refresh_all()
            self.set_status("Конфликты разрешены. Выбранные версии сохранены.")
        except (VaultError, OSError, ValueError) as ex:
            messagebox.showwarning(APP_NAME, str(ex), parent=self.root)

    def set_status(self, text, color=None):
        self.status_left.config(text=text, foreground=color or self.t["good"])

    def saved_note(self):
        self.set_status("✓ Автосохранено " + time.strftime("%H:%M:%S"))

    def copy_text(self, text, what):
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._last_clip_text = text
        self.root.update()
        secs = int(self.settings.get("clipboard_seconds"))
        if self._clip_job:
            self.root.after_cancel(self._clip_job)
        self._clip_job = self.root.after(secs * 1000, lambda: self._clear_clip(text))
        try:
            self.set_status(f"{what} скопирован — буфер очистится через {secs} с")
        except (AttributeError, tk.TclError):
            pass

    def _clear_clip(self, text):
        try:
            if self.root.clipboard_get() == text:
                self.root.clipboard_clear()
                self._last_clip_text = None
        except tk.TclError:
            pass

    def lock(self):
        for w in self.root.winfo_children():
            if w.winfo_class() == "Toplevel":
                w.destroy()
        if self._clip_job:
            self.root.after_cancel(self._clip_job)
            self._clip_job = None
        # При блокировке не оставляем скопированный пароль в буфере.
        try:
            if getattr(self, "_last_clip_text", None) is not None:
                self._clear_clip(self._last_clip_text)
        finally:
            self._last_clip_text = None
        self._hide_pw(refresh=False)
        self.vault.lock()
        self.show_login()

    # ---------------- вход
    def show_login(self):
        new = not self.vault.exists()
        t = self.t
        f = ttk.Frame(self.root)
        self._swap(f)
        ttk.Label(f, text="◈  Мои пароли", style="Hero.TLabel").place(x=40, y=32)
        ttk.Label(f, text="Личное пространство для ваших доступов", style="HeroMuted.TLabel").place(x=42, y=80)
        card = ttk.Frame(f, style="Panel.TFrame", padding=(48, 36))
        card.place(relx=0.5, rely=0.46, anchor="center")
        if self.icon:
            ttk.Label(card, image=self.icon, style="Panel.TLabel").pack()
        ttk.Label(card, text="Начнём с защиты" if new else "С возвращением", style="Title.TLabel").pack(pady=(10, 0))
        ttk.Label(card, text=("Создайте мастер-пароль для нового хранилища" if new
                              else "Введите мастер-пароль, чтобы открыть хранилище"),
                  style="Muted.TLabel").pack(pady=(4, 20))
        ttk.Label(card, text="Мастер-пароль", style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        pw1 = ttk.Entry(card, show="•", width=34, font=(FF, 11))
        pw1.pack(pady=4, fill="x")
        pw1.focus_set()
        pw2 = None
        if new:
            bar = ttk.Progressbar(card, maximum=100, length=260)
            bar.pack(pady=(6, 0), fill="x")
            lbl = ttk.Label(card, text="", style="Muted.TLabel")
            lbl.pack(anchor="w")
            ttk.Label(card, text="Повторите пароль", style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
            pw2 = ttk.Entry(card, show="•", width=34, font=(FF, 11))
            pw2.pack(pady=4, fill="x")
            ttk.Label(card, text=f"Минимум {MIN_MASTER_LEN} символов. Лучше — фраза из нескольких слов. "
                      "Если вы забудете мастер-пароль, данные восстановить невозможно.",
                      style="Muted.TLabel", wraplength=300, foreground=t["warn"]).pack(pady=(8, 0))

            def meter(*_):
                bits, text, level = strength(pw1.get())
                bar["value"] = min(100, bits)
                bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
                lbl.config(text=text)
            pw1.bind("<KeyRelease>", meter)
        needs_kf = (not new) and Vault.header_needs_keyfile(self.vault.path)
        kf = {"path": self.settings.get("keyfile_path") or ""}
        if needs_kf:
            kf_row = ttk.Frame(card, style="Panel.TFrame")
            kf_row.pack(fill="x", pady=(8, 0))
            kf_lbl = ttk.Label(kf_row, style="Muted.TLabel", wraplength=170,
                               text=os.path.basename(kf["path"]) if kf["path"] else "ключевой файл не выбран")
            kf_lbl.pack(side="left")

            def pick_kf():
                p = filedialog.askopenfilename(parent=self.root, title="Ключевой файл")
                if p:
                    kf["path"] = p
                    kf_lbl.config(text=os.path.basename(p))
            ttk.Button(kf_row, text="Ключевой файл…", command=pick_kf).pack(side="right")
        if new and self.settings.get("vault_path"):
            ttk.Label(card, style="Muted.TLabel", wraplength=300, foreground=t["warn"],
                      text="Файл хранилища не найден:\n" + self.vault.path + "\nЕсли это облачная папка, "
                           "дождитесь синхронизации. Иначе будет создано новое пустое хранилище."
                      ).pack(pady=(8, 0))
        err = ttk.Label(card, text="", style="Panel.TLabel", foreground=t["bad"], wraplength=300)
        err.pack(pady=8)

        def submit(_=None):
            wait = self._next_try - time.time()
            if wait > 0:
                err.config(text=f"Слишком много попыток. Подождите {int(wait) + 1} с.")
                return
            pw = pw1.get()
            if new:
                if len(pw) < MIN_MASTER_LEN:
                    err.config(text=f"Пароль короче {MIN_MASTER_LEN} символов")
                    return
                if pw != pw2.get():
                    err.config(text="Пароли не совпадают")
                    return
            err.config(text="Проверка…", foreground=t["muted"])
            self.root.update_idletasks()
            try:
                if new:
                    self.vault.create(pw)
                else:
                    content = None
                    if needs_kf:
                        if not kf["path"]:
                            err.config(text="Выберите ключевой файл", foreground=t["bad"])
                            return
                        try:
                            with open(kf["path"], "rb") as fh:
                                content = fh.read()
                        except OSError as ex:
                            err.config(text=f"Не удаётся прочитать ключевой файл: {ex}",
                                       foreground=t["bad"])
                            return
                    self.vault.unlock(pw, content)
                    if needs_kf:
                        self.settings.set("keyfile_path", kf["path"])
            except WrongPassword:
                self._fails += 1
                if self._fails >= 3:
                    self._next_try = time.time() + min(2 ** (self._fails - 2), 30)
                err.config(text="Неверный мастер-пароль" + (" или ключевой файл" if needs_kf else ""),
                           foreground=t["bad"])
                pw1.delete(0, "end")
                return
            except KeyfileRequired:
                err.config(text="Для этого хранилища нужен ключевой файл", foreground=t["bad"])
                return
            except VaultError as ex:
                err.config(text=f"Файл хранилища повреждён: {ex}. Можно восстановить из резервной "
                                "копии (папка backups).", foreground=t["bad"])
                return
            except OSError as ex:
                err.config(text=f"Ошибка доступа к файлу: {ex}", foreground=t["bad"])
                return
            self._fails = 0
            self.show_main()

        ttk.Button(card, text=("Создать хранилище" if new else "Открыть"),
                   style="Accent.TButton", command=submit).pack(fill="x", ipady=3)
        if not new and not needs_kf and self.hello.enabled():
            ttk.Button(card, text="◉  Войти через Windows Hello",
                       command=lambda: self.hello_login(err)).pack(fill="x", pady=(10, 0))
        self.root.bind("<Return>", submit)
        ttk.Label(f, text="AES-256-GCM  ·  данные хранятся только на этом компьютере",
                  style="BgMuted.TLabel").place(relx=0.5, rely=0.96, anchor="s")

    def hello_login(self, err_label):
        """Verify OS user presence off the Tk event loop; never send password to browser."""
        import asyncio
        hwnd = self.root.winfo_id()
        if sys.platform == "win32":
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(hwnd) or hwnd
        err_label.config(text="Ожидание подтверждения Windows Hello…", foreground=self.t["muted"])
        def work():
            try:
                if not self.hello.verify(hwnd):
                    self._q.put(lambda: err_label.config(text="Подтверждение Windows Hello отменено"))
                    return
                password = self.hello.retrieve_after_verification()
                def finish():
                    try:
                        if not self.vault.exists():
                            raise VaultError("Хранилище отсутствует")
                        self.vault.unlock(password)
                        self._fails = 0
                        self.show_main()
                    except (VaultError, OSError, ValueError) as ex:
                        err_label.config(text=f"Не удалось открыть хранилище: {ex}",
                                         foreground=self.t["bad"])
                self._q.put(finish)
            except (HelloUnavailable, OSError, ValueError, KeyError) as ex:
                self._q.put(lambda msg=str(ex): err_label.config(text=msg, foreground=self.t["bad"]))
        threading.Thread(target=work, daemon=True).start()

    def configure_hello(self):
        if not self.vault.unlocked:
            return
        if self.hello.enabled():
            if messagebox.askyesno("Windows Hello", "Отключить быстрый вход Windows Hello?", parent=self.root):
                self.hello.disable()
                messagebox.showinfo("Windows Hello", "Быстрый вход отключён.", parent=self.root)
            return
        if Vault.header_needs_keyfile(self.vault.path):
            messagebox.showwarning("Windows Hello", "Быстрый вход недоступен для хранилища с ключевым файлом.")
            return
        if sys.platform != "win32":
            messagebox.showwarning("Windows Hello", "Эта функция доступна только в Windows 10/11.")
            return
        password = simpledialog.askstring("Windows Hello", "Введите мастер-пароль для включения быстрого входа:",
                                          parent=self.root, show="•")
        if password is None:
            return
        if not self.vault.verify_password(password):
            messagebox.showerror("Windows Hello", "Неверный мастер-пароль.", parent=self.root)
            return
        hwnd = self.root.winfo_id()
        if sys.platform == "win32":
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(hwnd) or hwnd
        def work():
            import asyncio
            try:
                if not self.hello.verify(hwnd):
                    self._q.put(lambda: messagebox.showwarning("Windows Hello", "Проверка не пройдена."))
                    return
                self.hello.enroll(password)
                self._q.put(lambda: messagebox.showinfo("Windows Hello", "Быстрый вход включён. "
                    "Секрет защищён DPAPI текущего пользователя Windows; это не аппаратная привязка к Hello."))
            except (HelloUnavailable, OSError, ValueError) as ex:
                self._q.put(lambda msg=str(ex): messagebox.showerror("Windows Hello", msg))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- главный экран
    def show_main(self):
        self.root.unbind("<Return>")
        self._touch()
        t = self.t
        f = ttk.Frame(self.root)
        self._swap(f)

        head = ttk.Frame(f, style="Panel.TFrame", padding=(24, 14))
        head.pack(fill="x")
        ttk.Label(head, text="◈  Мои пароли", style="Title.TLabel").pack(side="left", padx=(0, 24))
        menus = ttk.Frame(f, style="Panel.TFrame", padding=(24, 0, 24, 8))
        menus.pack(fill="x")
        for text, menu in (("Файл", self._file_menu()), ("Инструменты", self._tools_menu()),
                           ("Справка", self._help_menu())):
            ttk.Menubutton(menus, text=text, menu=menu).pack(side="left", padx=3)
        ttk.Button(head, text="Заблокировать", command=self.lock).pack(side="right")
        ttk.Button(head, text="Светлая / тёмная", command=self.toggle_theme).pack(side="right", padx=8)

        hero = ttk.Frame(f, padding=(24, 22))
        hero.pack(fill="x")
        ttk.Button(hero, text="＋  Новая запись", style="Accent.TButton",
                   command=self.add).pack(side="right", pady=8)
        ttk.Label(hero, text="Личное хранилище", style="Hero.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Ваши аккаунты, пароли и коды доступа — в одном месте.",
                  style="HeroMuted.TLabel").pack(anchor="w", pady=(5, 0))
        overview = ttk.Frame(f, padding=(24, 0))
        overview.pack(fill="x")
        self._build_stats(overview)

        bottom = ttk.Frame(f, style="Side.TFrame", padding=(14, 5))
        bottom.pack(side="bottom", fill="x")
        self.status_left = ttk.Label(bottom, text="", style="Side.TLabel", foreground=t["good"])
        self.status_left.pack(side="left")
        self.status_right = ttk.Label(bottom, text="", style="SideMuted.TLabel")
        self.status_right.pack(side="right")

        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True, padx=24, pady=(12, 20))

        side_fr = ttk.Frame(body, style="Side.TFrame", width=240)
        ttk.Label(side_fr, text="ХРАНИЛИЩЕ", style="SideHeading.TLabel").pack(fill="x", padx=12, pady=(20, 7))
        navigation = ttk.Frame(side_fr, style="Side.TFrame")
        self.side = ttk.Treeview(navigation, show="tree", selectmode="browse", style="Side.Treeview")
        self.side.column("#0", width=225)
        self.side.tag_configure("head", foreground=t["muted"], font=(FF, 8, "bold"))
        tools = ttk.Frame(side_fr, style="Side.TFrame", padding=12)
        tools.pack(side="bottom", fill="x")
        ttk.Separator(tools).pack(fill="x", pady=(0, 12))
        for text, command in (("Аудит безопасности", self.audit),
                              ("Генератор паролей", lambda: GeneratorDialog(self, self.root)),
                              ("Настройки", lambda: SettingsDialog(self, self.root))):
            ttk.Button(tools, text=text, style="Ghost.TButton", command=command).pack(fill="x", pady=3)
        navigation.pack(fill="both", expand=True)
        self.side.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)
        nav_scroll = ttk.Scrollbar(navigation, orient="vertical", command=self.side.yview)
        nav_scroll.pack(side="right", fill="y")
        self.side.configure(yscrollcommand=nav_scroll.set)
        self.side.bind("<<TreeviewSelect>>", self.on_side_select)
        body.add(side_fr, weight=0)

        center = ttk.Frame(body)
        toolbar = ttk.Frame(center, style="Panel.TFrame", padding=(16, 14))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="Поиск по сервису, логину или тегу",
                  style="Muted.TLabel").pack(side="bottom", anchor="w", pady=(8, 0))
        ttk.Label(toolbar, text="Записи", style="Section.TLabel").pack(side="left", padx=(0, 18))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *a: self.refresh_list())
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search, style="Search.TEntry")
        self.search_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(toolbar, text="Найти", style="Compact.TButton",
                   command=lambda: self.search_entry.focus_set()).pack(side="left", padx=(8, 0))
        lst = ttk.Frame(center, style="Panel.TFrame")
        lst.pack(fill="both", expand=True)
        cols = [c[0] for c in self.COLUMNS]
        horizontal = ttk.Scrollbar(lst, orient="horizontal")
        horizontal.pack(side="bottom", fill="x")
        self.tree = ttk.Treeview(lst, columns=cols, show="headings", selectmode="browse")
        from tkinter import font as tkfont
        column_font = tkfont.Font(family=FF, size=10)
        for key, name, width in self.COLUMNS:
            self.tree.heading(key, text=name, command=lambda k=key: self.sort_by(k))
            minimum = max(width, column_font.measure(name) + 32)
            self.tree.column(key, width=minimum, minwidth=minimum, anchor="center" if key == "fav" else "w",
                             stretch=(key != "fav"))
        sb = ttk.Scrollbar(lst, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.configure(xscrollcommand=horizontal.set)
        horizontal.configure(command=self.tree.xview)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.empty_lbl = ttk.Label(lst, text="", style="Muted.TLabel", justify="center",
                                   font=(FF, 11))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.edit())
        self.tree.bind("<Return>", lambda e: self.edit())
        self.tree.bind("<Delete>", lambda e: self.delete())
        self.tree.bind("<Control-c>", lambda e: self.copy_login())
        self.tree.bind("<Control-Shift-C>", lambda e: self.copy_password())
        self.tree.bind("<Button-3>", self.context_menu)
        body.add(center, weight=3)

        det = ttk.Frame(body, style="Panel.TFrame", width=400)
        detail_canvas = tk.Canvas(det, bg=t["panel"], highlightthickness=0, width=400)
        detail_scroll = ttk.Scrollbar(det, orient="vertical", command=detail_canvas.yview)
        detail_scroll.pack(side="right", fill="y")
        detail_canvas.pack(side="left", fill="both", expand=True)
        detail_canvas.configure(yscrollcommand=detail_scroll.set)
        detail_content = ttk.Frame(detail_canvas, style="Panel.TFrame", padding=20)
        detail_window = detail_canvas.create_window((0, 0), window=detail_content, anchor="nw")
        detail_canvas.bind("<Configure>", lambda event: detail_canvas.itemconfigure(
            detail_window, width=event.width))
        detail_content.bind("<Configure>", lambda event: detail_canvas.configure(
            scrollregion=detail_canvas.bbox("all")))
        self._build_details(detail_content)
        body.add(det, weight=1)

        self.ctx = self._menu()
        r = self.root
        r.bind("<Control-n>", self._guard(self.add))
        r.bind("<Escape>", self._guard(self.lock))
        r.bind("<Control-f>", self._guard(lambda: self.search_entry.focus_set()))
        r.bind("<Control-l>", self._guard(self.lock))
        r.bind("<Control-b>", self._guard(self.copy_login))
        r.bind("<Control-Shift-C>", self._guard(self.copy_password))
        self.refresh_all()
        self.set_status("Хранилище открыто. Изменения сохраняются автоматически.")
        if self._totp_job:
            r.after_cancel(self._totp_job)
        self._totp_tick()

    def _file_menu(self):
        m = self._menu()
        m.add_command(label="Заблокировать", accelerator="Ctrl+L", command=self.lock)
        m.add_separator()
        m.add_command(label="Импорт из CSV / Excel…", command=self.import_csv)
        m.add_command(label="Экспорт зашифрованной копии…", command=self.export_encrypted)
        m.add_command(label="Экспорт в CSV (открытый текст)…", command=self.export_csv)
        m.add_command(label="Восстановить из резервной копии…", command=self.restore_backup)
        m.add_separator()
        m.add_command(label="Хранилище в облачной папке…", command=self.move_vault)
        m.add_command(label="Подключить существующее хранилище…", command=self.attach_vault)
        m.add_separator()
        m.add_command(label="Сменить мастер-пароль…", command=self.change_master)
        m.add_command(label="Ключевой файл…", command=self.manage_keyfile)
        m.add_separator()
        m.add_command(label="Выход", command=self.quit_app)
        return m

    def _tools_menu(self):
        m = self._menu()
        m.add_command(label="Разрешить конфликты…", command=self.resolve_conflicts)
        m.add_command(label="Быстрый поиск", command=self.quick_search)
        m.add_command(label="Аудит безопасности…", command=self.audit)
        m.add_command(label="Проверка на утечки (интернет)…", command=self.check_breaches)
        m.add_command(label="Генератор паролей…",
                      command=lambda: GeneratorDialog(self, self.root))
        m.add_command(label="Очистить корзину", command=self.empty_trash)
        m.add_separator()
        m.add_command(label="Светлая / тёмная тема", command=self.toggle_theme)
        m.add_command(label="Настройки…", command=lambda: SettingsDialog(self, self.root))
        return m

    def _help_menu(self):
        m = self._menu()
        m.add_command(label="Открыть папку с данными", command=self.open_data_dir)
        m.add_command(label="Горячие клавиши", command=lambda: messagebox.showinfo(
            APP_NAME, "Ctrl+N — новая запись\nCtrl+F — поиск\nCtrl+L — заблокировать\n"
                      "Ctrl+B — копировать логин\nCtrl+Shift+C — копировать пароль\n"
                      "Enter / двойной клик — изменить\nDelete — удалить\nEscape — заблокировать", parent=self.root))
        m.add_command(label="Проверить обновления…", command=self.check_updates)
        m.add_command(label="О программе", command=self.about)
        return m

    def about(self):
        t = self.t
        top = _new_top(self, self.root, "О программе")
        frm = ttk.Frame(top, padding=30)
        frm.pack()
        if self.icon:
            ttk.Label(frm, image=self.icon).pack()
        ttk.Label(frm, text=APP_NAME, font=(FF, 17, "bold")).pack(pady=(8, 0))
        ttk.Label(frm, text=f"Версия {APP_VERSION}", foreground=t["muted"]).pack()
        ttk.Label(frm, text="Шифрование AES-256-GCM, ключ из мастер-пароля (scrypt).\n"
                            "Данные хранятся только на вашем компьютере.\n\n" + self.vault.path,
                  justify="center", wraplength=380, foreground=t["muted"]).pack(pady=14)
        ttk.Button(frm, text="Закрыть", command=top.destroy).pack()
        top.grab_set()
        self.root.wait_window(top)

    # ---------------- панель показателей
    def _build_stats(self, parent):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 10))
        self.stat = {}
        spec = (("total", "Записей"), ("weak", "Слабых паролей"), ("reused", "Повторов"),
                ("old", "Устаревшие"), ("score", "Оценка безопасности"))
        for i, (key, caption) in enumerate(spec):
            row.columnconfigure(i, weight=1, uniform="stat")
            card = ttk.Frame(row, style="Card.TFrame", padding=(18, 14))
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            num = ttk.Label(card, text="0", style="Big.TLabel")
            num.pack(anchor="w")
            cap = ttk.Label(card, text=caption, style="CardMuted.TLabel")
            cap.pack(anchor="w")
            for w in (card, num, cap):
                w.bind("<Button-1>", lambda e: self.audit())
            self.stat[key] = num

    def refresh_stats(self):
        t, s = self.t, self.vault.summary()
        self.stat["total"].config(text=str(s["total"]))
        for key in ("weak", "reused", "old"):
            bad = t["warn"] if key == "old" else t["bad"]
            self.stat[key].config(text=str(s[key]), foreground=t["good"] if s[key] == 0 else bad)
        if s["total"]:
            color = t["good"] if s["score"] >= 80 else t["warn"] if s["score"] >= 50 else t["bad"]
            self.stat["score"].config(text=f'{s["score"]}%', foreground=color)
        else:
            self.stat["score"].config(text="—", foreground=t["muted"])

    # ---------------- панель деталей
    def _build_details(self, p):
        p.columnconfigure(0, weight=1)
        self.d_title = ttk.Label(p, text="", style="Title.TLabel", wraplength=320, justify="left")
        self.d_title.grid(row=0, column=0, sticky="we", pady=(0, 8))
        self.d_empty = ttk.Label(p, text="Выберите запись в списке\nили нажмите «＋ Добавить»",
                                 style="Muted.TLabel", justify="center")
        self.dvars, self.dfields = {}, {}
        spec = (("url", "САЙТ", (("Открыть", self.open_url),)),
                ("login", "ЛОГИН", (("Копировать", self.copy_login),)),
                ("password", "ПАРОЛЬ", (("Показать", self.toggle_pw), ("Копировать", self.copy_password))),
                ("totp", "КОД 2FA", (("Копировать", self.copy_totp),)),
                ("category", "КАТЕГОРИЯ", ()), ("tags", "ТЕГИ", ()),
                ("source", "ИСТОЧНИК", ()), ("updated", "ИЗМЕНЕНО", ()))
        for i, (key, text, btns) in enumerate(spec, start=1):
            fr = ttk.Frame(p, style="Panel.TFrame")
            ttk.Label(fr, text=text, style="Muted.TLabel", font=(FF, 9)).pack(anchor="w")
            line = ttk.Frame(fr, style="Panel.TFrame")
            line.pack(fill="x", pady=(2, 0))
            var = tk.StringVar()
            lbl_style = "Mono.TLabel" if key in ("password", "totp") else "Panel.TLabel"
            ttk.Label(line, textvariable=var, style=lbl_style, wraplength=190,
                      justify="left").pack(side="left", fill="x", expand=True)
            for btn_text, cmd in reversed(btns):
                b = ttk.Button(line, text=btn_text, command=cmd, width=10, style="Compact.TButton")
                b.pack(side="right", padx=(4, 0))
                if key == "password" and btn_text == "Показать":
                    self.pw_btn = b
            if key == "password":
                self.pw_bar = ttk.Progressbar(fr, maximum=100)
                self.pw_bar.pack(fill="x", pady=(6, 0))
                self.pw_bar_lbl = ttk.Label(fr, text="", style="Muted.TLabel")
                self.pw_bar_lbl.pack(anchor="w")
            fr.grid(row=i, column=0, sticky="we", pady=6)
            self.dvars[key], self.dfields[key] = var, fr

        cf = ttk.Frame(p, style="Panel.TFrame")
        ttk.Label(cf, text="ДОПОЛНИТЕЛЬНО", style="Muted.TLabel", font=(FF, 8, "bold")).pack(anchor="w")
        self.d_custom = ttk.Frame(cf, style="Panel.TFrame")
        self.d_custom.pack(fill="x")
        cf.grid(row=9, column=0, sticky="we", pady=6)
        self.dfields["custom"] = cf

        nf = ttk.Frame(p, style="Panel.TFrame")
        ttk.Label(nf, text="ЗАМЕТКА", style="Muted.TLabel", font=(FF, 8, "bold")).pack(anchor="w")
        self.d_note = tk.Text(nf, height=4, width=30, wrap="word", relief="flat", state="disabled",
                              bg=self.t["card"], fg=self.t["fg"], highlightthickness=0,
                              padx=8, pady=6)
        self.d_note.pack(fill="x", pady=(2, 0))
        nf.grid(row=10, column=0, sticky="we", pady=6)
        self.dfields["note"] = nf

        self.act_normal = ttk.Frame(p, style="Panel.TFrame")
        r1 = ttk.Frame(self.act_normal, style="Panel.TFrame")
        r1.pack(fill="x")
        ttk.Button(r1, text="Изменить", style="Accent.TButton", command=self.edit).pack(side="left")
        self.fav_btn = ttk.Button(r1, text="★", width=3, command=self.toggle_fav)
        self.fav_btn.pack(side="left", padx=4)
        ttk.Button(r1, text="⌨ Ввести", command=self.autotype_selected).pack(side="left")
        r2 = ttk.Frame(self.act_normal, style="Panel.TFrame")
        r2.pack(fill="x", pady=(6, 0))
        self.hist_btn = ttk.Button(r2, text="История", command=self.show_history)
        self.hist_btn.pack(side="left")
        self.att_btn = ttk.Button(r2, text="Вложения", command=self.attachments)
        self.att_btn.pack(side="left", padx=4)
        ttk.Button(r2, text="Утечки?", command=self.check_pwned_selected).pack(side="left")
        ttk.Button(self.act_normal, text="Удалить запись", style="Compact.TButton",
                   command=self.delete).pack(anchor="w", pady=(10, 0))
        self.act_trash = ttk.Frame(p, style="Panel.TFrame")
        ttk.Button(self.act_trash, text="Восстановить", style="Accent.TButton",
                   command=self.restore).pack(side="left")
        ttk.Button(self.act_trash, text="Удалить навсегда", command=self.purge).pack(side="right")
        self.act_normal.grid(row=11, column=0, sticky="we", pady=(14, 0))
        self.act_trash.grid(row=11, column=0, sticky="we", pady=(14, 0))
        self.show_details()

    def _on_select(self, _=None):
        sel = self.tree.selection()
        cur = sel[0] if sel else None
        if cur != self._last_sel:
            self._last_sel = cur
            self._hide_pw(refresh=False)
        self.show_details()

    def show_details(self):
        e = self.selected()
        for fr in self.dfields.values():
            fr.grid_remove()
        self.act_normal.grid_remove()
        self.act_trash.grid_remove()
        if not e:
            self.d_title.config(text="")
            self.d_empty.grid(row=1, column=0, pady=70)
            return
        self.d_empty.grid_remove()
        self.d_title.config(text=("★ " if e["favorite"] else "") + e["title"])
        values = {"url": e["url"], "login": e["login"], "category": e["category"],
                  "tags": e["tags"], "source": e["source"],
                  "updated": f'{e["updated"]}  (создано {e["created"]})'}
        for key, val in values.items():
            self.dvars[key].set(val)
            if val:
                self.dfields[key].grid()
        self._show_password(e)
        if e["password"]:
            self.dfields["password"].grid()
        if e["totp"]:
            self.dfields["totp"].grid()
            self._totp_update(e)
        self.d_note.config(state="normal")
        self.d_note.delete("1.0", "end")
        self.d_note.insert("1.0", e["note"])
        self.d_note.config(state="disabled")
        if e["note"]:
            self.dfields["note"].grid()
        if e["deleted"]:
            self.act_trash.grid()
        else:
            self.act_normal.grid()
            self.fav_btn.config(text="☆" if e["favorite"] else "★")
            self.hist_btn.config(state="normal" if e["history"] else "disabled")
            n_att = len(e["attachments"])
            self.att_btn.config(text=f"Вложения ({n_att})" if n_att else "Вложения")

    def _show_password(self, e):
        self.dvars["password"].set(e["password"] if self.pw_visible else "•" * 10)
        self.pw_btn.config(text="Скрыть" if self.pw_visible else "Показать")
        bits, text, level = strength(e["password"])
        self.pw_bar["value"] = min(100, bits)
        self.pw_bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
        self.pw_bar_lbl.config(text=f"Надёжность: {text}")
        self._render_custom(e)

    def toggle_pw(self):
        e = self.selected()
        if not e:
            return
        if self.pw_visible:
            self._hide_pw()
            return
        self.pw_visible = True
        self._show_password(e)
        self._pw_job = self.root.after(15000, self._hide_pw)  # автоскрытие через 15 с

    def _hide_pw(self, refresh=True):
        if self._pw_job:
            try:
                self.root.after_cancel(self._pw_job)
            except tk.TclError:
                pass
            self._pw_job = None
        self.pw_visible = False
        if refresh and self.vault.unlocked:
            try:
                e = self.selected()
                if e:
                    self._show_password(e)
            except tk.TclError:
                pass

    def _totp_update(self, e):
        try:
            code = totp_now(e["totp"])
            left = 30 - int(time.time()) % 30
            self.dvars["totp"].set(f"{code[:3]} {code[3:]}   ({left} с)")
        except Exception:
            self.dvars["totp"].set("ключ 2FA не распознан")

    def _totp_tick(self):
        if self.vault.unlocked:
            e = self.selected()
            if e and e["totp"] and not e["deleted"]:
                self._totp_update(e)
        self._totp_job = self.root.after(1000, self._totp_tick)

    # ---------------- списки
    def selected(self):
        sel = self.tree.selection()
        return self.vault.get(sel[0]) if sel else None

    def refresh_all(self):
        self.refresh_sidebar()
        self.refresh_list()
        self.refresh_stats()

    def refresh_sidebar(self):
        v = self.vault
        act = v.active()
        ins = self.side.insert
        self.side.delete(*self.side.get_children())
        ins("", "end", iid="all", text=f"  📁   Все записи  ({len(act)})")
        ins("", "end", iid="fav", text=f"  ★   Избранное  ({sum(1 for e in act if e['favorite'])})")
        cats = v.categories()
        unc = sum(1 for e in act if not e["category"])
        if cats or unc:
            ins("", "end", iid="h_cat", text="   КАТЕГОРИИ", tags=("head",))
            for c in cats:
                n = sum(1 for e in act if e["category"] == c)
                ins("", "end", iid="cat:" + c, text=f"  🏷   {c}  ({n})")
            if unc:
                ins("", "end", iid="uncat", text=f"  ∅   Без категории  ({unc})")
        tags = sorted({x for e in act for x in split_tags(e["tags"])}, key=str.lower)
        if tags:
            ins("", "end", iid="h_tag", text="   ТЕГИ", tags=("head",))
            for tg in tags:
                n = sum(1 for e in act if tg.lower() in [x.lower() for x in split_tags(e["tags"])])
                ins("", "end", iid="tag:" + tg, text=f"  #   {tg}  ({n})")
        ins("", "end", iid="h_sys", text="   СИСТЕМА", tags=("head",))
        ins("", "end", iid="trash", text=f"  🗑   Корзина  ({len(v.trash())})")
        if not self.side.exists(self.cat_filter):
            self.cat_filter = "all"
        self.side.selection_set(self.cat_filter)

    def on_side_select(self, _=None):
        sel = self.side.selection()
        if not sel:
            return
        if sel[0].startswith("h_"):  # заголовки разделов не выбираются
            self.side.selection_set(self.cat_filter)
            return
        if sel[0] != self.cat_filter:
            self.cat_filter = sel[0]
            self.refresh_list()

    def _in_filter(self, e):
        f = self.cat_filter
        if f == "trash":
            return bool(e["deleted"])
        if e["deleted"]:
            return False
        if f == "all":
            return True
        if f == "fav":
            return e["favorite"]
        if f == "uncat":
            return not e["category"]
        if f.startswith("cat:"):
            return e["category"] == f[4:]
        if f.startswith("tag:"):
            return f[4:].lower() in [x.lower() for x in split_tags(e["tags"])]
        return True

    def sort_by(self, col):
        key, rev = self.sort
        self.sort = (col, (not rev) if key == col else False)
        self.refresh_list()

    def refresh_list(self):
        prev = self.tree.selection()
        q = self.search.get().strip().lower()
        key, rev = self.sort

        def sk(e):
            if key == "fav":
                return (not e["favorite"], e["title"].lower())
            return str(e.get(key, "")).lower()

        items = [e for e in self.vault.entries if self._in_filter(e) and (
            not q or q in " ".join((e["title"], e["url"], e["login"], e["tags"],
                                    e["note"], e["category"])).lower())]
        items.sort(key=sk, reverse=rev)
        self.tree.delete(*self.tree.get_children())
        self.tree.tag_configure("alternate", background=self.t["card"])
        for index, e in enumerate(items):
            self.tree.insert("", "end", iid=e["id"], tags=("alternate",) if index % 2 else (), values=(
                "★" if e["favorite"] else "", e["title"], e["login"], e["category"],
                (e["deleted"] if self.cat_filter == "trash" else e["updated"])[:10]))
        if prev and self.tree.exists(prev[0]):
            self.tree.selection_set(prev[0])
        total = len(self.vault.active()) if self.cat_filter != "trash" else len(self.vault.trash())
        self.status_right.config(text=f"Показано: {len(items)} из {total}")
        if items:
            self.empty_lbl.place_forget()
        else:
            if q:
                msg = "Ничего не найдено"
            elif self.cat_filter == "trash":
                msg = "Корзина пуста"
            elif self.cat_filter == "all":
                msg = ("Здесь пока пусто.\nНажмите «＋ Добавить» или импортируйте пароли\n"
                       "из браузера: Файл → Импорт из CSV…")
            else:
                msg = "В этом разделе пока нет записей"
            self.empty_lbl.config(text=msg)
            self.empty_lbl.place(relx=0.5, rely=0.38, anchor="center")
        self.show_details()

    def goto_entry(self, entry_id):
        self.search.set("")
        e = self.vault.get(entry_id)
        if e and not self._in_filter(e):
            self.cat_filter = "trash" if e["deleted"] else "all"
        self.refresh_all()
        if self.tree.exists(entry_id):
            self.tree.selection_set(entry_id)
            self.tree.see(entry_id)

    def context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        e = self.vault.get(iid)
        m = self.ctx
        m.delete(0, "end")
        if e["deleted"]:
            m.add_command(label="Восстановить", command=self.restore)
            m.add_command(label="Удалить навсегда", command=self.purge)
        else:
            m.add_command(label="Копировать пароль", command=self.copy_password)
            m.add_command(label="Копировать логин", command=self.copy_login)
            m.add_command(label="Открыть сайт", command=self.open_url)
            m.add_separator()
            m.add_command(label="Изменить", command=self.edit)
            m.add_command(label="В избранное / убрать", command=self.toggle_fav)
            m.add_command(label="Удалить", command=self.delete)
        m.tk_popup(event.x_root, event.y_root)

    # ---------------- действия с записями
    def add(self):
        cat = self.cat_filter[4:] if self.cat_filter.startswith("cat:") else ""
        d = EntryDialog(self, self.root, category=cat)
        if d.result:
            ok, e = self._do(self.vault.add, d.result)
            if ok:
                self.goto_entry(e["id"])
                self.saved_note()

    def edit(self):
        e = self.selected()
        if not e or e["deleted"]:
            return
        d = EntryDialog(self, self.root, e)
        if d.result:
            ok, _ = self._do(self.vault.update, e["id"], d.result)
            if ok:
                self.refresh_all()
                self.tree.selection_set(e["id"])
                self.saved_note()

    def toggle_fav(self):
        e = self.selected()
        if e and not e["deleted"]:
            ok, _ = self._do(self.vault.set_favorite, e["id"], not e["favorite"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def delete(self):
        e = self.selected()
        if not e:
            return
        if e["deleted"]:
            return self.purge()
        if messagebox.askyesno(APP_NAME, f"Переместить «{e['title']}» в корзину?\n"
                               f"Запись хранится {TRASH_DAYS} дней.", parent=self.root):
            ok, _ = self._do(self.vault.soft_delete, e["id"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def restore(self):
        e = self.selected()
        if e and e["deleted"]:
            ok, _ = self._do(self.vault.restore, e["id"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def purge(self):
        e = self.selected()
        if e and messagebox.askyesno(APP_NAME, f"Удалить «{e['title']}» навсегда?\n"
                                     "Это действие нельзя отменить.", parent=self.root):
            ok, _ = self._do(self.vault.purge, e["id"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def empty_trash(self):
        n = len(self.vault.trash())
        if n and messagebox.askyesno(APP_NAME, f"Удалить навсегда записей: {n}?", parent=self.root):
            ok, _ = self._do(self.vault.empty_trash)
            if ok:
                self.refresh_all()
                self.saved_note()

    def copy_password(self):
        e = self.selected()
        if e:
            self.copy_text(e["password"], "Пароль")

    def copy_login(self):
        e = self.selected()
        if e:
            self.copy_text(e["login"], "Логин")

    def copy_totp(self):
        e = self.selected()
        if e and e["totp"]:
            try:
                self.copy_text(totp_now(e["totp"]), "Код 2FA")
            except Exception:
                messagebox.showwarning(APP_NAME, "Ключ 2FA не распознан.", parent=self.root)

    def open_url(self):
        e = self.selected()
        if not e or not e["url"]:
            return
        url = e["url"] if "://" in e["url"] else "https://" + e["url"]
        if urlparse(url).scheme not in ("http", "https"):
            messagebox.showwarning(APP_NAME, "Открываются только ссылки http/https.", parent=self.root)
            return
        webbrowser.open(url)

    def show_history(self):
        e = self.selected()
        if e and e["history"]:
            HistoryDialog(self, self.root, e)

    def audit(self):
        d = AuditDialog(self, self.root)
        if d.chosen:
            self.goto_entry(d.chosen)

    # ---------------- импорт / экспорт / восстановление
    def import_csv(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="Выберите CSV или Excel-файл с паролями",
            filetypes=[("CSV и Excel", "*.csv *.xlsx"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            if path.lower().endswith((".xlsx", ".xlsm")):
                raw = xlsx_to_csv_bytes(path)
            else:
                with open(path, "rb") as f:
                    raw = f.read()
            source, items, skipped = parse_csv(raw)
        except (OSError, ValueError) as ex:
            messagebox.showerror(APP_NAME, f"Не удалось прочитать файл:\n{ex}", parent=self.root)
            return
        if not items:
            messagebox.showinfo(APP_NAME, "В файле не найдено записей с паролями.", parent=self.root)
            return
        if not messagebox.askyesno(
                APP_NAME, f"Источник: {source}\nНайдено записей: {len(items)}\n"
                          f"Пропущено строк (пустые, карты, заметки): {skipped}\n\nИмпортировать?",
                parent=self.root):
            return
        ok, res = self._do(self.vault.bulk_add, items, source)
        if not ok:
            return
        added, dup = res
        self.refresh_all()
        self.saved_note()
        messagebox.showinfo(APP_NAME, f"Добавлено: {added}\nПовторов пропущено: {dup}",
                            parent=self.root)
        if messagebox.askyesno(
                APP_NAME, "Файл хранит пароли в открытом виде.\n"
                          "Удалить его с диска сейчас (содержимое будет перезаписано)?",
                parent=self.root):
            try:
                shred_file(path)
            except OSError as ex:
                messagebox.showwarning(APP_NAME, f"Не удалось удалить файл:\n{ex}", parent=self.root)

    def export_encrypted(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Сохранить зашифрованную копию", defaultextension=".dat",
            initialfile="moi-paroli-" + datetime.now().strftime("%Y-%m-%d") + ".dat",
            filetypes=[("Хранилище", "*.dat")])
        if path:
            try:
                shutil.copyfile(self.vault.path, path)
                messagebox.showinfo(APP_NAME, "Копия сохранена. Она зашифрована тем же "
                                    "мастер-паролем.", parent=self.root)
            except OSError as ex:
                messagebox.showerror(APP_NAME, f"Ошибка: {ex}", parent=self.root)

    def export_csv(self):
        if not messagebox.askyesno(
                APP_NAME, "В CSV пароли будут записаны открытым текстом.\n"
                          "Любой, кто получит файл, сможет их прочитать. Продолжить?",
                icon="warning", parent=self.root):
            return
        pw = simpledialog.askstring(APP_NAME, "Введите мастер-пароль для подтверждения:",
                                    show="•", parent=self.root)
        if not pw:
            return
        if not self.vault.verify_password(pw):
            messagebox.showerror(APP_NAME, "Неверный мастер-пароль.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Сохранить CSV",
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            try:
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    f.write(export_csv_text(self.vault.active()))
                messagebox.showinfo(APP_NAME, "Файл сохранён. Не забудьте удалить его "
                                    "после использования.", parent=self.root)
            except OSError as ex:
                messagebox.showerror(APP_NAME, f"Ошибка: {ex}", parent=self.root)

    def restore_backup(self):
        start = self.vault.backups_dir()
        path = filedialog.askopenfilename(
            parent=self.root, title="Выберите резервную копию",
            initialdir=start if os.path.isdir(start) else os.path.dirname(self.vault.path),
            filetypes=[("Хранилище", "*.dat *.bak"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            if not (isinstance(blob, dict) and blob.get("magic") in ("passvault", "passvault-v1")):
                raise ValueError("это не файл хранилища")
        except (OSError, ValueError) as ex:
            messagebox.showerror(APP_NAME, f"Файл не подходит:\n{ex}", parent=self.root)
            return
        backup_password = simpledialog.askstring(APP_NAME, "Мастер-пароль резервной копии:",
                                                   show="•", parent=self.root)
        if backup_password is None:
            return
        try:
            keydata = None
            if Vault.header_needs_keyfile(path):
                keypath = filedialog.askopenfilename(parent=self.root, title="Ключевой файл резервной копии")
                if not keypath:
                    return
                with open(keypath, "rb") as key:
                    keydata = key.read()
            Vault.validate_backup(path, backup_password, keydata)
        except (VaultError, OSError, ValueError) as ex:
            messagebox.showerror(APP_NAME, f"Копия не прошла проверку: {ex}", parent=self.root)
            return
        if not messagebox.askyesno(
                APP_NAME, "Текущие данные будут заменены выбранной копией.\n"
                          "Прежний файл сохранится как vault.dat.before-restore.\n\nПродолжить?",
                parent=self.root):
            return
        try:
            shutil.copyfile(self.vault.path, self.vault.path + ".before-restore")
            staged = self.vault.path + ".restore.tmp"
            shutil.copyfile(path, staged)
            os.replace(staged, self.vault.path)
        except OSError as ex:
            messagebox.showerror(APP_NAME, f"Не удалось восстановить:\n{ex}", parent=self.root)
            return
        messagebox.showinfo(APP_NAME, "Копия восстановлена. Войдите мастер-паролем этой копии.",
                            parent=self.root)
        self.lock()

    def change_master(self):
        old = simpledialog.askstring(APP_NAME, "Текущий мастер-пароль:", show="•", parent=self.root)
        if not old:
            return
        if not self.vault.verify_password(old):
            messagebox.showerror(APP_NAME, "Неверный мастер-пароль.", parent=self.root)
            return
        p1 = simpledialog.askstring(APP_NAME, "Новый мастер-пароль:", show="•", parent=self.root)
        if not p1:
            return
        if len(p1) < MIN_MASTER_LEN:
            messagebox.showwarning(APP_NAME, f"Минимум {MIN_MASTER_LEN} символов.", parent=self.root)
            return
        if p1 != simpledialog.askstring(APP_NAME, "Повторите новый пароль:", show="•",
                                        parent=self.root):
            messagebox.showwarning(APP_NAME, "Пароли не совпадают.", parent=self.root)
            return
        ok, _ = self._do(self.vault.change_password, p1)
        if ok:
            messagebox.showinfo(APP_NAME, "Мастер-пароль изменён, хранилище пересохранено.\n"
                                "Старые резервные копии в папке backups остались под прежним паролем.",
                                parent=self.root)

    def open_data_dir(self):
        d = os.path.dirname(self.vault.path)
        if hasattr(os, "startfile"):
            os.startfile(d)  # только Windows
        else:
            messagebox.showinfo(APP_NAME, d, parent=self.root)

    def run(self):
        self.root.mainloop()


def main():
    if tk is None:
        print("Не найден tkinter. Установите Python с python.org (компонент tcl/tk).")
        sys.exit(1)
    if not win_single_instance():
        win_message("«Мои пароли» уже запущены. Найдите значок программы в области уведомлений (трей).")
        sys.exit(0)
    App().run()


if __name__ == "__main__":
    main()

