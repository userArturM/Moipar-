#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitora password 4.6.2 — менеджер личных паролей для Windows.

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
import subprocess
import sys
import time
import uuid
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from localization import tr
import feature_dialogs
from windows_hello import HelloUnlock, HelloUnavailable
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
    from midnight_ui import DesignButton,RecordModel,RecordList,rounded
except ImportError:  # tkinter нужен только для окна
    tk = ttk = messagebox = simpledialog = filedialog = None

APP_NAME = "Bitora password"
APP_ID = "MoiParoli"
APP_VERSION = "4.6.2"
KDF_N, KDF_R, KDF_P = 2 ** 16, 8, 1
KDF_MAX_N = 2 ** 20
MIN_MASTER_LEN = 4
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
        if len(password)<MIN_MASTER_LEN: raise ValueError("Master password must contain at least 4 characters")
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
        if not self.unlocked:raise VaultError('хранилище заблокировано')
        if len(new_password)<MIN_MASTER_LEN: raise ValueError("Master password must contain at least 4 characters")
        self.sync_from_disk(write=False)          # сначала подтянуть чужие правки (старым ключом)
        previous = (self.kdf, self.key)
        try:
            self.kdf = self._new_kdf()
            self.key = self.derive(new_password, **self.kdf, keyfile=self.keyfile)
            self.save(check_external=False)
        except Exception:
            self.kdf, self.key = previous
            raise

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
        props=self.meta.setdefault("category_properties",{})
        for name,data in (r_meta.get("category_properties") or {}).items():
            if isinstance(data,dict) and data.get("mtime","")>props.get(name,{}).get("mtime",""):props[name]=data
        retired=self.meta.setdefault("category_tombstones",{})
        for name,stamp_value in (r_meta.get("category_tombstones") or {}).items():
            if stamp_value>retired.get(name,""):retired[name]=stamp_value
        def removed(name):return name in retired and props.get(name,{}).get("mtime","")<=retired[name]
        self.meta["categories"]=[name for name in self.meta["categories"] if not removed(name)]
        for entry in self.entries:
            if removed(entry["category"]):entry["category"]=""
        changes=self.meta.setdefault("category_trash",{})
        for token,data in (r_meta.get("category_trash") or {}).items():
            if data.get("mtime","")>changes.get(token,{}).get("mtime",""):changes[token]=data
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
        before_meta=json.dumps(self.meta,sort_keys=True)
        self._assert_no_conflicts(r_entries)
        self._merge(r_entries, r_meta)
        after = self._fp(self.entries, self.meta.get("tombstones") or {})
        self._sig = sig
        self._remember_base()
        changed=after!=before or json.dumps(self.meta,sort_keys=True)!=before_meta
        if changed:self.merged=True
        if write and (after!=remote_fp or self.meta!=r_meta):self.save(check_external=False)
        return changed

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

    def delete_category(self, name):
        if not self.unlocked: raise VaultError("Хранилище заблокировано")
        self.sync_from_disk(write=False)
        import copy
        previous_entries,previous_meta=copy.deepcopy(self.entries),copy.deepcopy(self.meta)
        try:
            self.meta["categories"]=[c for c in self.meta.get("categories",[]) if c!=name]
            self.meta.get("category_properties",{}).pop(name,None)
            self.meta.setdefault("category_tombstones",{})[name]=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            for entry in self.entries:
                if entry["category"]==name:
                    entry["category"]=""
                    self._touch(entry)
            self.save()
        except Exception:
            self.entries,self.meta=previous_entries,previous_meta
            raise

    def _register_category(self, cat):
        if cat and cat not in self.meta["categories"]:
            self.meta["categories"].append(cat)
            self.meta.setdefault("category_properties",{}).setdefault(cat,{})["mtime"]=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

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
                "font_size": 10, "sidebar_collapsed": False, "external_backup_dir": "", "backup_reminders": True, "backup_reminded": "", "language": "ru", "animations": True, "update_repo": "userArturM/Moipar-", "vault_path": "", "keyfile_path": ""}

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

    def apply_midnight_design(self):
        if self.get("design_version")=="midnight":return False
        self.data.update(theme="dark",sidebar_collapsed=True,design_version="midnight")
        self.set("design_version","midnight")
        return True

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


def check_update(repo, timeout=8, token=""):
    from github_updates import check
    return check(repo, APP_VERSION, timeout, token)


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
            pystray.MenuItem(lambda item: tr("Открыть"), lambda *a: app.post(app.show_window), default=True),
            pystray.MenuItem(lambda item: tr("Быстрый поиск"), lambda *a: app.post(app.quick_search)),
            pystray.MenuItem(lambda item: tr("Заблокировать"), lambda *a: app.post(app.lock)),
            pystray.MenuItem(lambda item: tr("Выход"), lambda *a: app.post(app.quit_app)))
        icon = pystray.Icon("MoiParoli", img, tr(APP_NAME), menu)
        icon.run_detached()
        return icon
    except Exception:
        return None


# ==========================================================================
#  Оформление
# ==========================================================================
FF = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

DARK = {"bg": "#141c27", "side": "#101720", "panel": "#1b2635", "card": "#223044",
        "fg": "#edf3fc", "muted": "#a5b4c9", "accent": "#a7e0d7", "accent_hi": "#c1eee8",
        "accent_fg": "#132f2c", "sel": "#24433f", "border": "#334154", "hover": "#29394d",
        "good": "#8ddcb7", "warn": "#edc58e", "bad": "#ffa6af"}
LIGHT = {"bg": "#f2f5f8", "side": "#e7edf3", "panel": "#ffffff", "card": "#f1f5f8",
         "fg": "#1b2a3d", "muted": "#596a7d", "accent": "#23685d", "accent_hi": "#1c594f",
         "accent_fg": "#ffffff", "sel": "#dceeea", "border": "#d7e0e9", "hover": "#e4edf4",
         "good": "#247048", "warn": "#8e5800", "bad": "#ab3448"}
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


ICON_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAW7klEQVR4nO1bC7RdRXn+/tmPc869NzcPwkNEhIZICEaC0oB2YSoFqoIUikFatGB5dK1GWh+lWAQuqYJgVZZVW4uPWigLTRZIeVlBGxGEBMRCeAgKKEgMyb1Jbu7z7LP3nun6/5nZe85JvCCyWteyc9fc/Z6Z/5/vf84c4P/Lb3ehl/6pIQyB8NgaAlbg/6wshsElMCAy/wu9GcLytTEwpPCbVoaMwpCJYcyvNKn04l4zhBVQWENldevY0XnIxvaGyeciShNECaHgFo2BIgWKDBoJoTQGMX8QAwoEiu1MRa7vOOZR1Pf8OX8T+ZPCXxMSGCiphMRkSJKtiLAJq2i0GttqE+EUaB7My8AAowDScnr0M3tjevIUmPIdILMEZOZDNQmKiYuFTyB+PQKUsve4C+Wu+Zkc3XuRu8ejkHtgJtkauaN7tbrurbrUiDGMlDZQom7Rjck1uHBgU4WKVW7sL4kBK1ZHWHNKiSOebYGGPwyYlaB0N+jczgqgQbEWAoW4YJTKjVoIdMR6ZoT35D1HuSLHlODomRLxt+6ci3xGzGuFJFJIATR4zvUIEvM5TdEVWEVtrDBRF3JfNANWOOIP+/5ryairTZQcinKcP+mAFEH5ETrCfeVrTyAjoar8qieU32MiHTLQgwx+TxDE7/A9PnrCg3PhJRmjDL+nScEYpVIaIBDpH2qod+Nj9KOZmEAzEv/6tUegxK1Qah5MlsFQDKWohrIjRgj0RLNMq5pAhM9pZ5Hwla+Fp45ZnmEeDXLuGNAjIiImkX8mOqhAX9SgCMOqzI8rLk/vr2h6YQYYK/MH370AamodUMyHKTtQUVzPajhbjkA/i9WMuvshKvxIhbiQaQFTfA0ZxgwIAFehwD2W5iOCYZ0nXcjzAkmUItLDZpY6HBfRT3elE9QuGcKmzmy9BiafD93uwJQxdAGYEnIsC1Y+gNbuPAdMETzLgdJV7av7Xqq23/M5v1+6dqV9vseV32Elbtz7ur7HleeSK5Ojufv6npznJka76ECr3Wm0vEYswy6K6oG+nf3h8TNB0RuRj3agi9gSGAzaE+GOJMxwDBDiC5A88wwJiedzd80E+fvcRuGIr9pzTBaCtWMGn7vK544BUh2/hAmWGTEmiw4o+j21vjxDZp99hV8iAiT/j7iniR3PPgZjXg1dliDFNj2AvsNeAGEVRSCvvASD/NzpgtA69IpMl0h55efFhmBUZI2+WIwosAzeUoSm04mHeyzukD3XiLhB/bQ5MD4Yf42OI1d8hLhr9llJTGw6ClD7oZwqQNwjz5LnE59rb4BFVgkR9HjWLd9epv1oKpmOuhnjryuzyYT65wQkMZDGiJIIxhjo0usV27d1mchCn9HA4+TbfN8xgFUiCl1SI16AJ7EcoNutVZCvUDNgy+6Wyk72DhDbFaGWfS6APOQd4ezoaYIpCEZrvPaguejvS6ANu+R2xkhmz46CzyvGUATD9tu9VyPEa7N6lrdPlnh2uEBnGwHNBNGsFCWLhIgzD4yZ4ZwoFgluwqk40bmKxyiPNTQM8uIEALdjcY38uGLAnW9xJiJfyu4NjOZROrlTtYDx4OUFBerkuOryI3DmKQe4nnt1aqVwXYfMWC22yj3zHTgsc/HTB2SZxrNbCtzxQNt84eYpPPyTNmgwBSIDw6IsfPAWwilFNwRBgVQjo5Y/4FB5uMrOPhfXqwzA4NVrm0h/+gQZ7GuMLqAEu7UJc59EkRIJOWjxIB677UQqy9Jo0dhBcaTZc4vF6hGRQDo454OjvVZLViVYZGSdEp/4+ri5+F8noBopTJqIWyLoSZihAqvarZYGqqbYY41BxdNoJYtwFeWeZtU16MFftKDLlmHcoGQUyMAlPpFzWxn2PIljO9qYbucmiiIUpa5Q7rhd22kGvRucHRuLSj1O5oHnE5/6yiKV5xpZVsgkX/SeOXT1382GaWdQRQ4SE1oAeUliJXytLIevmty9AQB9IcmqiwF5i1UIuxROqVjbIgSL7FvlyQNTjQgbnxnD2effhfHJHK1miqJkaNYACKpXV7Uu6IEJSRgZfmS5qBSZOBaNbabbBd5zzCy66L2zUG5vQyHv8RscA4peZmhmEl9HKCtHehcMkMkpLcGVnbfehp04L9MausyhBlJc+/Uf4XePX4077noWzUYikNVWG1Zm2dZARJjUCvMWMO45SwY/rCVYJsKq0yQmkxclLjh1Fi08QKEc70A5v8MywfsNzmcRp8kzpATynQNDtdMdcXY42hPb4ojXMF4ExKmxDWmtke7Wjyd+OoFj/+QmvH/oe5huazTSBEXB3/Tw1hNfMcGS79kQ8sdxwgHFM4hNoTGNNMKZb+0DJq0ooAiZoGuiCxGP2rliUZiRAXraorXy2ryXZtFAjinMECvHBp2JTMaeDDbxmX96AIcf/zWsvffnFg2KULIM9jChIrgreRMY757CzKjUihw0lr+uQUhLlDnrAu9SOyawR+lFoxIR987W7g5UNzsKY11YzXF1IAKOeKcXGA18zcpowYJZOGD/AeTD40h378NjT4/iqHfdgPMu/R46uRFGeDR0iwQjlOfV/nWbwfA6RIezzIDZe35smi0D42OPCgX+uIsqumxsBgRwMezHF2Ar6H19w3pBYG8re5fIMuy9Z4r7rj+JHr7tXfjguW+gzo4pGXzan+CTV67Hm064Dnffv1EUZJxIPkzMnnIWSyJrOa8IE8TIOKXUTKkEwls48SZ83BDWAAnhzItY9MARu2BAJetVwKNrROhSjqIT8hx7zG9i3twG0pToUxe/Gd+89kTa/xV96IxMornXLDz0o21YfvIafOST92D79sy5s0zgzrXUBrEiNBoJ0jSWa68jgtHJUJj84e05pic7nPiox1lp/oDwIqvNIt/nnE5Q4q6rMZaxEobhzu6sU4LiTXEH4hA5x81olEVpCRJ7neOtv78/7rv1T+kDl6zFv1/3iKHBFlSS4LJ/WI8vrn4cu83t58jECXJ3MMQoaKUxDls0Gyv/bCGWLpqLLC8QBY6RZYGVj/WPjsOMZ4jnxyjEuQycSnE4+G03ZnaWBAXiwM7AgIE2mYnSRxfSmIWeHaAfgVVgVjdwv6yiOFjLshzz5zVxzT8ehz84cl/64NB3zfZtU6a5+yANj2QY3pwHGSQfCHGUx8GaVf8PPrgNV9/4DL5w6WF470n7I+tYJ8jj36f/v3rLZiDWVgdUFtWbeDtBNrJs1GF1r1lCrwgIPBjuXvb5vNb6uxKNLm5GCkWu0enkOGPFEqy/9d046s37UnvTqAR5yUAC1YwRtWxVfOxPZHBpv0JjVgSkhFwR/vy8e/H9B4bREHGw7eeFRprEuPa2X5j167Yi6mMr4/MGfOy45EvbuhLkiGfF6BV6MTGDFZjlrbIlmpwCDE2jiEegIAUUlrM2ICUyUaQMo2Hh/nPpO6tPoY8NHQlkHeRjU1DETlRhUw2mRDk2hbcu3wMbbjiaHr7haDp++V4SZDHVQ597yM4nMY8MWs0EG368AysveQSqQZKpq7JOfJ63gZJDc0ZWyynETp2tYvMYD5iZEaBr0+dTK7VFsErQ4pVNo2UAE21bdUaN10JiZRgJeV7gI3/1Rlq75p20eOEgii3boUzBQTp0J0PSKPHZC5fSgfsPYuF+g/j8xYdS2jDgNPe6h0aw8fkJpIlCmia48dvPYdkfr8XYZAeISmix90x8Biqn7bjifiBq1Zknbx3EP+AYp1sLKuzMAVuFEfyB1fpdsHepLYuOKrCrivNhxY9nJ66ddXDksleadTefinPOXIJydAfK6SlEigeVIe9wuG57ZpgzUSzrk5NtDG9j50xRWWrMnpXgLcvmwrSnYfIOCDlI85Fnth9I59mstIiCM4diHfykFr1uAHbhB7iIzxHKPoHlpk+6dZlG0uKmi26uHHhbahc3jiMRif5WjH+54lis/vLx2HM2odi6Hfn4BM7/xN3GOBf2/CvuQXt0ClFk3W6vfItS01sO35O++ZXl9LlVhwDtaSg2y+kATLobjOpzRIcJWZ+nDFCAmRhADXatjDhD7OmF7rCsBJU9ImKM2smft8EsJ2B8EMQI4XUUDpmzTo4Vxy/CultPw6nvPBBKFfjvR54XbZ93Sty/YbNBpGEKlt2cJ0Ka5n46eS6h8cp3v4au+vgyKjv9INbyAu8syEAHSVWflGVdoF+IASYjI3muQN7DDDA3xCEoB0sVY1j+bfBXObY+PxegwuY6SPwRjuj222c2zj5tCRLSmDMQoa+VotFMMI8zPmUOrXNJCQ7285qXLZFSYjHbWY6zTt4Xp54wH+XWccSc5+QxeWKrWfeIcCJhRXYGPwAITB47Q9SzXuJn2XpVpkp5VeGsW5123n2wZs+RI5dWI8HItmlccOm38cVrHxRbPbxtCld+6T7DecJNm8egmOapaXPQ6/aifV85SEXBouB6YlfaTdvQ2a+iG/5zi8k7nPmOqxykG0hgup0PIGAam4EBJnO5iyDz6xureFFniIMA1oW6/h91KUNWYP1NO5PX3fAQPvzR2/HsU9ug5s2WBOnm4Wl88G/vsP0MNpE2YnS2TtHfnHUIxbFClpWIY59W4Ww4ocgLLFowC4cvHcBd94whmt1E6b3AKtUYKm6JvoDx8RkYQA1jIz2X/dG+PWZG7R3WbqfFgMs9VgzyGCgLMYdC/OM/2YIPr7oN/3Hro0CraZp7DHCGlwwv+qcK8e59Ik3tdkGd57bi7HPfhPec/FoxoxHnBS1fRdq4F9aZPPhli/tw13dHQJwk1X5RwHslbswyjy45MrMIjAcKTzYuBOjwqSwv395M1rD3ytCmroH+ZoLxyQ6u+PQd+PQ/34kdI1NAmgLTGbUnOyaMBXL7IfXP7cd5Hz2ahj60XIi3GTQKcm0eYfZ67z3Y23NWShgQJFyqWfHLcXixOkC7Ga8QbgfqF0U4AhNrYNPtXtMz3FnTD/ZZuF9/84MY+vhteHTDc6JD+vacjTe+YT/09TUkyyWrSU4Pz+pLsfTgvXDi2xfRwt+ZzxBn6agyyEHWuDtZIJGeU3Kaff+eJEvXkt4LMcCkNk0jnPPg5tSzlQee6TqVx2JiV434kjU7h7GDjRgPPbIRF196E2765kO8SAkkCd7x9qW49MLjsGTxK/ACxbCpjBwhfszO23ZLE+J5ygsbt0x1Txgr614FKNB3IqBmUoLU4YDbCk0X5CuX1zYuS9gpQE1xUEoNw7O+dXQKQ1fejs9/6b8wuX1KoP2axfvgoxccj1NOer20Md3Jq/RW15S4U06SeOIDyrtgz4iIlEXC/Q8PAzEP28u7t+w+fnF5Te1zlIMzMaBhbYWYQCf31VoT/3PhZdQAVFuWtpppLOy5+mvr8PeX34ynfvy8MK5vbj/O/YujcP77j8XcwRamMqsv2CFySwNV6rtqvmsNpSdNZhdPZOI5MGK0PfmzUXPfDzeDWk0JruqGXUzjZ73yZ+iFzOCIXfCrFkQ51nav8IyrJiennYIpJCF597qncMnlt+A7397gJEbhbccegkuHTsShS/ZBu9AYm84lVJYudA9dnmg/x474bgGw+tXflWwRgE995VFko23E85u8/llzT2TeK8MeU6j6zQwMyJ1f71Lz1Q6MtCYc7KURqBnhiae34MgTPgNMTMmzBYv2xqoLTsBpK5YJbkYnczGDTHyou8Pgqct+dC2Y7Fz4bicv0d9K8d31G/Glqx9DNKfPWh1Zw2X33VsAgUE1+5Va08/TDCIwz8DssB8J8WwKmXhWLAxht5bvZolTYZjK0De7hfedcxTO+8AfYv6cPplxVpi8huj9j5757HIyPQy6/K2QD4JkLe0w8Y/8eCtO/cs7UPKunSiC4dyCxC5h1qqGv30mCDAY61oZQw8COi75btNg8tjBvdrPJ6N0KbJOiaOPXYLLhv4Ihx3yKoxNFxjekQnhbK04w7vruexJens3N3jgn3MGmb1AdqG5fONbT+Gc8+/EyKhGNMBLmd681esM4i85M22X+UpRgsIB1TeDCIBfKe14BPZOeYi99krRGoEyK7HPK+fh9hveV3072IoBri9zmZjOcc/9z+Pz1zyC6295SpypqL8BzbkD4u2jrLjFbbArSl1yb7NaNpHD6m1qVyJA9qB4U4AzAQJ5lwVmUaisEXdnQEmELSPjOOtDa7Bgv90lkcFWoTRcrRrztXvN1/HS+RR+RVTWBlzYa60DYSor8fONE3j48RE8+eSoIE4NtmRcnI2ukrPe7rOMuGtJ51VIqNz4EsmOrpAw7mJ10piEUVMgvVvVsMRETgSqlLaNDzqG8OUv3uW2trCVcFtmq/NwS0y4vc5v7Ku0bOC/B66sD6QTBdXXgOrnJKhXmzzrTnGI8DsUiMKzKLA5TUnyiqtqDCaxx5JJPFNPeuwnRO48s6qNOaf/AihfJfjivS0sO94Ueo47NPH+qXhePyhmgh3R/G6cyFG2ynCYGm6ykg8DLR0unrutHH5F2Bskpk8WT2RXmR8uv+hzFeKs2Qa0W8Rx4itM0LxvTvp+Dg8cltvd7qvEdAQIWB4Bd7ID/gPStAzgj/xArRMjhWGm6tw7r/sRIyT2Gx2d3vBbXcU+S7bPKiG/NO41tl8YEfGw28VtP7WodIfZzrX10Z53cytnx3LNZ7MYEcTyolJ2ctc7KqpYP64p28NhL74Z6KyEKZRNgvBtvynJxQY2EyRE8CYTkWfOuoQJCcke+Yllq+B3fvpzNpHBrpEqovSurEOEyHIgHqGCc5q+XsOolZ4gQeIXXuvMZTkT1PqGbfvgIHiviz0/4NyUhkc2wGQLLQvZpnn5jbtXdfweHZWCvKz7TKB7n1gUFB/d3j+3Jc4mO1006PcNega6fTbeH7PI4UO9Ql17fB7ujiGSt3San5GrOXOqWA4fMJvV4ZZUC/9eJWiA5TGe/Gxm5pxxGQFfhZ70C4KulN1LTxJn8yGD4dUYGbxnDjOKKWARyQFiveAIlrjd6wSfcOlRitJHmGN2+fcuE+eY4M11xRCfzZb3DKhFhpKLgIs0sLpriwxhp7IiAlZrmnPat6CzY2CKDCpK6sVMp+kFDS774wMljwiv4bs2S/NLwTO/+8wRLwhxSr165rz/evNQEOF1McMT67b01nmAHKrJaa5/w5bLzrC0rZnBDEpZLLrYxOecTp3yXqB8NbTst7XOgKxT8dGaRgtpTxRnYRk0znmSfIHbvCfXfiNfaAqZ8NKKTCj/3n+ooienAEUUQoXnGOBT9j6PwcRTowGjfwCat9JPbO+cK+xUWD6GCCNXbTLxwNtAzZ+BkhSmKGAKbbMvYQ4+2BVeLUf53eF+cSIPFi479Xnp22pXS1xVrfrx3/P98PuMUyfuW9ee9N3RKDulEA/6gaH0OGw+b9JN7E45IcIvLQ4u887aB+XUVwjlMdKZ9KQMVMxTLz/ZqPYIVz+RCdf/wx/+eIXn5T543iX/QYzcVbxv4DPSovCc3SvY7VOgJGZ9Yyi6BsWcldh6/nho938FBnAJPpx7+jmksw8B+jVVtCilhzj/IweBuPvRlNcB1XsBseF5173AG3T6oPIFgj2MtX/AffG9+D4TNT6OTatutI38cuJfBAOqBmxP+3yghYkdxxA6bwNK3ne7pzFo+W2ghiJe3Kj3sBP/fkX8fN7bXm9nlV0uvL3V+gLE/+zub2NIdhB5ned+AuKDCJ/t8RliUTITBrQRlN4HNG/F8xfead8Lxj1DIbzosrMGxQGfaWDbkw2YPoJuE1Rz586oaWDarp+53c92axm7Nc8VxddNAraj+x6/0/MtlyTSGFjatu7tC4z1ZSpkG1/usf2bUhQwFNux/WqFfs2OXyYmmF+3+5faAH7ry/8AMjWftmsfeOsAAAAASUVORK5CYII=")


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
        tr('Генератор паролей'): tr('Создайте уникальный пароль для новой учётной записи.'),
        tr('Новая запись'): tr('Сохраните доступ и упорядочьте его в хранилище.'),
        tr('Запись'): tr('Данные аккаунта и параметры доступа.'),
        tr('Настройки'): tr('Безопасность, быстрый вход и поведение приложения.'),
        tr('Аудит безопасности'): tr('Проверьте записи, которым требуется внимание.'),
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


def _centered_scroll_card(parent, palette):
    """Keep login/create controls reachable at large Windows text scales."""
    shell=ttk.Frame(parent)
    shell.place(relx=.5,rely=.54,relwidth=.74,relheight=.76,anchor='center')
    canvas=tk.Canvas(shell,bg=palette['bg'],highlightthickness=0)
    bar=ttk.Scrollbar(shell,orient='vertical',command=canvas.yview)
    bar.pack(side='right',fill='y')
    canvas.pack(side='left',fill='both',expand=True)
    canvas.configure(yscrollcommand=bar.set)
    card=ttk.Frame(canvas,style='Panel.TFrame',padding=(32,24))
    window=canvas.create_window((0,0),window=card,anchor='n')
    def arrange(event=None):
        if not canvas.winfo_exists():return
        width=max(1,canvas.winfo_width())
        height=max(1,canvas.winfo_height())
        canvas.itemconfigure(window,width=min(card.winfo_reqwidth(),width))
        needed=card.winfo_reqheight()
        canvas.coords(window,width/2,max(0,(height-needed)/2))
        canvas.configure(scrollregion=(0,0,width,max(height,needed)))
    card.bind('<Configure>',arrange)
    canvas.bind('<Configure>',arrange)
    root=parent.winfo_toplevel()
    def inside(widget):return widget is canvas or str(widget).startswith(str(card)+'.')
    def reveal(event):
        if not inside(event.widget) or not card.winfo_exists():return
        y=canvas.coords(window)[1]+event.widget.winfo_rooty()-card.winfo_rooty()
        start=canvas.canvasy(0)
        if y<start or y+event.widget.winfo_height()>start+canvas.winfo_height():
            extent=max(canvas.winfo_height(),card.winfo_reqheight())
            canvas.yview_moveto(max(0,(y-12)/max(1,extent)))
    def wheel(event):
        if inside(event.widget):canvas.yview_scroll(-int(event.delta/120),'units');return 'break'
    focus_binding=root.bind('<FocusIn>',reveal,add='+')
    wheel_binding=root.bind('<MouseWheel>',wheel,add='+')
    def cleanup(event):
        if event.widget is parent:
            root.unbind('<FocusIn>',focus_binding)
            root.unbind('<MouseWheel>',wheel_binding)
    parent.bind('<Destroy>',cleanup,add='+')
    card.scroll_canvas=canvas
    return card


def _scroll_dialog_body(top, padding=20):
    """Keep larger fonts and keyboard-focused controls accessible on small screens."""
    shell = ttk.Frame(top)
    shell.pack(fill="both", expand=True)
    canvas = tk.Canvas(shell, highlightthickness=0,
                       bg=ttk.Style(top).lookup("TFrame", "background"))
    vertical = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
    horizontal = ttk.Scrollbar(shell, orient="horizontal", command=canvas.xview)
    horizontal.pack(side="bottom", fill="x")
    vertical.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    canvas.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    frame = ttk.Frame(canvas, padding=padding)
    canvas.create_window((0,0), window=frame, anchor="nw")
    frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
    def fit():
        top.update_idletasks()
        header_height=sum(w.winfo_reqheight() for w in top.winfo_children() if w is not shell)
        width=min(frame.winfo_reqwidth()+24,top.winfo_screenwidth()-80)
        height=min(frame.winfo_reqheight()+header_height+24,top.winfo_screenheight()-100)
        canvas.configure(width=max(320,width-24),height=max(200,height-header_height-24))
    def reveal(event):
        widget=event.widget
        if not str(widget).startswith(str(frame)+"."):
            return
        y=widget.winfo_rooty()-frame.winfo_rooty()
        height=max(1,frame.winfo_height())
        view_start=float(canvas.yview()[0])*height
        if y<view_start or y+widget.winfo_height()>view_start+canvas.winfo_height():
            canvas.yview_moveto(max(0,(y-12)/height))
    top.resizable(True,True)
    top.bind("<FocusIn>",reveal,add="+")
    def wheel(event):
        if event.widget is canvas or str(event.widget).startswith(str(frame)+'.'):
            canvas.yview_scroll(-int(event.delta/120),'units')
            return 'break'
    top.bind('<MouseWheel>',wheel,add='+')
    top.after_idle(fit)
    return frame


class RoundedCard(ttk.Frame):
    def __init__(self,parent,palette):
        super().__init__(parent)
        self.canvas=tk.Canvas(self,bg=palette["bg"],highlightthickness=0,height=90)
        self.canvas.pack(fill="both",expand=True)
        self.body=ttk.Frame(self.canvas,style="Panel.TFrame")
        self.window=self.canvas.create_window((16,14),window=self.body,anchor="nw")
        def draw(event=None):
            width=max(48,self.canvas.winfo_width())
            height=max(60,self.body.winfo_reqheight()+28)
            self.canvas.configure(height=height)
            self.canvas.delete("surface")
            r=16
            points=[r,1,width-r,1,width-1,1,width-1,r,width-1,height-r,
                    width-1,height-1,width-r,height-1,r,height-1,1,height-1,1,height-r,1,r,1,1]
            self.canvas.create_polygon(points,smooth=True,splinesteps=24,fill=palette["panel"],
                                       outline=palette["border"],tags="surface")
            self.canvas.tag_lower("surface")
            self.canvas.itemconfigure(self.window,width=max(16,width-32))
        self.canvas.bind("<Configure>",draw)
        self.body.bind("<Configure>",draw)


class BrowserDialog:
    def __init__(self,app,parent):
        from browser_identity import EXTENSION_ID
        from browser_registration import register,diagnose,probe_host
        top=_new_top(app,parent,tr('Подключение браузера'))
        frame=_scroll_dialog_body(top,24)
        ttk.Label(frame,text=tr('Браузер и приложение'),font=(FF,18,"bold")).pack(anchor="w")
        ttk.Label(frame,text=tr('Заполняйте поля и сохраняйте новые пароли с подтверждением.'),
                  wraplength=520,foreground=app.t["muted"]).pack(anchor="w",pady=(6,18))
        ttk.Label(frame,text=tr('Постоянный ID расширения')).pack(anchor="w")
        value=tk.StringVar(value=EXTENSION_ID)
        ttk.Entry(frame,textvariable=value,state="readonly",width=48).pack(fill="x",pady=6)
        ttk.Label(frame,text=tr('В браузере загрузите папку browser_extension из каталога установки. ID должен совпадать с указанным выше. Регистрация выполняется установщиком автоматически.'),
                  wraplength=520,foreground=app.t["muted"]).pack(anchor="w",pady=(6,14))
        status=ttk.Label(frame,text="",wraplength=520,justify="left")
        status.pack(fill="x",pady=12)
        folder=os.path.dirname(sys.executable) if getattr(sys,"frozen",False) else os.path.dirname(__file__)
        exe=os.path.join(folder,"browser_host.exe")
        if not os.path.isfile(exe):exe=os.path.join(folder,"dist","browser_host.exe")
        ttk.Label(frame,text=tr('Версия приложения: ')+APP_VERSION,foreground=app.t['muted']).pack(anchor='w')
        ttk.Label(frame,text=tr('Регистрация не подтверждает установку расширения. В расширении нажмите «Проверить подключение», чтобы проверить всю цепочку.'),wraplength=520).pack(anchor='w',pady=8)
        checking={'busy':False}
        def check():
            try:
                checks=diagnose()
                names={"Google\\Chrome":"Chrome","Yandex\\YandexBrowser":tr('Яндекс'),
                       "Microsoft\\Edge":"Edge","Chromium":"Chromium"}
                lines=[]
                for browser,label in names.items():
                    valid=all(item["ok"] for item in checks if item["browser"]==browser)
                    lines.append(label+": "+(tr('регистрация настроена') if valid else tr('требуется восстановление')))
                status.config(text="\n".join(lines)+"\n\n"+tr('Проверка модуля…'))
                if checking['busy']:return
                checking['busy']=True
                def worker():
                    try:
                        result=probe_host(exe)
                        detail=tr('Версия модуля: ')+result['version']+' · '+(tr('Версии совпадают') if result['version']==APP_VERSION else tr('Обновите приложение и расширение'))
                        if not result['save'] or not result['fill']:detail+='\n'+tr('Нужна новая версия модуля приложения.')
                    except (OSError,ValueError,subprocess.TimeoutExpired):detail=tr('Модуль приложения не отвечает. Нажмите «Восстановить подключение» или переустановите приложение.')
                    def finish():
                        checking['busy']=False
                        if top.winfo_exists():status.config(text="\n".join(lines)+"\n\n"+detail)
                    app.post(finish)
                threading.Thread(target=worker,daemon=True).start()
            except (OSError,ValueError):
                status.config(text=tr('Не удалось проверить подключение.'))
        def repair():
            folder=os.path.dirname(sys.executable) if getattr(sys,"frozen",False) else os.path.dirname(__file__)
            exe=os.path.join(folder,"browser_host.exe")
            if not os.path.isfile(exe):exe=os.path.join(folder,"dist","browser_host.exe")
            try:
                register(EXTENSION_ID,exe)
                check()
            except (OSError,ValueError) as exc:
                status.config(text=tr('Подключение не восстановлено: ')+str(exc))
        ttk.Button(frame,text=tr('Восстановить подключение'),style="Accent.TButton",command=repair).pack(fill="x")
        ttk.Button(frame,text=tr('Проверить снова'),command=check).pack(fill="x",pady=(8,0))
        ttk.Button(frame,text=tr('Закрыть'),command=top.destroy).pack(anchor="e",pady=(16,0))
        check()
        top.bind("<Escape>",lambda event:top.destroy())
        top.grab_set()
        parent.wait_window(top)
class ConflictDialog:
    def __init__(self, app, snapshot):
        self.result = None
        self.choices = {}
        conflicts = snapshot["conflicts"]
        top = _new_top(app, app.root, tr('Разрешить конфликты'))
        frame = _scroll_dialog_body(top,24)
        ttk.Label(frame, text=tr('Выберите версию записи'), font=(FF, 18, "bold")).pack(anchor="w")
        ttk.Label(frame, text=tr('Пароли скрыты. Сохранение обеих версий создаёт отдельную запись.'),
                  wraplength=560, foreground=app.t["muted"]).pack(anchor="w", pady=(5, 18))
        heading = ttk.Label(frame, font=(FF, 12, "bold"))
        heading.pack(anchor="w")
        summary = ttk.Frame(frame)
        summary.pack(fill="x", pady=14)
        labels = []
        for column, title in enumerate((tr('На этом компьютере'), tr('В файле на диске'))):
            summary.columnconfigure(column, weight=1, uniform="version")
            panel = ttk.Frame(summary, style="Card.TFrame", padding=16)
            panel.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
            ttk.Label(panel, text=title, style="Card.TLabel", font=(FF, 10, "bold")).pack(anchor="w")
            label = ttk.Label(panel, style="CardMuted.TLabel", wraplength=240, justify="left")
            label.pack(anchor="w", pady=(10, 0))
            labels.append(label)
        choice = tk.StringVar(value="both")
        for value, text in (("both", tr('Сохранить обе версии')), ("local", tr('Оставить локальную')),
                            ("remote", tr('Взять версию с диска'))):
            ttk.Radiobutton(frame, text=tr(text), value=value, variable=choice).pack(anchor="w", pady=4)
        current = [0]
        def render():
            conflict = conflicts[current[0]]
            entry = conflict["local"] or conflict["remote"] or {}
            heading.config(text=f"{current[0] + 1} / {len(conflicts)} · {entry.get('title', 'Удалённая запись')}")
            for label, key in zip(labels, ("local", "remote")):
                entry = conflict[key]
                text = tr('Запись удалена') if entry is None else (
                    f"{tr('Логин: ')}{entry.get('login', '')}{tr('\nКатегория: ')}{entry.get('category', '')}{tr('\nИзменено: ')}{entry.get('updated', '')}{tr('\nВложений: ')}{len(entry.get('attachments', []))}{tr('\nПароль: ')}{('есть' if entry.get('password') else 'отсутствует')}")
                label.config(text=tr(text))
            choice.set("both")
            save.config(text=tr('Сохранить решения') if current[0] == len(conflicts)-1 else tr('Следующая запись'))
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
        ttk.Button(buttons, text=tr('Отмена'), command=top.destroy).pack(side="right")
        save = ttk.Button(buttons, style="Accent.TButton", command=advance)
        save.pack(side="right", padx=8)
        top.bind("<Escape>", lambda event: top.destroy())
        render()
        top.grab_set()
        app.root.wait_window(top)


class GeneratorDialog:
    def __init__(self, app, parent, select=False):
        self.app, self.result = app, None
        top = self.top = _new_top(app, parent, tr('Генератор паролей'))
        frm = _scroll_dialog_body(top,24)
        self.out = tk.StringVar()
        ttk.Entry(frm, textvariable=self.out, width=44, font=("Consolas", 11)).grid(
            row=0, column=0, columnspan=3, sticky="we", pady=(0, 6))
        self.bar = ttk.Progressbar(frm, maximum=100, length=300)
        self.bar.grid(row=1, column=0, columnspan=2, sticky="we")
        self.lbl = ttk.Label(frm, text="")
        self.lbl.grid(row=1, column=2, sticky="e", padx=(8, 0))

        ttk.Label(frm, text=tr('Длина')).grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.length = tk.IntVar(value=16)
        ttk.Spinbox(frm, from_=8, to=64, textvariable=self.length, width=6,
                    command=self.regen).grid(row=2, column=1, sticky="w", pady=(12, 0))
        self.opts = {}
        for i, (key, text, default) in enumerate((
                ("lower", tr('Строчные a–z'), True), ("upper", tr('Заглавные A–Z'), True),
                ("digits", tr('Цифры 0–9'), True), ("symbols", tr('Символы !@#$…'), True),
                ("ambiguous", tr('Разрешить похожие (O/0, l/1)'), False))):
            var = tk.BooleanVar(value=default)
            self.opts[key] = var
            ttk.Checkbutton(frm, text=tr(text), variable=var, command=self.regen).grid(
                row=3 + i, column=0, columnspan=3, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=3, sticky="e", pady=(14, 0))
        ttk.Button(btns, text=tr('Обновить'), command=self.regen).pack(side="left", padx=4)
        ttk.Button(btns, text=tr('Копировать'), command=self.copy).pack(side="left", padx=4)
        if select:
            ttk.Button(btns, text=tr('Использовать'), style="Accent.TButton",
                       command=self.use).pack(side="left", padx=4)
        else:
            ttk.Button(btns, text=tr('Закрыть'), command=top.destroy).pack(side="left", padx=4)
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
            messagebox.showwarning(tr(APP_NAME), tr('Выберите хотя бы один тип символов.'), parent=self.top)
            self.opts["lower"].set(True)
            return
        self.out.set(pw)
        bits, text, level = strength(pw)
        self.bar["value"] = min(100, bits)
        self.bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
        self.lbl.config(text=tr(text))

    def copy(self):
        self.app.copy_text(self.out.get(), tr('Пароль'))

    def use(self):
        self.result = self.out.get()
        self.top.destroy()


class EntryDialog:
    def __init__(self, app, parent, entry=None, category=""):
        self.app, self.result = app, None
        t = app.t
        is_new = not entry
        entry = entry or {}
        top = self.top = _new_top(app, parent, tr('Новая запись') if is_new else tr('Запись'))
        frm = _scroll_dialog_body(top,16)
        self.vars = {}
        r = 0

        def label(row, text):
            ttk.Label(frm, text=tr(text)).grid(row=row, column=0, sticky="nw", pady=5, padx=(0, 12))

        if is_new:
            label(r, tr('Шаблон'))
            self.tpl = tk.StringVar(value=tr('Пустая запись'))
            cb = ttk.Combobox(frm, textvariable=self.tpl, values=[tr(name) for name in TEMPLATES],
                              state="readonly", width=36)
            cb.grid(row=r, column=1, sticky="we")
            cb.bind("<<ComboboxSelected>>", self._apply_template)
            r += 1
        pw_row = None
        for key, text, show in (("title", tr('Сервис / название *'), ""), ("url", tr('Адрес сайта'), ""),
                                ("login", tr('Логин / e-mail'), ""), ("password", tr('Пароль'), "•")):
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
        ttk.Checkbutton(frm, text=tr('Показать'), variable=self.show_var,
                        command=self._toggle).grid(row=pw_row, column=2, padx=(8, 0), sticky="w")
        ttk.Button(frm, text=tr('Генератор…'), command=self._generate).grid(
            row=pw_row, column=3, padx=(4, 0))
        self.bar = ttk.Progressbar(frm, maximum=100)
        self.bar.grid(row=r, column=1, sticky="we", pady=(0, 2))
        self.bar_lbl = ttk.Label(frm, text="", foreground=t["muted"])
        self.bar_lbl.grid(row=r, column=2, columnspan=2, sticky="w", padx=(8, 0))
        self.vars["password"].trace_add("write", lambda *a: self._strength())
        self._strength()
        r += 1

        label(r, tr('Ключ 2FA (TOTP)'))
        self.vars["totp"] = tk.StringVar(value=entry.get("totp", ""))
        ttk.Entry(frm, textvariable=self.vars["totp"], width=38).grid(row=r, column=1, sticky="we")
        ttk.Label(frm, text=tr('секрет или otpauth://'), foreground=t["muted"]).grid(
            row=r, column=2, columnspan=2, sticky="w", padx=(8, 0))
        r += 1
        label(r, tr('Категория'))
        self.vars["category"] = tk.StringVar(value=entry.get("category", category))
        ttk.Combobox(frm, textvariable=self.vars["category"], values=app.vault.categories(),
                     width=36).grid(row=r, column=1, sticky="we")
        r += 1
        label(r, tr('Теги (через запятую)'))
        self.vars["tags"] = tk.StringVar(value=entry.get("tags", ""))
        ttk.Entry(frm, textvariable=self.vars["tags"], width=38).grid(row=r, column=1, sticky="we")
        r += 1
        self.fav = tk.BooleanVar(value=entry.get("favorite", False))
        ttk.Checkbutton(frm, text=tr('★ Избранное'), variable=self.fav).grid(
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

        self.fields = textbox(r, 3, tr('Доп. поля'), tr('по строке: «Название = значение», секретные — «Название* = значение»'))
        self.fields.insert("1.0", format_fields(entry.get("fields", [])))
        r += 2
        self.note = textbox(r, 3, tr('Заметка'))
        self.note.insert("1.0", entry.get("note", ""))
        r += 1

        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=4, sticky="e", pady=(14, 0))
        ttk.Button(btns, text=tr('Сохранить'), style="Accent.TButton", command=self._ok).pack(
            side="left", padx=4)
        ttk.Button(btns, text=tr('Отмена'), command=top.destroy).pack(side="left")
        top.bind("<Escape>", lambda e: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    def _apply_template(self, _=None):
        name=next((key for key in TEMPLATES if tr(key)==self.tpl.get()),self.tpl.get())
        tpl = TEMPLATES.get(name, {})
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
        self.bar_lbl.config(text=tr(text))

    def _generate(self):
        pw = GeneratorDialog(self.app, self.top, select=True).result
        if pw:
            self.vars["password"].set(pw)
            self.show_var.set(True)
            self._toggle()

    def _ok(self):
        title = self.vars["title"].get().strip()
        if not title:
            messagebox.showwarning(tr(APP_NAME), tr('Укажите название сервиса.'), parent=self.top)
            return
        totp = self.vars["totp"].get().strip()
        if totp:
            try:
                totp_now(totp)
            except Exception:
                messagebox.showwarning(tr(APP_NAME), tr('Ключ 2FA не распознан. Нужна строка base32 (буквы A–Z и цифры 2–7) или ссылка otpauth://.'),
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
        top = self.top = _new_top(app, parent, tr('Аудит безопасности'))
        top.resizable(True, True)
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        total = len(app.vault.active())
        head = (f"{tr('Проверено записей: ')}{total}{tr('. Найдено проблем: ')}{len(issues)}."
                if issues else f"{tr('Проверено записей: ')}{total}{tr('. Проблем не найдено 👍')}")
        ttk.Label(frm, text=head, font=(FF, 11, "bold")).pack(anchor="w", pady=(0, 8))
        cols = ("issue", "title", "login")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=14)
        for c, name, w in (("issue", tr('Проблема'), 230), ("title", tr('Сервис'), 200), ("login", tr('Логин'), 200)):
            self.tree.heading(c, text=tr(name))
            self.tree.column(c, width=w, anchor="w")
        self.ids = {}
        for i, (text, e) in enumerate(issues):
            iid = str(i)
            self.ids[iid] = e["id"]
            self.tree.insert("", "end", iid=iid, values=(text, e["title"], e["login"]))
        self.tree.pack(fill="both", expand=True)
        ttk.Label(frm, text=tr('Двойной клик — перейти к записи'), foreground=app.t["muted"]).pack(
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
        top = self.top = _new_top(app, parent, tr('История паролей — ') + entry["title"])
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frm, columns=("date", "pw"), show="headings", height=8)
        self.tree.heading("date", text=tr('Заменён'))
        self.tree.heading("pw", text=tr('Прежний пароль'))
        self.tree.column("date", width=150)
        self.tree.column("pw", width=260)
        self.tree.pack(fill="both", expand=True)
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text=tr('Показать/скрыть'), command=self._toggle).pack(side="left")
        ttk.Button(btns, text=tr('Копировать'), command=self._copy).pack(side="left", padx=6)
        ttk.Button(btns, text=tr('Закрыть'), command=top.destroy).pack(side="right")
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
            self.app.copy_text(self.entry["history"][int(sel[0])]["password"], tr('Пароль'))


class SettingsDialog:
    FLAGS = (("lock_on_minimize", tr('Блокировать при сворачивании окна')),
             ("lock_on_session_lock", tr('Блокировать при блокировке Windows (Win+L)')),
             ("close_to_tray", tr('Кнопка ✕ сворачивает в трей, а не закрывает')),
             ("hotkey_enabled", tr('Быстрый поиск по глобальной горячей клавише')),
             ("protect_capture", tr('Скрывать окно от скриншотов и записи экрана')),
             ("autotype_enter", tr('После автоввода нажимать Enter')),
             ("check_updates", tr('Проверять обновления при запуске')),
             ("animations", tr('Анимация входа')),
             ("backup_reminders",tr("Напоминать об отдельной резервной копии")))

    def __init__(self, app, parent):
        s = app.settings
        self.app = app
        top = self.top = _new_top(app, parent, tr('Настройки'))
        frm = _scroll_dialog_body(top,20)
        self.idle = tk.IntVar(value=s.get("idle_minutes"))
        self.clip = tk.IntVar(value=s.get("clipboard_seconds"))
        self.hotkey = tk.StringVar(value=s.get("hotkey"))
        self.repo = tk.StringVar(value=s.get("update_repo") or "userArturM/Moipar-")
        self.language=tk.StringVar(value="English" if s.get("language")=="en" else tr('Русский'))
        self.token=tk.StringVar()
        self.font_size=tk.IntVar(value=s.get("font_size"))
        self.flags = {k: tk.BooleanVar(value=bool(s.get(k))) for k, _ in self.FLAGS}
        hello_button = ttk.Button(frm, text=tr('Windows Hello: включить / отключить'),
                                  command=self._configure_hello)
        ttk.Label(frm, text=tr('Блокировать через (мин) бездействия')).grid(row=0, column=0, sticky="w", pady=5)
        ttk.Spinbox(frm, from_=1, to=120, textvariable=self.idle, width=6).grid(row=0, column=1, sticky="w", padx=12)
        ttk.Label(frm, text=tr('Очищать буфер обмена через (сек)')).grid(row=1, column=0, sticky="w", pady=5)
        ttk.Spinbox(frm, from_=5, to=300, textvariable=self.clip, width=6).grid(row=1, column=1, sticky="w", padx=12)
        ttk.Label(frm, text=tr('Горячая клавиша быстрого поиска')).grid(row=2, column=0, sticky="w", pady=5)
        ttk.Combobox(frm, textvariable=self.hotkey, width=18,
                     values=("Ctrl+Alt+P", "Ctrl+Alt+Space", "Ctrl+Shift+Space", "Ctrl+Alt+L")).grid(
            row=2, column=1, sticky="w", padx=12)
        for i, (key, text) in enumerate(self.FLAGS, start=3):
            ttk.Checkbutton(frm, text=tr(text), variable=self.flags[key]).grid(
                row=i, column=0, columnspan=2, sticky="w", pady=2)
        row = 3 + len(self.FLAGS)
        ttk.Label(frm, text=tr('Репозиторий GitHub для обновлений')).grid(row=row, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(frm, textvariable=self.repo, width=24).grid(row=row, column=1, sticky="w", padx=12, pady=(10, 0))
        ttk.Label(frm, text=tr('например: ivan/moi-paroli'), foreground=app.t["muted"], font=(FF, 8)).grid(
            row=row + 1, column=1, sticky="w", padx=12)
        hello_button.grid(row=row + 2, column=0, columnspan=2, sticky="ew", pady=(12, 6))
        btns = ttk.Frame(frm)
        ttk.Label(frm,text=tr('Язык / Language')).grid(row=row+3,column=0,sticky="w",pady=8)
        ttk.Combobox(frm,textvariable=self.language,values=(tr('Русский'),"English"),state="readonly",width=20).grid(row=row+3,column=1)
        ttk.Label(frm,text=tr('Токен GitHub (приватный репозиторий)')).grid(row=row+4,column=0,sticky="w",pady=8)
        ttk.Entry(frm,textvariable=self.token,show="•",width=24).grid(row=row+4,column=1)
        ttk.Label(frm,text=tr('Пустое поле сохраняет прежний токен. Защищён Windows DPAPI.'),wraplength=440).grid(row=row+5,column=0,columnspan=2,sticky="w")
        ttk.Button(frm,text=tr('Удалить токен'),command=self.clear_token).grid(row=row+6,column=0,sticky="w",pady=8)
        ttk.Label(frm,text=tr("Размер текста")).grid(row=row+7,column=0,sticky="w",pady=8)
        ttk.Spinbox(frm,from_=9,to=14,textvariable=self.font_size,width=6).grid(row=row+7,column=1,sticky="w")
        btns.grid(row=row + 8, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text=tr('Сохранить'), style="Accent.TButton", command=self.save).pack(side="left", padx=4)
        ttk.Button(btns, text=tr('Отмена'), command=top.destroy).pack(side="left")
        top.grab_set()
        parent.wait_window(top)

    def clear_token(self):
        from github_updates import save_token
        save_token(data_dir(),"")
        self.token.set("")

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
            messagebox.showwarning(tr(APP_NAME), tr('Введите числа.'), parent=self.top)
            return
        hk = self.hotkey.get().strip()
        try:
            parse_hotkey(hk)
        except ValueError as ex:
            messagebox.showwarning(tr(APP_NAME), f"{tr('Горячая клавиша: ')}{ex}", parent=self.top)
            return
        repo = self.repo.get().strip()
        if repo and not REPO_RE.match(repo):
            messagebox.showwarning(tr(APP_NAME), tr('Репозиторий нужно указать как «владелец/имя».'), parent=self.top)
            return
        if self.token.get().strip():
            from github_updates import save_token
            try: save_token(data_dir(),self.token.get().strip())
            except (OSError,ValueError) as exc:
                messagebox.showerror(tr(APP_NAME),tr('Не удалось сохранить токен GitHub.'),parent=self.top)
                return
        try:font_size=max(9,min(14,int(self.font_size.get())))
        except (ValueError,tk.TclError):return
        s.set("font_size",font_size)
        s.set("idle_minutes", idle)
        s.set("clipboard_seconds", clip)
        s.set("hotkey", hk)
        s.set("update_repo", repo)
        for k, v in self.flags.items():
            s.set(k, bool(v.get()))
        self.app.apply_settings()
        self.top.destroy()
        self.app.set_language("en" if self.language.get()=="English" else "ru")


class AttachmentsDialog:
    def __init__(self, app, parent, entry_id):
        self.app, self.eid = app, entry_id
        e = app.vault.get(entry_id)
        top = self.top = _new_top(app, parent, tr('Вложения — ') + e["title"])
        frm = ttk.Frame(top, padding=14)
        frm.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frm, columns=("name", "size"), show="headings", height=8)
        self.tree.heading("name", text=tr('Файл'))
        self.tree.heading("size", text=tr('Размер'))
        self.tree.column("name", width=300)
        self.tree.column("size", width=100, anchor="e")
        self.tree.pack(fill="both", expand=True)
        ttk.Label(frm, text=tr('Файлы хранятся внутри зашифрованного хранилища. Максимум 3 МБ на файл.'),
                  foreground=app.t["muted"]).pack(anchor="w", pady=(6, 0))
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text=tr('Добавить…'), style="Accent.TButton", command=self.add).pack(side="left")
        ttk.Button(btns, text=tr('Сохранить как…'), command=self.save_as).pack(side="left", padx=6)
        ttk.Button(btns, text=tr('Удалить'), command=self.remove).pack(side="left")
        ttk.Button(btns, text=tr('Закрыть'), command=top.destroy).pack(side="right")
        self._fill()
        top.bind("<Escape>", lambda ev: top.destroy())
        top.grab_set()
        parent.wait_window(top)

    @staticmethod
    def _size(n):
        return f"{n / 1024:.0f}{tr(' КБ')}" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f}{tr(' МБ')}"

    def _fill(self):
        self.tree.delete(*self.tree.get_children())
        e = self.app.vault.get(self.eid)
        for a in (e["attachments"] if e else []):
            self.tree.insert("", "end", iid=a["id"], values=(a["name"], self._size(a["size"])))

    def add(self):
        path = filedialog.askopenfilename(parent=self.top, title=tr('Выберите файл'))
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось прочитать файл:\n')}{ex}", parent=self.top)
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
                messagebox.showinfo(tr(APP_NAME), tr('Файл сохранён.'), parent=self.top)
            except OSError as ex:
                messagebox.showerror(tr(APP_NAME), f"{tr('Ошибка: ')}{ex}", parent=self.top)

    def remove(self):
        sel = self.tree.selection()
        if sel and messagebox.askyesno(tr(APP_NAME), tr('Удалить вложение?'), parent=self.top):
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
        top = self.top = _new_top(app, parent, tr('Проверка на утечки'))
        top.resizable(True, True)
        self.frm = ttk.Frame(top, padding=16)
        self.frm.pack(fill="both", expand=True)
        self.lbl = ttk.Label(self.frm, text=f"{tr('Проверено 0 из ')}{len(self.unique)}…", font=(FF, 11, "bold"))
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
                    self.lbl.config(text=f"{tr('Проверено ')}{val}{tr(' из ')}{len(self.unique)}…")
                elif kind == "error":
                    messagebox.showwarning(tr(APP_NAME), f"{tr('Не удалось проверить (нужен интернет):\n')}{val}",
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
            self.lbl.config(text=tr('Ваших паролей в известных утечках не найдено 👍'))
            ttk.Button(self.frm, text=tr('Закрыть'), command=self._close).pack(anchor="e", pady=(12, 0))
            return
        self.lbl.config(text=f"{tr('Найдено в утечках: ')}{len(bad)}{tr('. Смените эти пароли.')}")
        tree = ttk.Treeview(self.frm, columns=("title", "login", "n"), show="headings", height=12)
        for c, name, w in (("title", tr('Сервис'), 200), ("login", tr('Логин'), 180), ("n", tr('Встречается раз'), 120)):
            tree.heading(c, text=tr(name))
            tree.column(c, width=w, anchor="w")
        ids = {}
        for e, n in sorted(bad, key=lambda x: -x[1]):
            tree.insert("", "end", iid=e["id"], values=(e["title"], e["login"], f"{n:,}".replace(",", " ")))
            ids[e["id"]] = e["id"]
        tree.pack(fill="both", expand=True)
        ttk.Label(self.frm, text=tr('Двойной клик — перейти к записи'), foreground=self.app.t["muted"]).pack(
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
        top = self.top = _new_top(app, parent, tr('Ключевой файл'))
        frm = ttk.Frame(top, padding=20)
        frm.pack()
        ttk.Label(frm, text=tr('Ключевой файл сейчас ') + (tr('ВКЛЮЧЁН') if v.uses_keyfile else tr('выключен')),
                  font=(FF, 12, "bold")).pack(anchor="w")
        ttk.Label(frm, wraplength=440, justify="left", foreground=app.t["muted"], text=(
            tr('Ключевой файл — второй «ключ» к хранилищу. Для входа понадобятся и мастер-пароль, и этот файл (его удобно держать на флешке). Украв пароль или файл по отдельности, хранилище не открыть.\n\nВНИМАНИЕ: если потерять ключевой файл, данные восстановить невозможно, в том числе из резервных копий. Сразу сделайте копию файла в надёжном месте.'))
                  ).pack(anchor="w", pady=12)
        if v.uses_keyfile:
            ttk.Button(frm, text=tr('Выключить ключевой файл'), command=self.disable).pack(fill="x", pady=3)
        else:
            ttk.Button(frm, text=tr('Создать новый ключевой файл и включить…'), style="Accent.TButton",
                       command=self.create).pack(fill="x", pady=3)
            ttk.Button(frm, text=tr('Включить с уже имеющимся файлом…'), command=self.existing).pack(fill="x", pady=3)
        ttk.Button(frm, text=tr('Закрыть'), command=top.destroy).pack(fill="x", pady=(10, 0))
        top.grab_set()
        parent.wait_window(top)

    def _password(self):
        pw = simpledialog.askstring(APP_NAME, tr('Введите мастер-пароль для подтверждения:'),
                                    show="•", parent=self.top)
        if not pw:
            return None
        if not self.app.vault.verify_password(pw):
            messagebox.showerror(tr(APP_NAME), tr('Неверный мастер-пароль.'), parent=self.top)
            return None
        return pw

    def create(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.asksaveasfilename(parent=self.top, defaultextension=".key",
                                            title=tr('Куда сохранить ключевой файл (лучше на флешку)'),
                                            initialfile="moi-paroli.key")
        if not path:
            return
        content = secrets.token_bytes(64)
        try:
            with open(path, "wb") as f:
                f.write(content)
        except OSError as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось сохранить файл:\n')}{ex}", parent=self.top)
            return
        self._apply(pw, content, path)

    def existing(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.askopenfilename(parent=self.top, title=tr('Выберите ключевой файл'))
        if not path:
            return
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось прочитать файл:\n')}{ex}", parent=self.top)
            return
        if not content:
            messagebox.showerror(tr(APP_NAME), tr('Файл пустой.'), parent=self.top)
            return
        self._apply(pw, content, path)

    def disable(self):
        pw = self._password()
        if pw and messagebox.askyesno(tr(APP_NAME), tr('Выключить ключевой файл? Вход будет только по паролю.'),
                                      parent=self.top):
            self._apply(pw, None, "")

    def _apply(self, pw, content, path):
        ok, _ = self.app._do(self.app.vault.set_keyfile, pw, content)
        if ok:
            self.app.settings.set("keyfile_path", path)
            messagebox.showinfo(tr(APP_NAME), tr('Готово. Хранилище пересохранено.') + (
                tr('\nНе потеряйте ключевой файл!') if content else ""), parent=self.top)
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
        ttk.Label(inner, style="Muted.TLabel", text=tr('Enter — пароль   Shift+Enter — логин   Ctrl+Enter — ввести в окно   Esc — закрыть')).pack(anchor="w")
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
            self.app.copy_text(e["password"], tr('Пароль'))
        elif what == "login":
            self.app.copy_text(e["login"], tr('Логин'))
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
    COLUMNS = (("fav", "★", 38), ("title", tr('Сервис'), 200), ("login", tr('Логин'), 180),
               ("category", tr('Категория'), 130), ("updated", tr('Изменено'), 100))

    def __init__(self):
        from windows_branding import set_shell_identity
        set_shell_identity()
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.settings = Settings(os.path.join(data_dir(), "settings.json"))
        import localization
        localization.install()
        localization.set_language(self.settings.get("language"))
        self.root.title(tr(APP_NAME))
        self.settings.apply_midnight_design()
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
            icon_path=os.path.join(getattr(sys,"_MEIPASS",os.path.dirname(__file__)),"icon.ico")
            if IS_WIN and os.path.isfile(icon_path): self.root.iconbitmap(icon_path)
        except tk.TclError:
            pass
        self.frame = None
        self.last_activity = time.time()
        self._animation_id = None
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
        self.animate_entry()
        if self.settings.get("check_updates") and self.settings.get("update_repo"):
            self.root.after(3000, lambda: self.check_updates(manual=False))

    # ---------------- тема
    def apply_theme(self):
        font_size=max(9,min(14,int(self.settings.get("font_size") or 10)))
        def scaled_font(size):return max(8,round(size*font_size/10))
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
                    troughcolor=t["border"], focuscolor=t["accent"], font=(FF, scaled_font(10)))
        s.configure("TFrame", background=t["bg"])
        s.configure("Eyebrow.TLabel",background=t["bg"],foreground=t["muted"],font=(FF,scaled_font(9)))
        s.configure("Header.TMenubutton",background=t["panel"],foreground=t["muted"],padding=(6,5),borderwidth=0,relief="flat",arrowcolor=t["muted"])
        s.map("Header.TMenubutton",background=[("active",t["hover"])])
        s.configure("MidnightSearch.TEntry",fieldbackground=t["card"],foreground=t["fg"],borderwidth=0,padding=(6,8),relief="flat")
        s.configure("Quiet.TButton",background=t["bg"],foreground=t["muted"],borderwidth=0,padding=(6,4),relief="flat")
        s.map("Quiet.TButton",background=[("active",t["hover"])])
        s.configure("TextAction.TButton",background=t["card"],foreground=t["accent"],bordercolor=t["card"],borderwidth=0,padding=(4,4),relief="flat",font=(FF,scaled_font(9)))
        s.map("TextAction.TButton",background=[("active",t["hover"])],foreground=[("active",t["accent"])])
        s.configure("DetailAction.TButton",background=t["panel"],foreground=t["fg"],bordercolor=t["border"],padding=(10,7),font=(FF,scaled_font(9)))
        s.configure("CardMono.TLabel",background=t["card"],foreground=t["fg"],font=(MONO,scaled_font(10)))

        s.configure("Section.TLabel", background=t["panel"], foreground=t["fg"], font=(FF, scaled_font(13), "bold"))
        s.configure("DetailCaption.TLabel", background=t["panel"], foreground=t["muted"], font=(FF, scaled_font(10)))
        s.configure("Compact.TButton", padding=(10, 5))
        s.configure("Search.TEntry", padding=(12, 10), font=(FF, scaled_font(11)))
        s.configure("TLabel", background=t["bg"], foreground=t["fg"])
        for nm, col in (("Side", t["side"]), ("Panel", t["panel"]), ("Card", t["card"])):
            s.configure(f"{nm}.TFrame", background=col)
            s.configure(f"{nm}.TLabel", background=col, foreground=t["fg"])
        s.configure("BgMuted.TLabel", background=t["bg"], foreground=t["muted"], font=(FF, scaled_font(9)))
        s.configure("Muted.TLabel", background=t["panel"], foreground=t["muted"], font=(FF, scaled_font(9)))
        s.configure("CardMuted.TLabel", background=t["card"], foreground=t["muted"], font=(FF, scaled_font(9)))
        s.configure("SideMuted.TLabel", background=t["side"], foreground=t["muted"], font=(FF, scaled_font(9)))
        s.configure("Title.TLabel", background=t["panel"], foreground=t["fg"], font=(FF, scaled_font(16), "bold"))
        s.configure("Big.TLabel", background=t["card"], foreground=t["fg"], font=(FF, scaled_font(24), "bold"))
        s.configure("Brand.TLabel", background=t["side"], foreground=t["fg"], font=(FF, scaled_font(15), "bold"))
        s.configure("Hero.TLabel", background=t["bg"], foreground=t["fg"], font=(FF, scaled_font(22), "bold"))
        s.configure("HeroMuted.TLabel", background=t["bg"], foreground=t["muted"], font=(FF, scaled_font(10)))
        s.configure("SideHeading.TLabel", background=t["side"], foreground=t["muted"], font=(FF, scaled_font(9), "bold"))
        s.configure("Mono.TLabel", background=t["panel"], foreground=t["fg"], font=(MONO, 11))
        s.configure("StatValue.TLabel",background=t["panel"],foreground=t["fg"],font=(FF,22,"bold"))
        s.configure("StatCaption.TLabel",background=t["panel"],foreground=t["muted"],font=(FF,9))

        s.configure("TButton", padding=(14, 9), background=t["card"], foreground=t["fg"],
                    bordercolor=t["border"], relief="flat", focusthickness=0)
        s.map("TButton", background=[("active", t["hover"]), ("pressed", t["sel"])],
              bordercolor=[("focus", t["accent"])])
        s.configure("Accent.TButton", background=t["accent"], foreground=t["accent_fg"],
                    bordercolor=t["accent"])
        s.map("Accent.TButton", background=[("active", t["accent_hi"]), ("pressed", t["accent"])],
              bordercolor=[("active", t["accent_hi"])])
        s.configure("Rail.TButton",background=t["side"],foreground=t["muted"],bordercolor=t["side"],padding=(5,12),anchor="center",font=(FF,scaled_font(9)))
        s.map("Rail.TButton",background=[("active",t["hover"])],foreground=[("active",t["fg"])])
        s.configure("RailActive.TButton",background=t["sel"],foreground=t["accent"],bordercolor=t["sel"],padding=(5,12),anchor="center",font=(FF,scaled_font(9)))
        s.map("RailActive.TButton",background=[("active",t["sel"])],foreground=[("active",t["accent"])])
        s.configure("Ghost.TButton", background=t["side"], foreground=t["fg"], bordercolor=t["side"])
        s.map("Ghost.TButton", background=[("active", t["hover"])], bordercolor=[("active", t["hover"])])
        s.configure("Tool.TMenubutton", background=t["side"], foreground=t["fg"],
                    bordercolor=t["side"], arrowcolor=t["muted"], padding=(10, 6), relief="flat")
        s.map("Tool.TMenubutton", background=[("active", t["hover"])],
              bordercolor=[("active", t["hover"])])

        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=t["panel"], fieldbackground=t["panel"],
                    foreground=t["fg"], rowheight=scaled_font(56), borderwidth=0, relief="flat")
        s.map("Treeview", background=[("selected", t["sel"])], foreground=[("selected", t["fg"])])
        s.configure("Treeview.Heading", background=t["side"], foreground=t["muted"],
                    font=(FF, scaled_font(9), "bold"), relief="flat", padding=(8, 8), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", t["hover"])])
        s.configure("Side.Treeview", background=t["side"], fieldbackground=t["side"],
                    rowheight=scaled_font(44))
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
        s.configure("TNotebook", background=t["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", padding=(18, 9), background=t["card"], foreground=t["fg"])
        s.map("TNotebook.Tab", background=[("selected",t["sel"]),("active",t["hover"])])
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
            self.set_status(tr('Конфликт записей: Инструменты → Разрешить конфликты'), self.t["warn"])
            return
        except KeyChanged:
            messagebox.showwarning(tr(APP_NAME), tr('Хранилище изменено на другом устройстве с другим мастер-паролем или ключевым файлом.\nВойдите заново.'), parent=self.root)
            self.lock()
            return
        except (VaultError, OSError):
            return  # файл мог быть записан не до конца — повторим позже
        if changed:
            self.vault.merged = False
            self.refresh_all()
            self.set_status(tr('↻ Подтянуты изменения с другого устройства'), self.t["warn"])

    def _after_merge(self):
        if self.vault.merged:
            self.vault.merged = False
            self.refresh_all()
            self.set_status(tr('↻ Подтянуты изменения с другого устройства'), self.t["warn"])

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
            messagebox.showinfo(tr(APP_NAME), tr('Автоввод работает только в Windows.'), parent=self.root)
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
                self.post(lambda: self.set_status(tr('Автоввод отменён: не выбрано целевое окно'),
                                                  self.t["warn"]))
                return
            ok = win_autotype(login, pw, enter)
            self.post(lambda: self.set_status(tr('✓ Данные введены') if ok else tr('Не удалось ввести данные'),
                                              self.t["good"] if ok else self.t["bad"]))
        threading.Thread(target=work, daemon=True).start()

    def autotype_selected(self):
        e = self.selected()
        if not e or e["deleted"]:
            return
        if not IS_WIN:
            messagebox.showinfo(tr(APP_NAME), tr('Автоввод работает только в Windows.'), parent=self.root)
            return
        self.set_status(tr('Ввод через 3 секунды: кликните в нужное поле другого окна…'), self.t["warn"])
        self.root.after(3000, lambda: self.autotype_entry(e, 0, 0.0))

    # ---------------- проверки через интернет
    def check_updates(self, manual=True):
        if getattr(self,"_update_running",False):return
        repo = (self.settings.get("update_repo") or "userArturM/Moipar-").strip()
        if not REPO_RE.match(repo):
            if manual:
                messagebox.showinfo(tr(APP_NAME), tr('Укажите репозиторий GitHub в Сервис → Настройки (например, ivan/moi-paroli).'), parent=self.root)
            return

        self._update_running=True
        if manual and hasattr(self,"status_left") and self.status_left.winfo_exists():
            self.set_status(tr("Проверка обновлений GitHub…"),self.t["muted"])
        def finish(info):
            self._update_running=False
            if manual and hasattr(self,"status_left") and self.status_left.winfo_exists():
                self.set_status(tr("Проверка обновлений завершена"),self.t["bad"] if "error" in info else self.t["good"])
            self._show_update(info,manual)
        def work():
            try:
                from github_updates import load_token
                info = check_update(repo, token=load_token(data_dir()))
            except Exception as ex:
                info = {"error": str(ex)}
            self.post(lambda: finish(info))
        threading.Thread(target=work, daemon=True).start()

    def _show_update(self, info, manual):
        if "error" in info:
            if manual:
                messagebox.showwarning(tr(APP_NAME), f"{tr('Не удалось проверить обновления:\n')}{tr(info['error'])}",
                                       parent=self.root)
                if info.get("url") and messagebox.askyesno(tr(APP_NAME),tr('Открыть страницу сборок GitHub?'),parent=self.root):
                    webbrowser.open(info["url"])
            return
        if info["newer"] or manual:
            from feature_dialogs import updates
            updates(self,info)

    def check_breaches(self):
        if not self.vault.active():
            return
        if not messagebox.askyesno(
                tr(APP_NAME), tr('Пароли будут проверены по базе известных утечек Have I Been Pwned.\nДля каждого пароля в интернет уходят только первые 5 символов его хеша SHA-1, сам пароль и ваши логины с компьютера не уходят.\n\nНужен интернет. Продолжить?'),
                parent=self.root):
            return
        d = BreachDialog(self, self.root)
        if d.chosen:
            self.goto_entry(d.chosen)

    def check_pwned_selected(self):
        e = self.selected()
        if not e or not e["password"]:
            return
        self.set_status(tr('Проверка пароля по базе утечек…'), self.t["muted"])

        def work():
            try:
                n = pwned_count(e["password"])
            except Exception as ex:
                self.post(lambda: messagebox.showwarning(
                    tr(APP_NAME), f"{tr('Не удалось проверить (нужен интернет):\n')}{ex}", parent=self.root))
                return
            self.post(lambda: self._pwned_result(e, n))
        threading.Thread(target=work, daemon=True).start()

    def _pwned_result(self, e, n):
        if n:
            self.set_status(f"{tr('⚠ Пароль «')}{e['title']}{tr('» найден в утечках (')}{n}{tr(' раз)')}", self.t["bad"])
            messagebox.showwarning(tr(APP_NAME), f"{tr('Пароль записи «')}{e['title']}{tr('» найден в известных утечках (')}{n}{tr(' раз). Его нужно сменить.')}", parent=self.root)
        else:
            self.set_status(f"{tr('✓ Пароль «')}{e['title']}{tr('» в утечках не найден')}")

    # ---------------- облачная папка, ключевой файл, вложения
    def move_vault(self):
        folder = filedialog.askdirectory(
            parent=self.root, title=tr('Папка синхронизации (Яндекс.Диск, OneDrive, Dropbox…)'))
        if not folder:
            return
        target = os.path.join(folder, "MoiParoli-vault.dat")
        if os.path.exists(target) and not messagebox.askyesno(
                tr(APP_NAME), tr('В этой папке уже есть файл хранилища. Заменить его текущим?'), parent=self.root):
            return
        try:
            shutil.copyfile(self.vault.path, target)
        except OSError as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось скопировать:\n')}{ex}", parent=self.root)
            return
        self.vault.path = target
        self.vault._sig = self.vault._disk_sig()
        self.settings.set("vault_path", target)
        messagebox.showinfo(
            tr(APP_NAME), tr('Хранилище перенесено в выбранную папку и теперь синхронизируется вашим облаком.\n\nНа втором компьютере установите «Bitora password» и выберите Файл → «Подключить существующее хранилище…». Правки с обоих компьютеров объединяются автоматически.\nПрежний локальный файл остался на месте как резервная копия.'), parent=self.root)

    def attach_vault(self):
        path = filedialog.askopenfilename(parent=self.root, title=tr('Выберите файл хранилища'),
                                          filetypes=[(tr('Хранилище'), "*.dat"), (tr('Все файлы'), "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            if not (isinstance(blob, dict) and blob.get("magic") in ("passvault", "passvault-v1")):
                raise ValueError(tr('это не файл хранилища'))
        except (OSError, ValueError) as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Файл не подходит:\n')}{ex}", parent=self.root)
            return
        if not messagebox.askyesno(tr(APP_NAME), tr('Программа будет работать с выбранным файлом вместо хранилища на этом компьютере (прежний файл останется на месте). Продолжить?'), parent=self.root):
            return
        self._hide_pw(refresh=False)
        self.vault.lock()
        self.vault.path = path
        self.settings.set("vault_path", path)
        self.hello = HelloUnlock(path, os.path.join(data_dir(), 'hello_credential.json'))
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
            ttk.Button(line, text=tr('Копировать'), width=11,
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
            messagebox.showwarning(tr(APP_NAME), tr('Хранилище изменено на другом устройстве с другим мастер-паролем или ключевым файлом.\nВойдите заново.'), parent=self.root)
            self.lock()
            return False, None
        except (OSError, VaultError) as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось сохранить данные:\n')}{ex}", parent=self.root)
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
            self.set_status(tr('Конфликты разрешены. Выбранные версии сохранены.'))
        except (VaultError, OSError, ValueError) as ex:
            messagebox.showwarning(tr(APP_NAME), str(ex), parent=self.root)

    def set_status(self, text, color=None):
        self.status_left.config(text=tr(text), foreground=color or self.t["good"])

    def saved_note(self):
        self.set_status(tr('✓ Автосохранено ') + time.strftime("%H:%M:%S"))

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
            self.set_status(f"{what}{tr(' скопирован — буфер очистится через ')}{secs}{tr(' с')}")
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
        self._auth_epoch=getattr(self,"_auth_epoch",0)+1
        new = not self.vault.exists()
        t = self.t
        f = ttk.Frame(self.root)
        self._swap(f)
        ttk.Label(f, text=APP_NAME, style="Hero.TLabel").place(x=40, y=32)
        ttk.Label(f, text=tr('Личное пространство для ваших доступов'), style="HeroMuted.TLabel").place(x=42, y=80)
        card = _centered_scroll_card(f,t)
        self.login_card=card
        if self.icon:
            ttk.Label(card, image=self.icon, style="Panel.TLabel").pack()
        ttk.Label(card, text=tr('Начнём с защиты') if new else tr('С возвращением'), style="Title.TLabel").pack(pady=(10, 0))
        ttk.Label(card, text=(tr('Создайте мастер-пароль для нового хранилища') if new
                              else tr('Введите мастер-пароль, чтобы открыть хранилище')),
                  style="Muted.TLabel").pack(pady=(4, 20))
        ttk.Label(card, text=tr('Мастер-пароль'), style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        pw1 = ttk.Entry(card, show="•", width=34, font=(FF, 11))
        pw1.pack(pady=4, fill="x")
        pw1.focus_set()
        show_master = tk.BooleanVar(value=False)
        ttk.Checkbutton(card, text=tr('Показать мастер-пароль'), variable=show_master,
                        command=lambda: pw1.configure(show='' if show_master.get() else '•')).pack(anchor='w')
        ttk.Label(card, text=tr('Хранилище:')+'\n'+self.vault.path,
                  style='Muted.TLabel', wraplength=340).pack(anchor='w', pady=(8, 0))
        ttk.Button(card, text=tr('Выбрать другое хранилище…'), command=self.attach_vault).pack(anchor='w', pady=6)
        language=tk.StringVar(value="English" if self.settings.get("language")=="en" else "Русский")
        picker=ttk.Combobox(f,textvariable=language,values=("Русский","English"),state="readonly",width=12)
        picker.place(relx=1,x=-40,y=38,anchor="ne")
        picker.bind("<<ComboboxSelected>>",lambda event:self.set_language("en" if language.get()=="English" else "ru"))
        pw2 = None
        if new:
            bar = ttk.Progressbar(card, maximum=100, length=260)
            bar.pack(pady=(6, 0), fill="x")
            lbl = ttk.Label(card, text="", style="Muted.TLabel")
            lbl.pack(anchor="w")
            ttk.Label(card, text=tr('Повторите пароль'), style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
            pw2 = ttk.Entry(card, show="•", width=34, font=(FF, 11))
            pw2.pack(pady=4, fill="x")
            ttk.Label(card, text=f"{tr('Минимум ')}{MIN_MASTER_LEN}{tr(' символов. Лучше — фраза из нескольких слов. Если вы забудете мастер-пароль, данные восстановить невозможно.')}",
                      style="Muted.TLabel", wraplength=300, foreground=t["warn"]).pack(pady=(8, 0))

            def meter(*_):
                bits, text, level = strength(pw1.get())
                bar["value"] = min(100, bits)
                bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
                lbl.config(text=tr(text))
            pw1.bind("<KeyRelease>", meter)
        needs_kf = (not new) and Vault.header_needs_keyfile(self.vault.path)
        kf = {"path": self.settings.get("keyfile_path") or ""}
        if needs_kf:
            kf_row = ttk.Frame(card, style="Panel.TFrame")
            kf_row.pack(fill="x", pady=(8, 0))
            kf_lbl = ttk.Label(kf_row, style="Muted.TLabel", wraplength=170,
                               text=os.path.basename(kf["path"]) if kf["path"] else tr('ключевой файл не выбран'))
            kf_lbl.pack(side="left")

            def pick_kf():
                p = filedialog.askopenfilename(parent=self.root, title=tr('Ключевой файл'))
                if p:
                    kf["path"] = p
                    kf_lbl.config(text=os.path.basename(p))
            ttk.Button(kf_row, text=tr('Ключевой файл…'), command=pick_kf).pack(side="right")
        if new and self.settings.get("vault_path"):
            ttk.Label(card, style="Muted.TLabel", wraplength=300, foreground=t["warn"],
                      text=tr('Файл хранилища не найден:\n') + self.vault.path + tr('\nЕсли это облачная папка, дождитесь синхронизации. Иначе будет создано новое пустое хранилище.')
                      ).pack(pady=(8, 0))
        err = ttk.Label(card, text="", style="Panel.TLabel", foreground=t["bad"], wraplength=300)
        err.pack(pady=8)

        def submit(_=None):
            wait = self._next_try - time.time()
            if wait > 0:
                err.config(text=f"{tr('Слишком много попыток. Подождите ')}{int(wait) + 1}{tr(' с.')}")
                return
            pw = pw1.get()
            if new:
                if len(pw) < MIN_MASTER_LEN:
                    err.config(text=f"{tr('Пароль короче ')}{MIN_MASTER_LEN}{tr(' символов')}")
                    return
                if pw != pw2.get():
                    err.config(text=tr('Пароли не совпадают'))
                    return
            err.config(text=tr('Проверка…'), foreground=t["muted"])
            self.root.update_idletasks()
            try:
                if new:
                    self.vault.create(pw)
                else:
                    content = None
                    if needs_kf:
                        if not kf["path"]:
                            err.config(text=tr('Выберите ключевой файл'), foreground=t["bad"])
                            return
                        try:
                            with open(kf["path"], "rb") as fh:
                                content = fh.read()
                        except OSError as ex:
                            err.config(text=f"{tr('Не удаётся прочитать ключевой файл: ')}{ex}",
                                       foreground=t["bad"])
                            return
                    self.vault.unlock(pw, content)
                    if needs_kf:
                        self.settings.set("keyfile_path", kf["path"])
            except WrongPassword:
                self._fails += 1
                if self._fails >= 3:
                    self._next_try = time.time() + min(2 ** (self._fails - 2), 30)
                err.config(text=tr('Неверный мастер-пароль') + (tr(' или ключевой файл') if needs_kf else "")
                           + '. '+tr('Проверьте раскладку, Caps Lock и выбранное хранилище.'),
                           foreground=t["bad"])
                pw1.delete(0, "end")
                return
            except KeyfileRequired:
                err.config(text=tr('Для этого хранилища нужен ключевой файл'), foreground=t["bad"])
                return
            except VaultError as ex:
                err.config(text=f"{tr('Файл хранилища повреждён: ')}{ex}{tr('. Можно восстановить из резервной копии (папка backups).')}", foreground=t["bad"])
                return
            except OSError as ex:
                err.config(text=f"{tr('Ошибка доступа к файлу: ')}{ex}", foreground=t["bad"])
                return
            self._fails = 0
            self.show_main()
            self.animate_entry()

        ttk.Button(card, text=(tr('Создать хранилище') if new else tr('Открыть')),
                   style="Accent.TButton", command=submit).pack(fill="x", ipady=3)
        if not new and not needs_kf and self.hello.enabled():
            ttk.Button(card, text=tr('◉  Войти через Windows Hello'),
                       command=lambda: self.hello_login(err)).pack(fill="x", pady=(10, 0))
        self.root.bind("<Return>", submit)
        ttk.Label(f, text=tr('AES-256-GCM  ·  данные хранятся только на этом компьютере'),
                  style="BgMuted.TLabel").place(relx=0.5, rely=0.96, anchor="s")

    def hello_login(self, err_label):
        """Verify OS user presence off the Tk event loop; never send password to browser."""
        epoch=self._auth_epoch
        def report(text):
            if self._auth_epoch==epoch and err_label.winfo_exists():err_label.config(text=text,foreground=self.t["bad"])
        hwnd = self.root.winfo_id()
        if sys.platform == "win32":
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(hwnd) or hwnd
        err_label.config(text=tr('Ожидание подтверждения Windows Hello…'), foreground=self.t["muted"])
        def work():
            try:
                if not self.hello.verify(hwnd):
                    self._q.put(lambda: report(tr('Подтверждение Windows Hello отменено')))
                    return
                password = self.hello.retrieve_after_verification()
                def finish():
                    if self._auth_epoch!=epoch or self.vault.unlocked:return
                    try:
                        if not self.vault.exists():
                            raise VaultError(tr('Хранилище отсутствует'))
                        self.vault.unlock(password)
                        self._fails = 0
                        self.show_main()
                    except (VaultError, OSError, ValueError) as ex:
                        err_label.config(text=f"{tr('Не удалось открыть хранилище: ')}{ex}",
                                         foreground=self.t["bad"])
                self._q.put(finish)
            except (HelloUnavailable, OSError, ValueError, KeyError) as ex:
                self._q.put(lambda msg=str(ex): report(msg))
        threading.Thread(target=work, daemon=True).start()

    def configure_hello(self):
        if not self.vault.unlocked:
            return
        if self.hello.enabled():
            if messagebox.askyesno("Windows Hello", tr('Отключить быстрый вход Windows Hello?'), parent=self.root):
                self.hello.disable()
                messagebox.showinfo("Windows Hello", tr('Быстрый вход отключён.'), parent=self.root)
            return
        if Vault.header_needs_keyfile(self.vault.path):
            messagebox.showwarning("Windows Hello", tr('Быстрый вход недоступен для хранилища с ключевым файлом.'))
            return
        if sys.platform != "win32":
            messagebox.showwarning("Windows Hello", tr('Эта функция доступна только в Windows 10/11.'))
            return
        password = simpledialog.askstring("Windows Hello", tr('Введите мастер-пароль для включения быстрого входа:'),
                                          parent=self.root, show="•")
        if password is None:
            return
        if not self.vault.verify_password(password):
            messagebox.showerror("Windows Hello", tr('Неверный мастер-пароль.'), parent=self.root)
            return
        hwnd = self.root.winfo_id()
        if sys.platform == "win32":
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(hwnd) or hwnd
        epoch=self._auth_epoch
        def work():
            import asyncio
            try:
                if not self.hello.verify(hwnd):
                    self._q.put(lambda: messagebox.showwarning("Windows Hello", tr('Проверка не пройдена.')))
                    return
                if self._auth_epoch!=epoch or not self.vault.unlocked or not self.vault.verify_password(password):return
                self.hello.enroll(password)
                self._q.put(lambda: messagebox.showinfo("Windows Hello", tr('Быстрый вход включён. Секрет защищён DPAPI текущего пользователя Windows; это не аппаратная привязка к Hello.')))
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

        shell=f
        scale=max(1.0,float(self.root.tk.call("tk","scaling"))/(96/72))
        font_size=max(9,min(14,int(self.settings.get("font_size") or 10)))
        rail_height=max(46,min(68,(self.root.winfo_height()-100*scale)/(6*scale)))
        rail_width=int(max(80,80*font_size/10)*scale)
        self.rail=ttk.Frame(shell,style="Side.TFrame",padding=(7,18))
        self.rail.pack(side="left",fill="y")
        if self.logo:ttk.Label(self.rail,image=self.logo,style="Side.TLabel").pack(pady=(0,20))
        self.rail_buttons={}
        for value,icon,label in (("all","key",tr("Записи")),("fav","star",tr("Избранное")),("trash","trash",tr("Корзина"))):
            button=DesignButton(self.rail,label,lambda selected=value:self.set_library_filter(selected),t,
                kind="rail",icon=icon,width=rail_width,height=rail_height,scale=scale,font_size=round(9*font_size/10),vertical=True)
            button.pack(fill="x",pady=4);self.rail_buttons[value]=button
        DesignButton(self.rail,tr("Категории"),self.toggle_sidebar,t,kind="rail",icon="folder",width=rail_width,height=rail_height,scale=scale,font_size=round(9*font_size/10),vertical=True).pack(fill="x",pady=4)
        DesignButton(self.rail,tr("Браузеры"),lambda:BrowserDialog(self,self.root),t,kind="rail",icon="browser",width=rail_width,height=rail_height,scale=scale,font_size=round(9*font_size/10),vertical=True).pack(fill="x",pady=4)
        DesignButton(self.rail,tr("Настройки"),lambda:SettingsDialog(self,self.root),t,kind="rail",icon="settings",width=rail_width,height=rail_height,scale=scale,font_size=round(9*font_size/10),vertical=True).pack(side="bottom",fill="x",pady=4)
        f=ttk.Frame(shell);f.pack(side="left",fill="both",expand=True)
        head=ttk.Frame(f,style="Panel.TFrame",padding=(24,14));head.pack(fill="x")
        ttk.Label(head,text=tr("Личное хранилище"),style="Section.TLabel").pack(side="left")
        for text,menu in ((tr("Файл"),self._file_menu()),(tr("Инструменты"),self._tools_menu()),(tr("Справка"),self._help_menu())):
            ttk.Menubutton(head,text=text,menu=menu,style="Header.TMenubutton").pack(side="right",padx=3)
        self.hello_status=ttk.Label(head,text="Windows Hello" if self.hello.enabled() else tr("Хранилище открыто"),style="Muted.TLabel")
        self.hello_status.pack(side="right",padx=18)

        hero = ttk.Frame(f, padding=(24, 18))
        hero.pack(fill="x")
        DesignButton(hero,tr("Новая запись"),self.add,t,kind="primary",icon="plus",height=40,scale=scale,font_size=font_size).pack(side="right",pady=8)
        ttk.Label(hero,text="BITORA PASSWORD",style="Eyebrow.TLabel").pack(anchor="w",pady=(0,5))
        ttk.Label(hero,text=tr("Записи"),style="Hero.TLabel").pack(anchor="w")
        overview=ttk.Frame(f)
        self._build_stats(overview)

        controls=ttk.Frame(f,padding=(24,4));controls.pack(fill="x")
        self.category_chips=ttk.Frame(controls);self.category_chips.pack(side="left")
        self.category_chips_key=None
        controls.bind("<Configure>",lambda event:self.refresh_category_chips())
        self.search=tk.StringVar()
        self.search.trace_add("write",lambda *args:self.refresh_list())
        search_shell=tk.Frame(controls,bg=t["card"],highlightthickness=1,highlightbackground=t["border"])
        search_shell.pack(side="right",fill="x",expand=True,padx=(20,0))
        ttk.Label(search_shell,text=tr("Поиск"),style="CardMuted.TLabel").pack(side="left",padx=(12,6))
        self.search_entry=ttk.Entry(search_shell,textvariable=self.search,style="MidnightSearch.TEntry",width=18)
        self.search_entry.pack(side="left",fill="x",expand=True,padx=(0,8),pady=3)

        bottom = ttk.Frame(f, style="Side.TFrame", padding=(14, 5))
        bottom.pack(side="bottom", fill="x")
        self.status_left = ttk.Label(bottom, text="", style="Side.TLabel", foreground=t["good"])
        self.status_left.pack(side="left")
        self.status_right = ttk.Label(bottom, text="", style="SideMuted.TLabel")
        self.status_right.pack(side="right")

        self.root.update_idletasks()
        scale = max(1.0, float(self.root.tk.call("tk", "scaling")) / (96/72))
        compact = self.root.winfo_width() / scale < 1000
        if compact:self.hello_status.pack_forget()
        body = ttk.Notebook(f) if compact else ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True, padx=24, pady=(12, 20))
        self.body=body;self.compact=compact;self._sidebar_hidden=False

        side_fr = self.side_panel = ttk.Frame(body, style="Side.TFrame", width=200)
        ttk.Label(side_fr, text=tr('БИБЛИОТЕКА'), style="SideHeading.TLabel").pack(fill="x", padx=12, pady=(20, 7))
        navigation = ttk.Frame(side_fr, style="Side.TFrame")
        self.side = ttk.Treeview(navigation, show="tree", selectmode="browse", style="Side.Treeview")
        self.side.column("#0", width=190)
        self.side.tag_configure("head", foreground=t["muted"], font=(FF, 8, "bold"))
        tools = ttk.Frame(side_fr, style="Side.TFrame", padding=12)
        tools.pack(side="bottom", fill="x")
        ttk.Button(tools,text=tr('Браузеры'),style="Ghost.TButton",command=lambda:BrowserDialog(self,self.root)).pack(fill="x",pady=3)
        ttk.Separator(tools).pack(fill="x", pady=(0, 12))
        for text, command in ((tr('Аудит безопасности'), self.audit),
                              (tr('Генератор паролей'), lambda: GeneratorDialog(self, self.root)),
                              (tr('Настройки'), lambda: SettingsDialog(self, self.root))):
            ttk.Button(tools, text=tr(text), style="Ghost.TButton", command=command).pack(fill="x", pady=3)
        navigation.pack(fill="both", expand=True)
        self.side.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)
        nav_scroll = ttk.Scrollbar(navigation, orient="vertical", command=self.side.yview)
        nav_scroll.pack(side="right", fill="y")
        self.side.configure(yscrollcommand=nav_scroll.set)
        self.side.bind("<<TreeviewSelect>>", self.on_side_select)
        self.side.bind("<Button-3>", self.category_menu)
        if compact:
            body.add(side_fr, text=tr('Разделы'))
        else:
            body.add(side_fr, weight=0)

        center = self.center_panel = ttk.Frame(body)
        filter_bar=ttk.Frame(center,style="Panel.TFrame",padding=(16,10))
        self.filter_bar=filter_bar
        self.issue_choices={tr("Все записи"):None,tr("Слабые пароли"):ISSUE_WEAK,tr("Повторы паролей"):ISSUE_REUSED,tr("Устаревшие пароли"):ISSUE_OLD,tr("Без пароля"):ISSUE_EMPTY}
        self.issue_filter=tk.StringVar(value=tr("Все записи"))
        picker=ttk.Combobox(filter_bar,textvariable=self.issue_filter,values=list(self.issue_choices),state="readonly",width=22)
        picker.pack(side="left");picker.bind("<<ComboboxSelected>>",lambda event:self.refresh_list())
        self.library_filter=tk.StringVar()
        self.library_picker=ttk.Combobox(filter_bar,textvariable=self.library_filter,state="readonly",width=24)
        self.library_picker.pack(side="right",padx=(8,0))
        self.library_picker.bind("<<ComboboxSelected>>",lambda event:self.set_library_filter(self.library_choices[self.library_filter.get()]))
        utilities=ttk.Frame(center,padding=(4,0,4,8));utilities.pack(fill="x")
        self.list_count=ttk.Label(utilities,text="",style="BgMuted.TLabel");self.list_count.pack(side="left")
        ttk.Button(utilities,text=tr("Фильтры"),style="Quiet.TButton",command=self.toggle_filters).pack(side="right")
        ttk.Button(utilities,text=tr("Сортировка"),style="Quiet.TButton",command=lambda:self.sort_by("title")).pack(side="right",padx=8)
        lst = ttk.Frame(center)
        lst.pack(fill="both", expand=True)
        cols = [c[0] for c in self.COLUMNS]
        horizontal = ttk.Scrollbar(lst, orient="horizontal")
        self.tree = RecordModel(lst, columns=cols, displaycolumns=("fav","title","login"), show="headings", selectmode="extended")
        from tkinter import font as tkfont
        column_font = tkfont.Font(family=FF, size=10)
        for key, name, width in self.COLUMNS:
            self.tree.heading(key, text=tr(name), command=lambda k=key: self.sort_by(k))
            minimum = max(width, column_font.measure(name) + 32)
            self.tree.column(key, width=minimum, minwidth=minimum, anchor="center" if key == "fav" else "w",
                             stretch=(key != "fav"))
        self.record_view=RecordList(lst,self.tree,self.vault,t,scale,font_size,self.edit,self.delete,self.context_menu,self.copy_login,self.copy_password)
        sb=ttk.Scrollbar(lst,orient="vertical",command=self.record_view.yview)
        self.record_view.yscroll_callback=sb.set
        self.record_view.pack(side="left",fill="both",expand=True)
        sb.pack(side="right",fill="y")
        self.empty_lbl = ttk.Label(lst, text="", style="Muted.TLabel", justify="center",
                                   font=(FF, 11))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.edit())
        self.tree.bind("<Return>", lambda e: self.edit())
        self.tree.bind("<Delete>", lambda e: self.delete())
        self.tree.bind("<Control-c>", lambda e: self.copy_login())
        self.tree.bind("<Control-Shift-C>", lambda e: self.copy_password())
        self.tree.bind("<Button-3>", self.context_menu)
        if compact:
            body.add(center, text=tr('Записи'))
            body.select(center)
        else:
            body.add(center, weight=3)

        det = self.detail_panel = ttk.Frame(body, width=400)
        detail_canvas = self.detail_canvas = tk.Canvas(det, bg=t["bg"], highlightthickness=0, width=400)
        detail_scroll = ttk.Scrollbar(det, orient="vertical", command=detail_canvas.yview)
        detail_scroll.pack(side="right", fill="y")
        detail_canvas.pack(side="left", fill="both", expand=True)
        detail_canvas.configure(yscrollcommand=detail_scroll.set)
        detail_surface=RoundedCard(detail_canvas,t)
        detail_content = ttk.Frame(detail_surface.body, style="Panel.TFrame", padding=4)
        detail_content.pack(fill="x")
        detail_window = detail_canvas.create_window((0, 0), window=detail_surface, anchor="nw")
        detail_canvas.bind("<Configure>", lambda event: detail_canvas.itemconfigure(
            detail_window, width=event.width))
        detail_content.bind("<Configure>", lambda event: detail_canvas.configure(
            scrollregion=detail_canvas.bbox("all")))
        detail_surface.bind("<Configure>",lambda event:detail_canvas.configure(scrollregion=detail_canvas.bbox("all")))
        def detail_wheel(event):
            if str(event.widget).startswith(str(detail_surface)):
                detail_canvas.yview_scroll(-int(event.delta/120),'units')
                return 'break'
        wheel_binding=self.root.bind('<MouseWheel>',detail_wheel,add='+')
        det.bind('<Destroy>',lambda event:self.root.unbind('<MouseWheel>',wheel_binding) if event.widget is det else None,add='+')
        self._build_details(detail_content)
        if compact:
            body.add(det, text=tr('Подробности'))
        else:
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
        self.set_status(tr('Хранилище открыто. Изменения сохраняются автоматически.'))
        if self._totp_job:
            r.after_cancel(self._totp_job)
        self._totp_tick()
        if self.settings.get("sidebar_collapsed"): self.toggle_sidebar(persist=False)
        self.root.after(800,self.backup_reminder)

    def notify(self,text,action=None,action_label=None):
        if not self.frame or not self.frame.winfo_exists():return
        old=getattr(self,"_notification",None)
        if old and old.winfo_exists():old.destroy()
        panel=self._notification=ttk.Frame(self.frame,style="Panel.TFrame",padding=(18,12))
        ttk.Label(panel,text=text,style="Panel.TLabel",wraplength=500).pack(side="left")
        if action:ttk.Button(panel,text=action_label or tr("Открыть"),command=action).pack(side="left",padx=12)
        ttk.Button(panel,text="×",width=3,command=panel.destroy).pack(side="right",padx=(12,0))
        panel.place(relx=0.5,rely=0.96,anchor="s")
        self.root.after(10000,lambda:panel.destroy() if panel.winfo_exists() else None)

    def backup_reminder(self):
        if not self.vault.unlocked or not self.settings.get("backup_reminders"):return
        day=datetime.now().strftime("%Y-%m-%d")
        if self.settings.get("backup_reminded")==day:return
        from product_features import backup_info
        try:info=backup_info(self.vault,self.settings.get("external_backup_dir"))
        except OSError:return
        if info['days'] is None or info['days']>=7:
            self.settings.set("backup_reminded",day)
            self.notify(tr("Сохраните отдельную резервную копию на другом диске."),lambda:feature_dialogs.backups(self))

    def toggle_filters(self):
        if self.filter_bar.winfo_manager():self.filter_bar.pack_forget()
        else:self.filter_bar.pack(side="top",fill="x",before=self.center_panel.winfo_children()[-1])

    def refresh_category_chips(self):
        if not hasattr(self,"category_chips") or not self.category_chips.winfo_exists():return
        cats=self.vault.categories()
        scale=max(1.0,float(self.root.tk.call("tk","scaling"))/(96/72))
        available=self.root.winfo_width()/scale-self.rail.winfo_reqwidth()/scale-96-260
        limit=max(0,min(3,int((available-65)/108)))
        key=(tuple(cats[:limit]),self.cat_filter)
        if self.category_chips_key==key:return
        self.category_chips_key=key
        for child in self.category_chips.winfo_children():child.destroy()
        scale=max(1.0,float(self.root.tk.call("tk","scaling"))/(96/72))
        for value,label in [("all",tr("Все"))]+[("cat:"+cat,cat) for cat in cats[:limit]]:
            button=DesignButton(self.category_chips,label,lambda selected=value:self.set_library_filter(selected),self.t,kind="chip",width=int((60 if value=="all" else 108)*scale),height=34,scale=scale,font_size=9)
            button.selected=self.cat_filter==value;button.pack(side="left",padx=(0,4))

    def toggle_sidebar(self,persist=True):
        if not hasattr(self,"side_panel") or not self.side_panel.winfo_exists():return
        if self._sidebar_hidden:
            if self.compact:
                self.body.insert(0,self.side_panel,text=tr("Разделы"))
                self.body.tab(self.side_panel,state="normal")
                self.body.select(self.side_panel)
            else:self.body.insert(0,self.side_panel,weight=0)
        else:
            if self.compact:self.body.hide(self.side_panel)
            else:self.body.forget(self.side_panel)
        self._sidebar_hidden=not self._sidebar_hidden
        if persist:self.settings.set("sidebar_collapsed",self._sidebar_hidden)

    def animate_entry(self):
        if not self.settings.get("animations"): return
        if self._animation_id:
            self.root.after_cancel(self._animation_id)
        start=time.monotonic()
        def frame():
            progress=min(1,(time.monotonic()-start)/0.24)
            try: self.root.attributes("-alpha",0.72+0.28*(1-(1-progress)**3))
            except tk.TclError: return
            self._animation_id=self.root.after(16,frame) if progress<1 else None
        frame()

    def set_language(self, language):
        import localization
        self.settings.set("language",language)
        localization.set_language(language)
        self.root.title(localization.tr(APP_NAME))
        if self.tray:
            self.tray.title=tr(APP_NAME)
            self.tray.update_menu()
        if self.vault.unlocked:self.show_main()
        else:self.show_login()

    def category_menu(self,event):
        item=self.side.identify_row(event.y)
        if not item.startswith("cat:"):return
        self.side.selection_set(item)
        menu=self._menu()
        menu.add_command(label=tr("Изменить категорию…"),command=lambda:feature_dialogs.categories(self,item[4:]))
        menu.add_command(label=tr('Удалить категорию…'),command=lambda:self.delete_category(item[4:]))
        menu.tk_popup(event.x_root,event.y_root)

    def delete_category(self, name=None):
        if name is None:
            if self.cat_filter.startswith("cat:"):name=self.cat_filter[4:]
            else:
                top=_new_top(self,self.root,tr('Удалить категорию'))
                frame=ttk.Frame(top,padding=24);frame.pack()
                choice=tk.StringVar(value=self.vault.categories()[0] if self.vault.categories() else "")
                ttk.Combobox(frame,textvariable=choice,values=self.vault.categories(),state="readonly").pack()
                ttk.Button(frame,text=tr('Удалить'),command=lambda:(top.destroy(),self.delete_category(choice.get()))).pack(pady=12)
                return
        if not name:return
        feature_dialogs.delete_category(self,name)

    def _file_menu(self):
        m = self._menu()
        m.add_command(label=tr('Заблокировать'), accelerator="Ctrl+L", command=self.lock)
        m.add_separator()
        m.add_command(label=tr('Импорт из CSV / Excel…'), command=self.import_csv)
        m.add_command(label=tr('Экспорт зашифрованной копии…'), command=self.export_encrypted)
        m.add_command(label=tr('Экспорт в CSV (открытый текст)…'), command=self.export_csv)
        m.add_command(label=tr('Восстановить из резервной копии…'), command=self.restore_backup)
        m.add_separator()
        m.add_command(label=tr('Хранилище в облачной папке…'), command=self.move_vault)
        m.add_command(label=tr('Подключить существующее хранилище…'), command=self.attach_vault)
        m.add_separator()
        m.add_command(label=tr('Сменить мастер-пароль…'), command=self.change_master)
        m.add_command(label=tr('Сменить мастер-пароль через Windows Hello…'), command=self.change_master_hello)
        m.add_command(label=tr('Ключевой файл…'), command=self.manage_keyfile)
        m.add_separator()
        m.add_command(label=tr('Выход'), command=self.quit_app)
        return m

    def _tools_menu(self):
        m = self._menu()
        m.add_command(label=tr('Браузеры: подключение и диагностика'),command=lambda:BrowserDialog(self,self.root))
        m.add_command(label=tr('Разрешить конфликты…'), command=self.resolve_conflicts)
        m.add_command(label=tr('Быстрый поиск'), command=self.quick_search)
        m.add_command(label=tr('Аудит безопасности…'), command=self.audit)
        m.add_command(label=tr('Проверка на утечки (интернет)…'), command=self.check_breaches)
        m.add_command(label=tr('Генератор паролей…'),
                      command=lambda: GeneratorDialog(self, self.root))
        m.add_command(label=tr("Категории…"),command=lambda:feature_dialogs.categories(self))
        m.add_command(label=tr("Перенести выбранные…"),command=lambda:feature_dialogs.categories(self,move=True))
        m.add_command(label=tr("Резервные копии…"),command=lambda:feature_dialogs.backups(self))
        m.add_command(label=tr('Удалить категорию…'), command=self.delete_category)
        m.add_command(label=tr("Корзина категорий"),command=lambda:feature_dialogs.category_trash(self))
        m.add_command(label=tr("Объединить дубли…"),command=lambda:feature_dialogs.duplicates(self))
        m.add_command(label=tr('Очистить корзину'), command=self.empty_trash)
        m.add_separator()
        m.add_command(label=tr('Светлая / тёмная тема'), command=self.toggle_theme)
        m.add_command(label=tr('Настройки…'), command=lambda: SettingsDialog(self, self.root))
        return m

    def _help_menu(self):
        m = self._menu()
        m.add_command(label=tr('Открыть папку с данными'), command=self.open_data_dir)
        m.add_command(label=tr('Горячие клавиши'), command=lambda: messagebox.showinfo(
            tr(APP_NAME), tr('Ctrl+N — новая запись\nCtrl+F — поиск\nCtrl+L — заблокировать\nCtrl+B — копировать логин\nCtrl+Shift+C — копировать пароль\nEnter / двойной клик — изменить\nDelete — удалить\nEscape — заблокировать'), parent=self.root))
        m.add_command(label=tr('Проверить обновления…'), command=self.check_updates)
        m.add_command(label=tr('О программе'), command=self.about)
        return m

    def about(self):
        t = self.t
        top = _new_top(self, self.root, tr('О программе'))
        frm = ttk.Frame(top, padding=30)
        frm.pack()
        if self.icon:
            ttk.Label(frm, image=self.icon).pack()
        ttk.Label(frm, text=tr(APP_NAME), font=(FF, 17, "bold")).pack(pady=(8, 0))
        ttk.Label(frm, text=f"{tr('Версия ')}{APP_VERSION}", foreground=t["muted"]).pack()
        ttk.Label(frm, text=tr('Шифрование AES-256-GCM, ключ из мастер-пароля (scrypt).\nДанные хранятся только на вашем компьютере.\n\n') + self.vault.path,
                  justify="center", wraplength=380, foreground=t["muted"]).pack(pady=14)
        ttk.Button(frm, text=tr('Закрыть'), command=top.destroy).pack()
        top.grab_set()
        self.root.wait_window(top)

    # ---------------- панель показателей
    def _build_stats(self, parent):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 10))
        self.stat = {}
        spec = (("total", tr('Записей')), ("weak", tr('Слабых паролей')), ("reused", tr('Повторов')),
                ("old", tr('Устаревшие')), ("score", tr('Оценка безопасности')))
        for i, (key, caption) in enumerate(spec):
            row.columnconfigure(i, weight=1, uniform="stat")
            card = RoundedCard(row,self.t)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            num = ttk.Label(card.body, text="0", style="StatValue.TLabel")
            num.pack(anchor="w")
            cap = ttk.Label(card.body, text=caption, style="StatCaption.TLabel")
            cap.pack(anchor="w")
            for w in (card.canvas, num, cap):
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
        header=ttk.Frame(p,style="Panel.TFrame");header.grid(row=0,column=0,sticky="we",pady=(4,22))
        scale=max(1.0,float(self.root.tk.call("tk","scaling"))/(96/72))
        self.d_avatar=tk.Canvas(header,width=int(48*scale),height=int(48*scale),bg=self.t["panel"],highlightthickness=0)
        self.d_avatar.pack(side="left",padx=(0,12))
        heading=ttk.Frame(header,style="Panel.TFrame");heading.pack(side="left",fill="x",expand=True)
        self.d_title=ttk.Label(heading,text="",style="Title.TLabel",wraplength=250,justify="left");self.d_title.pack(anchor="w")
        self.d_domain=ttk.Label(heading,text="",style="Muted.TLabel",wraplength=250);self.d_domain.pack(anchor="w",pady=(3,0))
        self.d_empty = ttk.Label(p, text=tr('Выберите запись в списке\nили нажмите «＋ Добавить»'),
                                 style="Muted.TLabel", justify="center")
        self.dvars, self.dfields = {}, {}
        spec = (("url", tr('САЙТ'), ((tr('Открыть'), self.open_url),)),
                ("login", tr('ЛОГИН'), ((tr('Копировать'), self.copy_login),)),
                ("password", tr('ПАРОЛЬ'), ((tr('Показать'), self.toggle_pw), (tr('Копировать'), self.copy_password))),
                ("totp", tr('КОД 2FA'), ((tr('Копировать'), self.copy_totp),)),
                ("category", tr('КАТЕГОРИЯ'), ()), ("tags", tr('ТЕГИ'), ()),
                ("source", tr('ИСТОЧНИК'), ()), ("updated", tr('ИЗМЕНЕНО'), ()))
        for i, (key, text, btns) in enumerate(spec, start=1):
            palette=dict(self.t,bg=self.t["panel"],panel=self.t["card"])
            fr=RoundedCard(p,palette)
            fr.body.configure(style="Card.TFrame")
            ttk.Label(fr.body,text=tr(text),style="CardMuted.TLabel",font=(FF,9)).pack(anchor="w")
            line=ttk.Frame(fr.body,style="Card.TFrame");line.pack(fill="x",pady=(5,0))
            var=tk.StringVar()
            actions=ttk.Frame(line,style="Card.TFrame");actions.pack(side="right")
            for btn_text,cmd in reversed(btns):
                b=ttk.Button(actions,text=btn_text,command=cmd,style="TextAction.TButton")
                b.pack(side="right",padx=(5,0))
                if key=="password" and btn_text==tr("Показать"):self.pw_btn=b
            label=ttk.Label(line,textvariable=var,style="CardMono.TLabel" if key in ("password","totp") else "Card.TLabel",wraplength=180,justify="left")
            label.pack(side="left",fill="x",expand=True)
            line.bind("<Configure>",lambda event,field=label,buttons=actions:field.configure(wraplength=max(60,event.width-buttons.winfo_reqwidth()-8)))
            if key=="password":
                self.pw_bar=ttk.Progressbar(fr.body,maximum=100)
                self.pw_bar_lbl=ttk.Label(fr.body,text="",style="CardMuted.TLabel")
            fr.grid(row=i,column=0,sticky="we",pady=6)
            self.dvars[key],self.dfields[key]=var,fr

        cf = ttk.Frame(p, style="Panel.TFrame")
        ttk.Label(cf, text=tr('ДОПОЛНИТЕЛЬНО'), style="Muted.TLabel", font=(FF, 8, "bold")).pack(anchor="w")
        self.d_custom = ttk.Frame(cf, style="Panel.TFrame")
        self.d_custom.pack(fill="x")
        cf.grid(row=9, column=0, sticky="we", pady=6)
        self.dfields["custom"] = cf

        nf = ttk.Frame(p, style="Panel.TFrame")
        ttk.Label(nf, text=tr('ЗАМЕТКА'), style="Muted.TLabel", font=(FF, 8, "bold")).pack(anchor="w")
        self.d_note = tk.Text(nf, height=4, width=30, wrap="word", relief="flat", state="disabled",
                              bg=self.t["card"], fg=self.t["fg"], highlightthickness=0,
                              padx=8, pady=6)
        self.d_note.pack(fill="x", pady=(2, 0))
        nf.grid(row=10, column=0, sticky="we", pady=6)
        self.dfields["note"] = nf

        self.act_normal=ttk.Frame(p,style="Panel.TFrame")
        button_palette=dict(self.t,bg=self.t["panel"])
        DesignButton(self.act_normal,tr("Изменить"),self.edit,button_palette,scale=scale,height=36,font_size=9).pack(side="left")
        self.hist_btn=ttk.Button(self.act_normal,text=tr("История"),command=self.show_history,style="DetailAction.TButton");self.hist_btn.pack(side="left",padx=8)
        self.fav_btn=ttk.Button(self.act_normal,command=self.toggle_fav)
        self.att_btn=ttk.Button(self.act_normal,command=self.attachments)
        more=self._menu()
        for label,action in ((tr("Открыть сайт"),self.open_url),(tr("Избранное"),self.toggle_fav),(tr("Вложения"),self.attachments),(tr("⌨ Ввести"),self.autotype_selected),(tr("Утечки?"),self.check_pwned_selected),(tr("Удалить запись"),self.delete)):
            more.add_command(label=label,command=action)
        ttk.Menubutton(self.act_normal,text=tr("Ещё"),menu=more,style="Header.TMenubutton").pack(side="left")
        self.act_trash = ttk.Frame(p, style="Panel.TFrame")
        ttk.Button(self.act_trash, text=tr('Восстановить'), style="Accent.TButton",
                   command=self.restore).pack(side="left")
        ttk.Button(self.act_trash, text=tr('Удалить навсегда'), command=self.purge).pack(side="right")
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
        if hasattr(self,"record_view"):self.record_view.draw()

    def show_details(self):
        e = self.selected()
        for fr in self.dfields.values():
            fr.grid_remove()
        self.act_normal.grid_remove()
        self.act_trash.grid_remove()
        if not e:
            self.d_title.config(text="");self.d_domain.config(text="");self.d_avatar.delete("all")
            self.d_empty.grid(row=1, column=0, pady=70)
            return
        self.d_empty.grid_remove()
        self.d_title.config(text=e["title"])
        self.d_domain.config(text=hostname(e["url"]))
        self.d_avatar.delete("all")
        aw=max(48,self.d_avatar.winfo_reqwidth())
        rounded(self.d_avatar,0,0,aw,aw,12,self.t["sel"])
        self.d_avatar.create_text(aw/2,aw/2,text=(e["title"].strip()[:1] or "?").upper(),font=(FF,18,"bold"),fill=self.t["accent"])
        values = {"url": e["url"], "login": e["login"], "category": e["category"],
                  "tags": e["tags"], "source": e["source"],
                  "updated": e["updated"][:10]}
        for key, val in values.items():
            self.dvars[key].set(val)
            if val and key!="url":
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
            self.att_btn.config(text=f"{tr('Вложения (')}{n_att})" if n_att else tr('Вложения'))

    def _show_password(self, e):
        self.dvars["password"].set(e["password"] if self.pw_visible else "•" * 10)
        self.pw_btn.config(text=tr('Скрыть') if self.pw_visible else tr('Показать'))
        bits, text, level = strength(e["password"])
        self.pw_bar["value"] = min(100, bits)
        self.pw_bar.configure(style=f"{LEVEL_STYLE[level]}.Horizontal.TProgressbar")
        self.pw_bar_lbl.config(text=f"{tr('Надёжность: ')}{tr(text)}")
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
            self.dvars["totp"].set(f"{code[:3]} {code[3:]}   ({left}{tr(' с)')}")
        except Exception:
            self.dvars["totp"].set(tr('ключ 2FA не распознан'))

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
        ins("", "end", iid="all", text=f"{tr('  ▤   Все пароли  (')}{len(act)})")
        ins("", "end", iid="fav", text=f"{tr('  ★   Избранное  (')}{sum((1 for e in act if e['favorite']))})")
        cats = v.categories()
        unc = sum(1 for e in act if not e["category"])
        if cats or unc:
            ins("", "end", iid="h_cat", text=tr('   КАТЕГОРИИ'), tags=("head",))
            for c in cats:
                n = sum(1 for e in act if e["category"] == c)
                props=v.meta.get("category_properties",{}).get(c,{})
                from product_features import COLORS,ICONS
                color=props.get("color") if props.get("color") in COLORS else self.t["fg"]
                if self.theme_name=="dark":color=dict(zip(COLORS,("#409cff","#b398ff","#5bd68a","#ffa45c","#ff8293","#bbbcc5"))).get(color,color)
                icon=props.get("icon") if props.get("icon") in ICONS else "◇"
                self.side.tag_configure("cat:"+c,foreground=color)
                ins("", "end", iid="cat:" + c, text=f"  {icon}   {c}  ({n})",tags=("cat:"+c,))
            if unc:
                ins("", "end", iid="uncat", text=f"{tr('  —   Без категории  (')}{unc})")
        tags = sorted({x for e in act for x in split_tags(e["tags"])}, key=str.lower)
        if tags:
            ins("", "end", iid="h_tag", text=tr('   ТЕГИ'), tags=("head",))
            for tg in tags:
                n = sum(1 for e in act if tg.lower() in [x.lower() for x in split_tags(e["tags"])])
                ins("", "end", iid="tag:" + tg, text=f"  #   {tg}  ({n})")
        ins("", "end", iid="h_sys", text=tr('   СИСТЕМА'), tags=("head",))
        ins("", "end", iid="trash", text=f"{tr('  ⌫   Корзина  (')}{len(v.trash())})")
        if not self.side.exists(self.cat_filter):
            self.cat_filter = "all"
        self.side.selection_set(self.cat_filter)
        self.refresh_library_controls()

    def set_library_filter(self,value):
        if not self.side.exists(value):return
        self.cat_filter=value
        self.side.selection_set(value)
        self.refresh_list();self.refresh_library_controls()
        if self.compact:self.body.select(self.center_panel)

    def refresh_library_controls(self):
        if not hasattr(self,"library_picker") or not self.library_picker.winfo_exists():return
        self.library_choices={tr("Все категории"):"all",tr("Избранное"):"fav",tr("Без категории"):"uncat",tr("Корзина"):"trash"}
        self.library_choices.update({tr("Категория: ")+c:"cat:"+c for c in self.vault.categories()})
        tags=sorted({tag for entry in self.vault.active() for tag in split_tags(entry["tags"])})
        self.library_choices.update({tr("Тег: ")+tag:"tag:"+tag for tag in tags})
        self.library_picker.configure(values=list(self.library_choices))
        self.library_filter.set(next((label for label,value in self.library_choices.items() if value==self.cat_filter),tr("Все категории")))
        for value,button in self.rail_buttons.items():button.configure(style="RailActive.TButton" if value==self.cat_filter else "Rail.TButton")
        self.refresh_category_chips()

    def on_side_select(self, _=None):
        sel = self.side.selection()
        if not sel:
            return
        if sel[0].startswith("h_"):  # заголовки разделов не выбираются
            self.side.selection_set(self.cat_filter)
            return
        if sel[0] != self.cat_filter:
            self.cat_filter = sel[0]
            self.refresh_list();self.refresh_library_controls()
            if self.compact:self.body.select(self.center_panel)

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
        q = self.search.get().strip()
        from product_features import matches_query
        issues=self.vault.audit()
        issue_ids={label:{e["id"] for problem,e in issues if problem==label} for label in (ISSUE_WEAK,ISSUE_REUSED,ISSUE_OLD,ISSUE_EMPTY)}
        search_issues=dict(zip(("weak","reused","old","empty"),(issue_ids[label] for label in (ISSUE_WEAK,ISSUE_REUSED,ISSUE_OLD,ISSUE_EMPTY))))
        chosen=self.issue_choices.get(self.issue_filter.get()) if hasattr(self,"issue_filter") else None
        key, rev = self.sort

        def sk(e):
            if key == "fav":
                return (not e["favorite"], e["title"].lower())
            return str(e.get(key, "")).lower()

        items = [e for e in self.vault.entries if self._in_filter(e) and matches_query(e,q,search_issues)
                 and (chosen is None or e["id"] in issue_ids[chosen])]
        items.sort(key=sk, reverse=rev)
        self.tree.delete(*self.tree.get_children())
        self.tree.tag_configure("alternate", background=self.t["card"])
        for index, e in enumerate(items):
            self.tree.insert("", "end", iid=e["id"], tags=("alternate",) if index % 2 else (), values=(
                "★" if e["favorite"] else "", e["title"], e["login"], e["category"],
                (e["deleted"] if self.cat_filter == "trash" else e["updated"])[:10]))
        retained = [item for item in prev if self.tree.exists(item)]
        if retained:
            self.tree.selection_set(retained)
        if hasattr(self,"record_view") and self.record_view.winfo_exists():self.record_view.refresh()
        if hasattr(self,"list_count") and self.list_count.winfo_exists():self.list_count.configure(text=tr("Записей: ")+str(len(items)))
        total = len(self.vault.active()) if self.cat_filter != "trash" else len(self.vault.trash())
        self.status_right.config(text=f"{tr('Показано: ')}{len(items)}{tr(' из ')}{total}")
        if items:
            self.empty_lbl.place_forget()
        else:
            if q:
                msg = tr('Ничего не найдено')
            elif self.cat_filter == "trash":
                msg = tr('Корзина пуста')
            elif self.cat_filter == "all":
                msg = (tr('Здесь пока пусто.\nНажмите «＋ Добавить» или импортируйте пароли\nиз браузера: Файл → Импорт из CSV…'))
            else:
                msg = tr('В этом разделе пока нет записей')
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
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        e = self.vault.get(iid)
        m = self.ctx
        m.delete(0, "end")
        if e["deleted"]:
            m.add_command(label=tr('Восстановить'), command=self.restore)
            m.add_command(label=tr('Удалить навсегда'), command=self.purge)
        else:
            m.add_command(label=tr('Копировать пароль'), command=self.copy_password)
            m.add_command(label=tr('Копировать логин'), command=self.copy_login)
            m.add_command(label=tr('Открыть сайт'), command=self.open_url)
            m.add_separator()
            m.add_command(label=tr('Изменить'), command=self.edit)
            m.add_command(label=tr('В избранное / убрать'), command=self.toggle_fav)
            m.add_command(label=tr('Удалить'), command=self.delete)
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
        if messagebox.askyesno(tr(APP_NAME), f"{tr('Переместить «')}{e['title']}{tr('» в корзину?\nЗапись хранится ')}{TRASH_DAYS}{tr(' дней.')}", parent=self.root):
            ok, _ = self._do(self.vault.soft_delete, e["id"])
            if ok:
                self.refresh_all()
                entry_id=e["id"]
                self.notify(tr("Запись перемещена в корзину"),lambda:self.undo_delete(entry_id),action_label=tr("Отменить"))

    def undo_delete(self,entry_id):
        if not self.vault.unlocked:return
        entry=self.vault.get(entry_id)
        if entry and entry["deleted"]:
            ok,_=self._do(self.vault.restore,entry_id)
            if ok:self.refresh_all();self.notify(tr("Запись восстановлена"))

    def restore(self):
        e = self.selected()
        if e and e["deleted"]:
            ok, _ = self._do(self.vault.restore, e["id"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def purge(self):
        e = self.selected()
        if e and messagebox.askyesno(tr(APP_NAME), f"{tr('Удалить «')}{e['title']}{tr('» навсегда?\nЭто действие нельзя отменить.')}", parent=self.root):
            ok, _ = self._do(self.vault.purge, e["id"])
            if ok:
                self.refresh_all()
                self.saved_note()

    def empty_trash(self):
        n = len(self.vault.trash())
        if n and messagebox.askyesno(tr(APP_NAME), f"{tr('Удалить навсегда записей: ')}{n}?", parent=self.root):
            ok, _ = self._do(self.vault.empty_trash)
            if ok:
                self.refresh_all()
                self.saved_note()

    def copy_password(self):
        e = self.selected()
        if e:
            self.copy_text(e["password"], tr('Пароль'))

    def copy_login(self):
        e = self.selected()
        if e:
            self.copy_text(e["login"], tr('Логин'))

    def copy_totp(self):
        e = self.selected()
        if e and e["totp"]:
            try:
                self.copy_text(totp_now(e["totp"]), tr('Код 2FA'))
            except Exception:
                messagebox.showwarning(tr(APP_NAME), tr('Ключ 2FA не распознан.'), parent=self.root)

    def open_url(self):
        e = self.selected()
        if not e or not e["url"]:
            return
        url = e["url"] if "://" in e["url"] else "https://" + e["url"]
        if urlparse(url).scheme not in ("http", "https"):
            messagebox.showwarning(tr(APP_NAME), tr('Открываются только ссылки http/https.'), parent=self.root)
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
            parent=self.root, title=tr('Выберите CSV или Excel-файл с паролями'),
            filetypes=[(tr('CSV и Excel'), "*.csv *.xlsx"), (tr('Все файлы'), "*.*")])
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
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось прочитать файл:\n')}{ex}", parent=self.root)
            return
        if not items:
            messagebox.showinfo(tr(APP_NAME), tr('В файле не найдено записей с паролями.'), parent=self.root)
            return
        if not messagebox.askyesno(
                tr(APP_NAME), f"{tr('Источник: ')}{source}{tr('\nНайдено записей: ')}{len(items)}{tr('\nПропущено строк (пустые, карты, заметки): ')}{skipped}{tr('\n\nИмпортировать?')}",
                parent=self.root):
            return
        ok, res = self._do(self.vault.bulk_add, items, source)
        if not ok:
            return
        added, dup = res
        self.refresh_all()
        self.saved_note()
        messagebox.showinfo(tr(APP_NAME), f"{tr('Добавлено: ')}{added}{tr('\nПовторов пропущено: ')}{dup}",
                            parent=self.root)
        if messagebox.askyesno(
                tr(APP_NAME), tr('Файл хранит пароли в открытом виде.\nУдалить его с диска сейчас (содержимое будет перезаписано)?'),
                parent=self.root):
            try:
                shred_file(path)
            except OSError as ex:
                messagebox.showwarning(tr(APP_NAME), f"{tr('Не удалось удалить файл:\n')}{ex}", parent=self.root)

    def export_encrypted(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title=tr('Сохранить зашифрованную копию'), defaultextension=".dat",
            initialfile="moi-paroli-" + datetime.now().strftime("%Y-%m-%d") + ".dat",
            filetypes=[(tr('Хранилище'), "*.dat")])
        if path:
            try:
                shutil.copyfile(self.vault.path, path)
                self.notify(tr('Копия сохранена. Она зашифрована тем же мастер-паролем.'))
            except OSError as ex:
                messagebox.showerror(tr(APP_NAME), f"{tr('Ошибка: ')}{ex}", parent=self.root)

    def export_csv(self):
        if not messagebox.askyesno(
                tr(APP_NAME), tr('В CSV пароли будут записаны открытым текстом.\nЛюбой, кто получит файл, сможет их прочитать. Продолжить?'),
                icon="warning", parent=self.root):
            return
        pw = simpledialog.askstring(APP_NAME, tr('Введите мастер-пароль для подтверждения:'),
                                    show="•", parent=self.root)
        if not pw:
            return
        if not self.vault.verify_password(pw):
            messagebox.showerror(tr(APP_NAME), tr('Неверный мастер-пароль.'), parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title=tr('Сохранить CSV'),
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            try:
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    f.write(export_csv_text(self.vault.active()))
                messagebox.showinfo(tr(APP_NAME), tr('Файл сохранён. Не забудьте удалить его после использования.'), parent=self.root)
            except OSError as ex:
                messagebox.showerror(tr(APP_NAME), f"{tr('Ошибка: ')}{ex}", parent=self.root)

    def restore_backup(self):
        start = self.vault.backups_dir()
        path = filedialog.askopenfilename(
            parent=self.root, title=tr('Выберите резервную копию'),
            initialdir=start if os.path.isdir(start) else os.path.dirname(self.vault.path),
            filetypes=[(tr('Хранилище'), "*.dat *.bak"), (tr('Все файлы'), "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            if not (isinstance(blob, dict) and blob.get("magic") in ("passvault", "passvault-v1")):
                raise ValueError(tr('это не файл хранилища'))
        except (OSError, ValueError) as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Файл не подходит:\n')}{ex}", parent=self.root)
            return
        backup_password = simpledialog.askstring(APP_NAME, tr('Мастер-пароль резервной копии:'),
                                                   show="•", parent=self.root)
        if backup_password is None:
            return
        try:
            keydata = None
            if Vault.header_needs_keyfile(path):
                keypath = filedialog.askopenfilename(parent=self.root, title=tr('Ключевой файл резервной копии'))
                if not keypath:
                    return
                with open(keypath, "rb") as key:
                    keydata = key.read()
            Vault.validate_backup(path, backup_password, keydata)
        except (VaultError, OSError, ValueError) as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Копия не прошла проверку: ')}{ex}", parent=self.root)
            return
        if not messagebox.askyesno(
                tr(APP_NAME), tr('Текущие данные будут заменены выбранной копией.\nПрежний файл сохранится как vault.dat.before-restore.\n\nПродолжить?'),
                parent=self.root):
            return
        try:
            shutil.copyfile(self.vault.path, self.vault.path + ".before-restore")
            staged = self.vault.path + ".restore.tmp"
            shutil.copyfile(path, staged)
            os.replace(staged, self.vault.path)
        except OSError as ex:
            messagebox.showerror(tr(APP_NAME), f"{tr('Не удалось восстановить:\n')}{ex}", parent=self.root)
            return
        messagebox.showinfo(tr(APP_NAME), tr('Копия восстановлена. Войдите мастер-паролем этой копии.'),
                            parent=self.root)
        self.lock()

    def change_master(self):
        old = simpledialog.askstring(APP_NAME, tr('Текущий мастер-пароль:'), show="•", parent=self.root)
        if not old:
            return
        if not self.vault.verify_password(old):
            messagebox.showerror(tr(APP_NAME), tr('Неверный мастер-пароль.'), parent=self.root)
            return
        self._choose_new_master()

    def change_master_hello(self):
        if not self.vault.unlocked or self.vault.uses_keyfile or not self.hello.enabled():
            messagebox.showwarning(tr(APP_NAME),tr('Сначала откройте хранилище с настроенным Windows Hello.'),parent=self.root)
            return
        from native_auth import request_hello
        epoch=self._auth_epoch
        def approved(password):
            valid=(self._auth_epoch==epoch and self.vault.unlocked and self.vault.verify_password(password))
            password=None
            if valid:self._choose_new_master()
        def failed(text):
            if self._auth_epoch==epoch:messagebox.showwarning(tr(APP_NAME),text,parent=self.root)
        request_hello(self.root,self.hello,approved,failed)

    def _choose_new_master(self):
        epoch=self._auth_epoch
        vault=self.vault
        p1 = simpledialog.askstring(APP_NAME, tr('Новый мастер-пароль:'), show="•", parent=self.root)
        if not p1:
            return
        if len(p1) < MIN_MASTER_LEN:
            messagebox.showwarning(tr(APP_NAME), f"{tr('Минимум ')}{MIN_MASTER_LEN}{tr(' символов.')}", parent=self.root)
            return
        if p1 != simpledialog.askstring(APP_NAME, tr('Повторите новый пароль:'), show="•",
                                        parent=self.root):
            messagebox.showwarning(tr(APP_NAME), tr('Пароли не совпадают.'), parent=self.root)
            return
        if self._auth_epoch!=epoch or self.vault is not vault or not vault.unlocked:
            return
        ok, _ = self._do(vault.change_password, p1)
        if ok:
            self._auth_epoch+=1
            self.hello.disable()
            self.notify(tr('Мастер-пароль изменён, хранилище пересохранено.\nСтарые резервные копии в папке backups остались под прежним паролем.'))
            messagebox.showinfo(tr(APP_NAME),tr('Мастер-пароль изменён. Включите Windows Hello заново в настройках.'),parent=self.root)

    def open_data_dir(self):
        d = os.path.dirname(self.vault.path)
        if hasattr(os, "startfile"):
            os.startfile(d)  # только Windows
        else:
            messagebox.showinfo(tr(APP_NAME), d, parent=self.root)

    def run(self):
        self.root.mainloop()


def main():
    if tk is None:
        print(tr('Не найден tkinter. Установите Python с python.org (компонент tcl/tk).'))
        sys.exit(1)
    if not win_single_instance():
        win_message(tr('«Bitora password» уже запущены. Найдите значок программы в области уведомлений (трей).'))
        sys.exit(0)
    App().run()


if __name__ == "__main__":
    main()

