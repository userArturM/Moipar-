"""One-shot, user-approved Native Messaging host for Chromium browsers.

The browser never receives the master password. A fresh native dialog asks for it
for every credential retrieval; credentials are returned only after confirmation.
"""
import json
import os
import struct
import sys
from urllib.parse import urlparse

MAX_MESSAGE = 64 * 1024


def read_message(stream):
    raw = stream.read(4)
    if len(raw) != 4:
        raise ValueError('Missing native message length')
    n = struct.unpack('<I', raw)[0]
    if n < 1 or n > MAX_MESSAGE:
        raise ValueError('Invalid message length')
    payload = stream.read(n)
    if len(payload) != n:
        raise ValueError('Truncated message')
    msg = json.loads(payload.decode('utf-8'))
    if not isinstance(msg, dict):
        raise ValueError('Invalid message')
    return msg


def write_message(stream, obj):
    b = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    if len(b) > MAX_MESSAGE:
        raise ValueError('Response too long')
    stream.write(struct.pack('<I', len(b)) + b)
    stream.flush()


def verified_origin(raw):
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError('Invalid URL')
    parsed = urlparse(raw)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only HTTPS websites are supported')
    if parsed.port not in (None, 443):
        raise ValueError('Non-default port is not supported')
    host = parsed.hostname.lower().rstrip('.')
    if not host or host == 'localhost' or '.' not in host:
        raise ValueError('Invalid site hostname')
    return host


def matching_records(records, host):
    """Exact website hostname only, avoiding evil-example.com or subdomain confusion."""
    result = []
    for record in records:
        raw = record.get('url') or record.get('website') or ''
        try:
            parsed = urlparse(raw if '://' in raw else 'https://' + raw)
            match = parsed.hostname and parsed.hostname.lower().rstrip('.') == host
        except (ValueError, TypeError):
            match = False
        if match and not record.get('deleted') and record.get('password'):
            result.append(record)
    return result


def select_record(host):
    # Imported lazily so native protocol tests do not require a display.
    import tkinter as tk
    from tkinter import ttk, messagebox
    from moi_paroli import Vault, Settings, data_dir, VaultError, App
    from types import SimpleNamespace

    root = tk.Tk()
    root.title('Мои пароли — разрешить заполнение')
    root.geometry('540x390')
    root.resizable(False, False)
    settings = Settings(os.path.join(data_dir(), 'settings.json'))
    appearance = SimpleNamespace(root=root, settings=settings)
    App.apply_theme(appearance)
    result = {'ok': False, 'error': 'Отменено пользователем'}
    ttk.Label(root, text='Запрос пароля для сайта:', font=('Segoe UI', 11)).pack(pady=(16, 3))
    ttk.Label(root, text=host, font=('Segoe UI', 12, 'bold')).pack()
    ttk.Label(root, text='Проверьте адрес сайта перед подтверждением.').pack(pady=8)
    frame = ttk.Frame(root)
    frame.pack(fill='x', padx=24)
    ttk.Label(frame, text='Мастер-пароль:').pack(anchor='w')
    password = ttk.Entry(frame, show='•')
    password.pack(fill='x')
    password.focus_set()
    ttk.Label(frame, text='Ключевой файл (если используется):').pack(anchor='w', pady=(9, 0))
    keypath = ttk.Entry(frame)
    keypath.pack(fill='x')

    ttk.Label(root, text='Если есть несколько аккаунтов, выберите один после разблокировки.').pack(pady=(8, 0))

    def confirm():
        nonlocal result
        settings = Settings(os.path.join(data_dir(), 'settings.json'))
        path = settings.get('vault_path') or os.path.join(data_dir(), 'vault.dat')
        vault = Vault(path)
        try:
            keydata = None
            if keypath.get().strip():
                with open(keypath.get().strip(), 'rb') as f:
                    keydata = f.read()
            vault.unlock(password.get(), keydata)
            entries = matching_records(vault.active(), host)
            if not entries:
                result = {'ok': False, 'error': 'Для этого домена нет сохранённых паролей'}
            else:
                entry = entries[0]
                if len(entries) > 1:
                    # Do not expose record passwords until the user actively chooses.
                    chooser = tk.Toplevel(root)
                    chooser.title('Выбор аккаунта')
                    chooser.geometry('440x270')
                    chooser.grab_set()
                    ttk.Label(chooser, text='Выберите аккаунт для ' + host).pack(pady=12)
                    chooser.configure(bg=appearance.t['bg'])
                    choices = tk.Listbox(chooser, exportselection=False, relief='flat',
                                         bg=appearance.t['card'], fg=appearance.t['fg'],
                                         selectbackground=appearance.t['sel'],
                                         selectforeground=appearance.t['fg'])
                    for index, candidate in enumerate(entries):
                        choices.insert(tk.END, str(index + 1) + '. ' + str(candidate.get('login') or candidate.get('title') or 'Без имени'))
                    choices.pack(fill='both', expand=True, padx=16)
                    choices.selection_set(0)
                    selected = {'entry': None}
                    def choose():
                        indices = choices.curselection()
                        if indices:
                            selected['entry'] = entries[indices[0]]
                        chooser.destroy()
                    ttk.Button(chooser, text='Подтвердить выбранный аккаунт', command=choose).pack(pady=9)
                    root.wait_window(chooser)
                    entry = selected['entry']
                if entry is not None:
                    result = {'ok': True, 'login': entry.get('login', ''), 'password': entry['password']}
            vault.lock()
        except (OSError, ValueError, VaultError) as exc:
            result = {'ok': False, 'error': 'Не удалось открыть хранилище: ' + type(exc).__name__}
        finally:
            vault.lock()
            root.destroy()

    ttk.Button(root, text='Разрешить однократное заполнение', command=confirm).pack(pady=14)
    root.bind('<Return>', lambda _: confirm())
    root.mainloop()
    return result


def candidate_from_message(msg):
    host=verified_origin(msg.get("url"))
    credentials=msg.get("credentials")
    if not isinstance(credentials,dict):
        raise ValueError("Нет данных для сохранения")
    result={"url":msg["url"]}
    for key,limit in (("login",1024),("password",4096),("title",200)):
        value=credentials.get(key,"")
        if not isinstance(value,str) or len(value)>limit or "\x00" in value:
            raise ValueError("Неверные данные записи")
        result[key]=value
    if not result["password"]:
        raise ValueError("На странице не найден пароль")
    result["title"]=result["title"].strip() or host
    return host,result

def save_to_vault(vault,host,candidate):
    if not vault.unlocked:
        raise ValueError("Хранилище заблокировано")
    if verified_origin(candidate["url"])!=host:
        raise ValueError("Адрес сайта изменился")
    matches=[e for e in matching_records(vault.active(),host) if e.get("login","")==candidate["login"]]
    if len(matches)>1:
        raise ValueError("Для этого логина есть несколько записей. Объедините их в приложении.")
    if matches:
        if matches[0]["password"]==candidate["password"]:
            return {"ok":True,"message":"Этот пароль уже сохранён"}
        vault.update(matches[0]["id"],{"password":candidate["password"],"url":candidate["url"]})
        return {"ok":True,"message":"Пароль обновлён"}
    vault.add(dict(candidate,category="Из браузера",source="Browser extension"))
    return {"ok":True,"message":"Пароль сохранён"}

def save_record(host,candidate):
    import tkinter as tk
    from tkinter import ttk
    from types import SimpleNamespace
    from moi_paroli import App,Vault,Settings,data_dir,VaultError,_scroll_dialog_body
    root=tk.Tk()
    root.title("Мои пароли — сохранить пароль")
    settings=Settings(os.path.join(data_dir(),"settings.json"))
    App.apply_theme(SimpleNamespace(root=root,settings=settings))
    frame=_scroll_dialog_body(root,24)
    ttk.Label(frame,text="Сохранить пароль",font=("Segoe UI",20,"bold")).pack(anchor="w")
    ttk.Label(frame,text=host,font=("Segoe UI",12,"bold")).pack(anchor="w",pady=(8,16))
    ttk.Label(frame,text="Данные сайта").pack(anchor="w")
    ttk.Label(frame,text=candidate["login"] or "Без логина",wraplength=420).pack(anchor="w",pady=8)
    display=ttk.Entry(frame,show="•",width=44)
    display.insert(0,candidate["password"])
    display.configure(state="readonly")
    display.pack(fill="x")
    show=tk.BooleanVar(value=False)
    ttk.Checkbutton(frame,text="Показать сохраняемый пароль",variable=show,
                   command=lambda:display.configure(show="" if show.get() else "•")).pack(anchor="w",pady=8)
    ttk.Label(frame,text="Мастер-пароль хранилища").pack(anchor="w",pady=(12,4))
    master=ttk.Entry(frame,show="•")
    master.pack(fill="x")
    ttk.Label(frame,text="Ключевой файл, если используется").pack(anchor="w",pady=(10,4))
    keypath=ttk.Entry(frame)
    keypath.pack(fill="x")
    status=ttk.Label(frame,text="",wraplength=420)
    status.pack(fill="x",pady=12)
    result={"ok":False,"error":"Сохранение отменено"}
    def confirm():
        nonlocal result
        vault=Vault(settings.get("vault_path") or os.path.join(data_dir(),"vault.dat"))
        try:
            keydata=None
            if keypath.get().strip():
                with open(keypath.get().strip(),"rb") as f: keydata=f.read()
            vault.unlock(master.get(),keydata)
            result=save_to_vault(vault,host,candidate)
            root.destroy()
        except (VaultError,OSError,ValueError):
            status.config(text="Не удалось сохранить. Проверьте мастер-пароль, ключевой файл и доступ к хранилищу.")
            master.delete(0,"end")
        finally:
            vault.lock()
    ttk.Button(frame,text="Подтвердить и сохранить",style="Accent.TButton",command=confirm).pack(fill="x")
    ttk.Button(frame,text="Отмена",command=root.destroy).pack(fill="x",pady=(8,0))
    root.bind("<Return>",lambda event:confirm())
    root.bind("<Escape>",lambda event:root.destroy())
    master.focus_set()
    root.mainloop()
    return result

def handle(msg, selector=select_record, saver=save_record):
    if msg.get("action")=="ping":
        return {"ok":True,"version":"4.3","supports":["get_credentials","save_credentials"]}
    if msg.get("action")=="save_credentials":
        try:
            host,candidate=candidate_from_message(msg)
        except ValueError as exc:
            return {"ok":False,"error":str(exc)}
        return saver(host,candidate)
    if msg.get('action') != 'get_credentials':
        return {'ok': False, 'error': 'Unsupported action'}
    try:
        host = verified_origin(msg.get('url'))
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    return selector(host)


def main():
    if "--register" in sys.argv:
        from browser_registration import register
        from browser_identity import EXTENSION_ID
        from pathlib import Path
        identity=EXTENSION_ID
        if "--extension-id" in sys.argv:
            identity=sys.argv[sys.argv.index("--extension-id")+1]
        exe=sys.executable if getattr(sys,"frozen",False) else str(Path(__file__).parent/"dist/browser_host.exe")
        print(register(identity,exe))
        return
    if "--diagnose" in sys.argv:
        from browser_registration import diagnose
        print(json.dumps(diagnose(),ensure_ascii=False))
        return
    # Don't ever print to stdout: it is reserved for the native protocol.
    try:
        request = read_message(sys.stdin.buffer)
        response = handle(request)
    except Exception as exc:
        response = {'ok': False, 'error': type(exc).__name__}
    write_message(sys.stdout.buffer, response)


if __name__ == '__main__':
    main()

