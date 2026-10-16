from localization import tr
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

def midnight_button(*args,**kwargs):
    from midnight_ui import button
    return button(*args,**kwargs)

def apply_brand_icon(root):
    import tkinter as tk
    from moi_paroli import ICON_B64
    from windows_branding import set_shell_identity
    set_shell_identity()
    root.bitora_icon=tk.PhotoImage(master=root,data=ICON_B64)
    root.iconphoto(True,root.bitora_icon)


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


def add_hello_button(root, parent, path, approved, status, password_button):
    from tkinter import ttk
    from moi_paroli import Vault, data_dir
    from native_auth import hello_for_vault, request_hello
    hello = hello_for_vault(path, data_dir())
    if Vault.header_needs_keyfile(path) or not hello.enabled():
        return

    def restore():
        button.configure(state='normal')
        password_button.configure(state='normal')

    def accepted(password):
        restore()
        approved(password)
        password = None

    def failed(message):
        restore()
        status.configure(text=message)

    def begin():
        button.configure(state='disabled')
        password_button.configure(state='disabled')
        status.configure(text=tr('Ожидание подтверждения Windows Hello…'))
        request_hello(root, hello, accepted, failed)

    button = midnight_button(parent, text=tr('Подтвердить через Windows Hello'), command=begin)
    button.pack(fill='x', padx=12, pady=8)


def select_record(host):
    # Imported lazily so native protocol tests do not require a display.
    import tkinter as tk
    from tkinter import ttk
    from midnight_dialogs import messagebox
    from moi_paroli import Vault, Settings, data_dir, VaultError, App, _scroll_dialog_body
    from types import SimpleNamespace

    root = tk.Tk()
    apply_brand_icon(root)
    root.title(tr('Bitora Password Manager — разрешить заполнение'))
    root.geometry('620x580')
    root.resizable(True, True)
    settings = Settings(os.path.join(data_dir(), 'settings.json'))
    from localization import set_language
    set_language(settings.get('language'))
    path = settings.get('vault_path') or os.path.join(data_dir(), 'vault.dat')
    root.title(tr('Bitora Password Manager — разрешить заполнение'))
    appearance = SimpleNamespace(root=root, settings=settings)
    App.apply_theme(appearance)
    result = {'ok': False, 'error': tr('Отменено пользователем')}
    frame = _scroll_dialog_body(root,24)
    ttk.Label(frame, text=tr('Запрос пароля для сайта:'), font=('Segoe UI', 11)).pack(pady=(16, 3))
    ttk.Label(frame, text=host, font=('Segoe UI', 12, 'bold')).pack()
    ttk.Label(frame, text=tr('Проверьте адрес сайта перед подтверждением.')).pack(pady=8)
    ttk.Label(frame, text=tr('Хранилище:') + '\n' + path, wraplength=550).pack(anchor='w', pady=(0, 10))
    ttk.Label(frame, text=tr('Мастер-пароль:')).pack(anchor='w')
    password = ttk.Entry(frame, show='•')
    password.pack(fill='x')
    password.focus_set()
    visible = tk.BooleanVar(value=False)
    ttk.Checkbutton(frame, text=tr('Показать мастер-пароль'), variable=visible,
                    command=lambda: password.configure(show='' if visible.get() else '•')).pack(anchor='w')
    ttk.Label(frame, text=tr('Ключевой файл (если используется):')).pack(anchor='w', pady=(9, 0))
    keypath = ttk.Entry(frame)
    keypath.pack(fill='x')

    ttk.Label(frame, text=tr('Если есть несколько аккаунтов, выберите один после разблокировки.')).pack(pady=(8, 0))
    status = ttk.Label(frame, text='', wraplength=550)
    status.pack(padx=24, pady=8)

    def confirm(master_password=None):
        nonlocal result
        vault = Vault(path)
        finished = False
        try:
            keydata = None
            if keypath.get().strip():
                with open(keypath.get().strip(), 'rb') as f:
                    keydata = f.read()
            vault.unlock(password.get() if master_password is None else master_password, keydata)
            entries = matching_records(vault.active(), host)
            if not entries:
                result = {'ok': False, 'error': tr('Для этого домена нет сохранённых паролей')}
            else:
                entry = entries[0]
                if len(entries) > 1:
                    # Do not expose record passwords until the user actively chooses.
                    chooser = tk.Toplevel(root)
                    chooser.title(tr('Выбор аккаунта'))
                    chooser.geometry('440x270')
                    chooser.grab_set()
                    ttk.Label(chooser, text=tr('Выберите аккаунт для ') + host).pack(pady=12)
                    chooser.configure(bg=appearance.t['bg'])
                    choices = tk.Listbox(chooser, exportselection=False, relief='flat',
                                         bg=appearance.t['card'], fg=appearance.t['fg'],
                                         selectbackground=appearance.t['sel'],
                                         selectforeground=appearance.t['fg'])
                    for index, candidate in enumerate(entries):
                        choices.insert(tk.END, str(index + 1) + '. ' + str(candidate.get('login') or candidate.get('title') or tr('Без имени')))
                    choices.pack(fill='both', expand=True, padx=16)
                    choices.selection_set(0)
                    selected = {'entry': None}
                    def choose():
                        indices = choices.curselection()
                        if indices:
                            selected['entry'] = entries[indices[0]]
                        chooser.destroy()
                    midnight_button(chooser, text=tr('Подтвердить выбранный аккаунт'), command=choose).pack(pady=9)
                    root.wait_window(chooser)
                    entry = selected['entry']
                if entry is not None:
                    result = {'ok': True, 'login': entry.get('login', ''), 'password': entry['password']}
            vault.lock()
            finished = True
        except (OSError, ValueError, VaultError) as exc:
            from native_auth import unlock_error
            status.config(text=unlock_error(exc))
            password.delete(0, 'end')
            password.focus_set()
        finally:
            vault.lock()
            master_password = None
            if finished:
                root.destroy()

    approve = midnight_button(frame, text=tr('Разрешить однократное заполнение'), command=confirm)
    approve.pack(pady=8)
    add_hello_button(root, frame, path, confirm, status, approve)
    midnight_button(frame, text=tr('Отмена'), command=root.destroy).pack(pady=6)
    root.bind('<Return>', lambda _: confirm())
    root.mainloop()
    return result


def candidate_from_message(msg):
    host=verified_origin(msg.get("url"))
    credentials=msg.get("credentials")
    if not isinstance(credentials,dict):
        raise ValueError(tr('Нет данных для сохранения'))
    result={"url":msg["url"]}
    for key,limit in (("login",1024),("password",4096),("title",200)):
        value=credentials.get(key,"")
        if not isinstance(value,str) or len(value)>limit or "\x00" in value:
            raise ValueError(tr('Неверные данные записи'))
        result[key]=value
    if not result["password"]:
        raise ValueError(tr('На странице не найден пароль'))
    result["title"]=result["title"].strip() or host
    return host,result

def save_to_vault(vault,host,candidate):
    if not vault.unlocked:
        raise ValueError(tr('Хранилище заблокировано'))
    if verified_origin(candidate["url"])!=host:
        raise ValueError(tr('Адрес сайта изменился'))
    matches=[e for e in matching_records(vault.active(),host) if e.get("login","")==candidate["login"]]
    if len(matches)>1:
        raise ValueError(tr('Для этого логина есть несколько записей. Объедините их в приложении.'))
    if matches:
        if matches[0]["password"]==candidate["password"]:
            return {"ok":True,"message":tr('Этот пароль уже сохранён')}
        vault.update(matches[0]["id"],{"password":candidate["password"],"url":candidate["url"]})
        return {"ok":True,"message":tr('Пароль обновлён')}
    vault.add(dict(candidate,category=tr('Из браузера'),source="Browser extension"))
    return {"ok":True,"message":tr('Пароль сохранён')}

def save_record(host,candidate):
    import tkinter as tk
    from tkinter import ttk
    from types import SimpleNamespace
    from moi_paroli import App,Vault,Settings,data_dir,VaultError,_scroll_dialog_body
    root=tk.Tk()
    apply_brand_icon(root)
    root.title(tr('Bitora Password Manager — сохранить пароль'))
    settings=Settings(os.path.join(data_dir(),"settings.json"))
    from localization import set_language
    set_language(settings.get("language"))
    path = settings.get('vault_path') or os.path.join(data_dir(), 'vault.dat')
    root.title(tr("Bitora Password Manager — сохранить пароль"))
    App.apply_theme(SimpleNamespace(root=root,settings=settings))
    frame=_scroll_dialog_body(root,24)
    ttk.Label(frame,text=tr('Сохранить пароль'),font=("Segoe UI",20,"bold")).pack(anchor="w")
    ttk.Label(frame,text=host,font=("Segoe UI",12,"bold")).pack(anchor="w",pady=(8,16))
    ttk.Label(frame,text=tr('Хранилище:')+'\n'+path,wraplength=420).pack(anchor='w',pady=(0,10))
    ttk.Label(frame,text=tr('Данные сайта')).pack(anchor="w")
    login=ttk.Entry(frame)
    login.insert(0,candidate["login"])
    login.pack(fill="x",pady=8)
    ttk.Label(frame,text=tr("При двухэтапном входе проверьте или введите логин.")).pack(anchor="w")
    display=ttk.Entry(frame,show="•",width=44)
    display.insert(0,candidate["password"])
    display.configure(state="readonly")
    display.pack(fill="x")
    show=tk.BooleanVar(value=False)
    ttk.Checkbutton(frame,text=tr('Показать сохраняемый пароль'),variable=show,
                   command=lambda:display.configure(show="" if show.get() else "•")).pack(anchor="w",pady=8)
    ttk.Label(frame,text=tr('Мастер-пароль хранилища')).pack(anchor="w",pady=(12,4))
    master=ttk.Entry(frame,show="•")
    master.pack(fill="x")
    master_visible=tk.BooleanVar(value=False)
    ttk.Checkbutton(frame,text=tr('Показать мастер-пароль'),variable=master_visible,
                    command=lambda:master.configure(show='' if master_visible.get() else '•')).pack(anchor='w')
    ttk.Label(frame,text=tr('Ключевой файл, если используется')).pack(anchor="w",pady=(10,4))
    keypath=ttk.Entry(frame)
    keypath.pack(fill="x")
    status=ttk.Label(frame,text="",wraplength=420)
    status.pack(fill="x",pady=12)
    result={"ok":False,"error":tr('Сохранение отменено')}
    def confirm(master_password=None):
        nonlocal result
        vault=Vault(path)
        try:
            keydata=None
            if keypath.get().strip():
                with open(keypath.get().strip(),"rb") as f: keydata=f.read()
            vault.unlock(master.get() if master_password is None else master_password,keydata)
            updated=dict(candidate,login=login.get())
            if len(updated["login"])>1024:raise ValueError("Login too long")
            result=save_to_vault(vault,host,updated)
            root.destroy()
        except (VaultError,OSError,ValueError) as exc:
            from native_auth import unlock_error
            status.config(text=unlock_error(exc))
            master.delete(0,"end")
        finally:
            vault.lock()
            master_password=None
    approve=midnight_button(frame,text=tr('Подтвердить и сохранить'),style="Accent.TButton",command=confirm)
    approve.pack(fill="x")
    add_hello_button(root,frame,path,confirm,status,approve)
    midnight_button(frame,text=tr('Отмена'),command=root.destroy).pack(fill="x",pady=(8,0))
    root.bind("<Return>",lambda event:confirm())
    root.bind("<Escape>",lambda event:root.destroy())
    master.focus_set()
    root.mainloop()
    return result

def handle(msg, selector=select_record, saver=save_record):
    if msg.get('action') in ('passkey_create','passkey_get'):
        from passkey_dialog import approve
        from passkeys import PasskeyError
        try:return approve(msg['action'].partition('_')[2],msg.get('options'))
        except PasskeyError as exc:return {'ok':False,'name':exc.name,'error':str(exc)}
    if msg.get("action")=="ping":
        return {"ok":True,"version":"4.11.0","supports":["get_credentials","save_credentials","passkey_create","passkey_get"]}
    if msg.get("action")=="save_credentials":
        try:
            host,candidate=candidate_from_message(msg)
        except ValueError as exc:
            return {"ok":False,"error":str(exc)}
        from site_policy import excluded
        if excluded(host):return {'ok':False,'error':'Website excluded in Bitora settings'}
        return saver(host,candidate)
    if msg.get('action') != 'get_credentials':
        return {'ok': False, 'error': 'Unsupported action'}
    try:
        host = verified_origin(msg.get('url'))
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    from site_policy import excluded
    if excluded(host):return {'ok':False,'error':'Website excluded in Bitora settings'}
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

