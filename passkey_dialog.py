"""One explicit native approval per passkey registration or authentication."""
import os
import sys
import threading
from types import SimpleNamespace
from localization import tr,set_language
from passkeys import validate,create,get,candidates,PasskeyError


def approve(operation,options):
    rp,origin,_=validate(operation,options)
    from site_policy import excluded
    from urllib.parse import urlsplit
    if excluded(rp) or excluded(urlsplit(origin).hostname):raise PasskeyError('Website excluded in Bitora settings')
    import tkinter as tk
    from tkinter import ttk
    from moi_paroli import Settings,Vault,App,data_dir,_scroll_dialog_body
    from browser_host import apply_brand_icon,add_hello_button,midnight_button
    from native_auth import unlock_error
    settings=Settings(os.path.join(data_dir(),'settings.json'));set_language(settings.get('language'))
    path=settings.get('vault_path') or os.path.join(data_dir(),'vault.dat')
    root=tk.Tk();apply_brand_icon(root)
    root.title(tr('Bitora — ключ доступа'))
    root.geometry('640x620')
    App.apply_theme(SimpleNamespace(root=root,settings=settings))
    frame=_scroll_dialog_body(root,24)
    ttk.Label(frame,text=tr('Создать ключ доступа') if operation=='create' else tr('Войти с ключом доступа'),font=('Segoe UI',16,'bold')).pack(anchor='w',pady=10)
    ttk.Label(frame,text=origin,wraplength=570,font=('Segoe UI',12,'bold')).pack(anchor='w')
    ttk.Label(frame,text=tr('Проверьте домен перед подтверждением.'),wraplength=570).pack(anchor='w',pady=12)
    if operation=='create':ttk.Label(frame,text=options['user']['name'],wraplength=570).pack(anchor='w',pady=8)
    ttk.Label(frame,text=tr('Мастер-пароль:')).pack(anchor='w')
    password=ttk.Entry(frame,show='•');password.pack(fill='x',pady=6)
    ttk.Label(frame,text=tr('Ключевой файл (если используется):')).pack(anchor='w')
    keypath=ttk.Entry(frame);keypath.pack(fill='x',pady=6)
    keypath.insert(0,settings.get('keyfile_path') or '')
    status=ttk.Label(frame,text='',wraplength=570);status.pack(fill='x',pady=10)
    result={'ok':False,'name':'NotAllowedError','error':'Canceled'}
    cancel=threading.Event();alive={'yes':True}
    from session_guard import SessionGuard
    guard=SessionGuard(lambda reason:cancel.set())
    guard.start()
    def close():
        cancel.set()
        if alive['yes']:alive['yes']=False;root.destroy()
    # A disconnected native port means the browser aborted or navigated away.
    def watch():
        try:sys.stdin.buffer.read(1)
        except Exception:pass
        cancel.set()
    threading.Thread(target=watch,daemon=True).start()
    def poll():
        if cancel.is_set():close()
        elif alive['yes']:root.after(100,poll)
    def confirm(master=None):
        nonlocal result
        if cancel.is_set():close();return
        vault=Vault(path)
        try:
            keydata=None
            if keypath.get().strip():
                with open(keypath.get().strip(),'rb') as stream:keydata=stream.read()
            vault.unlock(password.get() if master is None else master,keydata)
            if cancel.is_set():return
            if operation=='create':
                _,response=create(vault,options,verified=True)
            else:
                rows=candidates(vault,options,rp)
                if not rows:raise PasskeyError('No matching passkey')
                if len(rows)>1:
                    status.configure(text=tr('Выберите аккаунт и подтвердите вход.'))
                    selected=choose_account(root,rows)
                    if selected is None:return
                else:selected=rows[0]['id']
                if cancel.is_set():return
                response=get(vault,options,selected,verified=True)
            result={'ok':True,'credential':response};close()
        except PasskeyError as exc:
            result={'ok':False,'name':exc.name,'error':str(exc)};status.configure(text=str(exc))
        except Exception as exc:status.configure(text=unlock_error(exc))
        finally:
            vault.lock();master=None
            if alive['yes']:password.delete(0,'end')
    accept=midnight_button(frame,text=tr('Подтвердить'),command=confirm,style='Accent.TButton');accept.pack(fill='x',pady=6)
    add_hello_button(root,frame,path,confirm,status,accept)
    midnight_button(frame,text=tr('Отмена'),command=close).pack(fill='x',pady=6)
    root.protocol('WM_DELETE_WINDOW',close);root.bind('<Escape>',lambda e:close())
    root.after(min(120000,max(15000,int(options.get('timeout') or 60000))),close)
    root.after(100,poll);password.focus_set()
    try:root.mainloop()
    finally:guard.stop()
    return result


def choose_account(root,rows):
    import tkinter as tk
    from tkinter import ttk
    from midnight_ui import button
    window=tk.Toplevel(root);window.title(tr('Выберите аккаунт'))
    names={f"{i+1}. {row['login']}":row['id'] for i,row in enumerate(rows)}
    selected=tk.StringVar(value=next(iter(names)))
    ttk.Combobox(window,textvariable=selected,values=list(names),state='readonly',width=48).pack(padx=22,pady=22)
    result={'id':None}
    def ok():result['id']=names.get(selected.get());window.destroy()
    button(window,text=tr('Подтвердить'),command=ok).pack(padx=22,pady=12)
    window.transient(root);window.grab_set();root.wait_window(window)
    return result['id']
