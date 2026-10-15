import os
import threading
import tkinter as tk
from tkinter import ttk,filedialog,simpledialog,messagebox,colorchooser
from localization import tr
from product_features import category_change,backup_info,copy_backup,ICONS,COLORS

def friendly_error(exc):
    messages={
        'Category already exists':'Категория с таким названием уже есть',
        'Category not found':'Категория не найдена',
        'Category name must contain 1–80 characters':'Название категории должно содержать 1–80 символов',
        'Invalid category name':'Введите название категории длиной 1–80 символов',
        'Select entries first':'Сначала выберите записи',
        'Invalid selection':'Выбранные записи изменились. Выберите их заново.',
        'Choose a separate backup folder':'Выберите отдельную папку для резервной копии',
        'Vault is locked':'Хранилище заблокировано'}
    return tr(messages.get(str(exc),str(exc)))

def top(app,title):
    from moi_paroli import _new_top,_scroll_dialog_body
    window=_new_top(app,app.root,tr(title))
    return window,_scroll_dialog_body(window,24)

def categories(app,selected=None,move=False):
    window,frame=top(app,'Управление категориями')
    ttk.Label(frame,text=tr('Название, цвет и значок'),font=('Segoe UI',17,'bold')).pack(anchor='w')
    names=app.vault.categories()
    current=tk.StringVar(value=selected or (names[0] if names else ''))
    name=tk.StringVar(value=current.get());color=tk.StringVar(value=COLORS[0]);icon=tk.StringVar(value=ICONS[0])
    picker=ttk.Combobox(frame,textvariable=current,values=names,state='readonly')
    picker.pack(fill='x',pady=12)
    def load(event=None):
        name.set(current.get());props=app.vault.meta.get('category_properties',{}).get(current.get(),{})
        color.set(props.get('color',COLORS[0]));icon.set(props.get('icon',ICONS[0]))
    picker.bind('<<ComboboxSelected>>',load);load()
    ttk.Label(frame,text=tr('Название')).pack(anchor='w')
    ttk.Entry(frame,textvariable=name,width=38).pack(fill='x',pady=6)
    ttk.Label(frame,text=tr('Цвет')).pack(anchor='w')
    palette=ttk.Frame(frame);palette.pack(fill='x',pady=6)
    for value in COLORS:
        tk.Radiobutton(palette,variable=color,value=value,text='●',fg=value,
                       bg=app.t['bg'],selectcolor=app.t['panel'],font=('Segoe UI',18),indicatoron=False,
                       relief='flat',width=2).pack(side='left',padx=3)
    ttk.Label(frame,text=tr('Значок')).pack(anchor='w')
    ttk.Combobox(frame,textvariable=icon,values=ICONS,state='readonly',width=10).pack(anchor='w',pady=6)
    status=ttk.Label(frame,text='',wraplength=430);status.pack(fill='x',pady=10)
    def save(new=False):
        try:
            if new:
                if name.get().strip() in app.vault.categories():raise ValueError('Category already exists')
                category_change(app.vault,name.get(),color=color.get(),icon=icon.get())
            else:category_change(app.vault,current.get(),new_name=name.get(),color=color.get(),icon=icon.get())
            app.cat_filter='all';app.refresh_all();window.destroy();app.notify(tr('Категория сохранена'))
        except Exception as exc:status.config(text=friendly_error(exc))
    ttk.Button(frame,text=tr('Создать категорию'),command=lambda:save(True)).pack(fill='x',pady=4)
    ttk.Button(frame,text=tr('Сохранить изменения'),style='Accent.TButton',command=save).pack(fill='x',pady=4)
    if move:
        ids=list(app.tree.selection())
        ttk.Label(frame,text=tr('Выбрано записей: ')+str(len(ids))).pack(anchor='w',pady=6)
        def transfer():
            try:
                category_change(app.vault,name.get(),ids=ids,color=color.get(),icon=icon.get())
                app.refresh_all();window.destroy();app.notify(tr('Записи перенесены'))
            except Exception as exc:status.config(text=friendly_error(exc))
        ttk.Button(frame,text=tr('Перенести выбранные записи'),command=transfer,state='normal' if ids else 'disabled').pack(fill='x',pady=4)
    ttk.Button(frame,text=tr('Удалить категорию'),command=lambda:(window.destroy(),app.delete_category(current.get()))).pack(fill='x',pady=4)
    ttk.Button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=12)
    window.grab_set()

def backups(app):
    window,frame=top(app,'Резервные копии')
    ttk.Label(frame,text=tr('Защита от потери данных'),font=('Segoe UI',18,'bold')).pack(anchor='w')
    status=ttk.Label(frame,text='',wraplength=520,justify='left');status.pack(fill='x',pady=16)
    def refresh():
        info=backup_info(app.vault,app.settings.get('external_backup_dir'))
        def label(path):
            if path is None:return tr('Копии пока нет')
            from datetime import datetime
            return datetime.fromtimestamp(path.stat().st_mtime).strftime('%Y-%m-%d %H:%M')+'\n'+str(path)
        status.config(text=tr('Локальная копия: ')+label(info['local'])+'\n\n'+
                      tr('Отдельная копия: ')+label(info['external']))
    def create():
        folder=filedialog.askdirectory(parent=window,title=tr('Выберите другой диск или папку резервных копий'),initialdir=app.settings.get('external_backup_dir') or None)
        if not folder:return
        try:
            copy_backup(app.vault,folder);app.settings.set('external_backup_dir',folder);refresh()
            app.notify(tr('Зашифрованная копия сохранена'))
        except (OSError,ValueError,RuntimeError) as exc:messagebox.showerror(tr('Резервные копии'),friendly_error(exc),parent=window)
    def validate():
        from moi_paroli import Vault
        path=filedialog.askopenfilename(parent=window,title=tr('Выберите резервную копию'),filetypes=[('Vault','*.dat'),(tr('Все файлы'),'*.*')])
        if not path:return
        password=simpledialog.askstring(tr('Проверка копии'),tr('Мастер-пароль резервной копии:'),show='•',parent=window)
        if password is None:return
        key=None
        if Vault.header_needs_keyfile(path):
            key_path=filedialog.askopenfilename(parent=window,title=tr('Ключевой файл резервной копии'))
            if not key_path:return
            try:key=open(key_path,'rb').read()
            except OSError as exc:status.config(text=str(exc));return
        status.config(text=tr('Проверка…'))
        def worker():
            try:
                count=Vault.validate_backup(path,password,key)
                text=tr('Проверка восстановления пройдена. Записей: ')+str(count)
            except Exception:text=tr('Копия не прошла проверку. Проверьте пароль, ключевой файл и целостность копии.')
            app.post(lambda:status.config(text=text) if window.winfo_exists() else None)
        threading.Thread(target=worker,daemon=True).start()
    ttk.Label(frame,text=tr('Локальные копии находятся рядом с хранилищем. Сохраняйте отдельную копию на другом диске.'),wraplength=520).pack(anchor='w',pady=8)
    ttk.Button(frame,text=tr('Сохранить отдельную копию'),style='Accent.TButton',command=create).pack(fill='x',pady=5)
    ttk.Button(frame,text=tr('Проверить восстановление'),command=validate).pack(fill='x',pady=5)
    ttk.Button(frame,text=tr('Восстановить из резервной копии…'),command=lambda:(window.destroy(),app.restore_backup())).pack(fill='x',pady=5)
    ttk.Button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=12)
    refresh();window.grab_set()

def updates(app,info):
    window,frame=top(app,'Обновление приложения')
    from moi_paroli import APP_VERSION
    ttk.Label(frame,text=tr('Доступная версия: ')+info['version'],font=('Segoe UI',18,'bold')).pack(anchor='w')
    ttk.Label(frame,text=tr('Установлена версия: ')+APP_VERSION).pack(anchor='w',pady=8)
    text=tk.Text(frame,width=64,height=12,wrap='word',relief='flat',bg=app.t['card'],fg=app.t['fg'])
    text.insert('1.0',info.get('notes') or tr('Изменения доступны на странице сборки.'));text.configure(state='disabled');text.pack(fill='both',expand=True,pady=8)
    status=ttk.Label(frame,text='',wraplength=520);status.pack(fill='x',pady=8)
    button=ttk.Button(frame,text=tr('Скачать установщик'),style='Accent.TButton');button.pack(fill='x',pady=5)
    def download():
        import webbrowser
        url=info.get('download_url') or info['url']
        if '/releases/download/' not in url:
            webbrowser.open(url);return
        destination=filedialog.asksaveasfilename(parent=window,title=tr('Сохранить установщик'),initialfile='MoiParoli-Setup.exe',defaultextension='.exe')
        if not destination:return
        button.configure(state='disabled');status.config(text=tr('Скачивание…'))
        def worker():
            from github_updates import download_installer
            try:
                download_installer(url,destination,info.get('sha256'))
                message=tr('Установщик сохранён. Закройте приложение и запустите файл: ')+destination
            except Exception:message=tr('Не удалось скачать установщик. Проверьте подключение и повторите.')
            def finish():
                if window.winfo_exists():status.config(text=message);button.configure(state='normal')
            app.post(finish)
        threading.Thread(target=worker,daemon=True).start()
    button.configure(command=download)
    ttk.Button(frame,text=tr('Открыть страницу выпуска'),command=lambda:__import__('webbrowser').open(info['url'])).pack(fill='x',pady=4)
    ttk.Button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=10)
    window.grab_set()
