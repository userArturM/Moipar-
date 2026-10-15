import os
import threading
import tkinter as tk
from tkinter import ttk,filedialog,simpledialog,messagebox,colorchooser
from localization import tr
from midnight_ui import button as midnight_button
from midnight_dialogs import messagebox,simpledialog
from product_features import category_change,backup_info,copy_backup,ICONS,COLORS

def friendly_error(exc):
    messages={
        'Category already exists':'Категория с таким названием уже есть',
        'Category not found':'Категория не найдена',
        'Category name must contain 1–80 characters':'Название категории должно содержать 1–80 символов',
        'Invalid category name':'Введите название категории длиной 1–80 символов',
        'Select entries first':'Сначала выберите записи',
        'Invalid selection':'Выбранные записи изменились. Выберите их заново.',
        'Selection changed':'Выбранные записи изменились. Выберите их заново.',
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
    ordering=ttk.Frame(frame);ordering.pack(fill='x',pady=4)
    def reorder(offset):
        app.reorder_category(current.get(),offset)
        picker.configure(values=app.vault.categories())
    midnight_button(ordering,text=tr('Выше'),command=lambda:reorder(-1)).pack(side='left',padx=4)
    midnight_button(ordering,text=tr('Ниже'),command=lambda:reorder(1)).pack(side='left',padx=4)
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
    midnight_button(frame,text=tr('Создать категорию'),command=lambda:save(True)).pack(fill='x',pady=4)
    midnight_button(frame,text=tr('Сохранить изменения'),style='Accent.TButton',command=save).pack(fill='x',pady=4)
    if move:
        ids=list(app.tree.selection())
        ttk.Label(frame,text=tr('Выбрано записей: ')+str(len(ids))).pack(anchor='w',pady=6)
        def transfer():
            try:
                app.move_to_category(ids,current.get())
                window.destroy()
            except Exception as exc:status.config(text=friendly_error(exc))
        midnight_button(frame,text=tr('Перенести выбранные записи'),command=transfer,state='normal' if ids else 'disabled').pack(fill='x',pady=4)
    midnight_button(frame,text=tr('Удалить категорию'),command=lambda:(window.destroy(),app.delete_category(current.get()))).pack(fill='x',pady=4)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=12)
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
            except OSError as exc:status.config(text=tr(str(exc)));return
        status.config(text=tr('Проверка…'))
        def worker():
            try:
                count=Vault.validate_backup(path,password,key)
                text=tr('Проверка восстановления пройдена. Записей: ')+str(count)
            except Exception:text=tr('Копия не прошла проверку. Проверьте пароль, ключевой файл и целостность копии.')
            app.post(lambda:status.config(text=text) if window.winfo_exists() else None)
        threading.Thread(target=worker,daemon=True).start()
    ttk.Label(frame,text=tr('Локальные копии находятся рядом с хранилищем. Сохраняйте отдельную копию на другом диске.'),wraplength=520).pack(anchor='w',pady=8)
    midnight_button(frame,text=tr('Сохранить отдельную копию'),style='Accent.TButton',command=create).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Проверить восстановление'),command=validate).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Просмотреть и восстановить отдельные записи…'),command=lambda:backup_preview(app)).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Восстановить из резервной копии…'),command=lambda:(window.destroy(),app.restore_backup())).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=12)
    refresh();window.grab_set()

def backup_preview(app):
    from moi_paroli import Vault
    from product_features import preview_backup,restore_selected
    path=filedialog.askopenfilename(parent=app.root,title=tr('Выберите резервную копию'),filetypes=[('Vault','*.dat *.bak')])
    if not path:return
    password=simpledialog.askstring(tr('Проверка копии'),tr('Мастер-пароль резервной копии:'),show='•',parent=app.root)
    if password is None:return
    key=None
    try:
        if Vault.header_needs_keyfile(path):
            keypath=filedialog.askopenfilename(parent=app.root,title=tr('Ключевой файл резервной копии'))
            if not keypath:return
            with open(keypath,'rb') as handle:key=handle.read()
        modified=os.path.getmtime(path)
        records=preview_backup(path,password,key)
    except Exception:
        messagebox.showerror(tr('Резервные копии'),tr('Копия не прошла проверку. Проверьте пароль, ключевой файл и целостность копии.'),parent=app.root)
        return
    finally:password=None;key=None
    window,frame=top(app,'Записи резервной копии')
    from datetime import datetime
    ttk.Label(frame,text=tr('Проверенная резервная копия'),font=('Segoe UI',18,'bold')).pack(anchor='w')
    ttk.Label(frame,text=datetime.fromtimestamp(modified).strftime('%Y-%m-%d %H:%M')+' · '+str(len(records))+' '+tr('записей'),foreground=app.t['muted']).pack(anchor='w',pady=8)
    ttk.Label(frame,text=tr('Выберите записи. Они будут добавлены как новые; существующие записи не заменяются. История и вложения сохраняются.'),wraplength=540).pack(anchor='w',pady=8)
    listing=ttk.Treeview(frame,columns=('login','updated'),show='tree headings',selectmode='extended',height=10)
    listing.heading('#0',text=tr('Название'));listing.heading('login',text=tr('Логин'));listing.heading('updated',text=tr('Изменено'))
    listing.column('#0',width=200);listing.column('login',width=180);listing.column('updated',width=100)
    listing.pack(fill='both',expand=True)
    for entry in records:listing.insert('','end',iid=entry['id'],text=entry['title'],values=(entry['login'],entry['updated'][:10]))
    status=ttk.Label(frame,text='',wraplength=540);status.pack(fill='x',pady=8)
    def restore():
        try:
            ids=restore_selected(app.vault,records,listing.selection())
            app.refresh_all();window.destroy();app.notify(tr('Восстановлено записей: ')+str(len(ids)))
        except Exception as exc:status.config(text=friendly_error(exc))
    midnight_button(frame,text=tr('Восстановить выбранные записи'),style='Accent.TButton',command=restore).pack(fill='x',pady=6)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=8)
    window.bind('<Destroy>',lambda event:records.clear() if event.widget is window else None,add='+')
    window.grab_set()

def delete_category(app,name):
    from product_features import remove_category,restore_category
    window,frame=top(app,'Удалить категорию')
    ttk.Label(frame,text=name,font=('Segoe UI',18,'bold')).pack(anchor='w')
    count=sum(e['category']==name for e in app.vault.active())
    ttk.Label(frame,text=tr('Записей в категории: ')+str(count),foreground=app.t['muted']).pack(anchor='w',pady=10)
    mode=tk.BooleanVar(value=False)
    ttk.Radiobutton(frame,text=tr('Оставить записи без категории'),variable=mode,value=False).pack(anchor='w',pady=6)
    ttk.Radiobutton(frame,text=tr('Переместить записи в корзину'),variable=mode,value=True).pack(anchor='w',pady=6)
    ttk.Label(frame,text=tr('Категорию можно восстановить через «Корзина категорий». Изменённые после удаления записи не перезаписываются.'),wraplength=520).pack(anchor='w',pady=14)
    status=ttk.Label(frame,text='',wraplength=520);status.pack(fill='x')
    def remove():
        try:
            token=remove_category(app.vault,name,mode.get())
            app.cat_filter='all';app.refresh_all();window.destroy()
            app.notify(tr('Категория удалена'),lambda:undo(token),action_label=tr('Отменить'))
        except Exception as exc:status.config(text=friendly_error(exc))
    def undo(token):
        if not app.vault.unlocked:return
        try:restore_category(app.vault,token);app.refresh_all();app.notify(tr('Категория восстановлена'))
        except Exception as exc:messagebox.showerror(tr('Корзина категорий'),friendly_error(exc),parent=app.root)
    midnight_button(frame,text=tr('Удалить категорию'),style='Accent.TButton',command=remove).pack(fill='x',pady=8)
    midnight_button(frame,text=tr('Отмена'),command=window.destroy).pack(anchor='e',pady=8)
    window.grab_set()

def category_trash(app):
    from product_features import restore_category
    window,frame=top(app,'Корзина категорий')
    ttk.Label(frame,text=tr('Удалённые категории'),font=('Segoe UI',18,'bold')).pack(anchor='w',pady=8)
    listing=ttk.Treeview(frame,columns=('date',),show='tree headings',height=9)
    listing.heading('#0',text=tr('Название'));listing.heading('date',text=tr('Удалено'));listing.pack(fill='both',expand=True)
    for token,change in app.vault.meta.get('category_trash',{}).items():
        if not change.get('restored'):listing.insert('','end',iid=token,text=change['name'],values=(change['mtime'][:19],))
    status=ttk.Label(frame,text=tr('Изменённые после удаления записи сохранят свои текущие данные.'),wraplength=520);status.pack(fill='x',pady=12)
    def restore():
        ids=listing.selection()
        if not ids:return
        try:
            restore_category(app.vault,ids[0]);app.refresh_all();listing.delete(ids[0]);status.config(text=tr('Категория восстановлена'))
        except Exception as exc:status.config(text=friendly_error(exc))
    midnight_button(frame,text=tr('Восстановить'),style='Accent.TButton',command=restore).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=8)
    window.grab_set()

def duplicates(app):
    from product_features import duplicate_groups,merge_duplicates,MERGE_FIELDS
    groups=duplicate_groups(app.vault.active())
    window,frame=top(app,'Объединение дублей')
    ttk.Label(frame,text=tr('Одинаковый сайт и логин'),font=('Segoe UI',18,'bold')).pack(anchor='w')
    ttk.Label(frame,text=tr('Выберите группу, затем источник каждого поля. Пароли скрыты. Другие версии останутся в корзине; вложения объединяются.'),wraplength=560).pack(anchor='w',pady=12)
    listing=ttk.Treeview(frame,show='tree',height=5);listing.pack(fill='x')
    for index,group in enumerate(groups):listing.insert('','end',iid=str(index),text=group[0]['url']+' · '+group[0]['login']+' ('+str(len(group))+')')
    choices_frame=ttk.Frame(frame);choices_frame.pack(fill='x',pady=10)
    state={};variables={}
    labels={'title':'Название','url':'Сайт','login':'Логин','password':'Пароль','totp':'TOTP','category':'Категория','tags':'Теги','note':'Заметки','fields':'Дополнительные поля'}
    def select(event=None):
        for child in choices_frame.winfo_children():child.destroy()
        variables.clear()
        if not listing.selection():return
        group=groups[int(listing.selection()[0])]
        state['group']=group;state['expected']={e['id']:app.vault._record_hash(e) for e in group}
        names=[str(i+1)+'. '+e['title']+' · '+e['updated'] for i,e in enumerate(group)]
        for row,field in enumerate(MERGE_FIELDS):
            ttk.Label(choices_frame,text=tr(labels[field])).grid(row=row,column=0,sticky='w',pady=4)
            variable=variables[field]=tk.StringVar(value=names[0])
            ttk.Combobox(choices_frame,textvariable=variable,values=names,state='readonly',width=42).grid(row=row,column=1,sticky='ew',padx=12,pady=4)
        state['names']=names;choices_frame.columnconfigure(1,weight=1)
    listing.bind('<<TreeviewSelect>>',select)
    status=ttk.Label(frame,text=tr('Групп найдено: ')+str(len(groups)),wraplength=540);status.pack(fill='x',pady=8)
    def merge():
        if not state.get('group'):return
        group=state['group'];names=state['names']
        if not messagebox.askyesno(tr('Объединение дублей'),tr('Объединить выбранные версии? Остальные версии будут перемещены в корзину.'),parent=window):return
        choices={field:group[names.index(var.get())]['id'] for field,var in variables.items()}
        try:
            merge_duplicates(app.vault,[e['id'] for e in group],group[0]['id'],choices,state['expected'])
            app.refresh_all();window.destroy();app.notify(tr('Дубли объединены'))
        except Exception as exc:status.config(text=friendly_error(exc))
    midnight_button(frame,text=tr('Объединить выбранные версии'),style='Accent.TButton',command=merge).pack(fill='x',pady=5)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=8)
    window.bind('<Destroy>',lambda event:groups.clear() if event.widget is window else None,add='+')
    window.grab_set()

def updates(app,info):
    window,frame=top(app,'Обновление приложения')
    from moi_paroli import APP_VERSION
    ttk.Label(frame,text=tr('Доступная версия: ')+info['version'],font=('Segoe UI',18,'bold')).pack(anchor='w')
    ttk.Label(frame,text=tr('Установлена версия: ')+APP_VERSION).pack(anchor='w',pady=8)
    text=tk.Text(frame,width=64,height=12,wrap='word',relief='flat',bg=app.t['card'],fg=app.t['fg'])
    text.insert('1.0',info.get('notes') or tr('Изменения доступны на странице сборки.'));text.configure(state='disabled');text.pack(fill='both',expand=True,pady=8)
    status=ttk.Label(frame,text='',wraplength=520);status.pack(fill='x',pady=8)
    button=midnight_button(frame,text=tr('Скачать установщик'),style='Accent.TButton');button.pack(fill='x',pady=5)
    def download():
        import webbrowser
        url=info.get('download_url') or info['url']
        if '/releases/download/' not in url:
            webbrowser.open(url);return
        destination=filedialog.asksaveasfilename(parent=window,title=tr('Сохранить установщик'),initialfile='Bitora-password-Setup.exe',defaultextension='.exe')
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
    midnight_button(frame,text=tr('Открыть страницу выпуска'),command=lambda:__import__('webbrowser').open(info['url'])).pack(fill='x',pady=4)
    midnight_button(frame,text=tr('Закрыть'),command=window.destroy).pack(anchor='e',pady=10)
    window.grab_set()
