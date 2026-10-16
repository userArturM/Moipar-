"""Native desktop workspace: collections, security overview and sectioned settings."""
import hashlib
import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse
from localization import tr
from midnight_ui import button, IconButton, DesignButton, blend
from reference_ui import ScrollArea, entry_kind
from design_surfaces import Surface, AuditTile


def password_groups(app):
    from moi_paroli import strength
    rows=[e for e in app.vault.active() if e.get('password')]
    frequency={}
    for row in rows:frequency[row['password']]=frequency.get(row['password'],0)+1
    groups={key:[] for key in ('breached','weak','strong','unchecked','reused')}
    cache=getattr(app,'_breach_results',{})
    for row in rows:
        pw=row['password'];known=cache.get(row['id'])
        checked=known is not None and known[0]==hashlib.sha256(pw.encode()).hexdigest()
        weak=strength(pw)[2]==0;reused=frequency[pw]>1
        if weak:groups['weak'].append(row)
        if reused:groups['reused'].append(row)
        if not checked:groups['unchecked'].append(row)
        elif known[1]>0:groups['breached'].append(row)
        elif not weak and not reused and strength(pw)[2]>=2:groups['strong'].append(row)
    return rows,groups


def remember_breaches(app, results):
    if not app.vault.unlocked:return
    cache=getattr(app,'_breach_results',{})
    for row in app.vault.active():
        pw=row.get('password','')
        if pw and pw in results:
            cache[row['id']]=(hashlib.sha256(pw.encode()).hexdigest(),results[pw])
    app._breach_results=cache


def text(parent,value,app,size=10,muted=False):
    from moi_paroli import FF
    w=ttk.Label(parent,text=value,style='Muted.TLabel' if muted else 'Panel.TLabel',
                font=(FF,size,'bold' if size>=12 else 'normal'),
                background=ttk.Style(parent).lookup(parent.cget('style') or 'TFrame','background'))
    w.pack(anchor='w',pady=(0,8))
    w.bind('<Configure>',lambda e:w.configure(wraplength=max(80,parent.winfo_width()-40)))
    return w


class Cards(ScrollArea):
    def __init__(self,app,parent):
        super().__init__(parent,app.t)
        self.app=app;self.ids=[];self.limit=48;self.columns=0;self.tiles=[]
        self.content.configure(padding=(10,8))
        self.content.bind('<Configure>',self.reflow,add='+')

    def reflow(self,event=None):
        scale=max(1,float(self.tk.call('tk','scaling'))/(96/72))
        columns=max(1,min(6,int((self.canvas.winfo_width()-20)/(210*scale))))
        if columns==self.columns:return
        self.columns=columns
        for col in range(6):self.content.columnconfigure(col,weight=1 if col<columns else 0,uniform='tiles' if col<columns else '')
        for index,tile in enumerate(self.tiles):tile.grid(row=index//columns,column=index%columns,sticky='nsew',padx=7,pady=7)
        if hasattr(self,'more') and self.more.winfo_exists():self.more.grid(row=(len(self.tiles)+columns-1)//columns,column=0,columnspan=columns,pady=12)

    def refresh(self,reset=True):
        if getattr(self,'_rendering',False):return
        self._rendering=True
        try:self.render(reset)
        finally:self._rendering=False

    def render(self,reset=True):
        a=self.app
        self.ids=list(a.tree.get_children())
        if reset:self.limit=48
        for child in self.content.winfo_children():child.destroy()
        self.tiles=[];self.columns=0
        weak_ids={e['id'] for e in password_groups(a)[1]['weak']}
        for eid in self.ids[:self.limit]:
            row=a.vault.get(eid)
            if not row:continue
            surface=Surface(self.content,a.t,height=244+max(0,int(a.settings.get('font_size') or 10)-10)*22)
            tile=surface.body
            self.tiles.append(surface)
            header=ttk.Frame(tile,style='Panel.TFrame');header.pack(fill='x')
            from midnight_ui import monogram_colors, rounded
            bg,fg=monogram_colors(row['title'],a.t)
            mark=tk.Canvas(header,width=26,height=28,bg=a.t['panel'],highlightthickness=0)
            mark.pack(side='left',padx=(0,7))
            rounded(mark,1,2,23,23,6,bg)
            mark.create_text(12,13,text=(row['title'] or 'B')[0].upper(),fill=fg,font=('Segoe UI',10,'bold'))
            more=IconButton(header,tr('Меню'),lambda eid=eid:self.context(eid),dict(a.t,bg=a.t['panel']),'more',.7)
            more.pack(side='right')
            star=IconButton(header,tr('Избранное'),lambda eid=eid:self.favorite(eid),dict(a.t,bg=a.t['panel']),'star',.85)
            star.selected=bool(row['favorite'])
            star.pack(side='right')
            label=ttk.Label(header,text=row['title'][:24]+('…' if len(row['title'])>24 else ''),style='Panel.TLabel',wraplength=120,font=('Segoe UI',9,'bold'),cursor='hand2')
            label.pack(side='left',fill='x',expand=True)
            label.bind('<Button-1>',lambda e,eid=eid:self.open(eid))
            mark.bind('<Button-1>',lambda e,eid=eid:self.open(eid))
            url=row.get('url','') or tr('Запись в хранилище')
            ttk.Label(tile,text=url[:37]+('…' if len(url)>37 else ''),style='Muted.TLabel',foreground=a.t['accent']).pack(anchor='w',pady=(2,10))
            ttk.Separator(tile).pack(fill='x',pady=(0,12))
            if row.get('login'):self.field(tile,tr('Логин'),row['login'])
            if a.cat_filter=='auth' and row.get('totp'):self.totp(tile,eid)
            elif row.get('password'):self.password(tile,eid)
            elif row.get('totp'):self.totp(tile,eid)
            else:
                text(tile,tr('Поля и вложения зашифрованы'),a,muted=True)
            weak=bool(row.get('password')) and row['id'] in weak_ids
            if weak:ttk.Label(tile,text=tr('Слабый пароль'),style='Panel.TLabel',foreground=a.t['bad']).pack(anchor='w',pady=6)
            actions=ttk.Frame(tile,style='Panel.TFrame');actions.pack(side='bottom',fill='x',pady=(10,0))
            if row.get('url'):button(actions,text=tr('Перейти на сайт'),command=lambda eid=eid:self.site(eid)).pack(anchor='center')
            else:button(actions,text=tr('Открыть'),command=lambda eid=eid:self.open(eid)).pack(anchor='center')
        if not self.tiles:
            text(self.content,tr('В этом разделе пока нет записей'),a,muted=True)
            if a.cat_filter=='type:passkey':
                text(self.content,tr('Ключи доступа создаются на сайте через расширение Bitora. Включите «Ключи доступа Bitora» в расширении.'),a,muted=True)
                button(self.content,text=tr('Расширение и браузеры'),command=lambda:a.navigate_workspace('settings')).pack(anchor='w',padx=8,pady=12)
        if len(self.ids)>self.limit:
            self.more=button(self.content,text=tr('Показать ещё'),command=self.load_more)
        self.reflow()

    def load_more(self):self.limit+=48;self.refresh(False)

    def context(self,eid):
        a=self.app
        menu=a._menu()
        menu.add_command(label=tr('Открыть'),command=lambda:self.open(eid))
        def edit():
            a.tree.selection_set(eid);a.edit()
        menu.add_command(label=tr('Изменить'),command=edit)
        menu.add_command(label=tr('Копировать логин'),command=lambda:self.copy(eid,'login'))
        menu.add_command(label=tr('Копировать пароль'),command=lambda:self.copy(eid,'password'))
        menu.add_separator()
        menu.add_command(label=tr('Избранное'),command=lambda:self.favorite(eid))
        try:menu.tk_popup(self.winfo_pointerx(),self.winfo_pointery())
        finally:menu.grab_release()

    def field(self,parent,title,value):
        a=self.app
        box=ttk.Frame(parent,style='Card.TFrame',padding=(10,8));box.pack(fill='x',pady=4)
        line=ttk.Frame(box,style='Card.TFrame');line.pack(fill='x')
        shown=ttk.Label(line,text=value[:28]+('…' if len(value)>28 else ''),style='CardMono.TLabel');shown.pack(side='left',fill='x',expand=True)
        IconButton(line,tr('Копировать'),lambda:a.copy_text(value,title),dict(a.t,bg=a.t['card']),'copy',.85).pack(side='right')
        return shown,line

    def password(self,parent,eid):
        a=self.app
        box=ttk.Frame(parent,style='Card.TFrame',padding=(10,8));box.pack(fill='x',pady=4)
        line=ttk.Frame(box,style='Card.TFrame');line.pack(fill='x')
        value=ttk.Label(line,text='••••••••••',style='CardMono.TLabel',wraplength=160);value.pack(side='left',fill='x',expand=True)
        state={'visible':False,'job':None}
        def hide():
            state['job']=None;state['visible']=False
            if value.winfo_exists():value.configure(text='••••••••••')
        def reveal():
            if state['job']:a.root.after_cancel(state['job']);state['job']=None
            if state['visible']:hide();return
            row=a.vault.get(eid)
            if not a.vault.unlocked or not row:return
            value.configure(text=row['password']);state['visible']=True
            state['job']=a.root.after(15000,hide)
        def dispose(event):
            if event.widget is value and state['job']:a.root.after_cancel(state['job']);state['job']=None
        value.bind('<Destroy>',dispose)
        IconButton(line,tr('Копировать пароль'),lambda:self.copy(eid,'password'),dict(a.t,bg=a.t['card']),'copy',.85).pack(side='right')
        IconButton(line,tr('Показать'),reveal,dict(a.t,bg=a.t['card']),'eye',.85).pack(side='right')

    def totp(self,parent,eid):
        a=self.app
        box=ttk.Frame(parent,style='Card.TFrame',padding=10);box.pack(fill='x',pady=4)
        value=ttk.Label(box,text='••• •••',style='CardMono.TLabel');value.pack(anchor='w')
        state={'job':None}
        def generate():
            from moi_paroli import totp_now
            row=a.vault.get(eid)
            if row and a.vault.unlocked:
                value.configure(text=totp_now(row['totp']))
                state['job']=a.root.after(1000,generate)
        def start():
            if state['job']:a.root.after_cancel(state['job'])
            generate()
        def dispose(event):
            if event.widget is value and state['job']:a.root.after_cancel(state['job']);state['job']=None
        value.bind('<Destroy>',dispose)
        def copy():
            from moi_paroli import totp_now
            row=a.vault.get(eid)
            if row and a.vault.unlocked:a.copy_text(totp_now(row['totp']),tr('Код 2FA'))
        button(parent,text=tr('Показать код'),command=start).pack(anchor='w')
        button(parent,text=tr('Копировать код'),command=copy).pack(anchor='w')

    def copy(self,eid,key):
        row=self.app.vault.get(eid)
        if row and self.app.vault.unlocked:self.app.copy_text(row.get(key,''),tr('Пароль') if key=='password' else tr('Логин'))

    def open(self,eid):
        self.app.settings.set('record_layout','list')
        self.app.studio.navigate(self.app.cat_filter)
        self.app.goto_entry(eid);self.app.show_details()
        if self.app.compact:self.app.body.select(self.app.detail_panel)

    def site(self,eid):
        self.app.tree.selection_set(eid);self.app.open_url()

    def favorite(self,eid):
        row=self.app.vault.get(eid)
        if row:
            ok,_=self.app._do(self.app.vault.set_favorite,eid,not row['favorite'])
            if ok:self.app.refresh_all()


class Audit(ScrollArea):
    def __init__(self,app,parent):
        super().__init__(parent,app.t);self.app=app
        self.content.configure(padding=(18,16))
        self.column=ttk.Frame(self.content);self.column.pack(anchor='nw',fill='x')
        self.canvas.bind('<Configure>',self.fit_column,add='+')

    def fit_column(self,event=None):
        scale=max(1,float(self.tk.call('tk','scaling'))/(96/72))
        self.canvas.itemconfigure(self.window,width=min(int(780*scale),max(80,self.canvas.winfo_width())))

    def refresh(self):
        a=self.app
        for child in self.column.winfo_children():child.destroy()
        info=ttk.Frame(self.column,style='Panel.TFrame',padding=22);info.pack(fill='x',pady=(0,18))
        from midnight_ui import line_icon, rounded
        if not a.compact:
            illustration=tk.Canvas(info,width=112,height=112,bg=a.t['panel'],highlightthickness=0)
            illustration.pack(side='right',padx=(20,0))
            illustration.create_oval(12,12,100,100,fill=blend(a.t['panel'],a.t['accent'],.12),outline='')
            rounded(illustration,29,20,60,76,12,blend(a.t['panel'],a.t['accent'],.3))
            line_icon(illustration,'shield',42,35,37,a.t['accent'],2)
            for x in (31,48,65,82):line_icon(illustration,'key',x,86,12,a.t['accent'],1)
        info_text=ttk.Frame(info,style='Panel.TFrame');info_text.pack(side='left',fill='both',expand=True)
        info=info_text
        text(info,tr('Что нужно знать о безопасности паролей'),a,14)
        text(info,tr('Используйте сложные и уникальные пароли. Проверяйте утечки и меняйте обнаруженные пароли.'),a,muted=True)
        button(info,text=tr('Проверить утечки…'),command=self.check).pack(anchor='w')
        rows,groups=password_groups(a)
        text(self.column,tr('Всего паролей')+': '+str(len(rows)),a,15)
        for key,title,caption,color in (
            ('breached','Скомпрометированы','Эти пароли найдены в базе утечек. Смените их.',a.t['bad']),
            ('weak','Слабые','Эти пароли слишком простые. Создайте более сложные.',a.t['warn']),
            ('strong','Сильные','Сложные, уникальные пароли с выполненной проверкой утечек.',a.t['good']),
            ('unchecked','Не проверены','Для этих паролей ещё нет актуального результата проверки утечек.',a.t['muted']),
            ('reused','Повторяющиеся','Одинаковые пароли используются в нескольких записях.',a.t['warn'])):
            panel=AuditTile(self.column,a.t,len(groups[key]),tr(title),tr(caption),color,lambda group=key:self.show_group(group))
            panel.pack(fill='x',pady=6)
        text(self.column,tr('Группы могут пересекаться. Результаты проверки утечек действуют только в текущем сеансе.'),a,muted=True)
        self.fit_column()

    def check(self):self.app.check_breaches();self.refresh()

    def show_group(self,key):
        self.app.studio.audit_filter=key
        self.app.studio.navigate('all')
        self.app.refresh_list()


class Preferences(ttk.Frame):
    PAGES=('Общие','Браузеры','Игнорируемые сайты','Импорт и экспорт','Дополнительно','Подключение')
    def __init__(self,app,parent):
        super().__init__(parent);self.app=app;self.vars={};self.page='Общие'
        nav=ttk.Frame(self,style='Panel.TFrame',padding=12)
        nav.pack(side='top' if app.compact else 'left',fill='x' if app.compact else 'y')
        self.area=ScrollArea(self,app.t);self.area.pack(side='left',fill='both',expand=True)
        from ambient_ui import attach
        attach(self.area.canvas,app)
        scale=max(1,float(self.tk.call('tk','scaling'))/(96/72))
        self.area.canvas.bind('<Configure>',lambda e:self.area.canvas.itemconfigure(self.area.window,width=min(e.width,int(740*scale))))
        self.page_buttons={}
        if app.compact:
            choice=tk.StringVar(value=tr(self.page))
            picker=ttk.Combobox(nav,textvariable=choice,values=[tr(p) for p in self.PAGES],state='readonly')
            picker.pack(fill='x');picker.bind('<<ComboboxSelected>>',lambda e:self.show(next(p for p in self.PAGES if tr(p)==choice.get())))
        else:
            for page in self.PAGES:
                item=DesignButton(nav,tr(page),lambda page=page:self.show(page),dict(app.t,side=app.t['panel']),kind='rail',width=int(210*scale),height=42,scale=scale,align='left')
                item.pack(fill='x',pady=3);self.page_buttons[page]=item
        from command_window import open_commands
        button(nav,text=tr('Меню приложения'),command=lambda:open_commands(app)).pack(fill='x',pady=(18,4))
        self.show(self.page)

    def section(self,title):
        a=self.app
        card=ttk.Frame(self.area.content,padding=(24,18));card.pack(fill='x')
        text(card,tr(title),a,13)
        ttk.Separator(self.area.content).pack(fill='x',padx=24)
        return card

    def check(self,parent,key,title):
        var=tk.BooleanVar(value=bool(self.app.settings.get(key)))
        self.vars[key]=var
        ttk.Checkbutton(parent,text=tr(title),variable=var).pack(anchor='w',pady=5)

    def number(self,parent,key,title,low,high):
        text(parent,tr(title),self.app)
        var=tk.IntVar(value=self.app.settings.get(key));self.vars[key]=var
        ttk.Spinbox(parent,from_=low,to=high,textvariable=var,width=10).pack(anchor='w',pady=(0,10))

    def show(self,page):
        self.page=page;self.vars={};a=self.app
        for name,item in self.page_buttons.items():item.configure(style='RailActive.TButton' if name==page else 'Rail.TButton')
        for child in self.area.content.winfo_children():child.destroy()
        self.area.canvas.yview_moveto(0)
        if page=='Общие':
            startup=self.section('Автозапуск')
            self.check(startup,'autostart','Запускать Bitora при входе в Windows')
            text(startup,tr('При запуске хранилище остаётся заблокированным до подтверждения входа.'),a,muted=True)
            security=self.section('Блокировка и защита')
            button(security,text=tr('Изменить мастер-пароль'),command=a.change_master).pack(anchor='w',pady=5)
            button(security,text=tr('Windows Hello: включить / отключить'),command=a.configure_hello).pack(anchor='w',pady=5)
            self.number(security,'idle_minutes','Блокировать после бездействия в приложении (минуты)',0,1440)
            text(security,tr('0 — выключено; максимум 24 часа.'),a,muted=True)
            for key,label in (('lock_on_session_lock','Блокировать при блокировке Windows и смене пользователя'),
                              ('lock_on_suspend','Блокировать при сне и пробуждении компьютера'),('lock_on_minimize','Блокировать при сворачивании окна')):self.check(security,key,label)
            clipboard=self.section('Буфер обмена')
            self.number(clipboard,'clipboard_seconds','Очищать буфер обмена через (сек)',5,300)
            self.check(clipboard,'close_to_tray','Кнопка ✕ сворачивает в трей, а не закрывает')
            self.save_button()
        elif page=='Браузеры':
            from moi_paroli import BrowserDialog
            card=self.section('Расширение и браузеры')
            from desktop_options import BROWSERS
            choices={tr(label):key for key,label in BROWSERS.items()}
            selected=next((label for label,key in choices.items() if key==(a.settings.get('default_browser') or 'system')),tr('Системный браузер'))
            self.browser=tk.StringVar(value=selected);self.browser_choices=choices
            text(card,tr('Браузер для открытия сайтов'),a)
            ttk.Combobox(card,textvariable=self.browser,values=list(choices),state='readonly',width=26).pack(anchor='w',pady=8)
            text(card,tr('Chrome, Яндекс, Edge и Chromium: сохранение и заполнение через расширение Bitora.'),a,muted=True)
            button(card,text=tr('Проверить подключение'),command=lambda:BrowserDialog(a,a.root)).pack(anchor='w')
            self.save_button()
        elif page=='Игнорируемые сайты':
            card=self.section(page)
            text(card,tr('На этих доменах Bitora не сохраняет и не выдаёт пароли браузеру.'),a,muted=True)
            self.ignored=tk.Text(card,height=9,wrap='none',bg=a.t['card'],fg=a.t['fg'],insertbackground=a.t['fg'],relief='flat',padx=12,pady=12)
            self.ignored.pack(fill='x');self.ignored.insert('1.0','\n'.join(a.settings.get('ignored_sites') or []))
            self.save_button()
        elif page=='Импорт и экспорт':
            for title,description,action in (
                ('Импорт из CSV','Импортируйте файл, экспортированный браузером или другим менеджером паролей.',a.import_csv),
                ('Резервные копии','Создайте зашифрованную копию хранилища.',a.export_encrypted),
                ('Восстановить из копии','Восстановите хранилище из зашифрованной резервной копии.',a.restore_backup),
                ('Экспорт в CSV','Файл экспорта содержит открытые данные. Храните его только до завершения переноса.',a.export_csv)):
                card=self.section(title);text(card,tr(description),a,muted=True)
                button(card,text=tr('Открыть'),command=action).pack(anchor='w')
        elif page=='Дополнительно':
            card=self.section('Тема оформления')
            theme=tk.StringVar(value=a.settings.get('theme'));self.vars['theme']=theme
            for key,label in (('system','Как в Windows'),('dark','Тёмная'),('light','Светлая')):ttk.Radiobutton(card,text=tr(label),value=key,variable=theme).pack(anchor='w',pady=5)
            self.check(card,'animations','Анимации интерфейса')
            self.number(card,'font_size','Размер текста',9,14)
            language=tk.StringVar(value=a.settings.get('language'));self.vars['language']=language
            ttk.Combobox(card,textvariable=language,values=('ru','en'),state='readonly',width=12).pack(anchor='w',pady=6)
            self.check(card,'hotkey_enabled','Быстрый поиск по глобальной горячей клавише')
            hotkey=tk.StringVar(value=a.settings.get('hotkey'));self.vars['hotkey']=hotkey
            ttk.Combobox(card,textvariable=hotkey,values=('Ctrl+Alt+P','Ctrl+Alt+Space','Ctrl+Shift+Space'),width=22).pack(anchor='w',pady=5)
            self.save_button()
        else:
            card=self.section('Облачная синхронизация')
            text(card,str(a.vault.path),a,muted=True)
            text(card,tr('Зашифрованное хранилище можно разместить в папке OneDrive, Яндекс.Диска или другого облачного клиента.'),a,muted=True)
            button(card,text=tr('Выбрать облачную папку…'),command=a.move_vault).pack(anchor='w',pady=5)
            button(card,text=tr('Синхронизировать сейчас'),command=a._sync_now).pack(anchor='w',pady=5)
            button(card,text=tr('Разрешить конфликты'),command=a.resolve_conflicts).pack(anchor='w',pady=5)
            text(card,tr('Синхронизируется зашифрованный файл. Облачный клиент должен быть установлен на каждом устройстве.'),a,muted=True)
            updates=self.section('Обновления')
            self.check(updates,'check_updates','Проверять обновления при запуске')
            button(updates,text=tr('Проверить обновления'),command=lambda:a.check_updates(manual=True)).pack(anchor='w')
            self.save_button()

    def save_button(self):
        row=ttk.Frame(self.area.content,padding=20);row.pack(fill='x')
        button(row,text=tr('Сохранить'),command=self.save,style='Accent.TButton').pack(anchor='w')

    def save(self):
        from moi_paroli import parse_hotkey,messagebox
        try:
            values={key:var.get() for key,var in self.vars.items()}
            for key,low,high in (('idle_minutes',0,1440),('clipboard_seconds',5,300),('font_size',9,14)):
                if key in values and not low<=int(values[key])<=high:raise ValueError(tr('Проверьте диапазон значений'))
            if 'hotkey' in values:parse_hotkey(values['hotkey'])
            if self.page=='Игнорируемые сайты':
                from site_policy import normalize_sites
                values['ignored_sites']=normalize_sites(self.ignored.get('1.0','end').splitlines())
            if self.page=='Браузеры':values['default_browser']=self.browser_choices[self.browser.get()]
            if 'autostart' in values:
                from desktop_options import startup
                startup(values['autostart'])
        except (ValueError,OSError,tk.TclError) as exc:
            messagebox.showwarning(tr('Настройки'),str(exc),parent=self);return
        for key,value in values.items():self.app.settings.set(key,value)
        self.app.apply_settings()
        if 'language' in values:self.app.set_language(values['language'])
        else:self.app.apply_theme();self.app.show_main()


class Workspace:
    def __init__(self,app,parent):
        self.app=app;self.parent=parent;self.active='home';self.audit_filter=None
        self.cards=Cards(app,parent);self.audit=Audit(app,parent);self.preferences=None
        self.toolbar=ttk.Frame(app.atelier_search.master,style='Panel.TFrame')
        self.toolbar.pack(side='right',padx=8)
        self.layout_buttons={}
        for mode,label in (('list','Список'),('cards','Карточки')):
            item=IconButton(self.toolbar,tr(label),lambda mode=mode:self.set_layout(mode),dict(app.t,bg=app.t['panel']),'list' if mode=='list' else 'grid')
            item.pack(side='left',padx=2);self.layout_buttons[mode]=item
        self.collection=ttk.Frame(app.atelier_search.master,style='Panel.TFrame')
        self.collection.pack(side='left',fill='x',expand=True,padx=6)
        segment=ttk.Frame(self.collection,style='Panel.TFrame');segment.pack(anchor='center')
        self.collection_buttons={}
        for value,label,icon in (('all','Все записи','grid'),('fav','Избранное','star')):
            item=DesignButton(segment,tr(label),lambda value=value:app.navigate_workspace(value),dict(app.t,bg=app.t['panel']),kind='chip',icon=icon,height=30,font_size=9)
            item.pack(side='left',padx=2);self.collection_buttons[value]=item
        self.refresh_job=None
        self.transition_job=None;self.transition_surface=None
        def dispose(event):
            if event.widget is parent:
                if self.refresh_job:app.root.after_cancel(self.refresh_job);self.refresh_job=None
                self.stop_transition()
        parent.bind('<Destroy>',dispose,add='+')

    def stop_transition(self):
        if self.transition_job:self.app.root.after_cancel(self.transition_job);self.transition_job=None
        surface=self.transition_surface
        if surface is not None and surface.winfo_exists() and surface.winfo_manager()=='pack':
            surface.pack_configure(pady=(1,0) if surface is self.app.workspace_body else 0)
        self.transition_surface=None

    def transition(self,surface):
        self.stop_transition()
        if not self.app.settings.get('animations'):return
        self.transition_surface=surface
        final=1 if surface is self.app.workspace_body else 0
        def frame(index):
            self.transition_job=None
            if not surface.winfo_exists() or surface.winfo_manager()!='pack':return
            surface.pack_configure(pady=(final+round(8*(1-index/8)**3),0))
            if index<8:self.transition_job=self.app.root.after(20,lambda:frame(index+1))
            else:self.transition_surface=None
        frame(0)

    def set_layout(self,mode):
        self.app.settings.set('record_layout',mode);self.navigate(self.app.cat_filter)

    def navigate(self,value):
        a=self.app
        previous=self.active
        self.stop_transition()
        if self.refresh_job:a.root.after_cancel(self.refresh_job);self.refresh_job=None
        for mode,item in self.layout_buttons.items():item.configure(style='RailActive.TButton' if a.settings.get('record_layout')==mode else 'Rail.TButton')
        for key,item in self.collection_buttons.items():item.configure(style='RailActive.TButton' if key==('fav' if value=='fav' else 'all') else 'Rail.TButton')
        for surface in (a.home_scroll,a.workspace_body,a.workspace_controls,self.cards,self.audit,self.preferences):
            if surface is not None and surface.winfo_exists():surface.pack_forget()
        self.active=value
        a.home_active=value=='home'
        if value=='home':
            a.home_scroll.pack(fill='both',expand=True);a.home_view.refresh();a.search.set('');a.atelier_title.configure(text=tr('Главная'))
        elif value=='audit':
            self.audit.pack(fill='both',expand=True);self.audit.refresh();a.atelier_title.configure(text=tr('Проверка паролей'))
        elif value=='settings':
            if self.preferences is None or not self.preferences.winfo_exists():self.preferences=Preferences(a,self.parent)
            self.preferences.pack(fill='both',expand=True);a.atelier_title.configure(text=tr('Настройки'))
        else:
            a.set_library_filter(value)
            a.workspace_controls.pack(fill='x')
            if a.settings.get('record_layout')=='cards':
                a.workspace_body.pack_forget();self.cards.pack(fill='both',expand=True);self.cards.refresh()
            else:a.workspace_body.pack(fill='both',expand=True,padx=0,pady=(1,0))
        if value in ('home','audit','settings'):
            self.toolbar.pack_forget();self.collection.pack_forget()
        else:
            if not self.toolbar.winfo_manager():self.toolbar.pack(side='right',padx=8)
            if not self.collection.winfo_manager():self.collection.pack(side='left',fill='x',expand=True,padx=6)
        for key,item in a.rail_buttons.items():item.configure(style='RailActive.TButton' if key==value else 'Rail.TButton')
        if previous!=value:
            surface=a.home_scroll if value=='home' else self.audit if value=='audit' else self.preferences if value=='settings' else self.cards if a.settings.get('record_layout')=='cards' else a.workspace_body
            self.transition(surface)

    def refresh(self):
        if self.active in ('home','settings'):return
        if self.refresh_job:self.app.root.after_cancel(self.refresh_job)
        def finish():
            self.refresh_job=None
            if self.cards.winfo_ismapped():self.cards.refresh()
            elif self.audit.winfo_ismapped():self.audit.refresh()
        self.refresh_job=self.app.root.after_idle(finish)

    def clear_filter(self):self.audit_filter=None

