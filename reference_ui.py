"""Light mint workspace and local overview, using the existing encrypted vault."""
import tkinter as tk
from tkinter import ttk
from localization import tr

KINDS = {
    'website': 'Веб-сайты', 'application': 'Приложения', 'card': 'Банковские карты',
    'document': 'Документы', 'address': 'Адреса', 'note': 'Заметки',
    'file':'Файлы', 'passkey':'Ключи доступа',
}
FIELDS = {
    'card': [('Владелец карты', False), ('Номер карты', True), ('Срок действия', False), ('CVV', True)],
    'document': [('Тип документа', False), ('Номер документа', True), ('Дата выдачи', False)],
    'address': [('Получатель', False), ('Улица и дом', False), ('Город', False), ('Индекс', False), ('Страна', False)],
    'application': [('Приложение', False), ('Лицензионный ключ', True)],
}


def entry_kind(entry):
    # Legacy records are classified for display only; opening the UI never rewrites them.
    if entry.get('kind') in KINDS:
        return entry['kind']
    if entry.get('url'):
        return 'website'
    if entry.get('password') or entry.get('login'):
        return 'application'
    return 'note'


def overview(entries, strength):
    active = [e for e in entries if not e.get('deleted')]
    passwords = [e for e in active if e.get('password')]
    counts = {key: sum(entry_kind(e) == key for e in active) for key in KINDS}
    frequency = {}
    for e in passwords:
        frequency[e['password']] = frequency.get(e['password'], 0) + 1
    return dict(counts=counts, total=len(passwords),
                strong=sum(strength(e['password'])[2] >= 2 for e in passwords),
                weak=sum(strength(e['password'])[2] == 0 for e in passwords),
                reused=sum(frequency[e['password']] > 1 for e in passwords),
                recent=sorted(active, key=lambda e: e.get('updated', ''), reverse=True)[:3],
                favorites=[e for e in active if e.get('favorite')][:3])


class ScrollArea(ttk.Frame):
    """Scrollable native content; keyboard focus reveals offscreen controls."""
    def __init__(self, parent, palette, style='TFrame'):
        super().__init__(parent, style=style)
        self.canvas=tk.Canvas(self,bg=palette['bg'],highlightthickness=0,width=1)
        scroll=ttk.Scrollbar(self,orient='vertical',command=self.canvas.yview)
        scroll.pack(side='right',fill='y');self.canvas.pack(side='left',fill='both',expand=True)
        self.canvas.configure(yscrollcommand=scroll.set)
        self.content=ttk.Frame(self.canvas,style=style)
        self.window=self.canvas.create_window(0,0,window=self.content,anchor='nw')
        self.canvas.bind('<Configure>',lambda e:self.canvas.itemconfigure(self.window,width=e.width))
        self.content.bind('<Configure>',lambda e:self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        root=self.winfo_toplevel()
        def wheel(event):
            if str(event.widget).startswith(str(self)):
                self.canvas.yview_scroll(-int(event.delta/120),'units');return 'break'
        def focus(event):
            w=event.widget
            if str(w).startswith(str(self.content)):
                root.update_idletasks()
                y=w.winfo_rooty()-self.content.winfo_rooty()
                top=self.canvas.canvasy(0);height=self.canvas.winfo_height()
                if y<top or y+w.winfo_height()>top+height:
                    self.canvas.yview_moveto(max(0,y-height/3)/max(1,self.content.winfo_height()))
        bindings=[('<MouseWheel>',root.bind('<MouseWheel>',wheel,add='+')),('<FocusIn>',root.bind('<FocusIn>',focus,add='+'))]
        def cleanup(event):
            if event.widget is self:
                for name,binding in bindings:root.unbind(name,binding)
        self.bind('<Destroy>',cleanup)


class Home(ttk.Frame):
    def __init__(self, app, parent):
        super().__init__(parent, padding=(22, 16))
        self.app = app
        self.bind('<Configure>', self.reflow)
        self.columns = None
        self.top = ttk.Frame(self)
        self.top.pack(fill='x')
        self.recent = self.card(self.top)
        self.favorites = self.card(self.top)
        self.health = self.card(self)
        self.health.pack(fill='x', pady=(16, 0))
        self.tips = self.card(self)
        self.tips.pack(fill='x', pady=(16, 0))
        self.refresh()

    def card(self, parent):
        return ttk.Frame(parent, style='Panel.TFrame', padding=20, relief='solid', borderwidth=1)

    def label(self, parent, text, *, muted=False, size=10, color=None, surface='panel'):
        from moi_paroli import FF
        label = ttk.Label(parent, text=text, style='Muted.TLabel' if muted else 'Panel.TLabel',
                          font=(FF, size, 'bold' if size>=12 else 'normal'),
                          background=self.app.t[surface],foreground=color or self.app.t['muted' if muted else 'fg'])
        label.pack(anchor='w', pady=(0, 8))
        label.bind('<Configure>', lambda ev, w=label: w.configure(wraplength=max(60, parent.winfo_width()-44)))
        return label

    def button(self, parent, text, command, primary=False):
        from midnight_ui import button
        b = button(parent, text=text, command=command, style='Accent.TButton' if primary else 'TButton')
        b.pack(anchor='w', pady=(5, 0))
        return b

    def reflow(self, event=None):
        columns = 2 if self.winfo_width() >= 680 else 1
        if self.columns == columns:
            return
        self.columns = columns
        self.recent.grid_forget(); self.favorites.grid_forget()
        self.top.columnconfigure(0, weight=1, uniform='home')
        self.top.columnconfigure(1, weight=1 if columns == 2 else 0, uniform='home' if columns == 2 else '')
        self.recent.grid(row=0, column=0, sticky='nsew', padx=(0, 8 if columns == 2 else 0))
        self.favorites.grid(row=0 if columns == 2 else 1, column=1 if columns == 2 else 0,
                            sticky='nsew', padx=(8 if columns == 2 else 0, 0), pady=(0 if columns == 2 else 12, 0))
        if hasattr(self,'tip_cards'):
            self.tip_grid.columnconfigure(0,weight=1,uniform='tips')
            self.tip_grid.columnconfigure(1,weight=1 if columns==2 else 0,uniform='tips' if columns==2 else '')
            for index,card in enumerate(self.tip_cards):
                card.grid_forget()
                card.grid(row=0 if columns==2 else index,column=index if columns==2 else 0,
                          sticky='nsew',padx=(8 if index and columns==2 else 0,8 if not index and columns==2 else 0),
                          pady=(12 if index and columns==1 else 0,0))

    def refresh(self):
        from moi_paroli import strength, BrowserDialog, SettingsDialog, BreachDialog
        a = self.app
        data = overview(a.vault.entries, strength)
        for card, title, records, empty in (
            (self.recent, 'Недавнее', data['recent'], 'Добавьте первую запись — она появится здесь.'),
            (self.favorites, 'Избранное', data['favorites'], 'Отмечайте записи звёздочкой для быстрого доступа.')):
            for child in card.winfo_children(): child.destroy()
            self.label(card, tr(title), size=15)
            if not records:
                self.label(card, tr(empty), muted=True)
            for entry in records:
                row = ttk.Frame(card, style='Panel.TFrame'); row.pack(fill='x', pady=3)
                button = self.button(row, entry['title'], lambda eid=entry['id']: a.goto_entry(eid))
                button.align='left'
                button.configure(icon={'website':'browser','application':'application','card':'card','document':'document','address':'address','note':'note','file':'document','passkey':'key'}[entry_kind(entry)])
                button.pack_configure(fill='x')
                # Titles only: the overview never reveals logins, passwords or card numbers.
        for child in self.health.winfo_children(): child.destroy()
        self.label(self.health, tr('Состояние паролей'), size=15)
        metrics = ttk.Frame(self.health, style='Panel.TFrame'); metrics.pack(fill='x')
        for col, (key, title, color) in enumerate((('total', 'Всего паролей', 'fg'),
                ('strong', 'Сильные', 'good'), ('weak', 'Слабые', 'bad'), ('reused', 'Повторяются', 'warn'))):
            cell = ttk.Frame(metrics, style='Panel.TFrame', padding=(0, 4, 12, 4))
            cell.grid(row=0, column=col, sticky='nw'); metrics.columnconfigure(col, weight=1)
            self.label(cell, str(data[key]), size=23, color=a.t[color])
            self.label(cell, tr(title), muted=True)
        self.label(self.health, tr('Утечки: проверка ещё не выполнена. Группы могут пересекаться.'), muted=True)
        actions = ttk.Frame(self.health, style='Panel.TFrame'); actions.pack(fill='x')
        self.button(actions, tr('Подробнее'), a.audit).pack_configure(side='left', padx=(0, 12))
        self.button(actions, tr('Проверить утечки…'), lambda: BreachDialog(a, a.root)).pack_configure(side='left')
        for child in self.tips.winfo_children(): child.destroy()
        self.label(self.tips, tr('Полезные возможности'), size=15)
        self.tip_grid=ttk.Frame(self.tips,style='Panel.TFrame');self.tip_grid.pack(fill='x')
        self.tip_cards=[ttk.Frame(self.tip_grid,style='Card.TFrame',padding=16) for _ in range(2)]
        browser,settings=self.tip_cards
        self.label(browser, tr('Сохраняйте и заполняйте пароли в браузере'), size=12,surface='card')
        self.label(browser, tr('Установите расширение и проверьте подключение к Bitora.'), muted=True,surface='card')
        self.button(browser, tr('Расширение и браузеры'), lambda: BrowserDialog(a, a.root), primary=True)
        self.label(settings, tr('Быстрый вход и автоматическая блокировка'), size=12,surface='card')
        self.button(settings, tr('Перейти в настройки'), lambda: SettingsDialog(a, a.root))
        self.columns=None
        self.reflow()


def install(app, parent, controls, body, scale):
    """Install the overview beside the existing fully functional record workspace."""
    app.workspace_controls = controls
    app.home_scroll = ScrollArea(parent,app.t)
    app.home_view = Home(app, app.home_scroll.content)
    app.home_view.pack(fill='both',expand=True)
    app.home_active = True
    app.workspace_body = body
    navigate(app, 'home')


def navigate(app, value):
    app.home_active = value == 'home'
    if app.home_active:
        app.workspace_body.pack_forget()
        app.workspace_controls.pack_forget()
        app.home_scroll.pack(fill='both', expand=True)
        app.home_view.refresh()
        app.atelier_title.configure(text=tr('Главная'))
        app.search.set('')
    else:
        app.home_scroll.pack_forget()
        app.workspace_controls.pack(fill='x')
        app.workspace_body.pack(fill='both', expand=True, padx=22, pady=(12, 16))
        app.set_library_filter(value)
    for key, button in app.rail_buttons.items():
        selected = key == ('home' if app.home_active else app.cat_filter)
        button.configure(style='RailActive.TButton' if selected else 'Rail.TButton')

