"""Application commands in a separate, scrollable window opened from Settings."""
import tkinter as tk
from tkinter import ttk
from localization import tr
from midnight_ui import DesignButton
from reference_ui import ScrollArea


def open_commands(app):
    current=getattr(app,'_command_window',None)
    if current is not None:
        try:
            if current.winfo_exists():current.lift();current.focus_set();return current
        except tk.TclError:pass
    from moi_paroli import _new_top
    top=_new_top(app,app.root,tr('Меню приложения'))
    app._command_window=top
    scale=max(1,float(top.tk.call('tk','scaling'))/(96/72))
    width=min(int(620*scale),top.winfo_screenwidth()-80)
    height=min(int(620*scale),top.winfo_screenheight()-100)
    top.geometry(f'{width}x{height}');top.resizable(True,True)
    ttk.Label(top,text=tr('Меню приложения'),style='Hero.TLabel').pack(anchor='w',padx=22,pady=(18,12))
    tabs=ttk.Notebook(top);tabs.pack(fill='both',expand=True,padx=16,pady=(0,16))
    menus=[]
    def invoke(menu,index):
        top.withdraw()
        try:menu.invoke(index)
        finally:
            try:
                if top.winfo_exists():top.destroy()
            except tk.TclError:pass
    def populate(parent,menu):
        menus.append(menu)
        end=menu.index('end')
        for index in range((end if end is not None else -1)+1):
            kind=menu.type(index)
            if kind=='separator':ttk.Separator(parent).pack(fill='x',pady=10);continue
            label=menu.entrycget(index,'label')
            if kind=='cascade':
                ttk.Label(parent,text=label,style='BgMuted.TLabel').pack(anchor='w',pady=(14,6))
                populate(parent,app.root.nametowidget(menu.entrycget(index,'menu')))
            elif kind=='command':
                command=DesignButton(parent,label,lambda m=menu,i=index:invoke(m,i),app.t,
                    kind='secondary',align='left',height=38,scale=scale,
                    badge=menu.entrycget(index,'accelerator'))
                command.pack(fill='x',pady=3)
                command.configure(state=menu.entrycget(index,'state'))
    for label,factory in (('Файл',app._file_menu),('Инструменты',app._tools_menu),('Справка',app._help_menu)):
        area=ScrollArea(tabs,app.t);area.content.configure(padding=(12,8))
        tabs.add(area,text=tr(label));populate(area.content,factory())
    def cleanup(event):
        if event.widget is top:
            app._command_window=None
            for menu in menus:
                try:menu.destroy()
                except tk.TclError:pass
    top.bind('<Destroy>',cleanup,add='+')
    top.bind('<Escape>',lambda e:top.destroy())
    top.focus_set()
    return top
