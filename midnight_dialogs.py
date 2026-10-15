"""Modal Midnight messages and text prompts; native file pickers stay native."""
import tkinter as tk
from tkinter import ttk,messagebox as native_messagebox,simpledialog as native_simpledialog
from localization import tr
from midnight_ui import button


def _window(parent,title):
    root=parent._root()
    from moi_paroli import _new_top
    app=getattr(root,'_bitora_app',None)
    if app is None:return None
    top=_new_top(app,parent,title)
    top.resizable(True,True)
    return top


def _modal(title,message,parent,choices,initial=None,show=None):
    top=_window(parent,title)
    if top is None:return None,False
    previous=parent.grab_current()
    frame=ttk.Frame(top,padding=24);frame.pack(fill='both',expand=True)
    ttk.Label(frame,text=tr('BITORA'),style='Eyebrow.TLabel').pack(anchor='w')
    ttk.Label(frame,text=title,font=('Segoe UI',18,'bold'),wraplength=520).pack(anchor='w',pady=(8,16))
    # Long errors remain scrollable and selectable without enlarging the window.
    text=tk.Text(frame,height=min(10,max(2,len(message)//65+message.count('\n')+1)),wrap='word',
                 relief='flat',borderwidth=0,font=('Segoe UI',11),takefocus=True)
    palette=parent._root()._midnight_palette
    text.configure(bg=palette['card'],fg=palette['fg'],insertbackground=palette['fg'],padx=14,pady=12)
    text.insert('1.0',message);text.configure(state='disabled');text.pack(fill='both',expand=True)
    value=tk.StringVar(value=initial or '')
    field=None
    if show is not None:
        field=ttk.Entry(frame,textvariable=value,show=show,width=42)
        field.pack(fill='x',pady=(16,0))
    result=[None]
    def finish(answer):
        result[0]=value.get() if answer=='input' else answer
        top.destroy()
    footer=ttk.Frame(frame);footer.pack(fill='x',pady=(20,0))
    first=None
    for index,(label,answer) in enumerate(choices):
        item=button(footer,text=tr(label),style='Accent.TButton' if index==0 else '',command=lambda a=answer:finish(a))
        item.pack(side='left',padx=(0,8))
        if first is None:first=item
    top.protocol('WM_DELETE_WINDOW',lambda:finish(None))
    top.bind('<Escape>',lambda e:finish(None))
    top.bind('<Return>',lambda e:finish(choices[0][1]))
    top.update_idletasks()
    top.geometry(f'{min(top.winfo_screenwidth()-80,max(480,frame.winfo_reqwidth()))}x{min(top.winfo_screenheight()-100,frame.winfo_reqheight())}')
    top.grab_set();(field or first).focus_set()
    try:parent.wait_window(top)
    finally:
        if previous and previous.winfo_exists():previous.grab_set()
    return result[0],True


class Messages:
    def _ask(self,name,title='',message='',**kwargs):
        title=tr(title);message=tr(str(message))
        parent=kwargs.get('parent')
        if parent is None or not hasattr(parent._root(),'_bitora_app'):
            return getattr(native_messagebox,name)(title,message,**kwargs)
        choices=[('Понятно','ok')]
        if name in ('askyesno','askyesnocancel'):choices=[('Да','yes'),('Нет','no')]
        if name=='askyesnocancel':choices.append(('Отмена',None))
        if name=='askokcancel':choices=[('Продолжить','ok'),('Отмена',None)]
        heading={'showerror':tr('Не удалось выполнить действие'),'showwarning':tr('Обратите внимание')}.get(name,title)
        answer,_=_modal(heading,str(message),parent,choices)
        if name=='askyesnocancel':return None if answer is None else answer=='yes'
        if name=='askyesno':return answer=='yes'
        if name=='askokcancel':return answer=='ok'
        return answer or 'ok'

    def showinfo(self,*args,**kwargs):return self._ask('showinfo',*args,**kwargs)
    def showerror(self,*args,**kwargs):return self._ask('showerror',*args,**kwargs)
    def showwarning(self,*args,**kwargs):return self._ask('showwarning',*args,**kwargs)
    def askyesno(self,*args,**kwargs):return self._ask('askyesno',*args,**kwargs)
    def askyesnocancel(self,*args,**kwargs):return self._ask('askyesnocancel',*args,**kwargs)
    def askokcancel(self,*args,**kwargs):return self._ask('askokcancel',*args,**kwargs)


class Inputs:
    def askstring(self,title,prompt,**kwargs):
        title=tr(title);prompt=tr(prompt)
        parent=kwargs.get('parent')
        if parent is None or not hasattr(parent._root(),'_bitora_app'):
            return native_simpledialog.askstring(title,prompt,**kwargs)
        answer,_=_modal(title,prompt,parent,[('Продолжить','input'),('Отмена',None)],
                        initial=kwargs.get('initialvalue'),show=kwargs.get('show',''))
        return answer

messagebox=Messages()
simpledialog=Inputs()
