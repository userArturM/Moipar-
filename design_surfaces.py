"""Code-native surfaces for the reference-inspired Bitora desktop design."""
import tkinter as tk
from tkinter import ttk
from midnight_ui import rounded, blend, line_icon


class Surface(tk.Canvas):
    def __init__(self,parent,palette,height=250):
        self.palette=palette
        self.hover_amount=0.;self.motion_job=None;self.motion_root=parent._root()
        self.scale=max(1,float(parent.tk.call('tk','scaling'))/(96/72))
        super().__init__(parent,bg=palette['bg'],height=int(height*self.scale),
                         highlightthickness=0,borderwidth=0,width=1)
        self.body=ttk.Frame(self,style='Panel.TFrame',padding=12)
        self.window=self.create_window(8,8,window=self.body,anchor='nw')
        self.bind('<Configure>',self.draw)
        self.bind('<Enter>',lambda e:self.hover(True))
        self.bind('<Leave>',lambda e:self.hover(False))
        self.bind('<FocusIn>',lambda e:self.hover(True))
        self.bind('<FocusOut>',lambda e:self.hover(False))
        self.bind('<Destroy>',self.dispose,add='+')

    def hover(self,value):
        if not value:
            x,y=self.winfo_pointerxy()
            if self.winfo_rootx()<=x<self.winfo_rootx()+self.winfo_width() and self.winfo_rooty()<=y<self.winfo_rooty()+self.winfo_height():return
        if self.motion_job:self.motion_root.after_cancel(self.motion_job);self.motion_job=None
        app=getattr(self.motion_root,'_bitora_app',None)
        target=1. if value else 0.
        if not app or not app.settings.get('animations'):
            self.hover_amount=target;self.draw();return
        origin=self.hover_amount
        def tick(index):
            self.motion_job=None
            if not self.winfo_exists():return
            self.hover_amount=origin+(target-origin)*(1-(1-index/7)**3)
            self.draw()
            if index<7:self.motion_job=self.motion_root.after(20,lambda:tick(index+1))
        tick(1)

    def dispose(self,event):
        if event.widget is self and self.motion_job:
            self.motion_root.after_cancel(self.motion_job);self.motion_job=None

    def draw(self,event=None):
        w=self.winfo_width();h=self.winfo_height();t=self.palette
        self.delete('surface')
        border=blend(blend(t['panel'],t['fg'],.12),t['accent'],self.hover_amount*.78)
        item=rounded(self,1,1,w-2,h-2,10*self.scale,t['panel'],border)
        self.addtag_withtag('surface',item);self.tag_lower('surface')
        if self.hover_amount>.01:
            item=self.create_line(14,2,w-14,2,fill=blend(t['panel'],t['accent'],self.hover_amount*.7),width=2)
            self.addtag_withtag('surface',item)
        self.itemconfigure(self.window,width=max(1,w-16),height=max(1,h-16))


class AuditTile(tk.Canvas):
    """A bounded, keyboard-reachable audit panel with an integral colour sweep."""
    def __init__(self,parent,palette,count,title,caption,color,command):
        self.palette=palette;self.count=count;self.title=title;self.caption=caption
        self.color=color;self.command=command;self.hover=False
        self.scale=max(1,float(parent.tk.call('tk','scaling'))/(96/72))
        super().__init__(parent,bg=palette['bg'],highlightthickness=0,
                         height=int(106*self.scale),width=1,takefocus=True,cursor='hand2')
        self.bind('<Configure>',self.draw)
        self.bind('<Enter>',lambda e:self.enter(True));self.bind('<Leave>',lambda e:self.enter(False))
        self.bind('<FocusIn>',self.draw);self.bind('<FocusOut>',self.draw)
        for event in ('<Button-1>','<Return>','<space>'):
            self.bind(event,lambda e:self.invoke())

    def enter(self,value):self.hover=value;self.draw()

    def invoke(self):self.command();return 'break'

    def draw(self,event=None):
        self.delete('all');t=self.palette;s=self.scale;w=self.winfo_width();h=self.winfo_height()
        if w<20:return
        base=blend(t['panel'],t['accent'],.06 if self.hover else 0)
        focused=self.focus_get() is self
        rounded(self,1,1,w-2,h-2,12*s,base,t['accent'] if focused else blend(base,t['fg'],.12))
        # A continuous angled sweep, matching the reference's broad tinted edge.
        cut=min(w*.43,245*s)
        for y in range(3,max(4,int(h-3)),2):
            progress=y/max(1,h)
            edge=cut+48*s*(progress**.7)
            inset=8*s*(1-min(1,y/(12*s))) if y<12*s else 8*s*(1-min(1,(h-y)/(12*s))) if y>h-12*s else 0
            self.create_line(3+inset,y,min(w-4,edge),y,fill=blend(base,self.color,.40-.15*progress),width=2)
        line_icon(self,'shield',20*s,21*s,21*s,self.color,1.6*s)
        self.create_text(53*s,31*s,text=str(self.count),anchor='w',fill=t['fg'],font=('Segoe UI',20,'bold'))
        x=(85+max(0,len(str(self.count))-1)*17)*s
        self.create_text(x,32*s,text=self.title,anchor='w',fill=t['fg'],font=('Segoe UI',11,'bold'),width=max(40,w-x-40*s))
        self.create_text(22*s,58*s,text=self.caption,anchor='nw',fill=t['fg'],font=('Segoe UI',9),width=max(35,w-66*s))
        self.create_text(w-24*s,h/2,text='›',fill=t['accent'],font=('Segoe UI',23))
