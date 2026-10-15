"""Native Midnight drawing components; credentials remain in the existing app model."""
import math
import tkinter as tk
from tkinter import ttk,font as tkfont


def rounded(canvas,x,y,width,height,radius,fill,outline=''):
    r=max(0,min(radius,width/2,height/2))
    points=(x+r,y,x+width-r,y,x+width,y,x+width,y+r,x+width,y+height-r,
        x+width,y+height,x+width-r,y+height,x+r,y+height,x,y+height,x,y+height-r,x,y+r,x,y)
    return canvas.create_polygon(points,smooth=True,splinesteps=24,fill=fill,
        outline=outline,width=1)


def line_icon(canvas,name,x,y,size,color,width=1.6):
    """Small consistent outline icons drawn in logical coordinates."""
    def p(a,b):return x+a*size/24,y+b*size/24
    def line(*coords):
        flat=[]
        for i in range(0,len(coords),2):flat.extend(p(coords[i],coords[i+1]))
        canvas.create_line(*flat,fill=color,width=width,capstyle='round',joinstyle='round')
    def rect(a,b,c,d):canvas.create_rectangle(*p(a,b),*p(c,d),outline=color,width=width)
    def oval(a,b,c,d):canvas.create_oval(*p(a,b),*p(c,d),outline=color,width=width)
    if name=='key':oval(3,3,13,13);line(11,11,21,21);line(16,16,19,13);line(19,19,22,16)
    elif name=='star':
        points=[]
        for i in range(10):
            angle=-math.pi/2+i*math.pi/5;r=10 if i%2==0 else 4.4
            points.extend(p(12+math.cos(angle)*r,12+math.sin(angle)*r))
        canvas.create_polygon(points,fill='',outline=color,width=width,joinstyle='round')
    elif name=='browser':rect(3,4,21,21);line(3,9,21,9);oval(6,6,6.5,6.5);oval(9,6,9.5,6.5)
    elif name=='trash':line(4,6,20,6);line(9,3,15,3);line(6,6,7,21,17,21,18,6);line(10,10,10,17);line(14,10,14,17)
    elif name=='folder':line(3,7,3,20,21,20,21,7,13,7,10,4,3,4,3,7)
    elif name=='settings':
        oval(8,8,16,16)
        for i in range(8):
            angle=i*math.pi/4
            line(12+7*math.cos(angle),12+7*math.sin(angle),12+10*math.cos(angle),12+10*math.sin(angle))
    elif name=='plus':line(12,5,12,19);line(5,12,19,12)
    elif name=='search':oval(3,3,17,17);line(15,15,22,22)
    elif name=='copy':rect(8,8,21,21);line(16,4,4,4,4,16)
    elif name=='lock':rect(5,10,19,22);line(8,10,8,6,10,3,14,3,16,6,16,10)
    elif name=='more':
        for xx in (5,12,19):canvas.create_oval(*p(xx-1,11),*p(xx+1,13),fill=color,outline='')


class DesignButton(tk.Canvas):
    def __init__(self,parent,text,command,palette,*,kind='secondary',icon=None,
                 width=None,height=40,scale=1,font_size=10,vertical=False):
        self.palette=palette;self.kind=kind;self.command=command;self.label=text
        self.icon=icon;self.scale=scale;self.vertical=vertical;self.disabled=False;self.selected=False;self.hover=False
        self.text_font=tkfont.Font(parent,family='Segoe UI',size=font_size)
        self.parent_bg=palette['side'] if kind=='rail' else palette['bg']
        minimum=self.text_font.measure(text)+int((40 if icon else 28)*scale)
        super().__init__(parent,width=width or minimum,height=int(height*scale),highlightthickness=0,
            borderwidth=0,bg=self.parent_bg,takefocus=True,cursor='hand2')
        self.bind('<Configure>',lambda e:self.draw())
        self.bind('<Enter>',lambda e:self._hover(True));self.bind('<Leave>',lambda e:self._hover(False))
        self.bind('<Button-1>',lambda e:self.invoke())
        self.bind('<Return>',lambda e:self.invoke());self.bind('<space>',lambda e:self.invoke())
        self.bind('<FocusIn>',lambda e:self.draw());self.bind('<FocusOut>',lambda e:self.draw())
        self.draw()

    def _hover(self,value):self.hover=value;self.draw()

    def configure(self,cnf=None,**kwargs):
        if cnf:kwargs.update(cnf)
        if 'style' in kwargs:self.selected=kwargs.pop('style')=='RailActive.TButton'
        if 'state' in kwargs:self.disabled=kwargs.pop('state')=='disabled'
        if 'text' in kwargs:self.label=kwargs.pop('text')
        if kwargs:super().configure(**kwargs)
        if hasattr(self,'text_font'):self.draw()

    config=configure

    def invoke(self):
        if not self.disabled:
            self.focus_set();self.command()
        return 'break'

    def cget(self,key):
        if key=='text':return self.label
        if key=='state':return 'disabled' if self.disabled else 'normal'
        return super().cget(key)

    def draw(self):
        if not self.winfo_exists():return
        self.delete('all');t=self.palette;s=self.scale;w=self.winfo_width();h=self.winfo_height()
        if w<2:return
        primary=self.kind=='primary'
        fill=t['accent'] if primary else t['sel'] if self.selected else t['hover'] if self.hover else self.parent_bg
        color=t['muted'] if self.disabled else t['accent_fg'] if primary else t['accent'] if self.selected else t['muted'] if self.kind=='rail' else t['fg']
        border=t['accent'] if self.focus_get() is self else '' if self.kind in ('rail','chip') else t['border'] if not primary else t['accent']
        rounded(self,1,1,w-2,h-2,9*s,fill,border)
        if self.vertical:
            if self.icon:line_icon(self,self.icon,w/2-9*s,8*s,18*s,color,1.7*s)
            self.create_text(w/2,h-13*s,text=self.label,font=self.text_font,fill=color)
        else:
            label=self.label
            while label and self.text_font.measure(label)>w-(42 if self.icon else 24)*s:label=label[:-1]
            if label!=self.label:label=label.rstrip()+'…'
            total=self.text_font.measure(label)+(25*s if self.icon else 0)
            start=(w-total)/2
            if self.icon:line_icon(self,self.icon,start,h/2-8*s,16*s,color,1.6*s)
            self.create_text(start+(25*s if self.icon else 0),h/2,text=label,font=self.text_font,fill=color,anchor='w')


class RecordModel(ttk.Treeview):
    """Keep all existing selection, sorting and export behavior behind the view."""
    view=None

    def selection_set(self,*items):
        super().selection_set(*items)
        if self.view:self.view.draw()

    def see(self,item):
        if self.view:self.view.see(item)
        else:super().see(item)

    def identify_row(self,y):
        if self.view:
            index=self.view.index_at(y)
            return self.view.ids[index] if index is not None else ''
        return super().identify_row(y)


class RecordList(tk.Canvas):
    def __init__(self,parent,model,vault,palette,scale,font_size,edit,delete,context,copy_login,copy_password):
        super().__init__(parent,background=palette['bg'],highlightthickness=0,borderwidth=0,takefocus=True)
        self.model=model;model.view=self;self.vault=vault;self.palette=palette;self.scale=scale
        self.row_height=int(78*scale);self.ids=[];self.anchor=None;self.drawn=[]
        self.title_font=tkfont.Font(self,family='Segoe UI',size=font_size+1,weight='bold')
        self.sub_font=tkfont.Font(self,family='Segoe UI',size=max(9,font_size-1))
        self.avatar_font=tkfont.Font(self,family='Segoe UI',size=font_size+3)
        self.bind('<Configure>',lambda e:self.draw())
        self.bind('<Button-1>',self.select_at);self.bind('<Double-1>',lambda e:edit())
        self.bind('<Button-3>',lambda e:self.context_at(e,context))
        self.bind('<MouseWheel>',lambda e:self.scroll(-int(e.delta/120)))
        for key,step in (('Up',-1),('Down',1),('Home','first'),('End','last'),('Prior',-6),('Next',6)):
            self.bind('<'+key+'>',lambda e,n=step:self.move(n))
        self.bind('<Return>',lambda e:edit());self.bind('<Delete>',lambda e:delete())
        self.bind('<Control-c>',lambda e:copy_login());self.bind('<Control-Shift-C>',lambda e:copy_password())
        self.bind('<FocusIn>',lambda e:self.draw());self.bind('<FocusOut>',lambda e:self.draw())
        self.yscroll_callback=None
        self.configure(yscrollcommand=self._scrolled)

    def _scrolled(self,first,last):
        if self.yscroll_callback:self.yscroll_callback(first,last)
        self.draw()

    def refresh(self):
        self.ids=list(self.model.get_children());self.configure(scrollregion=(0,0,max(1,self.winfo_width()),len(self.ids)*self.row_height))
        self.draw()

    def shorten(self,text,font,width):
        if font.measure(text)<=width:return text
        low,high=0,len(text)
        while low<high:
            middle=(low+high+1)//2
            if font.measure(text[:middle]+'…')<=width:low=middle
            else:high=middle-1
        return text[:low]+'…' if low else ''

    def draw(self):
        if not self.winfo_exists():return
        self.delete('all');self.drawn=[]
        s=self.scale;t=self.palette;w=self.winfo_width()
        if w<10:return
        top=self.canvasy(0);bottom=top+self.winfo_height()
        first=max(0,int(top//self.row_height)-1);last=min(len(self.ids),int(bottom//self.row_height)+2)
        selected=set(self.model.selection())
        for index in range(first,last):
            item=self.ids[index];entry=self.vault.get(item)
            if not entry:continue
            y=index*self.row_height;active=item in selected
            if active:rounded(self,1,y+2*s,w-3,self.row_height-4*s,10*s,t['sel'])
            else:self.create_line(12*s,y+self.row_height,w-12*s,y+self.row_height,fill=t['border'])
            rounded(self,13*s,y+19*s,38*s,38*s,10*s,t['card'],t['border'])
            self.create_text(32*s,y+38*s,text=(entry['title'].strip()[:1] or '?').upper(),font=self.avatar_font,fill=t['accent'] if active else t['fg'])
            left=66*s;space=max(30,w-left-38*s)
            self.create_text(left,y+27*s,anchor='w',text=self.shorten(entry['title'],self.title_font,space),font=self.title_font,fill=t['fg'])
            self.create_text(left,y+49*s,anchor='w',text=self.shorten(entry['login'] or entry['url'],self.sub_font,space),font=self.sub_font,fill=t['muted'])
            if entry['favorite']:line_icon(self,'star',w-28*s,y+30*s,14*s,t['accent'],1.2*s)
            self.drawn.append(item)
        if self.focus_get() is self and self.ids:
            self.create_rectangle(1,top+1,w-2,bottom-2,outline=t['border'])

    def index_at(self,y):
        index=int(self.canvasy(y)//self.row_height)
        return index if 0<=index<len(self.ids) else None

    def select_at(self,event):
        self.focus_set();index=self.index_at(event.y)
        if index is None:return
        item=self.ids[index]
        if event.state&4:
            chosen=set(self.model.selection());chosen.symmetric_difference_update([item]);self.model.selection_set(list(chosen))
        elif event.state&1 and self.anchor in self.ids:
            begin=self.ids.index(self.anchor);self.model.selection_set(self.ids[min(begin,index):max(begin,index)+1])
        else:self.model.selection_set(item);self.anchor=item
        self.model.focus(item);self.model.event_generate('<<TreeviewSelect>>');self.draw()

    def context_at(self,event,callback):
        index=self.index_at(event.y)
        if index is None:return
        item=self.ids[index]
        if item not in self.model.selection():self.model.selection_set(item)
        self.model.focus(item);self.model.event_generate('<<TreeviewSelect>>')
        callback(event)

    def move(self,step):
        if not self.ids:return 'break'
        selected=self.model.selection();index=self.ids.index(selected[-1]) if selected and selected[-1] in self.ids else -1
        index=0 if step=='first' else len(self.ids)-1 if step=='last' else max(0,min(len(self.ids)-1,index+step))
        self.model.selection_set(self.ids[index]);self.model.focus(self.ids[index]);self.anchor=self.ids[index]
        self.model.event_generate('<<TreeviewSelect>>');self.see(self.ids[index]);return 'break'

    def see(self,item):
        if item not in self.ids:return
        y=self.ids.index(item)*self.row_height;top=self.canvasy(0);height=self.winfo_height();total=max(1,len(self.ids)*self.row_height)
        if y<top:self.yview_moveto(y/total)
        elif y+self.row_height>top+height:self.yview_moveto((y+self.row_height-height)/total)
        self.draw()

    def scroll(self,amount):self.yview_scroll(amount,'units');self.draw();return 'break'
