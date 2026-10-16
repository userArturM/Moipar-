"""Low-frequency blue ambient lighting behind native controls."""
import math
import time
from midnight_ui import blend


class Ambient:
    def __init__(self,canvas,app,band=False):
        self.canvas=canvas;self.app=app;self.job=None;self.started=time.monotonic()
        self.band=band
        self.root=canvas._root()
        canvas.bind('<Configure>',self.draw,add='+')
        canvas.bind('<Map>',self.resume,add='+')
        canvas.bind('<Unmap>',self.pause,add='+')
        canvas.bind('<Destroy>',self.dispose,add='+')
        self.draw();self.schedule()

    def draw(self,event=None):
        c=self.canvas
        if not c.winfo_exists():return
        c.delete('bitora-ambient')
        w=c.winfo_width();h=c.winfo_height()
        if w<2 or h<2:return
        dark=self.app.theme_name=='dark'
        base=self.app.t['bg']
        active=self.app.settings.get('animations')
        phase=(time.monotonic()-self.started)/13 if active else 0
        blue='#0062fb' if dark else '#c2d1e9'
        if self.band:
            center=.5+.4*math.sin(phase)
            for i in range(80):
                x=i/80
                color=blend('#0731a1' if dark else self.app.t['panel'],'#0062fb' if dark else self.app.t['accent'],(.14+.80*math.exp(-((x-center)/.18)**2)) if dark else (.05+.26*math.exp(-((x-center)/.22)**2)))
                c.create_rectangle(int(w*x),0,int(w*(i+1)/80)+1,h,fill=color,outline='',tags='bitora-ambient')
            c.tag_lower('bitora-ambient');return
        for i in range(48):
            y=i/48
            amount=(.075+.07*math.exp(-((y-(.48+.22*math.sin(phase)))/.28)**2)) if dark else (.10+.18*math.exp(-((y-(.48+.22*math.sin(phase)))/.32)**2))
            color=blend(base,blue,amount)
            c.create_rectangle(0,int(h*y),w,int(h*(i+1)/48)+1,fill=color,outline='',tags='bitora-ambient')
        c.tag_lower('bitora-ambient')

    def schedule(self):
        if self.job is None and self.canvas.winfo_ismapped() and self.app.settings.get('animations'):
            self.job=self.root.after(160,self.tick)

    def tick(self):
        self.job=None
        if not self.canvas.winfo_exists():return
        if self.canvas.winfo_ismapped():self.draw();self.schedule()

    def resume(self,event=None):self.draw();self.schedule()

    def pause(self,event=None):
        if self.job is not None:self.root.after_cancel(self.job);self.job=None

    def dispose(self,event):
        if event.widget is self.canvas:self.pause()


def attach(canvas,app,band=False):
    if not hasattr(canvas,'_ambient'):canvas._ambient=Ambient(canvas,app,band)
    return canvas._ambient
