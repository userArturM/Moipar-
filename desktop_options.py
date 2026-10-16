"""Explicit user-selected desktop conveniences, with no shell-built commands."""
import os
from pathlib import Path
import subprocess
import sys
import webbrowser

BROWSERS={'system':'Системный браузер','chrome':'Google Chrome','edge':'Microsoft Edge','yandex':'Яндекс Браузер'}

def system_theme():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as handle:
            return 'light' if winreg.QueryValueEx(handle,'AppsUseLightTheme')[0] else 'dark'
    except (OSError,ImportError):return 'dark'

def browser_path(kind):
    local=Path(os.environ.get('LOCALAPPDATA',''))
    programs=Path(os.environ.get('PROGRAMFILES','C:/Program Files'))
    programs32=Path(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))
    paths={
        'chrome':[programs/'Google/Chrome/Application/chrome.exe',local/'Google/Chrome/Application/chrome.exe'],
        'edge':[programs32/'Microsoft/Edge/Application/msedge.exe',programs/'Microsoft/Edge/Application/msedge.exe'],
        'yandex':[local/'Yandex/YandexBrowser/Application/browser.exe'],
    }
    return next((p for p in paths.get(kind,[]) if p.is_file()),None)

def open_site(url,kind='system'):
    from urllib.parse import urlsplit
    if urlsplit(url).scheme not in ('http','https'):raise ValueError('Only HTTP/HTTPS URLs are allowed')
    if kind=='system':return webbrowser.open(url)
    executable=browser_path(kind)
    if not executable:raise ValueError('Selected browser is not installed')
    subprocess.Popen([str(executable),url],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

def startup(enabled):
    # Source previews and tests must not register a Python interpreter in Windows.
    if sys.platform!='win32' or not getattr(sys,'frozen',False):return
    import winreg
    key=r'Software\Microsoft\Windows\CurrentVersion\Run'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,key,0,winreg.KEY_SET_VALUE) as handle:
        if enabled:winreg.SetValueEx(handle,'Bitora Password Manager',0,winreg.REG_SZ,'"'+sys.executable+'" --startup')
        else:
            try:winreg.DeleteValue(handle,'Bitora Password Manager')
            except FileNotFoundError:pass
