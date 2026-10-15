"""Register and diagnose native messaging for all supported browsers, per user."""
import json
import os
import re
import struct
import subprocess
from pathlib import Path
from browser_identity import HOST, EXTENSION_ID

BROWSERS=("Google\\Chrome","Yandex\\YandexBrowser","Microsoft\\Edge","Chromium")

def probe_host(host_exe):
    """A framed ping only: never opens a vault or asks for credentials."""
    payload=json.dumps({'action':'ping'}).encode('utf-8')
    completed=subprocess.run([str(host_exe)],input=struct.pack('<I',len(payload))+payload,
        capture_output=True,timeout=15,check=False,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    raw=completed.stdout
    if completed.returncode or len(raw)<4:raise ValueError('Native host did not respond')
    length=struct.unpack('<I',raw[:4])[0]
    if not 1<=length<=65536 or len(raw)!=4+length:raise ValueError('Invalid native response')
    data=json.loads(raw[4:].decode('utf-8'))
    if not isinstance(data,dict) or data.get('ok') is not True:raise ValueError('Invalid native response')
    if not isinstance(data.get('supports'),list) or not isinstance(data.get('version'),str):
        raise ValueError('Invalid native response')
    return {'version':str(data.get('version','?'))[:32],
            'save':'save_credentials' in data.get('supports',[]),'fill':'get_credentials' in data.get('supports',[])}

def make_manifest(extension_id,host_exe):
    if not re.fullmatch(r"[a-p]{32}",extension_id):
        raise ValueError("Неверный ID расширения")
    if not os.path.isfile(host_exe) or not host_exe.lower().endswith(".exe"):
        raise ValueError("Не найден browser_host.exe")
    return {"name":HOST,"description":"Bitora Paswword Manager — заполнение и сохранение",
            "path":os.path.abspath(host_exe),"type":"stdio",
            "allowed_origins":["chrome-extension://"+extension_id+"/"]}

def register(extension_id,host_exe):
    import winreg
    manifest=make_manifest(extension_id,host_exe)
    folder=Path(os.environ.get("APPDATA") or Path(host_exe).resolve().parent)/"MoiParoli"/"native"
    folder.mkdir(parents=True,exist_ok=True)
    path=folder/"browser_host_manifest.json"
    if path.is_file():
        try:
            old=json.loads(path.read_text(encoding="utf-8-sig"))
            if old.get("name")==HOST:
                manifest["allowed_origins"] += [origin for origin in old.get("allowed_origins",[])
                    if isinstance(origin,str) and re.fullmatch(r"chrome-extension://[a-p]{32}/",origin)]
        except (ValueError,OSError):
            pass
    manifest["allowed_origins"]=sorted(set(manifest["allowed_origins"]))
    temporary=path.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    os.replace(temporary,path)
    for browser in BROWSERS:
        key="Software\\"+browser+"\\NativeMessagingHosts\\"+HOST
        for view in (winreg.KEY_WOW64_32KEY,winreg.KEY_WOW64_64KEY):
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,key,0,winreg.KEY_SET_VALUE|view) as handle:
                winreg.SetValueEx(handle,"",0,winreg.REG_SZ,str(path))
    return str(path)

def diagnose():
    import winreg
    result=[]
    for browser in BROWSERS:
        for view in (winreg.KEY_WOW64_32KEY,winreg.KEY_WOW64_64KEY):
            status={"browser":browser,"view":32 if view==winreg.KEY_WOW64_32KEY else 64,"ok":False}
            try:
                key="Software\\"+browser+"\\NativeMessagingHosts\\"+HOST
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,key,0,winreg.KEY_READ|view) as handle:
                    path=winreg.QueryValueEx(handle,"")[0]
                data=json.loads(Path(path).read_text(encoding="utf-8-sig"))
                status["ok"]=(data.get("name")==HOST and data.get("type")=="stdio"
                    and Path(data.get("path","")).is_file()
                    and "chrome-extension://"+EXTENSION_ID+"/" in data.get("allowed_origins",[]))
                status["manifest"]=path
            except (OSError,ValueError,TypeError) as exc:
                status["error"]=type(exc).__name__
            result.append(status)
    return result
