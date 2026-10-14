"""Register packaged browser_host.exe for a specific unpacked browser extension.

Run: python register_browser_host.py <extension-id> <path-to-browser_host.exe>
Requires Windows; registers only for the current user.
"""
import json
import os
import re
import sys

HOST = 'ru.moiparoli.host'

def make_manifest(extension_id, host_exe):
    if not re.fullmatch(r'[a-p]{32}', extension_id):
        raise ValueError('Invalid Chrome extension ID')
    if not os.path.isfile(host_exe) or not host_exe.lower().endswith('.exe'):
        raise ValueError('Build browser_host.exe first')
    return {'name': HOST, 'description': 'Moi Paroli one-shot approved autofill',
            'path': os.path.abspath(host_exe), 'type': 'stdio',
            'allowed_origins': ['chrome-extension://' + extension_id + '/']}


def register(extension_id, host_exe):
    import winreg
    manifest = make_manifest(extension_id, host_exe)
    directory = os.path.dirname(os.path.abspath(host_exe))
    path = os.path.join(directory, 'browser_host_manifest.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    for product in ('Google\\Chrome', 'Yandex\\YandexBrowser'):
        key = 'Software\\' + product + '\\NativeMessagingHosts\\' + HOST
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as reg:
            winreg.SetValueEx(reg, '', 0, winreg.REG_SZ, path)
    return path

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Usage: python register_browser_host.py EXTENSION_ID BROWSER_HOST_EXE')
    print(register(sys.argv[1], sys.argv[2]))
