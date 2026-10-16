"""Exact-host browser exclusions shared by the desktop and native host."""
import re
from urllib.parse import urlsplit

def normalize_sites(values):
    result=set()
    for value in values:
        value=value.strip()
        if not value:continue
        parsed=urlsplit(value if '://' in value else 'https://'+value)
        host=(parsed.hostname or '').rstrip('.').encode('idna').decode('ascii').lower()
        if parsed.username or parsed.password or parsed.port not in (None,443) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or '.' not in host:
            raise ValueError('Use website domains without credentials or ports')
        result.add(host)
    return sorted(result)

def excluded(host):
    from moi_paroli import Settings,data_dir
    import os
    values=Settings(os.path.join(data_dir(),'settings.json')).get('ignored_sites') or []
    return host.lower().rstrip('.') in values
