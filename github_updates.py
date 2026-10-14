"""Read release or successful build metadata; never execute downloaded files."""
import base64
import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from windows_hello import _dpapi

DEFAULT_REPO='userArturM/Moipar-'
def version(value):
    parts=[int(x) for x in re.findall(r'\d+',value or '')[:4]]
    return tuple((parts+[0]*4)[:4])

def save_token(folder,token):
    path=Path(folder)/'github_update_token.bin'
    if not token:
        path.unlink(missing_ok=True)
        return
    if any(c.isspace() for c in token):raise ValueError('Invalid GitHub token')
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(_dpapi(token.encode(),True,b'MoiParoli GitHub updates'))

def load_token(folder):
    path=Path(folder)/'github_update_token.bin'
    if not path.exists():return ''
    return _dpapi(path.read_bytes(),False,b'MoiParoli GitHub updates').decode()

def check(repo,current,timeout=8,token=''):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo):
        raise ValueError('Use owner/repository')
    def get(path):
        headers={'User-Agent':'MoiParoli','Accept':'application/vnd.github+json'}
        if token:headers['Authorization']='Bearer '+token
        req=urllib.request.Request('https://api.github.com/repos/'+repo+'/'+path,headers=headers)
        with urllib.request.urlopen(req,timeout=timeout) as response:
            return json.loads(response.read(1024*1024).decode())
    try:
        try:
            data=get('releases/latest')
            tag=data['tag_name']
            url=data['html_url']
        except urllib.error.HTTPError as error:
            if error.code!=404:raise
            runs=get('actions/workflows/build.yml/runs?status=success&branch=main&per_page=1')
            if not runs.get('workflow_runs'):
                return {'error':'Успешных сборок пока нет.','url':'https://github.com/'+repo+'/actions'}
            run=runs['workflow_runs'][0]
            data=get('contents/moi_paroli.py?ref='+run['head_sha'])
            source=base64.b64decode(data['content']).decode('utf-8')
            found=re.search(r'^APP_VERSION\s*=\s*[\"\x27]([^\"\x27]+)',source,re.M)
            if not found:raise ValueError('Build version missing')
            tag=found.group(1)
            url=run['html_url']
        if not url.startswith('https://github.com/'+repo+'/'):raise ValueError('Invalid update URL')
        return {'version':tag,'newer':version(tag)>version(current),'url':url}
    except urllib.error.HTTPError as error:
        if error.code in (401,403,404):
            return {'error':'GitHub не разрешил доступ. Для приватного репозитория добавьте токен в настройках '
                           'с доступом Contents: Read и Actions: Read. Можно открыть страницу сборок в браузере.',
                    'url':'https://github.com/'+repo+'/actions'}
        raise
