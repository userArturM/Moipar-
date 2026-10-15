"""Read release or successful build metadata; never execute downloaded files."""
import base64
import json
import re
import hashlib
import os
from urllib.parse import urlparse
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
            notes=data.get('body','') or ''
            assets=data.get('assets') or []
            setup=next((a for a in assets if a.get('name')=='MoiParoli-Setup.exe'),{})
            download_url=setup.get('browser_download_url') or url
            digest=setup.get('digest','') or ''
            sha256=digest.removeprefix('sha256:') if digest.startswith('sha256:') else None
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
            notes=run.get('display_title') or 'Windows build '+tag
            download_url=url
            sha256=None
            if run.get('id'):
                artifacts=get('actions/runs/'+str(run['id'])+'/artifacts')
                setup=next((a for a in artifacts.get('artifacts',[]) if a.get('name')=='MoiParoli-Setup' and not a.get('expired')),None)
                if setup:download_url=url+'/artifacts/'+str(setup['id'])
        if not url.startswith('https://github.com/'+repo+'/'):raise ValueError('Invalid update URL')
        if not download_url.startswith('https://github.com/'+repo+'/'):raise ValueError('Invalid download URL')
        return {'version':tag,'newer':version(tag)>version(current),'url':url,'notes':notes,
                'download_url':download_url,'sha256':sha256}
    except urllib.error.HTTPError as error:
        if error.code in (401,403,404):
            return {'error':'GitHub не разрешил доступ. Для приватного репозитория добавьте токен в настройках '
                           'с доступом Contents: Read и Actions: Read. Можно открыть страницу сборок в браузере.',
                    'url':'https://github.com/'+repo+'/actions'}
        raise

class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urlparse(newurl)
        if parsed.scheme!='https' or parsed.hostname not in ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'):
            raise ValueError('Untrusted download redirect')
        redirected=super().redirect_request(req,fp,code,msg,headers,newurl)
        if redirected:
            redirected.remove_header('Authorization')
            redirected.remove_header('Cookie')
        return redirected

def download_installer(url,destination,sha256):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.hostname!='github.com' or '/releases/download/' not in parsed.path:
        raise ValueError('Only GitHub release downloads are supported')
    if not isinstance(sha256,str) or not re.fullmatch('[0-9a-fA-F]{64}',sha256):
        raise ValueError('A verified download digest is required')
    target=Path(destination);temporary=target.with_suffix(target.suffix+'.part')
    digest=hashlib.sha256();size=0
    try:
        opener=urllib.request.build_opener(DownloadRedirect())
        with opener.open(urllib.request.Request(url,headers={'User-Agent':'MoiParoli'}),timeout=30) as response, temporary.open('wb') as stream:
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>200*1024*1024:raise ValueError('Installer is too large')
                digest.update(chunk);stream.write(chunk)
        if size<1024 or digest.hexdigest().lower()!=sha256.lower():raise ValueError('Installer digest mismatch')
        os.replace(temporary,target)
    finally:temporary.unlink(missing_ok=True)
