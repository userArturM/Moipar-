"""Transactional categories, search and independent encrypted backup copies."""
import copy
import os
import re
import shlex
import shutil
import uuid
import tempfile
from contextlib import contextmanager
from urllib.parse import urlsplit
from pathlib import Path
from datetime import datetime

ICONS=('▣','●','◆','★','⌂','▤','✉','⚙')
COLORS=('#0067d9','#7048bd','#16803c','#b24c00','#c52d46','#67676f')

@contextmanager
def transaction(vault):
    if not vault.unlocked:raise ValueError('Vault is locked')
    vault.sync_from_disk(write=False)
    before=copy.deepcopy((vault.entries,vault.meta))
    try:
        yield
        vault.save()
    except Exception:
        vault.entries,vault.meta=before
        raise

def preview_backup(path,password,keyfile=None):
    """Unlock a disposable copy: migration/retention must not alter the backup."""
    from moi_paroli import Vault
    with tempfile.TemporaryDirectory() as folder:
        staged=Path(folder)/'preview.dat'
        shutil.copyfile(path,staged)
        probe=Vault(str(staged))
        try:
            probe.unlock(password,keyfile)
            return copy.deepcopy(probe.active())
        finally:probe.lock()

def restore_selected(vault,records,ids):
    from moi_paroli import normalize,now_str
    selected=[e for e in records if e['id'] in set(ids)]
    if not selected or len(selected)!=len(set(ids)):raise ValueError('Invalid selection')
    created=[]
    with transaction(vault):
        for source in selected:
            entry=normalize(copy.deepcopy(source))
            entry['id']=uuid.uuid4().hex
            entry['deleted']=None
            entry['mtime']=now_str()
            vault.entries.append(entry)
            vault._register_category(entry['category'])
            created.append(entry['id'])
    return created

def remove_category(vault,name,trash_entries=False):
    from moi_paroli import now_str
    token=uuid.uuid4().hex
    with transaction(vault):
        if name not in vault.categories():raise ValueError('Category not found')
        change={'name':name,'properties':copy.deepcopy(vault.meta.get('category_properties',{}).get(name,{})),
                'records':[],'mtime':datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),'restored':False}
        for entry in vault.active():
            if entry['category']!=name:continue
            entry['category']=''
            if trash_entries:entry['deleted']=now_str()
            vault._touch(entry)
            change['records'].append({'id':entry['id'],'hash':vault._record_hash(entry),'deleted':trash_entries})
        vault.meta['categories']=[c for c in vault.meta.get('categories',[]) if c!=name]
        vault.meta.get('category_properties',{}).pop(name,None)
        vault.meta.setdefault('category_tombstones',{})[name]=change['mtime']
        vault.meta.setdefault('category_trash',{})[token]=change
    return token

def restore_category(vault,token):
    restored=0
    with transaction(vault):
        change=vault.meta.get('category_trash',{}).get(token)
        if not change or change.get('restored'):raise ValueError('Invalid selection')
        name=change['name']
        if name in vault.categories():raise ValueError('Category already exists')
        props=copy.deepcopy(change['properties'])
        props['mtime']=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        vault.meta.setdefault('category_properties',{})[name]=props
        vault.meta.setdefault('categories',[]).append(name)
        for saved in change['records']:
            entry=vault.get(saved['id'])
            # Do not overwrite edits, moves, restores or permanent deletion since removal.
            if entry and vault._record_hash(entry)==saved['hash']:
                entry['category']=name
                if saved['deleted']:entry['deleted']=None
                vault._touch(entry);restored+=1
        change['restored']=True;change['mtime']=props['mtime']
    return restored

def duplicate_groups(records):
    groups={}
    for entry in records:
        if entry.get('deleted'):continue
        try:
            raw=entry.get('url','').strip()
            parsed=urlsplit(raw if '://' in raw else 'https://'+raw)
            host=(parsed.hostname or '').lower().rstrip('.')
            port=parsed.port
            site=host+(':'+str(port) if port and port not in (80,443) else '')
        except ValueError:continue
        login=entry.get('login','').strip()
        if host and login:groups.setdefault((site,login),[]).append(entry)
    return [group for group in groups.values() if len(group)>1]

MERGE_FIELDS=('title','url','login','password','totp','category','tags','note','fields')

def merge_duplicates(vault,ids,keep_id,choices,expected):
    from moi_paroli import now_str,HISTORY_LIMIT
    ids=list(dict.fromkeys(ids))
    if len(ids)<2 or keep_id not in ids or any(k not in MERGE_FIELDS or v not in ids for k,v in choices.items()):
        raise ValueError('Invalid selection')
    with transaction(vault):
        entries=[vault.get(i) for i in ids]
        if any(e is None or e['deleted'] or vault._record_hash(e)!=expected.get(e['id']) for e in entries):
            raise ValueError('Selection changed')
        if not any({e['id'] for e in group}>=set(ids) for group in duplicate_groups(entries)):
            raise ValueError('Invalid selection')
        selected={e['id']:e for e in entries}
        keep=selected[keep_id]
        history=[];attachments=[]
        for entry in entries:
            for item in [{'password':entry['password'],'changed':entry['updated']}]+entry['history']:
                if item.get('password') and not any(h['password']==item['password'] for h in history):history.append(copy.deepcopy(item))
            for item in entry['attachments']:
                if item not in attachments:attachments.append(copy.deepcopy(item))
        for field,source in choices.items():keep[field]=copy.deepcopy(selected[source][field])
        keep['history']=[h for h in history if h['password']!=keep['password']][:HISTORY_LIMIT]
        keep['attachments']=attachments
        keep['favorite']=any(e['favorite'] for e in entries)
        keep['updated']=now_str();vault._touch(keep);vault._register_category(keep['category'])
        for entry in entries:
            if entry['id']!=keep_id:entry['deleted']=now_str();vault._touch(entry)
    return keep_id

def category_change(vault,name,new_name=None,color=None,icon=None,ids=None):
    if not vault.unlocked:raise ValueError('Vault is locked')
    if ids is not None and not ids:raise ValueError('Select entries first')
    name=name.strip()
    if not name or len(name)>80:raise ValueError('Category name must contain 1–80 characters')
    if color is not None and color not in COLORS:raise ValueError('Invalid category color')
    if icon is not None and icon not in ICONS:raise ValueError('Invalid category icon')
    vault.sync_from_disk(write=False)
    before=(copy.deepcopy(vault.entries),copy.deepcopy(vault.meta))
    try:
        target=(new_name if new_name is not None else name).strip()
        if not target or len(target)>80:raise ValueError('Invalid category name')
        if new_name is not None and target!=name and target in vault.categories():
            raise ValueError('Category already exists')
        props=vault.meta.setdefault('category_properties',{})
        if new_name is not None:
            if name not in vault.categories():raise ValueError('Category not found')
            vault.meta['categories']=[c for c in vault.meta['categories'] if c!=name]
            props[target]=props.pop(name,{})
            if target!=name:vault.meta.setdefault('category_tombstones',{})[name]=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            if target!=name and name in vault.meta.get('category_order',{}).get('names',[]):
                vault.meta['category_order']={'names':[target if value==name else value for value in vault.meta['category_order']['names']],
                    'mtime':datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}
            for entry in vault.entries:
                if entry['category']==name:entry['category']=target;vault._touch(entry)
        if target not in vault.meta['categories']:vault.meta['categories'].append(target)
        data=props.setdefault(target,{})
        if color is not None:data['color']=color
        if icon is not None:data['icon']=icon
        data['mtime']=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        if ids is not None:
            selected=[vault.get(i) for i in dict.fromkeys(ids)]
            if any(e is None or e['deleted'] for e in selected):raise ValueError('Invalid selection')
            for entry in selected:entry['category']=target;vault._touch(entry)
        vault.save()
    except Exception:
        vault.entries,vault.meta=before
        raise

def reorder_categories(vault,names):
    names=list(names)
    with transaction(vault):
        current=vault.categories()
        if len(names)!=len(set(names)) or set(names)!=set(current):raise ValueError('Selection changed')
        before=current
        stamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        vault.meta['category_order']={'names':names,'mtime':stamp}
    return {'kind':'order','before':before,'expected':stamp}


def move_records(vault,ids,target):
    ids=list(dict.fromkeys(ids))
    if not ids:raise ValueError('Select entries first')
    changes=[]
    with transaction(vault):
        if target and target not in vault.categories():raise ValueError('Category not found')
        records=[vault.get(item) for item in ids]
        if any(entry is None or entry['deleted'] for entry in records):raise ValueError('Selection changed')
        for entry in records:
            if entry['category']==target:continue
            changes.append({'id':entry['id'],'category':entry['category']})
            entry['category']=target;vault._touch(entry)
            changes[-1]['hash']=vault._record_hash(entry)
    return {'kind':'move','records':changes}


def trash_records(vault,ids):
    from moi_paroli import now_str
    ids=list(dict.fromkeys(ids));changes=[]
    if not ids:raise ValueError('Select entries first')
    with transaction(vault):
        records=[vault.get(item) for item in ids]
        if any(entry is None or entry['deleted'] for entry in records):raise ValueError('Selection changed')
        for entry in records:
            entry['deleted']=now_str();vault._touch(entry)
            changes.append({'id':entry['id'],'category':entry['category'],'hash':vault._record_hash(entry)})
    return {'kind':'trash','records':changes}


def undo_change(vault,change):
    with transaction(vault):
        if change['kind']=='order':
            if vault.meta.get('category_order',{}).get('mtime')!=change['expected']:raise ValueError('Selection changed')
            if set(vault.categories())!=set(change['before']):raise ValueError('Selection changed')
            vault.meta['category_order']={'names':change['before'],
                'mtime':datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}
        else:
            records=[vault.get(item['id']) for item in change['records']]
            if any(entry is None or vault._record_hash(entry)!=item['hash']
                   for entry,item in zip(records,change['records'])):raise ValueError('Selection changed')
            for entry,item in zip(records,change['records']):
                if change['kind']=='trash':entry['deleted']=None
                entry['category']=item['category'];vault._register_category(item['category']);vault._touch(entry)


def matches_query(entry,query,issue_ids=None):
    try:tokens=shlex.split(query)
    except ValueError:tokens=query.split()
    hay=' '.join(str(entry.get(k,'')) for k in ('title','url','login','category','tags','note')).casefold()
    for token in tokens:
        field,sep,value=token.partition(':');value=value.casefold()
        if sep and field.casefold() in ('category','cat','категория','tag','тег','is','site','сайт','login','логин','note','заметка'):
            field=field.casefold()
            if field in ('site','сайт','login','логин','note','заметка'):
                name={'site':'url','сайт':'url','login':'login','логин':'login','note':'note','заметка':'note'}[field]
                if value not in str(entry.get(name,'')).casefold():return False
            elif field in ('category','cat','категория'):
                if value not in entry['category'].casefold():return False
            elif field in ('tag','тег'):
                if value not in [t.strip().casefold() for t in entry['tags'].split(',')]:return False
            elif value in ('favorite','избранное'):
                if not entry['favorite']:return False
            elif value in ('weak','reused','old','empty'):
                if entry['id'] not in (issue_ids or {}).get(value,set()):return False
            else:return False
        elif token.casefold() not in hay:return False
    return True

def backup_info(vault,external_folder=''):
    def latest(folder):
        if not folder:return None
        directory=Path(folder)
        if not directory.is_dir():return None
        files=[p for p in directory.glob('*.dat') if p.is_file()]
        return max(files,key=lambda p:p.stat().st_mtime) if files else None
    local=latest(vault.backups_dir());external=latest(external_folder)
    return {'local':local,'external':external,
            'days':None if external is None else (datetime.now()-datetime.fromtimestamp(external.stat().st_mtime)).days}

def copy_backup(vault,folder):
    if not vault.unlocked:raise ValueError('Vault is locked')
    directory=Path(folder).resolve();directory.mkdir(parents=True,exist_ok=True)
    if directory==Path(vault.path).resolve().parent or directory==Path(vault.backups_dir()).resolve():
        raise ValueError('Choose a separate backup folder')
    # Sync first; never replace the active vault or an earlier backup.
    vault.sync_from_disk(write=False)
    target=directory/('MoiParoli-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.dat')
    temporary=target.with_suffix('.tmp')
    try:
        shutil.copyfile(vault.path,temporary)
        os.replace(temporary,target)
    finally:temporary.unlink(missing_ok=True)
    return target
