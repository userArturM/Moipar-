"""Transactional categories, search and independent encrypted backup copies."""
import copy
import os
import re
import shlex
import shutil
from pathlib import Path
from datetime import datetime

ICONS=('▣','●','◆','★','⌂','▤','✉','⚙')
COLORS=('#0067d9','#7048bd','#16803c','#b24c00','#c52d46','#67676f')

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

def matches_query(entry,query,issue_ids=None):
    try:tokens=shlex.split(query)
    except ValueError:tokens=query.split()
    hay=' '.join(str(entry.get(k,'')) for k in ('title','url','login','category','tags','note')).casefold()
    for token in tokens:
        field,sep,value=token.partition(':');value=value.casefold()
        if sep and field.casefold() in ('category','cat','категория','tag','тег','is'):
            field=field.casefold()
            if field in ('category','cat','категория'):
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
