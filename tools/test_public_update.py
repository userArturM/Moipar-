import sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from github_updates import check,download_installer,DEFAULT_REPO,version
from moi_paroli import APP_VERSION
for attempt in range(5):
    try:
        info=check(DEFAULT_REPO,'0.0')
        assert version(info['version'])==version(APP_VERSION),info
        assert info['newer'] and info.get('sha256'),info
        assert '/releases/download/' in info['download_url'],info
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'setup.exe'
            download_installer(info['download_url'],target,info['sha256'])
            assert target.stat().st_size>1024
        print('Public release API, installer download and SHA-256 verification passed')
        break
    except Exception:
        if attempt==4:raise
        time.sleep(5)
