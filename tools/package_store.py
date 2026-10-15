"""Build a deterministic upload ZIP from an explicit public-asset allowlist."""
from pathlib import Path
import hashlib
import json
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
FILES=('manifest.json','background.js','fill.js','popup.html','popup.js','save.js',
       'form_capture.js','save_offer.js','icon16.png','icon32.png','icon48.png','icon128.png')

def build(folder):
    folder=Path(folder)
    folder.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((ROOT/'browser_extension/manifest.json').read_text(encoding='utf-8'))
    manifest.pop('key',None)
    assert manifest['manifest_version']==3
    assert set(manifest['permissions'])=={'activeTab','scripting','nativeMessaging','storage'}
    name=f'Bitora-password-extension-store-{manifest["version"]}.zip'
    target=folder/name
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            path=ROOT/'browser_extension'/name
            content=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode() if name=='manifest.json' else path.read_bytes()
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(info,content)
    for name in ('PRIVACY.md','STORE_LISTING.md','SIGNING.md'):
        (folder/name).write_bytes((ROOT/name).read_bytes())
    report={'version':manifest['version'],'zip':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'store_id':'Assigned by store; native-host registration must be verified before publishing',
            'publisher_account_required':True,'submitted':False}
    (folder/'PACKAGE.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return target

if __name__=='__main__':print(build(sys.argv[1] if len(sys.argv)>1 else ROOT/'store_package'))
