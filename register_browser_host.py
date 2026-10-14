import sys, json
from browser_registration import register, make_manifest, diagnose
if __name__ == '__main__':
    if len(sys.argv)==2 and sys.argv[1]=='--diagnose':
        print(json.dumps(diagnose(),ensure_ascii=False))
    elif len(sys.argv)==3:
        print(register(sys.argv[1],sys.argv[2]))
    else:
        sys.exit('Usage: register_browser_host.py EXTENSION_ID HOST_EXE')
