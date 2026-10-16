"""Software ES256 WebAuthn credentials stored only inside the encrypted vault.

Input is the browser WebAuthenticationProxy JSON, including its trusted origin
override. No private key or master password is ever part of a browser response.
"""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
from urllib.parse import urlsplit
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec


class PasskeyError(ValueError):
    def __init__(self,message,name='NotAllowedError'):
        super().__init__(message);self.name=name


def encode(value):return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def decode(value,minimum=1,maximum=4096):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',value) or len(value)>maximum*2:
        raise PasskeyError('Invalid binary parameter','DataError')
    try:raw=base64.b64decode(value+'='*((-len(value))%4),altchars=b'-_',validate=True)
    except Exception as exc:raise PasskeyError('Invalid binary parameter','DataError') from exc
    if not minimum<=len(raw)<=maximum or encode(raw)!=value:raise PasskeyError('Invalid binary size','DataError')
    return raw


def domain(value):
    if not isinstance(value,str) or len(value)>253 or value.endswith('.'):
        raise PasskeyError('Invalid relying party','SecurityError')
    try:host=value.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:raise PasskeyError('Invalid relying party','SecurityError') from exc
    if host=='localhost':return host
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or '.' not in host or '..' in host:
        raise PasskeyError('Invalid relying party','SecurityError')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')):
        raise PasskeyError('Invalid domain label','SecurityError')
    try:ipaddress.ip_address(host)
    except ValueError:pass
    else:raise PasskeyError('IP relying parties are unsupported','SecurityError')
    return host


def validate(operation,options):
    if operation not in ('create','get') or not isinstance(options,dict):raise PasskeyError('Invalid operation','DataError')
    if len(json.dumps(options))>60000:raise PasskeyError('Request too large','DataError')
    extensions=options.get('extensions') or {}
    override=extensions.get('remoteDesktopClientOverride') or {}
    if override.get('sameOriginWithAncestors') is not True:
        raise PasskeyError('Only same-origin top-level requests are supported','SecurityError')
    origin=override.get('origin','')
    parsed=urlsplit(origin)
    local=parsed.scheme=='http' and parsed.hostname=='localhost'
    if (parsed.scheme!='https' and not local) or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise PasskeyError('A trusted HTTPS origin is required','SecurityError')
    host=domain(parsed.hostname)
    rp=domain((options.get('rp') or {}).get('id',host) if operation=='create' else options.get('rpId',host))
    if host!=rp and not host.endswith('.'+rp):raise PasskeyError('Relying party does not match origin','SecurityError')
    if any(name in extensions for name in ('appid','prf','largeBlob','payment')):
        raise PasskeyError('Requested credential extension is unsupported','NotSupportedError')
    challenge=decode(options.get('challenge'),16,1024)
    if operation=='create':
        if not any(p.get('type')=='public-key' and p.get('alg')==-7 for p in options.get('pubKeyCredParams',[]) if isinstance(p,dict)):
            raise PasskeyError('ES256 is required','NotSupportedError')
        user=options.get('user') or {}
        decode(user.get('id'),1,64)
        if not isinstance(user.get('name'),str) or not 1<=len(user['name'])<=256:
            raise PasskeyError('A valid account name is required','DataError')
        if options.get('attestation')=='enterprise':raise PasskeyError('Enterprise attestation is unsupported','NotSupportedError')
    return rp,origin,challenge


def cbor(value):
    def header(major,n):
        if n<24:return bytes([major*32+n])
        if n<256:return bytes([major*32+24,n])
        if n<65536:return bytes([major*32+25])+n.to_bytes(2,'big')
        return bytes([major*32+26])+n.to_bytes(4,'big')
    if isinstance(value,int):return header(0,value) if value>=0 else header(1,-1-value)
    if isinstance(value,bytes):return header(2,len(value))+value
    if isinstance(value,str):return header(3,len(value.encode()))+value.encode()
    if isinstance(value,dict):return header(5,len(value))+b''.join(cbor(k)+cbor(v) for k,v in value.items())
    raise TypeError('Unsupported CBOR value')


def candidates(vault,options,rp):
    allow=options.get('allowCredentials') or []
    allowed={item.get('id') for item in allow if isinstance(item,dict) and item.get('type')=='public-key'}
    return [row for row in vault.active() if row.get('kind')=='passkey'
            and isinstance(row.get('passkey'),dict) and row['passkey'].get('rp_id')==rp
            and (not allow or row['passkey'].get('credential_id') in allowed)]


def client_data(operation,origin,challenge):
    return json.dumps(dict(type='webauthn.'+operation,challenge=encode(challenge),origin=origin,crossOrigin=False),separators=(',',':')).encode()


def create(vault,options,*,verified=False):
    if not verified or not vault.unlocked:raise PasskeyError('User verification is required')
    rp,origin,challenge=validate('create',options)
    excluded={e.get('id') for e in options.get('excludeCredentials',[]) if isinstance(e,dict) and e.get('type')=='public-key'}
    if any(e.get('passkey',{}).get('rp_id')==rp and e.get('passkey',{}).get('credential_id') in excluded for e in vault.active()):
        raise PasskeyError('Credential already exists','InvalidStateError')
    private=ec.generate_private_key(ec.SECP256R1());public=private.public_key();numbers=public.public_numbers()
    credential=secrets.token_bytes(32)
    auth=hashlib.sha256(rp.encode()).digest()+bytes([0x4d])+bytes(4)+bytes(16)+len(credential).to_bytes(2,'big')+credential
    auth+=cbor({1:2,3:-7,-1:1,-2:numbers.x.to_bytes(32,'big'),-3:numbers.y.to_bytes(32,'big')})
    client=client_data('create',origin,challenge)
    record=dict(title=rp,kind='passkey',url='https://'+rp,login=options['user']['name'],
        passkey=dict(rp_id=rp,credential_id=encode(credential),user_handle=options['user']['id'],
            private_key=encode(private.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))))
    row=vault.add(record)
    response=dict(id=encode(credential),rawId=encode(credential),type='public-key',authenticatorAttachment='platform',
        clientExtensionResults={'credProps':{'rk':True}} if (options.get('extensions') or {}).get('credProps') else {},
        response=dict(clientDataJSON=encode(client),authenticatorData=encode(auth),
            attestationObject=encode(cbor({'fmt':'none','attStmt':{},'authData':auth})),transports=['internal'],
            publicKeyAlgorithm=-7,publicKey=encode(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))))
    return row,response


def get(vault,options,entry_id,*,verified=False):
    if not verified or not vault.unlocked:raise PasskeyError('User verification is required')
    rp,origin,challenge=validate('get',options)
    row=next((e for e in candidates(vault,options,rp) if e['id']==entry_id),None)
    if row is None:raise PasskeyError('No matching passkey')
    data=row['passkey'];private=serialization.load_der_private_key(decode(data['private_key']),password=None)
    if not isinstance(private,ec.EllipticCurvePrivateKey) or not isinstance(private.curve,ec.SECP256R1):raise PasskeyError('Invalid key')
    client=client_data('get',origin,challenge)
    # Multi-device credential: no shared mutable counter; backup status is not claimed.
    auth=hashlib.sha256(rp.encode()).digest()+bytes([0x0d])+bytes(4)
    signature=private.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
    return dict(id=data['credential_id'],rawId=data['credential_id'],type='public-key',authenticatorAttachment='platform',
        clientExtensionResults={},response=dict(clientDataJSON=encode(client),authenticatorData=encode(auth),
            signature=encode(signature),userHandle=data['user_handle']))
