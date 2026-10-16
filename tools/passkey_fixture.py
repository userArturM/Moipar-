"""Synthetic-only independent WebAuthn relying party and native core adapter."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData
from moi_paroli import Vault
import passkeys as p

folder=Path(sys.argv[1]);folder.mkdir(parents=True,exist_ok=True)
operation=sys.argv[2]
if operation=='certificate':
    import base64,hashlib
    from datetime import datetime,timedelta,timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'example.test')])
    now=datetime.now(timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('example.test')]),critical=False).sign(key,hashes.SHA256())
    (folder/'test-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (folder/'test-cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pin=base64.b64encode(hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
    print(json.dumps(dict(pin=pin)));sys.exit(0)
server=Fido2Server(dict(id='localhost',name='Synthetic RP'))
state_path=folder/'server-state.json'
if operation=='options_create':
    options,state=server.register_begin(dict(id=b'fixture-user',name='fixture@example.test',displayName='Synthetic account'),user_verification='required',resident_key_requirement='required')
    state_path.write_text(json.dumps(state),encoding='utf8');print(json.dumps(dict(options)))
elif operation=='options_get':
    credential=AttestedCredentialData(p.decode((folder/'public-credential.txt').read_text()))
    options,state=server.authenticate_begin([credential],user_verification='required')
    state_path.write_text(json.dumps(state),encoding='utf8');print(json.dumps(dict(options)))
elif operation.startswith('verify_'):
    response=json.load(sys.stdin);state=json.loads(state_path.read_text())
    if operation=='verify_create':
        auth=server.register_complete(state,response)
        (folder/'public-credential.txt').write_text(p.encode(bytes(auth.credential_data)))
    else:
        credential=AttestedCredentialData(p.decode((folder/'public-credential.txt').read_text()))
        server.authenticate_complete(state,[credential],response)
    print(json.dumps(dict(ok=True)))
else:
    message=json.load(sys.stdin)
    vault=Vault(str(folder/'synthetic-vault.dat'))
    if vault.exists():vault.unlock('SyntheticWebAuthnOnly!2026')
    else:vault.create('SyntheticWebAuthnOnly!2026')
    try:
        options=message['options']
        if operation=='create':_,response=p.create(vault,options,verified=True)
        else:
            rp,_,_=p.validate('get',options)
            rows=p.candidates(vault,options,rp)
            response=p.get(vault,options,rows[0]['id'],verified=True)
        print(json.dumps(dict(ok=True,credential=response)))
    finally:vault.lock()
