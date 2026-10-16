import copy
import json
import tempfile
import unittest
from pathlib import Path
import moi_paroli as m
import passkeys as p

def request(operation='create'):
    options=dict(challenge=p.encode(bytes(range(32))),extensions={'remoteDesktopClientOverride':{'origin':'https://example.test','sameOriginWithAncestors':True}})
    if operation=='create':options.update(rp=dict(id='example.test',name='Test'),user=dict(id=p.encode(b'test-user'),name='synthetic@example.test'),pubKeyCredParams=[dict(type='public-key',alg=-7)])
    else:options.update(rpId='example.test')
    return options

class PasskeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.vault=m.Vault(str(Path(self.tmp.name)/'vault.dat'));self.vault.create('SyntheticOnly!2026')

    def test_verification_is_mandatory_and_key_is_not_exported(self):
        with self.assertRaises(p.PasskeyError):p.create(self.vault,request())
        row,result=p.create(self.vault,request(),verified=True)
        self.assertEqual(row['kind'],'passkey')
        self.assertNotIn(row['passkey']['private_key'],json.dumps(result))
        disk=Path(self.vault.path).read_text()
        self.assertNotIn(row['passkey']['private_key'],disk)
        self.assertNotIn('synthetic@example.test',disk)
        self.vault.lock();self.vault.unlock('SyntheticOnly!2026')
        self.assertEqual(self.vault.get(row['id'])['passkey'],row['passkey'])

    def test_origin_mismatch_iframe_missing_origin_and_excluded_credential(self):
        for mutate in (
            lambda q:q['rp'].update(id='evil.test'),
            lambda q:q['extensions']['remoteDesktopClientOverride'].update(sameOriginWithAncestors=False),
            lambda q:q.update(extensions={}),
            lambda q:q.update(challenge='short'),
            lambda q:q.update(pubKeyCredParams=[dict(type='public-key',alg=-257)])):
            q=request();mutate(q)
            with self.assertRaises(p.PasskeyError):p.create(self.vault,q,verified=True)
        row,_=p.create(self.vault,request(),verified=True)
        q=request();q['excludeCredentials']=[dict(id=row['passkey']['credential_id'],type='public-key')]
        with self.assertRaises(p.PasskeyError) as error:p.create(self.vault,q,verified=True)
        self.assertEqual(error.exception.name,'InvalidStateError')

    def test_assertion_verified_by_independent_fido2_server(self):
        try:from fido2.server import Fido2Server
        except ImportError:self.skipTest('Independent FIDO2 verifier is an optional test dependency')
        server=Fido2Server(dict(id='example.test',name='Fixture'))
        options,state=server.register_begin(dict(id=b'synthetic-user',name='synthetic@example.test'),user_verification='required',resident_key_requirement='required')
        q=json.loads(json.dumps(dict(options)))['publicKey'];q['extensions']=request()['extensions']
        row,registration=p.create(self.vault,q,verified=True)
        auth=server.register_complete(state,registration)
        credential=auth.credential_data
        options,state=server.authenticate_begin([credential],user_verification='required')
        q=json.loads(json.dumps(dict(options)))['publicKey'];q['extensions']=request()['extensions']
        response=p.get(self.vault,q,row['id'],verified=True)
        self.assertEqual(server.authenticate_complete(state,[credential],response),credential)
        altered=copy.deepcopy(response);altered['response']['signature']=p.encode(bytes(64))
        with self.assertRaises(Exception):server.authenticate_complete(state,[credential],altered)

    def test_credentials_are_scoped_to_rp_and_csv_cannot_drop_private_keys(self):
        row,_=p.create(self.vault,request(),verified=True)
        q=request('get');q['rpId']='other.test';q['extensions']['remoteDesktopClientOverride']['origin']='https://other.test'
        with self.assertRaises(p.PasskeyError):p.get(self.vault,q,row['id'],verified=True)
        with self.assertRaises(ValueError):m.export_csv_text(self.vault.active())
        self.assertEqual(self.vault.audit(),[])
